package laneshunt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	tempFilePrefix = ".laneshunt-"
	ioBufferSize   = 64 * 1024
)

// driftResetError 表示分段下载中途检测到远端文件变化或范围失效，需清空临时文件并从头重探。
type driftResetError struct {
	cause error
}

func (e *driftResetError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("remote resource changed mid-download: %v", e.cause)
	}
	return "remote resource changed mid-download"
}

func (e *driftResetError) Unwrap() error { return e.cause }

// progressEmitter 串行化进度回调，保证单调递增、不超过总字节数并在高频写入时按最小间隔节流。
type progressEmitter struct {
	mu          sync.Mutex
	onProgress  func(Progress)
	minInterval time.Duration
	lastEmitted int64
	lastEmitAt  time.Time
}

func newProgressEmitter(cb func(Progress), minInterval time.Duration) *progressEmitter {
	return &progressEmitter{
		onProgress:  cb,
		minInterval: minInterval,
	}
}

func (p *progressEmitter) report(bytesReceived, totalBytes int64) {
	if p.onProgress == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if totalBytes > 0 && bytesReceived > totalBytes {
		bytesReceived = totalBytes
	}
	if bytesReceived < 0 {
		bytesReceived = 0
	}
	if bytesReceived <= p.lastEmitted && bytesReceived > 0 {
		return
	}
	if bytesReceived == 0 && p.lastEmitted == 0 && totalBytes != 0 {
		return
	}
	now := time.Now()
	isFirst := p.lastEmitted == 0
	isComplete := totalBytes > 0 && bytesReceived >= totalBytes
	if !isFirst && !isComplete && p.minInterval > 0 && !p.lastEmitAt.IsZero() && now.Sub(p.lastEmitAt) < p.minInterval {
		return
	}
	p.lastEmitted = bytesReceived
	p.lastEmitAt = now
	p.onProgress(Progress{
		BytesReceived: bytesReceived,
		TotalBytes:    totalBytes,
		IsReset:       false,
	})
}

func (p *progressEmitter) reset(totalBytes int64) {
	if p.onProgress == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastEmitted = 0
	p.lastEmitAt = time.Time{}
	p.onProgress(Progress{
		BytesReceived: 0,
		TotalBytes:    totalBytes,
		IsReset:       true,
	})
}

// Downloader 是零第三方依赖的多连接弹性 HTTP 下载引擎。
type Downloader struct {
	cfg Config
}

// New 创建下载器实例并应用默认配置。
func New(cfg Config) *Downloader {
	return &Downloader{cfg: cfg.normalized()}
}

// Download 为便捷入口，按配置下载目标文件到指定路径。
func Download(ctx context.Context, rawURL string, destinationPath string, cfg Config) (Result, error) {
	return New(cfg).Download(ctx, rawURL, destinationPath)
}

// Download 将 rawURL 下载到 destinationPath，成功时原子落位，失败或取消时彻底清理临时文件。
func (d *Downloader) Download(ctx context.Context, rawURL string, destinationPath string) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := classifyParentOrTotalErr(ctx, ctx, nil); err != nil {
		return Result{}, err
	}

	if _, err := ValidateURL(rawURL, d.cfg.RequireHTTPS()); err != nil {
		return Result{}, err
	}

	cleanDest, parentDir, err := validateDestinationParent(destinationPath)
	if err != nil {
		return Result{}, err
	}

	totalCtx, totalCancel := context.WithTimeout(ctx, d.cfg.TotalTimeout)
	defer totalCancel()

	emitter := newProgressEmitter(d.cfg.OnProgress, d.cfg.progressMinInterval)

	skipProbe := (d.cfg.ExpectedSizeHint > 0 && d.cfg.ExpectedSizeHint < d.cfg.MinSegmentedSize) || d.cfg.MaxConnections <= 1
	if skipProbe {
		return d.downloadSingleStreamLoop(ctx, totalCtx, rawURL, cleanDest, parentDir, emitter, 1, 0, nil)
	}
	return d.downloadWithProbeLoop(ctx, totalCtx, rawURL, cleanDest, parentDir, emitter)
}

func createTempFile(parentDir string) (*os.File, error) {
	f, err := os.CreateTemp(parentDir, tempFilePrefix+"*.tmp")
	if err != nil {
		return nil, &FileIOError{Op: "create_temp", Cause: err}
	}
	return f, nil
}

func validateDestinationParent(destinationPath string) (cleanDest, parentDir string, err error) {
	cleanDest = filepath.Clean(strings.TrimSpace(destinationPath))
	if cleanDest == "" || cleanDest == "." {
		return "", "", &FileIOError{Op: "validate_destination", Cause: errors.New("empty destination path")}
	}
	parentDir = filepath.Dir(cleanDest)
	fi, lstatErr := os.Lstat(parentDir)
	if lstatErr != nil {
		return "", "", &FileIOError{Op: "lstat_parent", Cause: lstatErr}
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", "", &FileIOError{Op: "lstat_parent", Cause: errors.New("destination parent directory is a symlink")}
	}
	if !fi.IsDir() {
		return "", "", &FileIOError{Op: "lstat_parent", Cause: errors.New("destination parent is not a directory")}
	}
	return cleanDest, parentDir, nil
}

func finalizeTempFile(f *os.File, tempPath, destPath string, expectedSize int64) error {
	if expectedSize >= 0 {
		if err := f.Truncate(expectedSize); err != nil {
			cleanupTempFile(&f, tempPath)
			return &FileIOError{Op: "truncate", Cause: err}
		}
		st, err := f.Stat()
		if err != nil {
			cleanupTempFile(&f, tempPath)
			return &FileIOError{Op: "stat", Cause: err}
		}
		if st.Size() != expectedSize {
			cleanupTempFile(&f, tempPath)
			return &FileIOError{Op: "verify_size", Cause: fmt.Errorf("size mismatch: got %d, want %d", st.Size(), expectedSize)}
		}
	}
	if err := f.Sync(); err != nil {
		cleanupTempFile(&f, tempPath)
		return &FileIOError{Op: "sync", Cause: err}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tempPath)
		return &FileIOError{Op: "close", Cause: err}
	}
	_ = os.Remove(destPath)
	if err := os.Rename(tempPath, destPath); err != nil {
		_ = os.Remove(tempPath)
		return &FileIOError{Op: "rename", Cause: err}
	}
	return nil
}

func cleanupTempFile(f **os.File, tempPath string) {
	if f != nil && *f != nil {
		_ = (*f).Close()
		*f = nil
	}
	if tempPath != "" {
		_ = os.Remove(tempPath)
	}
}

func unknownOrHint(hint int64) int64 {
	if hint > 0 {
		return hint
	}
	return -1
}

// downloadWithProbeLoop 使用独立短生命周期探针发 GET Range: bytes=0-0，按响应能力路由至快路径、分段并发或单流复用/降级。
func (d *Downloader) downloadWithProbeLoop(
	parentCtx, totalCtx context.Context,
	rawURL, cleanDest, parentDir string,
	emitter *progressEmitter,
) (Result, error) {
	fullResetsUsed := 0
	attemptsTotal := 0
	var lastTransientErr error

	outerAttempt := 1
	for outerAttempt <= d.cfg.MaxAttempts {
		if err := classifyParentOrTotalErr(parentCtx, totalCtx, nil); err != nil {
			return Result{}, err
		}
		attemptsTotal++

		probe, fatalErr, transientErr := d.startHTTPAttempt(parentCtx, totalCtx, rawURL, "bytes=0-0", "")
		if fatalErr != nil {
			return Result{}, fatalErr
		}
		if transientErr != nil {
			lastTransientErr = transientErr
			if err := retryOrExhaust(parentCtx, totalCtx, outerAttempt, d.cfg.MaxAttempts, attemptsTotal, lastTransientErr, d.cfg.RetryDelay); err != nil {
				return Result{}, err
			}
			outerAttempt++
			continue
		}

		resp := probe.resp
		finalURL := probe.finalURL

		// 探针返回 200 OK 时直接复用当前响应流完成单流下载
		if resp.StatusCode == http.StatusOK {
			return d.downloadSingleStreamLoop(parentCtx, totalCtx, rawURL, cleanDest, parentDir, emitter, outerAttempt, attemptsTotal-1, probe)
		}

		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			cr, ok := parseContentRange(resp.Header.Get("Content-Range"))
			probe.close()
			if ok && cr.isUnsatisfied && cr.hasTotal && cr.total == 0 {
				f, createErr := createTempFile(parentDir)
				if createErr != nil {
					return Result{}, createErr
				}
				tempPath := f.Name()
				if finErr := finalizeTempFile(f, tempPath, cleanDest, 0); finErr != nil {
					return Result{}, finErr
				}
				emitter.report(0, 0)
				return Result{
					FinalURL:      finalURL,
					BytesWritten:  0,
					TotalBytes:    0,
					AttemptsUsed:  attemptsTotal,
					UsedSegmented: false,
				}, nil
			}
			// 非空文件探针收到 416 时，在同一次 attempt 内直接降级为无 Range 的单流 GET
			return d.downloadSingleStreamLoop(parentCtx, totalCtx, finalURL, cleanDest, parentDir, emitter, outerAttempt, attemptsTotal-1, nil)
		}

		if isRateLimitOrGatewayStatus(resp.StatusCode) || isRetryableServerStatus(resp.StatusCode) {
			waitDelay := retryDelayForStatus(resp, d.cfg)
			code := resp.StatusCode
			probe.close()
			lastTransientErr = &HTTPStatusError{StatusCode: code}
			if err := retryOrExhaust(parentCtx, totalCtx, outerAttempt, d.cfg.MaxAttempts, attemptsTotal, lastTransientErr, waitDelay); err != nil {
				return Result{}, err
			}
			outerAttempt++
			continue
		}

		if resp.StatusCode != http.StatusPartialContent {
			code := resp.StatusCode
			probe.close()
			return Result{}, &HTTPStatusError{StatusCode: code}
		}

		cr, crOK := parseContentRange(resp.Header.Get("Content-Range"))
		identityOK := isIdentityContentEncoding(resp.Header)
		multipart := isMultipartByteranges(resp.Header)

		if crOK && !cr.isUnsatisfied && cr.hasTotal && cr.total > d.cfg.MaxBytes {
			probe.close()
			return Result{}, &SizeLimitExceededError{Limit: d.cfg.MaxBytes, Actual: cr.total}
		}

		// 1 字节快路径（bytes 0-0/1 且无压缩编码），零额外请求直接落盘
		if crOK && !cr.isUnsatisfied && cr.hasTotal && cr.start == 0 && cr.end == 0 && cr.total == 1 && identityOK && !multipart && 1 <= d.cfg.MaxBytes {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 2))
			wasIdle := probe.wasIdle()
			probe.close()
			if readErr != nil {
				fatal, transient := classifyRequestError(parentCtx, totalCtx, readErr, wasIdle)
				if fatal != nil {
					return Result{}, fatal
				}
				lastTransientErr = transient
				if err := retryOrExhaust(parentCtx, totalCtx, outerAttempt, d.cfg.MaxAttempts, attemptsTotal, lastTransientErr, d.cfg.RetryDelay); err != nil {
					return Result{}, err
				}
				outerAttempt++
				continue
			}
			if int64(len(data)) > 1 {
				return Result{}, &SizeLimitExceededError{Limit: 1, Actual: int64(len(data))}
			}
			if len(data) != 1 {
				lastTransientErr = io.ErrUnexpectedEOF
				if err := retryOrExhaust(parentCtx, totalCtx, outerAttempt, d.cfg.MaxAttempts, attemptsTotal, lastTransientErr, d.cfg.RetryDelay); err != nil {
					return Result{}, err
				}
				outerAttempt++
				continue
			}
			f, createErr := createTempFile(parentDir)
			if createErr != nil {
				return Result{}, createErr
			}
			tempPath := f.Name()
			if _, wErr := f.WriteAt(data, 0); wErr != nil {
				cleanupTempFile(&f, tempPath)
				return Result{}, &FileIOError{Op: "write", Cause: wErr}
			}
			if finErr := finalizeTempFile(f, tempPath, cleanDest, 1); finErr != nil {
				return Result{}, finErr
			}
			emitter.report(1, 1)
			return Result{
				FinalURL:      finalURL,
				BytesWritten:  1,
				TotalBytes:    1,
				AttemptsUsed:  attemptsTotal,
				UsedSegmented: false,
			}, nil
		}

		strongVal := extractStrongValidator(resp.Header)
		probe.close()

		eligibleSegmented := crOK &&
			!cr.isUnsatisfied &&
			cr.hasTotal &&
			cr.start == 0 &&
			cr.end == 0 &&
			cr.total >= d.cfg.MinSegmentedSize &&
			cr.total <= d.cfg.MaxBytes &&
			identityOK &&
			!multipart &&
			strongVal.kind != validatorNone

		if !eligibleSegmented {
			// 不合格 206 在同一次 attempt 内直接降级为无 Range 单流 GET（不耗重试预算）
			return d.downloadSingleStreamLoop(parentCtx, totalCtx, finalURL, cleanDest, parentDir, emitter, outerAttempt, attemptsTotal-1, nil)
		}

		segErr := d.downloadSegmented(parentCtx, totalCtx, finalURL, cr.total, strongVal, cleanDest, parentDir, emitter)
		if segErr == nil {
			return Result{
				FinalURL:      finalURL,
				BytesWritten:  cr.total,
				TotalBytes:    cr.total,
				AttemptsUsed:  attemptsTotal,
				UsedSegmented: true,
			}, nil
		}

		var driftErr *driftResetError
		if errors.As(segErr, &driftErr) {
			fullResetsUsed++
			emitter.reset(-1)
			if fullResetsUsed > d.cfg.MaxFullResets {
				return Result{}, &RetriesExhaustedError{
					Attempts: fullResetsUsed,
					Cause:    driftErr.cause,
				}
			}
			if sleepErr := sleepWithContext(totalCtx, d.cfg.RetryDelay); sleepErr != nil {
				return Result{}, classifyParentOrTotalErr(parentCtx, totalCtx, sleepErr)
			}
			// 资源漂移重置拥有独立重置预算，不递增 outerAttempt
			continue
		}

		return Result{}, segErr
	}

	return Result{}, &RetriesExhaustedError{Attempts: attemptsTotal, Cause: lastTransientErr}
}
