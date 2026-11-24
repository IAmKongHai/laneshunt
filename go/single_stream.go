package laneshunt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

// downloadSingleStreamLoop 在外层 MaxAttempts 预算内执行单流下载与基于 Range + If-Range 的断点续传。
func (d *Downloader) downloadSingleStreamLoop(
	parentCtx, totalCtx context.Context,
	rawURL, cleanDest, parentDir string,
	emitter *progressEmitter,
	startAttempt int,
	priorAttempts int,
	reused *httpAttempt,
) (Result, error) {
	f, err := createTempFile(parentDir)
	if err != nil {
		reused.close()
		return Result{}, err
	}
	tempPath := f.Name()
	success := false
	defer func() {
		if !success {
			cleanupTempFile(&f, tempPath)
		}
	}()

	var (
		currentOffset    int64
		lockedTotal      int64 = -1
		ifRangeToken     string
		resumeStrongVal  lockedValidator
		lastTransientErr error
		attemptsUsed     = priorAttempts
		buf              = make([]byte, ioBufferSize)
	)

	for attempt := startAttempt; attempt <= d.cfg.MaxAttempts; attempt++ {
		if err := classifyParentOrTotalErr(parentCtx, totalCtx, nil); err != nil {
			reused.close()
			reused = nil
			return Result{}, err
		}
		attemptsUsed++

		var cur *httpAttempt
		if reused != nil {
			cur = reused
			reused = nil
		} else {
			// 未持有强校验器（弱 ETag 或缺失强校验器）时禁止盲发 Range 续传，必须清空临时文件从头完整拉取
			if currentOffset > 0 && resumeStrongVal.kind == validatorNone {
				if truncErr := f.Truncate(0); truncErr != nil {
					return Result{}, &FileIOError{Op: "truncate", Cause: truncErr}
				}
				currentOffset = 0
				lockedTotal = -1
				ifRangeToken = ""
				emitter.reset(unknownOrHint(d.cfg.ExpectedSizeHint))
			}

			var rangeHdr, ifRangeHdr string
			if currentOffset > 0 {
				rangeHdr = fmt.Sprintf("bytes=%d-", currentOffset)
				ifRangeHdr = ifRangeToken
			}
			var fatalErr, transientErr error
			cur, fatalErr, transientErr = d.startHTTPAttempt(parentCtx, totalCtx, rawURL, rangeHdr, ifRangeHdr)
			if fatalErr != nil {
				return Result{}, fatalErr
			}
			if transientErr != nil {
				lastTransientErr = transientErr
				if err := retryOrExhaust(parentCtx, totalCtx, attempt, d.cfg.MaxAttempts, attemptsUsed, lastTransientErr, d.cfg.RetryDelay); err != nil {
					return Result{}, err
				}
				continue
			}
		}

		resp := cur.resp
		finalURL := cur.finalURL
		crossOrigin := cur.crossOrigin

		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			cr, ok := parseContentRange(resp.Header.Get("Content-Range"))
			cur.close()
			if currentOffset == 0 && ok && cr.isUnsatisfied && cr.hasTotal && cr.total == 0 {
				if finErr := finalizeTempFile(f, tempPath, cleanDest, 0); finErr != nil {
					f = nil
					return Result{}, finErr
				}
				f = nil
				success = true
				emitter.report(0, 0)
				return Result{
					FinalURL:      finalURL,
					BytesWritten:  0,
					TotalBytes:    0,
					AttemptsUsed:  attemptsUsed,
					UsedSegmented: false,
				}, nil
			}
			if currentOffset > 0 {
				if truncErr := f.Truncate(0); truncErr != nil {
					return Result{}, &FileIOError{Op: "truncate", Cause: truncErr}
				}
				currentOffset = 0
				lockedTotal = -1
				ifRangeToken = ""
				resumeStrongVal = lockedValidator{}
				emitter.reset(unknownOrHint(d.cfg.ExpectedSizeHint))
				lastTransientErr = &HTTPStatusError{StatusCode: http.StatusRequestedRangeNotSatisfiable}
				if err := retryOrExhaust(parentCtx, totalCtx, attempt, d.cfg.MaxAttempts, attemptsUsed, lastTransientErr, d.cfg.RetryDelay); err != nil {
					return Result{}, err
				}
				continue
			}
			return Result{}, &HTTPStatusError{StatusCode: resp.StatusCode}
		}

		if isRateLimitOrGatewayStatus(resp.StatusCode) || isRetryableServerStatus(resp.StatusCode) {
			waitDelay := retryDelayForStatus(resp, d.cfg)
			code := resp.StatusCode
			cur.close()
			lastTransientErr = &HTTPStatusError{StatusCode: code}
			if err := retryOrExhaust(parentCtx, totalCtx, attempt, d.cfg.MaxAttempts, attemptsUsed, lastTransientErr, waitDelay); err != nil {
				return Result{}, err
			}
			continue
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			code := resp.StatusCode
			cur.close()
			return Result{}, &HTTPStatusError{StatusCode: code}
		}

		var (
			totalBytes         int64 = -1
			expectedBodyLen    int64 = -1
			authoritativeTotal int64 = -1
		)

		if resp.StatusCode == http.StatusPartialContent {
			// 未发送 Range 请求却收到非预期 206 时立即拒绝，避免无界或截断落盘
			if currentOffset == 0 {
				cur.close()
				return Result{}, &HTTPStatusError{StatusCode: http.StatusPartialContent}
			}
			cr, crOK := parseContentRange(resp.Header.Get("Content-Range"))
			if crOK && !cr.isUnsatisfied {
				if cr.hasTotal && cr.total > d.cfg.MaxBytes {
					cur.close()
					return Result{}, &SizeLimitExceededError{Limit: d.cfg.MaxBytes, Actual: cr.total}
				}
				if cr.end >= d.cfg.MaxBytes {
					actual := int64(math.MaxInt64)
					if cr.end < math.MaxInt64 {
						actual = cr.end + 1
					}
					cur.close()
					return Result{}, &SizeLimitExceededError{Limit: d.cfg.MaxBytes, Actual: actual}
				}
			}
			validResume := crOK &&
				!cr.isUnsatisfied &&
				cr.start == currentOffset &&
				isIdentityContentEncoding(resp.Header) &&
				!isMultipartByteranges(resp.Header)
			if validResume && lockedTotal >= 0 && cr.hasTotal && cr.total != lockedTotal {
				validResume = false
			}
			if validResume && resumeStrongVal.kind != validatorNone {
				hasRespValidator := strings.TrimSpace(resp.Header.Get("ETag")) != "" ||
					strings.TrimSpace(resp.Header.Get("Last-Modified")) != ""
				if crossOrigin || hasRespValidator {
					validResume = resumeStrongVal.matchesResponse(resp.Header)
				}
			}
			if !validResume {
				cur.close()
				if truncErr := f.Truncate(0); truncErr != nil {
					return Result{}, &FileIOError{Op: "truncate", Cause: truncErr}
				}
				currentOffset = 0
				lockedTotal = -1
				ifRangeToken = ""
				resumeStrongVal = lockedValidator{}
				emitter.reset(unknownOrHint(d.cfg.ExpectedSizeHint))
				lastTransientErr = errors.New("invalid or mismatched 206 resume response")
				if err := retryOrExhaust(parentCtx, totalCtx, attempt, d.cfg.MaxAttempts, attemptsUsed, lastTransientErr, d.cfg.RetryDelay); err != nil {
					return Result{}, err
				}
				continue
			}

			expectedBodyLen = cr.end - cr.start + 1
			if cr.hasTotal {
				totalBytes = cr.total
				authoritativeTotal = cr.total
				if lockedTotal < 0 {
					lockedTotal = cr.total
				}
			} else if lockedTotal >= 0 {
				totalBytes = lockedTotal
				authoritativeTotal = lockedTotal
			} else if resp.ContentLength >= 0 && resp.ContentLength <= d.cfg.MaxBytes-currentOffset {
				totalBytes = currentOffset + resp.ContentLength
			} else {
				totalBytes = unknownOrHint(d.cfg.ExpectedSizeHint)
			}
		} else {
			if resp.ContentLength > d.cfg.MaxBytes {
				actual := resp.ContentLength
				cur.close()
				return Result{}, &SizeLimitExceededError{Limit: d.cfg.MaxBytes, Actual: actual}
			}
			identityOK := isIdentityContentEncoding(resp.Header)
			if resp.ContentLength >= 0 {
				totalBytes = resp.ContentLength
				expectedBodyLen = resp.ContentLength
				if identityOK {
					lockedTotal = resp.ContentLength
					authoritativeTotal = resp.ContentLength
				} else {
					lockedTotal = -1
				}
			} else {
				totalBytes = unknownOrHint(d.cfg.ExpectedSizeHint)
				lockedTotal = -1
			}
			if currentOffset > 0 {
				if truncErr := f.Truncate(0); truncErr != nil {
					cur.close()
					return Result{}, &FileIOError{Op: "truncate", Cause: truncErr}
				}
				currentOffset = 0
				emitter.reset(totalBytes)
			}
			if identityOK {
				if sv := extractStrongValidator(resp.Header); sv.kind != validatorNone {
					resumeStrongVal = sv
					ifRangeToken = sv.value
				} else {
					ifRangeToken = ""
					resumeStrongVal = lockedValidator{}
				}
			} else {
				ifRangeToken = ""
				resumeStrongVal = lockedValidator{}
			}
		}

		var bodyRead int64
		var readFailed error
		for {
			n, rErr := resp.Body.Read(buf)
			if n > 0 {
				cur.resetIdle(d.cfg.SingleStreamIdleTimeout)
				if currentOffset+int64(n) > d.cfg.MaxBytes {
					actual := currentOffset + int64(n)
					cur.close()
					return Result{}, &SizeLimitExceededError{Limit: d.cfg.MaxBytes, Actual: actual}
				}
				if expectedBodyLen >= 0 && bodyRead+int64(n) > expectedBodyLen {
					actual := bodyRead + int64(n)
					cur.close()
					return Result{}, &SizeLimitExceededError{Limit: expectedBodyLen, Actual: actual}
				}
				if _, wErr := f.WriteAt(buf[:n], currentOffset); wErr != nil {
					cur.close()
					return Result{}, &FileIOError{Op: "write", Cause: wErr}
				}
				currentOffset += int64(n)
				bodyRead += int64(n)
				emitter.report(currentOffset, totalBytes)
			}
			if rErr == io.EOF {
				if expectedBodyLen >= 0 && bodyRead < expectedBodyLen {
					readFailed = io.ErrUnexpectedEOF
				}
				break
			}
			if rErr != nil {
				readFailed = rErr
				break
			}
		}

		if readFailed == nil {
			cur.close()
			// 若服务端返回限长 206 导致本轮正常 EOF 但尚未达完整总长，继续续传剩余区间，严禁提前截断落盘
			if authoritativeTotal > 0 && currentOffset < authoritativeTotal {
				lastTransientErr = io.ErrUnexpectedEOF
				delay := d.cfg.RetryDelay
				if bodyRead > 0 {
					delay = 0
				}
				if err := retryOrExhaust(parentCtx, totalCtx, attempt, d.cfg.MaxAttempts, attemptsUsed, lastTransientErr, delay); err != nil {
					return Result{}, err
				}
				continue
			}
			if finErr := finalizeTempFile(f, tempPath, cleanDest, currentOffset); finErr != nil {
				f = nil
				return Result{}, finErr
			}
			f = nil
			success = true
			emitter.report(currentOffset, currentOffset)
			return Result{
				FinalURL:      finalURL,
				BytesWritten:  currentOffset,
				TotalBytes:    currentOffset,
				AttemptsUsed:  attemptsUsed,
				UsedSegmented: false,
			}, nil
		}

		wasIdle := cur.wasIdle()
		cur.close()

		fatal, transient := classifyRequestError(parentCtx, totalCtx, readFailed, wasIdle)
		if fatal != nil {
			return Result{}, fatal
		}
		lastTransientErr = transient
		if err := retryOrExhaust(parentCtx, totalCtx, attempt, d.cfg.MaxAttempts, attemptsUsed, lastTransientErr, d.cfg.RetryDelay); err != nil {
			return Result{}, err
		}
	}

	return Result{}, &RetriesExhaustedError{Attempts: attemptsUsed, Cause: lastTransientErr}
}
