package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	laneshunt "github.com/IAmKongHai/laneshunt/go"
)

func main() {
	var (
		conns    = flag.Int("conns", laneshunt.DefaultMaxConnections, "maximum concurrent HTTP/1.1 connections")
		chunk    = flag.Int64("chunk", laneshunt.DefaultChunkSize, "chunk size in bytes")
		maxBytes = flag.Int64("max-bytes", laneshunt.DefaultMaxBytes, "maximum allowed download size in bytes")
		insecure = flag.Bool("insecure", false, "allow plain http:// URLs")
		ua       = flag.String("ua", "", "custom User-Agent header")
		timeout  = flag.Duration("timeout", laneshunt.DefaultTotalTimeout, "total download timeout")
		bench    = flag.Bool("bench", false, "run local slow-lane loopback benchmark (http.Client vs laneshunt)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  laneshunt [flags] <url> <output>\n")
		fmt.Fprintf(os.Stderr, "  laneshunt -bench\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *bench {
		if err := runBenchmark(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	rawURL := flag.Arg(0)
	outputPath := flag.Arg(1)

	cfg := laneshunt.Config{
		MaxConnections:    *conns,
		ChunkSize:         *chunk,
		MaxBytes:          *maxBytes,
		AllowInsecureHTTP: *insecure,
		UserAgent:         *ua,
		TotalTimeout:      *timeout,
	}

	if err := runDownload(ctx, rawURL, outputPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\ndownload failed: %v\n", err)
		os.Exit(1)
	}
}

// runDownload 执行命令行下载并实时输出进度与最终汇总统计。
func runDownload(ctx context.Context, rawURL, outputPath string, cfg laneshunt.Config) error {
	start := time.Now()
	var printedProgress bool

	cfg.OnProgress = func(p laneshunt.Progress) {
		elapsed := time.Since(start)
		speed := bytesPerSec(p.BytesReceived, elapsed)
		if p.TotalBytes > 0 {
			pct := float64(p.BytesReceived) * 100.0 / float64(p.TotalBytes)
			fmt.Fprintf(os.Stderr, "\r[laneshunt] %s / %s (%.1f%%)  %s/s",
				formatBytes(p.BytesReceived), formatBytes(p.TotalBytes), pct, formatBytes(int64(speed)))
		} else {
			fmt.Fprintf(os.Stderr, "\r[laneshunt] %s  %s/s",
				formatBytes(p.BytesReceived), formatBytes(int64(speed)))
		}
		printedProgress = true
	}

	res, err := laneshunt.Download(ctx, rawURL, outputPath, cfg)
	if printedProgress {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		return err
	}

	elapsed := time.Since(start)
	mode := "single-stream"
	if res.UsedSegmented {
		mode = "segmented"
	}
	avgSpeed := bytesPerSec(res.BytesWritten, elapsed)

	fmt.Printf("Saved:      %s\n", outputPath)
	fmt.Printf("Final URL:  %s\n", res.FinalURL)
	fmt.Printf("Mode:       %s\n", mode)
	fmt.Printf("Bytes:      %d (%s)\n", res.BytesWritten, formatBytes(res.BytesWritten))
	fmt.Printf("Elapsed:    %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Avg Speed:  %s/s\n", formatBytes(int64(avgSpeed)))
	return nil
}

// runBenchmark 启动本地回环模拟慢道服务器（4 条 ~20 KB/s 慢道 + 2 条 ~512 KB/s 快道，轮换新连接为快道），
// 对比标准单连接 http.Client 与 laneshunt.Download，并校验两者落盘文件的 SHA-256。
func runBenchmark(ctx context.Context) error {
	const (
		payloadSize = 4 << 20 // 4 MiB
		slowSpeed   = 20 * 1024
		fastSpeed   = 512 * 1024
	)

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i*31 + 17) & 0xff)
	}
	wantSum := sha256.Sum256(payload)
	wantSHA := hex.EncodeToString(wantSum[:])

	var (
		mu        sync.Mutex
		connRoles = make(map[string]string)
		connOrder int
	)
	resetServerLanes := func() {
		mu.Lock()
		connRoles = make(map[string]string)
		connOrder = 0
		mu.Unlock()
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHdr := r.Header.Get("Range")
		if rangeHdr == "bytes=0-0" {
			w.Header().Set("ETag", `"bench-v1"`)
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-0/%d", len(payload)))
			w.Header().Set("Content-Length", "1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[:1])
			return
		}

		mu.Lock()
		role, exists := connRoles[r.RemoteAddr]
		if !exists {
			connOrder++
			switch {
			case connOrder <= 2:
				role = "fast"
			case connOrder <= 6:
				role = "slow"
			default:
				role = "fast"
			}
			connRoles[r.RemoteAddr] = role
		}
		mu.Unlock()

		speed := fastSpeed
		if role == "slow" {
			speed = slowSpeed
		}

		w.Header().Set("ETag", `"bench-v1"`)
		w.Header().Set("Accept-Ranges", "bytes")

		if rangeHdr == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			writeThrottled(w, r, payload, speed)
			return
		}

		start, end, ok := parseSimpleRange(rangeHdr, int64(len(payload)))
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(payload)))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		slice := payload[start : end+1]
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
		w.WriteHeader(http.StatusPartialContent)
		writeThrottled(w, r, slice, speed)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen loopback: %w", err)
	}
	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	url := "http://" + ln.Addr().String() + "/bench-4mib.bin"
	tmpDir, err := os.MkdirTemp("", "laneshunt-bench-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("LaneShunt Local Slow-Lane Benchmark\n")
	fmt.Printf("Payload: 4 MiB | Simulated lanes: 2 fast (~512 KB/s) + 4 throttled (~20 KB/s), rotated lanes fast\n\n")

	// 1. 标准单连接 http.Client
	resetServerLanes()
	stdOut := filepath.Join(tmpDir, "std.bin")
	fmt.Printf("Running standard http.Client...\n")
	stdStart := time.Now()
	stdBytes, err := downloadWithStdHTTP(ctx, url, stdOut)
	if err != nil {
		return fmt.Errorf("standard http.Client failed: %w", err)
	}
	stdElapsed := time.Since(stdStart)
	stdSHA, err := fileSHA256(stdOut)
	if err != nil {
		return err
	}
	if stdSHA != wantSHA {
		return fmt.Errorf("standard http.Client SHA-256 mismatch: got %s want %s", stdSHA, wantSHA)
	}

	// 2. laneshunt.Download（6 并发连接）
	resetServerLanes()
	lsOut := filepath.Join(tmpDir, "laneshunt.bin")
	fmt.Printf("Running laneshunt.Download (6 connections)...\n")
	lsStart := time.Now()
	lsRes, err := laneshunt.Download(ctx, url, lsOut, laneshunt.Config{
		AllowInsecureHTTP: true,
		MaxConnections:    6,
		ChunkSize:         256 << 10,
	})
	if err != nil {
		return fmt.Errorf("laneshunt.Download failed: %w", err)
	}
	lsElapsed := time.Since(lsStart)
	lsSHA, err := fileSHA256(lsOut)
	if err != nil {
		return err
	}
	if lsSHA != wantSHA {
		return fmt.Errorf("laneshunt.Download SHA-256 mismatch: got %s want %s", lsSHA, wantSHA)
	}

	stdRate := bytesPerSec(stdBytes, stdElapsed)
	lsRate := bytesPerSec(lsRes.BytesWritten, lsElapsed)
	speedup := stdElapsed.Seconds() / lsElapsed.Seconds()

	fmt.Println()
	fmt.Printf("%-22s  %10s  %12s  %8s  %s\n", "Client", "Elapsed", "Avg Speed", "SHA-256", "Mode")
	fmt.Printf("%-22s  %10s  %12s  %8s  %s\n", strings.Repeat("-", 22), strings.Repeat("-", 10), strings.Repeat("-", 12), strings.Repeat("-", 8), strings.Repeat("-", 14))
	fmt.Printf("%-22s  %10s  %10s/s  %8s  %s\n",
		"net/http (1 conn)", stdElapsed.Round(time.Millisecond), formatBytes(int64(stdRate)), "OK", "single-stream")
	mode := "single-stream"
	if lsRes.UsedSegmented {
		mode = "segmented (6)"
	}
	fmt.Printf("%-22s  %10s  %10s/s  %8s  %s\n",
		"laneshunt", lsElapsed.Round(time.Millisecond), formatBytes(int64(lsRate)), "OK", mode)
	fmt.Printf("\nSpeedup: %.2fx | Verified SHA-256: %s\n", speedup, wantSHA[:16]+"...")
	return nil
}

func downloadWithStdHTTP(ctx context.Context, rawURL, outPath string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func writeThrottled(w http.ResponseWriter, r *http.Request, data []byte, speedBytesPerSec int) {
	flusher, _ := w.(http.Flusher)
	step := 4096
	if speedBytesPerSec < 32*1024 {
		step = 1024
	}
	interval := time.Duration(float64(step) / float64(speedBytesPerSec) * float64(time.Second))
	if interval < 2*time.Millisecond {
		interval = 2 * time.Millisecond
	}
	for off := 0; off < len(data); off += step {
		end := min(off+step, len(data))
		if _, err := w.Write(data[off:end]); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		timer := time.NewTimer(interval)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func parseSimpleRange(rangeHdr string, total int64) (int64, int64, bool) {
	if !strings.HasPrefix(rangeHdr, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(rangeHdr, "bytes=")
	dash := strings.IndexByte(spec, '-')
	if dash <= 0 {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(spec[:dash], 10, 64)
	if err != nil || start < 0 || start >= total {
		return 0, 0, false
	}
	end := total - 1
	if spec[dash+1:] != "" {
		parsedEnd, err := strconv.ParseInt(spec[dash+1:], 10, 64)
		if err != nil || parsedEnd < start {
			return 0, 0, false
		}
		if parsedEnd < end {
			end = parsedEnd
		}
	}
	return start, end, true
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func bytesPerSec(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / d.Seconds()
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
