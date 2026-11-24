package laneshunt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memWriterAt struct {
	mu  sync.Mutex
	buf []byte
}

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy(m.buf[off:], p)
	return len(p), nil
}

func makeDeterministicPayload(size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte((i*31 + 17) & 0xff)
	}
	return buf
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// serveByteRange 按标准 HTTP 字节范围语义响应 206/200/416 请求，便于在多场景单测中复用。
func serveByteRange(w http.ResponseWriter, r *http.Request, payload []byte, etag string, lastMod string, extraDelay func(start, end int64)) {
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if lastMod != "" {
		w.Header().Set("Last-Modified", lastMod)
	}
	w.Header().Set("Accept-Ranges", "bytes")

	rangeHdr := r.Header.Get("Range")
	if rangeHdr == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return
	}

	if !strings.HasPrefix(rangeHdr, "bytes=") {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	spec := strings.TrimPrefix(rangeHdr, "bytes=")
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if len(payload) == 0 {
		w.Header().Set("Content-Range", "bytes */0")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	start, err := strconv.ParseInt(spec[:dash], 10, 64)
	if err != nil || start < 0 || start >= int64(len(payload)) {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(payload)))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	end := int64(len(payload) - 1)
	if spec[dash+1:] != "" {
		parsedEnd, err := strconv.ParseInt(spec[dash+1:], 10, 64)
		if err != nil || parsedEnd < start {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(payload)))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if parsedEnd < end {
			end = parsedEnd
		}
	}

	if extraDelay != nil {
		extraDelay(start, end)
	}
	slice := payload[start : end+1]
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
	w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(slice)
}

func assertNoLeftoverTempFiles(t *testing.T, dir string, allowedName string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.Name() == allowedName {
			continue
		}
		if strings.HasPrefix(e.Name(), tempFilePrefix) || strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("unexpected leftover temp file: %s", e.Name())
		}
	}
}

func TestParseContentRangeAndValidators(t *testing.T) {
	cr, ok := parseContentRange("bytes 0-0/1048576")
	if !ok || cr.isUnsatisfied || cr.start != 0 || cr.end != 0 || cr.total != 1048576 {
		t.Fatalf("unexpected parseContentRange result: %+v ok=%v", cr, ok)
	}
	cr, ok = parseContentRange("bytes */0")
	if !ok || !cr.isUnsatisfied || cr.total != 0 {
		t.Fatalf("expected unsatisfied zero-byte range, got %+v ok=%v", cr, ok)
	}
	if _, ok := parseContentRange("bytes 10-5/20"); ok {
		t.Fatal("expected inverted range to fail")
	}
	if _, ok := parseContentRange("bytes 0-20/20"); ok {
		t.Fatal("expected end >= total to fail")
	}

	hStrong := http.Header{"Etag": []string{`"v1-strong"`}}
	v := extractStrongValidator(hStrong)
	if v.kind != validatorStrongETag || !v.matchesResponse(hStrong) {
		t.Fatalf("expected strong ETag validator, got %+v", v)
	}
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	hWeak := http.Header{
		"Etag":          []string{`W/"v1-weak"`},
		"Date":          []string{now.Format(http.TimeFormat)},
		"Last-Modified": []string{now.Add(-90 * time.Second).Format(http.TimeFormat)},
	}
	if vw := extractStrongValidator(hWeak); vw.kind != validatorNone {
		t.Fatalf("expected weak ETag to be rejected without Last-Modified fallback, got %+v", vw)
	}

	hOldLM := http.Header{
		"Date":          []string{now.Format(http.TimeFormat)},
		"Last-Modified": []string{now.Add(-90 * time.Second).Format(http.TimeFormat)},
	}
	vLM := extractStrongValidator(hOldLM)
	if vLM.kind != validatorSafeLastModified || !vLM.matchesResponse(hOldLM) {
		t.Fatalf("expected safe Last-Modified validator, got %+v", vLM)
	}
	hOldLMWithETag := hOldLM.Clone()
	hOldLMWithETag.Set("ETag", `"unexpected-etag"`)
	if vLM.matchesResponse(hOldLMWithETag) {
		t.Fatal("expected Last-Modified validator to reject response with unexpected ETag")
	}
	hFreshLM := http.Header{
		"Date":          []string{now.Format(http.TimeFormat)},
		"Last-Modified": []string{now.Add(-30 * time.Second).Format(http.TimeFormat)},
	}
	if vFresh := extractStrongValidator(hFreshLM); vFresh.kind != validatorNone {
		t.Fatalf("expected fresh Last-Modified (<60s) to be rejected, got %+v", vFresh)
	}

	if d, ok := parseRetryAfter("12", now, 60*time.Second); !ok || d != 12*time.Second {
		t.Fatalf("expected 12s, got %v ok=%v", d, ok)
	}
	if d, ok := parseRetryAfter("180", now, 60*time.Second); !ok || d != 60*time.Second {
		t.Fatalf("expected 60s cap, got %v ok=%v", d, ok)
	}
	if d, ok := parseRetryAfter(now.Add(15*time.Second).Format(http.TimeFormat), now, 60*time.Second); !ok || d != 15*time.Second {
		t.Fatalf("expected 15s from HTTP-date, got %v ok=%v", d, ok)
	}
}

func TestIsolatedHTTP1TransportClearsALPNAndHandlesNilTransport(t *testing.T) {
	baseTr := http.DefaultTransport.(*http.Transport).Clone()
	baseTr.ForceAttemptHTTP2 = true
	baseTr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	slot := newIsolatedHTTP1Client(&http.Client{Transport: baseTr}, true, 10, 5*time.Second, nil)
	defer slot.closeIdle()

	if slot.transport == nil {
		t.Fatal("expected cloned *http.Transport")
	}
	if slot.transport == baseTr {
		t.Fatal("expected isolated cloned transport, got shared pointer")
	}
	if !hasHTTP1OnlyProtocols(slot.transport) {
		t.Fatalf("expected HTTP/1-only Protocols")
	}
	if slot.transport.ForceAttemptHTTP2 {
		t.Fatal("expected ForceAttemptHTTP2 == false")
	}
	if slot.transport.TLSClientConfig == nil || len(slot.transport.TLSClientConfig.NextProtos) != 1 || slot.transport.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected TLSClientConfig.NextProtos=[http/1.1], got %+v", slot.transport.TLSClientConfig)
	}
	if len(baseTr.TLSClientConfig.NextProtos) != 2 || baseTr.TLSClientConfig.NextProtos[0] != "h2" {
		t.Fatalf("base transport NextProtos mutated: %v", baseTr.TLSClientConfig.NextProtos)
	}

	// BaseClient.Transport == nil（如 http.DefaultClient）不得触发 nil 解引用 panic
	nilSlot := newIsolatedHTTP1Client(http.DefaultClient, true, 10, 5*time.Second, nil)
	defer nilSlot.closeIdle()
	if nilSlot.transport == nil || !nilSlot.transport.DisableCompression {
		t.Fatalf("expected cloned default transport for nil BaseClient.Transport, got %+v", nilSlot.transport)
	}
}

func TestChunkLedgerFirstWriterWinsTailHedge(t *testing.T) {
	const totalSize = 512 * 1024
	const chunkSize = 256 * 1024
	ledger := newChunkLedger(totalSize, chunkSize, 4, 2, 0, 0)
	if ledger.chunkCount() != 2 {
		t.Fatalf("expected 2 chunks, got %d", ledger.chunkCount())
	}

	now := time.Now()
	c0 := ledger.claim(0, nil, now, nil)
	c1 := ledger.claim(1, nil, now, nil)
	if c0.kind != claimWork || c1.kind != claimWork || c0.chunkIndex != 0 || c1.chunkIndex != 1 {
		t.Fatalf("unexpected initial claims: %+v %+v", c0, c1)
	}

	hedge := ledger.claim(2, func() bool { return true }, now, func(slot int) float64 {
		if slot == 0 {
			return 1000
		}
		return 500000
	})
	if hedge.kind != claimWork || !hedge.isHedge || hedge.chunkIndex != 0 {
		t.Fatalf("expected hedge on slowest chunk 0, got %+v", hedge)
	}

	var loserCanceled bool
	ledger.registerAttemptCancel(0, c0.attemptID, func() { loserCanceled = true })
	ledger.registerAttemptCancel(0, hedge.attemptID, func() {})

	mem := &memWriterAt{buf: make([]byte, totalSize)}
	wantChunk0 := bytes.Repeat([]byte("A"), chunkSize)

	res1, err := ledger.commitBytes(0, c0.attemptID, mem, 0, wantChunk0[:chunkSize/2])
	if err != nil || res1.bytesAdded != chunkSize/2 || res1.chunkDone {
		t.Fatalf("unexpected primary commit: %+v err=%v", res1, err)
	}
	res2, err := ledger.commitBytes(0, hedge.attemptID, mem, 0, wantChunk0)
	if err != nil || res2.bytesAdded != chunkSize/2 || !res2.chunkDone || res2.progressBytes != chunkSize {
		t.Fatalf("unexpected hedge commit: %+v err=%v", res2, err)
	}
	for _, fn := range res2.loserCancels {
		fn()
	}
	if !loserCanceled {
		t.Fatal("expected loser attempt cancel to be invoked")
	}
	if !bytes.Equal(mem.buf[:chunkSize], wantChunk0) {
		t.Fatal("chunk 0 bytes mismatch")
	}
}

// TestHTTP2PreventionAndMultipleTCPPorts 验证面对启用 HTTP/2（ALPN h2, http/1.1）的 TLS 源站，
// 从带残留 NextProtos=["h2","http/1.1"] 的默认 Transport 克隆后能强制回退 HTTP/1.1 并建立多条独立 TCP 套接字。
func TestHTTP2PreventionAndMultipleTCPPorts(t *testing.T) {
	payload := makeDeterministicPayload(2 << 20) // 2 MiB
	wantSHA := sha256Hex(payload)

	var (
		mu          sync.Mutex
		phase       = "control"
		ctrlPorts   = make(map[string]struct{})
		ctrlProtos  = make(map[int]int)
		dlPorts     = make(map[string]struct{})
		dlProtos    = make(map[int]int)
		inFlightBar = make(chan struct{})
		barOnce     sync.Once
		activeCount int32
	)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		curPhase := phase
		if curPhase == "control" {
			ctrlPorts[r.RemoteAddr] = struct{}{}
			ctrlProtos[r.ProtoMajor]++
		} else {
			dlPorts[r.RemoteAddr] = struct{}{}
			dlProtos[r.ProtoMajor]++
		}
		mu.Unlock()

		// 略微延迟非探针分片响应，确保并发多槽位同时处于在途态
		var delayFn func(start, end int64)
		if curPhase == "downloader" && r.Header.Get("Range") != "bytes=0-0" {
			delayFn = func(start, end int64) {
				if atomic.AddInt32(&activeCount, 1) >= 2 {
					barOnce.Do(func() { close(inFlightBar) })
				}
				select {
				case <-inFlightBar:
					time.Sleep(15 * time.Millisecond)
				case <-time.After(150 * time.Millisecond):
				}
			}
		}
		serveByteRange(w, r, payload, `"h2-test-etag"`, "", delayFn)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	// 构造带 Go 1.27 已初始化 NextProtos=["h2","http/1.1"] 特征的共享基础 Transport
	srvTLS := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	srvTLS.NextProtos = []string{"h2", "http/1.1"}
	h2BaseTr := http.DefaultTransport.(*http.Transport).Clone()
	h2BaseTr.ForceAttemptHTTP2 = true
	h2BaseTr.TLSClientConfig = srvTLS
	h2Client := &http.Client{Transport: h2BaseTr}
	defer h2BaseTr.CloseIdleConnections()

	// 对照组：先发 1 个预热请求建立 HTTP/2 连接，再并发 4 请求，确认默认共享客户端复用为单条 TCP/HTTP2 连接
	if resp, err := h2Client.Get(srv.URL + "/pkg.bin"); err != nil {
		t.Fatalf("control warmup failed: %v", err)
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	var ctrlWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		ctrlWg.Add(1)
		go func() {
			defer ctrlWg.Done()
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/pkg.bin", nil)
			req.Header.Set("Range", "bytes=0-1023")
			resp, err := h2Client.Do(req)
			if err != nil {
				t.Errorf("control request failed: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	ctrlWg.Wait()

	mu.Lock()
	if ctrlProtos[2] == 0 || len(ctrlPorts) != 1 {
		mu.Unlock()
		t.Fatalf("control group expected HTTP/2 coalesced to 1 port, got protos=%v ports=%d", ctrlProtos, len(ctrlPorts))
	}
	phase = "downloader"
	mu.Unlock()

	// 实验组：使用同一带 h2 NextProtos 的 h2Client 作为 BaseClient，以 MaxConnections=4 下载 2 MiB
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "out.bin")
	res, err := Download(context.Background(), srv.URL+"/pkg.bin", dest, Config{
		BaseClient:     h2Client,
		MaxConnections: 4,
		ChunkSize:      256 << 10,
	})
	if err != nil {
		t.Fatalf("downloader failed against HTTP/2 server: %v", err)
	}
	if !res.UsedSegmented || res.BytesWritten != int64(len(payload)) {
		t.Fatalf("unexpected download result: %+v", res)
	}

	gotBytes, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if sha256Hex(gotBytes) != wantSHA {
		t.Fatalf("SHA-256 mismatch")
	}

	mu.Lock()
	defer mu.Unlock()
	if dlProtos[2] != 0 || dlProtos[1] == 0 {
		t.Fatalf("expected all downloader requests over HTTP/1.1, got protos=%v", dlProtos)
	}
	if len(dlPorts) <= 1 {
		t.Fatalf("expected >1 distinct TCP source ports, got %d", len(dlPorts))
	}
	assertNoLeftoverTempFiles(t, tmpDir, "out.bin")
}

// TestSegmentedOutOfOrderWriteAtAndMonotonicProgress 验证并发乱序分块写盘字节精确且进度严格单调不超 100%。
func TestSegmentedOutOfOrderWriteAtAndMonotonicProgress(t *testing.T) {
	payload := makeDeterministicPayload((1 << 20) + 33333) // 1 MiB + 非整块尾字节
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveByteRange(w, r, payload, `"out-of-order-v1"`, "", func(start, end int64) {
			// 让靠前的分块稍慢、靠后的分块更快，制造并发乱序 WriteAt
			if start == 0 && end > 0 {
				time.Sleep(40 * time.Millisecond)
			} else if start == 256<<10 {
				time.Sleep(25 * time.Millisecond)
			}
		})
	}))
	defer srv.Close()

	var (
		progMu   sync.Mutex
		progress []Progress
	)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "installer.exe")
	res, err := Download(context.Background(), srv.URL+"/installer.exe", dest, Config{
		BaseClient:     srv.Client(),
		MaxConnections: 4,
		ChunkSize:      256 << 10,
		OnProgress: func(p Progress) {
			progMu.Lock()
			progress = append(progress, p)
			progMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("segmented download failed: %v", err)
	}
	if !res.UsedSegmented || res.BytesWritten != int64(len(payload)) {
		t.Fatalf("unexpected result: %+v", res)
	}

	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("file content mismatch: err=%v len=%d", err, len(got))
	}

	progMu.Lock()
	defer progMu.Unlock()
	if len(progress) == 0 {
		t.Fatal("expected progress callbacks")
	}
	var prev int64 = -1
	for _, p := range progress {
		if p.IsReset {
			t.Fatalf("unexpected reset progress: %+v", p)
		}
		if p.BytesReceived < prev || p.BytesReceived > int64(len(payload)) {
			t.Fatalf("non-monotonic or out-of-bounds progress: prev=%d cur=%+v", prev, p)
		}
		prev = p.BytesReceived
	}
	if prev != int64(len(payload)) {
		t.Fatalf("expected final progress == %d, got %d", len(payload), prev)
	}
	assertNoLeftoverTempFiles(t, tmpDir, "installer.exe")
}

// TestSmallPayloadSingleStreamResumeAndProbe200Reuse 验证小文件直通单流续传/416 重置以及未知大小探针 200 OK 零额外请求复用。
func TestSmallPayloadSingleStreamResumeAndProbe200Reuse(t *testing.T) {
	t.Run("small_payload_skips_probe_and_resumes", func(t *testing.T) {
		payload := makeDeterministicPayload(128 << 10)
		splitAt := len(payload) / 2
		var reqCount int32
		var gotRange, gotIfRange atomic.Value

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			w.Header().Set("ETag", `"small-v1"`)
			if n == 1 {
				if r.Header.Get("Range") != "" {
					t.Errorf("expected small payload to skip probe, got Range=%q", r.Header.Get("Range"))
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload[:splitAt])
				w.(http.Flusher).Flush()
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
				return
			}
			gotRange.Store(r.Header.Get("Range"))
			gotIfRange.Store(r.Header.Get("If-Range"))
			serveByteRange(w, r, payload, `"small-v1"`, "", nil)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "small.bin")
		res, err := Download(context.Background(), srv.URL+"/small.bin", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: int64(len(payload)),
			RetryDelay:       10 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("small resume failed: %v", err)
		}
		if res.UsedSegmented || atomic.LoadInt32(&reqCount) != 2 {
			t.Fatalf("expected single-stream with 2 requests, got res=%+v reqs=%d", res, reqCount)
		}
		if got, _ := gotRange.Load().(string); got != fmt.Sprintf("bytes=%d-", splitAt) {
			t.Fatalf("unexpected Range header: %q", got)
		}
		if got, _ := gotIfRange.Load().(string); got != `"small-v1"` {
			t.Fatalf("unexpected If-Range header: %q", got)
		}
		gotBytes, _ := os.ReadFile(dest)
		if !bytes.Equal(gotBytes, payload) {
			t.Fatal("resumed payload mismatch")
		}
	})

	t.Run("small_payload_416_resets_and_retries", func(t *testing.T) {
		oldPayload := makeDeterministicPayload(64 << 10)
		newPayload := makeDeterministicPayload(80 << 10)
		var reqCount int32

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			switch n {
			case 1:
				w.Header().Set("ETag", `"old-416-v1"`)
				w.Header().Set("Content-Length", strconv.Itoa(len(oldPayload)))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(oldPayload[:len(oldPayload)/2])
				w.(http.Flusher).Flush()
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
			case 2:
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			default:
				if r.Header.Get("Range") != "" {
					t.Errorf("expected no Range after 416 reset, got %q", r.Header.Get("Range"))
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(newPayload)))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(newPayload)
			}
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "reset416.bin")
		_, err := Download(context.Background(), srv.URL+"/file", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: int64(len(oldPayload)),
			RetryDelay:       10 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("expected recovery after 416: %v", err)
		}
		if got := atomic.LoadInt32(&reqCount); got != 3 {
			t.Fatalf("expected 3 requests, got %d", got)
		}
		gotBytes, _ := os.ReadFile(dest)
		if !bytes.Equal(gotBytes, newPayload) {
			t.Fatal("payload mismatch after 416 reset")
		}
	})

	t.Run("unknown_size_probe_200_reuses_stream_single_request", func(t *testing.T) {
		payload := makeDeterministicPayload(1500 << 10)
		var reqCount int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqCount, 1)
			// 忽略 Range: bytes=0-0，直接返回 200 OK 全量流
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "reuse200.bin")
		res, err := Download(context.Background(), srv.URL+"/reuse", dest, Config{
			BaseClient: srv.Client(),
		})
		if err != nil {
			t.Fatalf("probe 200 reuse failed: %v", err)
		}
		if res.UsedSegmented || atomic.LoadInt32(&reqCount) != 1 {
			t.Fatalf("expected 1 request single-stream reuse, got res=%+v reqs=%d", res, reqCount)
		}
		gotBytes, _ := os.ReadFile(dest)
		if !bytes.Equal(gotBytes, payload) {
			t.Fatal("reused 200 stream payload mismatch")
		}
	})
}

// TestProtocolEdgeCases 覆盖 0/1 字节文件、不合格 206 零成本降级、超限保护、截短 206、nil Transport、编码/multipart 拒绝、Last-Modified 锁定与 404/403 立即失败。
func TestProtocolEdgeCases(t *testing.T) {
	t.Run("zero_byte_file_416_star_0", func(t *testing.T) {
		var reqs int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqs, 1)
			w.Header().Set("Content-Range", "bytes */0")
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "empty.bin")
		res, err := Download(context.Background(), srv.URL+"/empty", dest, Config{BaseClient: srv.Client()})
		if err != nil || res.BytesWritten != 0 || atomic.LoadInt32(&reqs) != 1 {
			t.Fatalf("unexpected 0-byte result: res=%+v err=%v reqs=%d", res, err, reqs)
		}
		data, err := os.ReadFile(dest)
		if err != nil || len(data) != 0 {
			t.Fatalf("expected 0-byte file, got len=%d err=%v", len(data), err)
		}
	})

	t.Run("one_byte_fast_path_single_request", func(t *testing.T) {
		var reqs int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqs, 1)
			w.Header().Set("Content-Range", "bytes 0-0/1")
			w.Header().Set("Content-Length", "1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{'Z'})
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "one.bin")
		res, err := Download(context.Background(), srv.URL+"/one", dest, Config{BaseClient: srv.Client()})
		if err != nil || res.BytesWritten != 1 || atomic.LoadInt32(&reqs) != 1 {
			t.Fatalf("unexpected 1-byte result: res=%+v err=%v reqs=%d", res, err, reqs)
		}
		data, _ := os.ReadFile(dest)
		if !bytes.Equal(data, []byte{'Z'}) {
			t.Fatalf("expected 'Z', got %q", data)
		}
	})

	t.Run("weak_etag_zero_cost_downgrade_same_attempt", func(t *testing.T) {
		payload := makeDeterministicPayload(1200 << 10)
		var reqs int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqs, 1)
			if n == 1 {
				serveByteRange(w, r, payload, `W/"weak-etag"`, "", nil)
				return
			}
			if r.Header.Get("Range") != "" {
				t.Errorf("expected plain GET without Range after downgrade, got %q", r.Header.Get("Range"))
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "weak.bin")
		res, err := Download(context.Background(), srv.URL+"/weak", dest, Config{
			BaseClient:  srv.Client(),
			MaxAttempts: 1, // 证明降级发生在同一次 attempt 内、未消耗重试预算
		})
		if err != nil || res.UsedSegmented || atomic.LoadInt32(&reqs) != 2 {
			t.Fatalf("unexpected weak ETag downgrade result: res=%+v err=%v reqs=%d", res, err, reqs)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("payload mismatch after weak ETag downgrade")
		}
	})

	t.Run("fresh_last_modified_under_60s_downgrades", func(t *testing.T) {
		payload := makeDeterministicPayload(1200 << 10)
		var reqs int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqs, 1)
			freshLM := time.Now().UTC().Add(-10 * time.Second).Format(http.TimeFormat)
			if n == 1 {
				serveByteRange(w, r, payload, "", freshLM, nil)
				return
			}
			if r.Header.Get("Range") != "" {
				t.Errorf("expected plain GET without Range, got %q", r.Header.Get("Range"))
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "freshlm.bin")
		res, err := Download(context.Background(), srv.URL+"/fresh", dest, Config{
			BaseClient:  srv.Client(),
			MaxAttempts: 1,
		})
		if err != nil || res.UsedSegmented || atomic.LoadInt32(&reqs) != 2 {
			t.Fatalf("unexpected fresh Last-Modified result: res=%+v err=%v reqs=%d", res, err, reqs)
		}
	})

	t.Run("size_limit_exceeded_probe_and_stream", func(t *testing.T) {
		var reqs int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqs, 1)
			w.Header().Set("ETag", `"huge"`)
			w.Header().Set("Content-Range", "bytes 0-0/10485760")
			w.Header().Set("Content-Length", "1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{'x'})
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "huge.bin")
		_, err := Download(context.Background(), srv.URL+"/huge", dest, Config{
			BaseClient: srv.Client(),
			MaxBytes:   2 << 20,
		})
		if !errors.Is(err, ErrSizeLimitExceeded) || atomic.LoadInt32(&reqs) != 1 {
			t.Fatalf("expected immediate SizeLimitExceeded in 1 request, got err=%v reqs=%d", err, reqs)
		}

		// 流式 200 无 Content-Length 超发保护
		streamSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(makeDeterministicPayload(200 << 10))
		}))
		defer streamSrv.Close()

		_, err = Download(context.Background(), streamSrv.URL+"/stream", filepath.Join(t.TempDir(), "s.bin"), Config{
			BaseClient: streamSrv.Client(),
			MaxBytes:   64 << 10,
		})
		if !errors.Is(err, ErrSizeLimitExceeded) {
			t.Fatalf("expected stream SizeLimitExceeded, got %v", err)
		}
	})

	t.Run("truncated_206_completes_tail_without_overflow", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		var truncatedOnce atomic.Bool
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-262143" && truncatedOnce.CompareAndSwap(false, true) {
				// 只返回前 100 KiB，测试截短 206 后精准补拉剩余尾段
				subEnd := int64(100<<10) - 1
				w.Header().Set("ETag", `"trunc-v1"`)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", subEnd, len(payload)))
				w.Header().Set("Content-Length", strconv.FormatInt(subEnd+1, 10))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(payload[:subEnd+1])
				return
			}
			serveByteRange(w, r, payload, `"trunc-v1"`, "", nil)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "trunc.bin")
		res, err := Download(context.Background(), srv.URL+"/trunc", dest, Config{
			BaseClient:     srv.Client(),
			MaxConnections: 3,
			ChunkSize:      256 << 10,
		})
		if err != nil || !res.UsedSegmented {
			t.Fatalf("expected truncated 206 to succeed: res=%+v err=%v", res, err)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("truncated 206 final bytes mismatch")
		}
	})

	t.Run("nil_base_client_transport_no_panic", func(t *testing.T) {
		payload := []byte("hello-default-client")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "def.bin")
		_, err := Download(context.Background(), srv.URL+"/def", dest, Config{
			BaseClient:        http.DefaultClient, // Transport == nil
			AllowInsecureHTTP: true,
			ExpectedSizeHint:  int64(len(payload)),
		})
		if err != nil {
			t.Fatalf("nil Transport BaseClient failed: %v", err)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("payload mismatch with http.DefaultClient")
		}
	})

	t.Run("reject_chunk_gzip_and_multipart", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		for _, mode := range []string{"gzip", "multipart"} {
			t.Run(mode, func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Range") == "bytes=0-0" {
						serveByteRange(w, r, payload, `"proto-v1"`, "", nil)
						return
					}
					if mode == "gzip" {
						w.Header().Set("Content-Encoding", "gzip")
					} else {
						w.Header().Set("Content-Type", "multipart/byteranges; boundary=abc")
					}
					serveByteRange(w, r, payload, `"proto-v1"`, "", nil)
				}))
				defer srv.Close()

				dest := filepath.Join(t.TempDir(), mode+".bin")
				_, err := Download(context.Background(), srv.URL+"/p", dest, Config{
					BaseClient:    srv.Client(),
					MaxFullResets: 1,
					RetryDelay:    5 * time.Millisecond,
				})
				if err == nil {
					t.Fatalf("expected error for %s chunk 206", mode)
				}
				if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
					t.Fatalf("expected no destination file written on %s rejection", mode)
				}
			})
		}
	})

	t.Run("locked_last_modified_consistent_and_reset_on_change", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		oldLM := time.Now().UTC().Add(-10 * time.Minute).Format(http.TimeFormat)

		// 一致时正常分段完成
		okSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveByteRange(w, r, payload, "", oldLM, nil)
		}))
		defer okSrv.Close()

		dest := filepath.Join(t.TempDir(), "lm-ok.bin")
		res, err := Download(context.Background(), okSrv.URL+"/lm", dest, Config{
			BaseClient:     okSrv.Client(),
			MaxConnections: 4,
		})
		if err != nil || !res.UsedSegmented {
			t.Fatalf("expected Last-Modified segmented success, got res=%+v err=%v", res, err)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("Last-Modified payload mismatch")
		}

		// 中途 Last-Modified 变更或缺失时触发全量重置并下回新版
		newPayload := makeDeterministicPayload((1 << 20) + 1234)
		newLM := time.Now().UTC().Add(-5 * time.Minute).Format(http.TimeFormat)
		var switched atomic.Bool
		var resets int32
		driftSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if switched.Load() {
				serveByteRange(w, r, newPayload, "", newLM, nil)
				return
			}
			if r.Header.Get("Range") != "bytes=0-0" && strings.HasPrefix(r.Header.Get("Range"), "bytes=262144-") {
				switched.Store(true)
				// 返回缺失 Last-Modified 的 206 触发校验器漂移重置
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 262144-524287/%d", len(payload)))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(payload[262144:524288])
				return
			}
			serveByteRange(w, r, payload, "", oldLM, nil)
		}))
		defer driftSrv.Close()

		dest2 := filepath.Join(t.TempDir(), "lm-drift.bin")
		_, err = Download(context.Background(), driftSrv.URL+"/lm", dest2, Config{
			BaseClient:     driftSrv.Client(),
			MaxConnections: 4,
			RetryDelay:     5 * time.Millisecond,
			OnProgress: func(p Progress) {
				if p.IsReset {
					atomic.AddInt32(&resets, 1)
				}
			},
		})
		if err != nil {
			t.Fatalf("expected Last-Modified drift recovery, got %v", err)
		}
		if atomic.LoadInt32(&resets) == 0 {
			t.Fatal("expected IsReset callback on Last-Modified drift")
		}
		got2, _ := os.ReadFile(dest2)
		if !bytes.Equal(got2, newPayload) {
			t.Fatal("expected new payload after Last-Modified drift reset")
		}
	})

	t.Run("per_chunk_oversized_body_rejected", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-0" {
				serveByteRange(w, r, payload, `"over-v1"`, "", nil)
				return
			}
			// 按请求的合法区间声明 Content-Range，但采用分块传输多发 64 字节，验证硬上限立即报 SizeLimitExceededError
			spec := strings.TrimPrefix(r.Header.Get("Range"), "bytes=")
			parts := strings.Split(spec, "-")
			start, _ := strconv.ParseInt(parts[0], 10, 64)
			end, _ := strconv.ParseInt(parts[1], 10, 64)
			w.Header().Set("ETag", `"over-v1"`)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[start : end+1])
			_, _ = w.Write(bytes.Repeat([]byte("X"), 64))
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "over.bin")
		_, err := Download(context.Background(), srv.URL+"/over", dest, Config{
			BaseClient:     srv.Client(),
			MaxConnections: 2,
		})
		if !errors.Is(err, ErrSizeLimitExceeded) {
			t.Fatalf("expected ErrSizeLimitExceeded on oversized chunk body, got %v", err)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("destination file must not exist on oversized chunk failure")
		}
	})

	t.Run("deterministic_404_403_single_request", func(t *testing.T) {
		for _, code := range []int{http.StatusNotFound, http.StatusForbidden} {
			var reqs int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reqs, 1)
				w.WriteHeader(code)
			}))
			_, err := Download(context.Background(), srv.URL+"/missing", filepath.Join(t.TempDir(), "x"), Config{
				BaseClient: srv.Client(),
			})
			srv.Close()
			var statusErr *HTTPStatusError
			if !errors.As(err, &statusErr) || statusErr.StatusCode != code {
				t.Fatalf("expected HTTPStatusError(%d), got %v", code, err)
			}
			if got := atomic.LoadInt32(&reqs); got != 1 {
				t.Fatalf("expected 1 request on HTTP %d, got %d", code, got)
			}
		}
	})
}

// TestRedirectSecurity 验证 https->http 明文降级立即拦截、跨源 https 重定向头语义与强校验器复检以及超跳拦截。
func TestRedirectSecurity(t *testing.T) {
	t.Run("https_to_http_downgrade_blocked_immediately", func(t *testing.T) {
		plainHit := int32(0)
		plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&plainHit, 1)
			_, _ = w.Write([]byte("insecure"))
		}))
		defer plainSrv.Close()

		var tlsReqs int32
		tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&tlsReqs, 1)
			http.Redirect(w, r, plainSrv.URL+"/dl", http.StatusFound)
		}))
		defer tlsSrv.Close()

		_, err := Download(context.Background(), tlsSrv.URL+"/start", filepath.Join(t.TempDir(), "out"), Config{
			BaseClient: tlsSrv.Client(),
		})
		if !errors.Is(err, ErrInsecureRedirect) {
			t.Fatalf("expected ErrInsecureRedirect, got %v", err)
		}
		if atomic.LoadInt32(&tlsReqs) != 1 || atomic.LoadInt32(&plainHit) != 0 {
			t.Fatalf("expected 1 TLS request and 0 HTTP hits, got tls=%d http=%d", tlsReqs, plainHit)
		}
	})

	t.Run("cross_origin_https_redirect_preserves_range_strips_if_range_and_verifies_validator", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		oldLM := time.Now().UTC().Add(-10 * time.Minute).Format(http.TimeFormat)

		for _, useLastMod := range []bool{false, true} {
			name := "strong_etag"
			etag := `"cross-origin-v1"`
			lm := ""
			if useLastMod {
				name = "last_modified"
				etag = ""
				lm = oldLM
			}
			t.Run(name, func(t *testing.T) {
				var (
					sawRange   atomic.Value
					sawAccept  atomic.Value
					sawIfRange atomic.Value
					sawCookie  atomic.Value
					sawAuth    atomic.Value
					sawReferer atomic.Value
				)
				cdnSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Range") != "bytes=0-0" {
						sawRange.Store(r.Header.Get("Range"))
						sawAccept.Store(r.Header.Get("Accept-Encoding"))
						sawIfRange.Store(r.Header.Get("If-Range"))
						sawCookie.Store(r.Header.Get("Cookie"))
						sawAuth.Store(r.Header.Get("Authorization"))
						sawReferer.Store(r.Header.Get("Referer"))
					}
					serveByteRange(w, r, payload, etag, lm, nil)
				}))
				defer cdnSrv.Close()

				// 源站对探针直接返回 206（令 lockedURL 停留在 origin），随后对分片请求 302 跳转至不同端口的 cdnSrv（跨源！）
				originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Range") == "bytes=0-0" {
						serveByteRange(w, r, payload, etag, lm, nil)
						return
					}
					http.Redirect(w, r, cdnSrv.URL+"/cdn-file", http.StatusFound)
				}))
				defer originSrv.Close()

				// 信任两个测试自签证书
				combinedTr := originSrv.Client().Transport.(*http.Transport).Clone()
				combinedTr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
				defer combinedTr.CloseIdleConnections()

				dest := filepath.Join(t.TempDir(), name+".bin")
				res, err := Download(context.Background(), originSrv.URL+"/origin-file", dest, Config{
					BaseClient:     &http.Client{Transport: combinedTr},
					MaxConnections: 2,
				})
				if err != nil || !res.UsedSegmented {
					t.Fatalf("cross-origin segmented download failed: res=%+v err=%v", res, err)
				}
				if got, _ := sawRange.Load().(string); !strings.HasPrefix(got, "bytes=") {
					t.Fatalf("expected Range preserved across cross-origin redirect, got %q", got)
				}
				if got, _ := sawAccept.Load().(string); got != "identity" {
					t.Fatalf("expected Accept-Encoding: identity preserved, got %q", got)
				}
				if got, _ := sawIfRange.Load().(string); got != "" {
					t.Fatalf("expected If-Range stripped on cross-origin redirect, got %q", got)
				}
				if got, _ := sawCookie.Load().(string); got != "" {
					t.Fatalf("expected Cookie stripped, got %q", got)
				}
				if got, _ := sawAuth.Load().(string); got != "" {
					t.Fatalf("expected Authorization stripped, got %q", got)
				}
				if got, _ := sawReferer.Load().(string); got != "" {
					t.Fatalf("expected Referer stripped, got %q", got)
				}
				gotBytes, _ := os.ReadFile(dest)
				if !bytes.Equal(gotBytes, payload) {
					t.Fatal("cross-origin payload mismatch")
				}
			})
		}
	})

	t.Run("cross_origin_validator_mismatch_rejected", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		cdnSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 跨源目标返回不一致的强 ETag，必须触发校验器漂移拒绝而非盲目拼接
			serveByteRange(w, r, payload, `"mismatched-etag"`, "", nil)
		}))
		defer cdnSrv.Close()

		originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-0" {
				serveByteRange(w, r, payload, `"origin-etag"`, "", nil)
				return
			}
			http.Redirect(w, r, cdnSrv.URL+"/cdn", http.StatusFound)
		}))
		defer originSrv.Close()

		tr := originSrv.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		defer tr.CloseIdleConnections()

		dest := filepath.Join(t.TempDir(), "mismatch.bin")
		_, err := Download(context.Background(), originSrv.URL+"/orig", dest, Config{
			BaseClient:     &http.Client{Transport: tr},
			MaxConnections: 2,
			MaxFullResets:  1,
			RetryDelay:     5 * time.Millisecond,
		})
		if err == nil {
			t.Fatal("expected error when cross-origin redirect returns mismatched validator")
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("destination file must not exist on cross-origin validator mismatch")
		}
	})

	t.Run("exported_safe_redirect_checker_blocks_downgrade_and_strips_sensitive_headers", func(t *testing.T) {
		var sawAuth, sawCookie, sawReferer, sawIfRange atomic.Value
		targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawAuth.Store(r.Header.Get("Authorization"))
			sawCookie.Store(r.Header.Get("Cookie"))
			sawReferer.Store(r.Header.Get("Referer"))
			sawIfRange.Store(r.Header.Get("If-Range"))
			w.WriteHeader(http.StatusOK)
		}))
		defer targetSrv.Close()

		originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, targetSrv.URL+"/dest", http.StatusFound)
		}))
		defer originSrv.Close()

		tr := originSrv.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		defer tr.CloseIdleConnections()

		client := &http.Client{
			Transport:     tr,
			CheckRedirect: NewSafeRedirectChecker(true, 3),
		}
		req, _ := http.NewRequest(http.MethodGet, originSrv.URL+"/start", nil)
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Cookie", "sid=123")
		req.Header.Set("Referer", originSrv.URL+"/ref")
		req.Header.Set("If-Range", `"etag-1"`)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("expected valid https cross-origin redirect to succeed, got %v", err)
		}
		_ = resp.Body.Close()

		if v, _ := sawAuth.Load().(string); v != "" {
			t.Fatalf("expected Authorization stripped, got %q", v)
		}
		if v, _ := sawCookie.Load().(string); v != "" {
			t.Fatalf("expected Cookie stripped, got %q", v)
		}
		if v, _ := sawReferer.Load().(string); v != "" {
			t.Fatalf("expected Referer stripped, got %q", v)
		}
		if v, _ := sawIfRange.Load().(string); v != "" {
			t.Fatalf("expected If-Range stripped, got %q", v)
		}
	})

	t.Run("too_many_redirects", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
		}))
		defer srv.Close()

		_, err := Download(context.Background(), srv.URL+"/loop", filepath.Join(t.TempDir(), "loop"), Config{
			BaseClient:   srv.Client(),
			MaxRedirects: 3,
		})
		if !errors.Is(err, ErrTooManyRedirects) {
			t.Fatalf("expected ErrTooManyRedirects, got %v", err)
		}
	})
}

// TestMidDownloadDriftReset 验证分段下载中途远端文件替换后，中止全部兄弟协程、清空临时文件、复位进度并完整下回新版本。
func TestMidDownloadDriftReset(t *testing.T) {
	v1 := makeDeterministicPayload(1536 << 10) // 1.5 MiB (6 chunks)
	v2 := makeDeterministicPayload(1792 << 10) // 1.75 MiB (7 chunks, 新内容与新总长)
	for i := range v2 {
		v2[i] ^= 0x5A
	}

	var (
		version atomic.Int32
		chunks  atomic.Int32
	)
	version.Store(1)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version.Load() == 2 {
			serveByteRange(w, r, v2, `"release-v2"`, "", nil)
			return
		}
		if r.Header.Get("Range") != "bytes=0-0" {
			// 完成超过 50%（3 个分块）后原地切换远端资源为 v2
			if chunks.Add(1) >= 4 {
				version.Store(2)
				serveByteRange(w, r, v2, `"release-v2"`, "", nil)
				return
			}
		}
		serveByteRange(w, r, v1, `"release-v1"`, "", nil)
	}))
	defer srv.Close()

	var (
		progMu    sync.Mutex
		sawReset  bool
		maxBefore int64
	)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "update.exe")
	res, err := Download(context.Background(), srv.URL+"/release-pkg.bin", dest, Config{
		BaseClient:     srv.Client(),
		MaxConnections: 3,
		ChunkSize:      256 << 10,
		RetryDelay:     10 * time.Millisecond,
		OnProgress: func(p Progress) {
			progMu.Lock()
			if p.IsReset {
				sawReset = true
			} else if !sawReset && p.BytesReceived > maxBefore {
				maxBefore = p.BytesReceived
			}
			progMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("drift reset recovery failed: %v", err)
	}
	if !res.UsedSegmented || res.BytesWritten != int64(len(v2)) {
		t.Fatalf("expected v2 segmented result, got %+v", res)
	}
	progMu.Lock()
	if !sawReset || maxBefore == 0 {
		progMu.Unlock()
		t.Fatalf("expected progress advance then reset: sawReset=%v maxBefore=%d", sawReset, maxBefore)
	}
	progMu.Unlock()

	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, v2) {
		t.Fatalf("expected exact v2 payload after reset: err=%v len=%d", err, len(got))
	}
	assertNoLeftoverTempFiles(t, tmpDir, "update.exe")
}

// throttledWrite 按固定字节/秒节奏流式写出，并在请求取消时立刻退出。
func throttledWrite(w http.ResponseWriter, r *http.Request, data []byte, bytesPerSec int) {
	flusher, _ := w.(http.Flusher)
	step := 4096
	if bytesPerSec < 16*1024 {
		step = 1024
	}
	interval := time.Duration(float64(step) / float64(bytesPerSec) * float64(time.Second))
	if interval < 5*time.Millisecond {
		interval = 5 * time.Millisecond
	}
	for off := 0; off < len(data); off += step {
		end := off + step
		if end > len(data) {
			end = len(data)
		}
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

// TestSlowStreamRotationAndBoundedScout 覆盖慢流相对轮换（验证新 TCP 端口）、均匀高丢包保并发、窄带热点缩并发至 2 与零字节假死看门狗。
func TestSlowStreamRotationAndBoundedScout(t *testing.T) {
	t.Run("scenario_a_4_slow_2_fast_retains_baseline_and_rotates_new_port", func(t *testing.T) {
		payload := makeDeterministicPayload(3 << 20) // 12 chunks of 256 KiB

		var (
			mu          sync.Mutex
			connRoles   = make(map[string]string) // RemoteAddr -> "fast" | "slow"
			connOrder   int
			slowPorts   = make(map[string]struct{})
			allPorts    = make(map[string]struct{})
			rotatedSeen atomic.Bool
		)

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-0" {
				serveByteRange(w, r, payload, `"scen-a"`, "", nil)
				return
			}
			mu.Lock()
			role, exists := connRoles[r.RemoteAddr]
			if !exists {
				connOrder++
				allPorts[r.RemoteAddr] = struct{}{}
				if connOrder <= 2 {
					role = "fast"
				} else if connOrder <= 6 {
					role = "slow"
					slowPorts[r.RemoteAddr] = struct{}{}
				} else {
					// 第 7 条及以上代表慢槽轮换后新建的全新 TCP 连接，恢复高速
					role = "fast"
					rotatedSeen.Store(true)
				}
				connRoles[r.RemoteAddr] = role
			}
			mu.Unlock()

			spec := strings.TrimPrefix(r.Header.Get("Range"), "bytes=")
			parts := strings.Split(spec, "-")
			start, _ := strconv.ParseInt(parts[0], 10, 64)
			end, _ := strconv.ParseInt(parts[1], 10, 64)
			slice := payload[start : end+1]
			w.Header().Set("ETag", `"scen-a"`)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
			w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
			w.WriteHeader(http.StatusPartialContent)

			if role == "slow" {
				throttledWrite(w, r, slice, 10*1024)
			} else {
				throttledWrite(w, r, slice, 900*1024)
			}
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "scenA.bin")
		res, err := Download(context.Background(), srv.URL+"/scenA", dest, Config{
			BaseClient:           srv.Client(),
			MaxConnections:       6,
			ChunkSize:            256 << 10,
			warmupGrace:          100 * time.Millisecond,
			rateWindow:           200 * time.Millisecond,
			refHighSpeedWindow:   10 * time.Second,
			relativeSlowDuration: 180 * time.Millisecond,
			slotRotateCooldown:   300 * time.Millisecond,
			globalRotateCooldown: 100 * time.Millisecond,
			watchdogInterval:     40 * time.Millisecond,
			ChunkStallTimeout:    5 * time.Second,
		})
		if err != nil || !res.UsedSegmented {
			t.Fatalf("scenario A failed: res=%+v err=%v", res, err)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("scenario A payload mismatch")
		}
		mu.Lock()
		totalDistinctPorts := len(allPorts)
		mu.Unlock()
		if !rotatedSeen.Load() || totalDistinctPorts <= 6 {
			t.Fatalf("expected slow slots to rotate onto new TCP ports (>6), got totalPorts=%d rotatedSeen=%v", totalDistinctPorts, rotatedSeen.Load())
		}
	})

	t.Run("scenario_b_uniform_slow_high_aggregate_stops_scouting_and_keeps_concurrency", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MaxConnections = 6
		cfg.warmupGrace = 100 * time.Millisecond
		cfg.rateWindow = 200 * time.Millisecond
		cfg.scoutTriggerDuration = 150 * time.Millisecond
		cfg.scoutCooldown = 150 * time.Millisecond
		cfg.maxScouts = 2

		base := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
		tracker := newSpeedTracker(cfg, 6, base)
		ledger := newChunkLedger(6<<20, 256<<10, 6, 2, 0, 0)

		var reasons [6]atomic.Int32
		for i := 0; i < 6; i++ {
			tracker.startAttempt(i, uint64(i+1), func() {}, &reasons[i], base)
		}

		// 模拟 6 条连接每条均匀 25 KiB/s（总聚合 150 KiB/s >= 48 KiB/s），连续推进时钟
		scoutsTriggered := 0
		for step := 1; step <= 40; step++ {
			now := base.Add(time.Duration(step) * 50 * time.Millisecond)
			for i := 0; i < 6; i++ {
				// 每 50ms 每槽写入 1280 字节 = 25 KiB/s
				tracker.recordBytes(i, 1280, now)
			}
			actions := tracker.evaluateTick(now)
			if len(actions.cancels) > 0 {
				scoutsTriggered += len(actions.cancels)
				for i := 0; i < 6; i++ {
					if reasons[i].Load() == cancelReasonRotate {
						reasons[i].Store(cancelReasonNone)
						tracker.markConnectionRebuilt(i, now)
						tracker.startAttempt(i, uint64(step*100+i), func() {}, &reasons[i], now)
					}
				}
			}
			if actions.shrinkTo > 0 {
				ledger.shrinkConcurrency(actions.shrinkTo)
			}
		}

		if scoutsTriggered != 2 {
			t.Fatalf("expected exactly 2 bounded scouts in uniform slow mode, got %d", scoutsTriggered)
		}
		if !tracker.scoutingStopped {
			t.Fatal("expected scouting to stop permanently after 2 unsuccessful scouts")
		}
		if got := ledger.targetConcurrencyValue(); got != 6 {
			t.Fatalf("expected concurrency preserved at 6 when aggregate >= 48 KiB/s, got %d", got)
		}
	})

	t.Run("scenario_c_narrowband_hotspot_stops_scouting_and_shrinks_to_2", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MaxConnections = 6
		cfg.warmupGrace = 100 * time.Millisecond
		cfg.rateWindow = 200 * time.Millisecond
		cfg.scoutTriggerDuration = 150 * time.Millisecond
		cfg.scoutCooldown = 150 * time.Millisecond
		cfg.maxScouts = 2

		base := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
		tracker := newSpeedTracker(cfg, 6, base)
		ledger := newChunkLedger(6<<20, 256<<10, 6, 2, 0, 0)

		var reasons [6]atomic.Int32
		for i := 0; i < 6; i++ {
			tracker.startAttempt(i, uint64(i+1), func() {}, &reasons[i], base)
		}

		// 模拟 15 KiB/s 真窄带热点被 6 条连接均分（每槽 ~2.5 KiB/s，总聚合 ~15 KiB/s < 48 KiB/s）
		scoutsTriggered := 0
		for step := 1; step <= 40; step++ {
			now := base.Add(time.Duration(step) * 50 * time.Millisecond)
			for i := 0; i < 6; i++ {
				// 每 50ms 每槽 128 字节 => 单槽 2.5 KiB/s，总聚合 15 KiB/s
				tracker.recordBytes(i, 128, now)
			}
			actions := tracker.evaluateTick(now)
			if len(actions.cancels) > 0 {
				scoutsTriggered += len(actions.cancels)
				for i := 0; i < 6; i++ {
					if reasons[i].Load() == cancelReasonRotate {
						reasons[i].Store(cancelReasonNone)
						tracker.markConnectionRebuilt(i, now)
						tracker.startAttempt(i, uint64(step*100+i), func() {}, &reasons[i], now)
					}
				}
			}
			if actions.shrinkTo > 0 {
				ledger.shrinkConcurrency(actions.shrinkTo)
			}
		}

		if scoutsTriggered != 2 {
			t.Fatalf("expected exactly 2 bounded scouts in narrowband mode, got %d", scoutsTriggered)
		}
		if !tracker.scoutingStopped {
			t.Fatal("expected scouting to stop permanently after 2 unsuccessful scouts")
		}
		if got := ledger.targetConcurrencyValue(); got != 2 {
			t.Fatalf("expected concurrency shrunk to 2 when aggregate < 48 KiB/s, got %d", got)
		}
	})

	t.Run("zero_byte_stall_watchdog_recovers", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		var stalledChunk0, stalledChunk1 atomic.Bool
		var canceledChunk0, canceledChunk1 atomic.Bool
		chunk0Done := make(chan struct{})
		chunk1Done := make(chan struct{})
		release := make(chan struct{})

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rangeHdr := r.Header.Get("Range")
			if rangeHdr == "bytes=0-262143" && stalledChunk0.CompareAndSwap(false, true) {
				defer close(chunk0Done)
				// 写入响应头后卡死发 0 字节，迫使零字节假死看门狗介入中断
				w.Header().Set("ETag", `"stall-v1"`)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-262143/%d", len(payload)))
				w.Header().Set("Content-Length", "262144")
				w.WriteHeader(http.StatusPartialContent)
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					canceledChunk0.Store(true)
				case <-release:
				}
				return
			}
			if rangeHdr == "bytes=262144-524287" && stalledChunk1.CompareAndSwap(false, true) {
				defer close(chunk1Done)
				w.Header().Set("ETag", `"stall-v1"`)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 262144-524287/%d", len(payload)))
				w.Header().Set("Content-Length", "262144")
				w.WriteHeader(http.StatusPartialContent)
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					canceledChunk1.Store(true)
				case <-release:
				}
				return
			}
			serveByteRange(w, r, payload, `"stall-v1"`, "", nil)
		}))
		defer srv.Close()
		defer close(release)

		dest := filepath.Join(t.TempDir(), "stall.bin")
		start := time.Now()
		res, err := Download(context.Background(), srv.URL+"/stall", dest, Config{
			BaseClient:        srv.Client(),
			MaxConnections:    2,
			ChunkStallTimeout: 180 * time.Millisecond,
			watchdogInterval:  40 * time.Millisecond,
			RetryDelay:        10 * time.Millisecond,
		})
		elapsed := time.Since(start)
		if err != nil || !res.UsedSegmented {
			t.Fatalf("expected stall watchdog recovery, got res=%+v err=%v", res, err)
		}
		if elapsed < 180*time.Millisecond {
			t.Fatalf("expected stall watchdog to wait at least 180ms before recovery, elapsed=%v", elapsed)
		}
		for i, ch := range []chan struct{}{chunk0Done, chunk1Done} {
			select {
			case <-ch:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for stalled chunk %d handler exit", i)
			}
		}
		if !canceledChunk0.Load() || !canceledChunk1.Load() {
			t.Fatalf("expected both stalled handlers to observe context cancellation: c0=%v c1=%v", canceledChunk0.Load(), canceledChunk1.Load())
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("stall watchdog recovered payload mismatch")
		}
	})

	t.Run("permanent_chunk_stall_exhausts_retries", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		release := make(chan struct{})

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-262143" {
				// 每次拉取 chunk 0 均在响应头后卡死 0 字节，验证看门狗不会无限旋转而是耗尽分片重试预算
				w.Header().Set("ETag", `"perm-stall-v1"`)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-262143/%d", len(payload)))
				w.Header().Set("Content-Length", "262144")
				w.WriteHeader(http.StatusPartialContent)
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-release:
				}
				return
			}
			serveByteRange(w, r, payload, `"perm-stall-v1"`, "", nil)
		}))
		defer srv.Close()
		defer close(release)

		tmpDir := t.TempDir()
		dest := filepath.Join(tmpDir, "perm-stall.bin")
		_, err := Download(context.Background(), srv.URL+"/perm-stall", dest, Config{
			BaseClient:        srv.Client(),
			MaxConnections:    2,
			ChunkStallTimeout: 80 * time.Millisecond,
			watchdogInterval:  20 * time.Millisecond,
			RetryDelay:        10 * time.Millisecond,
			TotalTimeout:      10 * time.Second,
		})
		var retriesErr *RetriesExhaustedError
		if !errors.As(err, &retriesErr) {
			t.Fatalf("expected RetriesExhaustedError on permanent chunk stall, got %T (%v)", err, err)
		}
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("expected RetriesExhaustedError wrapping ErrTimeout, got %v", err)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("destination file must not exist after permanent stall failure")
		}
		assertNoLeftoverTempFiles(t, tmpDir, "")
	})
}

// TestTailHedgingUnderRace 验证队列排空后空闲快槽对停滞尾块发起有上限对冲，-race 下零竞态、无空洞且进度不超 100%。
func TestTailHedgingUnderRace(t *testing.T) {
	payload := makeDeterministicPayload(1 << 20) // 4 chunks
	const chunk3Start = int64(786432)

	t.Run("incremental_tail_hedge_resumes_from_committed_offset", func(t *testing.T) {
		var chunk3Calls int32
		var primaryCanceled atomic.Bool
		var hedgeStartOffset atomic.Int64
		chunk3HalfCommitted := make(chan struct{})
		var halfOnce sync.Once
		primaryDone := make(chan struct{})
		releaseStalled := make(chan struct{})

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rangeHdr := r.Header.Get("Range")
			if rangeHdr == "bytes=0-0" {
				serveByteRange(w, r, payload, `"hedge-v1"`, "", nil)
				return
			}
			if strings.HasPrefix(rangeHdr, "bytes=") {
				spec := strings.TrimPrefix(rangeHdr, "bytes=")
				if dash := strings.IndexByte(spec, '-'); dash > 0 {
					if start, err := strconv.ParseInt(spec[:dash], 10, 64); err == nil {
						if start >= chunk3Start {
							callNum := atomic.AddInt32(&chunk3Calls, 1)
							if callNum == 1 {
								defer close(primaryDone)
								// 首次拉取最后一块时先发一半字节再卡住，等待空闲快槽从已提交偏移对冲接管
								part := payload[chunk3Start:]
								w.Header().Set("ETag", `"hedge-v1"`)
								w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", chunk3Start, len(payload)-1, len(payload)))
								w.Header().Set("Content-Length", strconv.Itoa(len(part)))
								w.WriteHeader(http.StatusPartialContent)
								_, _ = w.Write(part[:len(part)/2])
								w.(http.Flusher).Flush()
								select {
								case <-r.Context().Done():
									primaryCanceled.Store(true)
								case <-releaseStalled:
								}
								return
							}
							hedgeStartOffset.Store(start)
						} else {
							// 暂留前三个分块直到 chunk 3 主流提交前半段字节，确保快槽从严格大于 chunk3Start 的偏移接管
							select {
							case <-chunk3HalfCommitted:
							case <-r.Context().Done():
								return
							case <-releaseStalled:
							}
						}
					}
				}
			}
			serveByteRange(w, r, payload, `"hedge-v1"`, "", nil)
		}))
		defer srv.Close()
		defer close(releaseStalled)

		var (
			progMu  sync.Mutex
			maxProg int64
		)
		dest := filepath.Join(t.TempDir(), "hedge.bin")
		res, err := Download(context.Background(), srv.URL+"/hedge", dest, Config{
			BaseClient:          srv.Client(),
			MaxConnections:      4,
			ChunkSize:           256 << 10,
			ChunkStallTimeout:   5 * time.Second, // 远大于测试耗时，确保由尾块对冲而非死连接超时完成
			progressMinInterval: -1,
			OnProgress: func(p Progress) {
				progMu.Lock()
				if p.BytesReceived > int64(len(payload)) {
					t.Errorf("progress exceeded 100%%: %d > %d", p.BytesReceived, len(payload))
				}
				if p.BytesReceived > maxProg {
					maxProg = p.BytesReceived
				}
				if p.BytesReceived >= int64(128<<10) {
					halfOnce.Do(func() { close(chunk3HalfCommitted) })
				}
				progMu.Unlock()
			},
		})
		if err != nil || !res.UsedSegmented {
			t.Fatalf("tail hedge download failed: res=%+v err=%v", res, err)
		}
		select {
		case <-primaryDone:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for primary stalled chunk 3 handler to cancel")
		}
		if atomic.LoadInt32(&chunk3Calls) < 2 {
			t.Fatalf("expected hedge request on stalled tail chunk, got %d requests", chunk3Calls)
		}
		if hedgeStartOffset.Load() <= chunk3Start {
			t.Fatalf("expected hedge start strictly greater than %d, got %d", chunk3Start, hedgeStartOffset.Load())
		}
		if !primaryCanceled.Load() {
			t.Fatal("expected stalled primary attempt to be canceled when hedge won")
		}
		progMu.Lock()
		gotMaxProg := maxProg
		progMu.Unlock()
		if gotMaxProg != int64(len(payload)) {
			t.Fatalf("expected max progress == %d, got %d", len(payload), gotMaxProg)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("tail hedge payload mismatch")
		}
	})

	t.Run("overlapping_primary_and_hedge_first_writer_wins_race_free", func(t *testing.T) {
		var chunk3Calls int32
		hedgeArrived := make(chan struct{})
		var hedgeOnce sync.Once

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.Header.Get("Range"), "bytes=786432-") {
				if atomic.AddInt32(&chunk3Calls, 1) == 1 {
					// 挂起直到对冲请求到达，再与对冲流并发吐出同一区间，压测 First-Writer-Wins 串行提交
					select {
					case <-hedgeArrived:
					case <-r.Context().Done():
						return
					case <-time.After(2 * time.Second):
					}
					serveByteRange(w, r, payload, `"hedge-race"`, "", nil)
					return
				}
				hedgeOnce.Do(func() { close(hedgeArrived) })
			}
			serveByteRange(w, r, payload, `"hedge-race"`, "", nil)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "hedge-race.bin")
		res, err := Download(context.Background(), srv.URL+"/hedge-race", dest, Config{
			BaseClient:        srv.Client(),
			MaxConnections:    4,
			ChunkSize:         256 << 10,
			ChunkStallTimeout: 5 * time.Second,
		})
		if err != nil || !res.UsedSegmented {
			t.Fatalf("overlapping hedge failed: res=%+v err=%v", res, err)
		}
		if atomic.LoadInt32(&chunk3Calls) < 2 {
			t.Fatalf("expected overlapping hedge request, got %d", chunk3Calls)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("overlapping hedge payload mismatch")
		}
	})
}

// TestURLAndDestinationValidation 验证 HTTPS 默认强制、userinfo 拒绝与符号链接父目录拦截。
func TestURLAndDestinationValidation(t *testing.T) {
	tmpDir := t.TempDir()
	// 默认 Config{} 强制 HTTPS，拒绝明文 http://
	if _, err := Download(context.Background(), "http://example.invalid/pkg.exe", filepath.Join(tmpDir, "a.bin"), Config{}); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("expected ErrInsecureURL for plain http by default, got %v", err)
	}
	// 拒绝含 userinfo 的 URL
	if _, err := Download(context.Background(), "https://user:pass@example.invalid/pkg.exe", filepath.Join(tmpDir, "b.bin"), Config{}); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("expected ErrInsecureURL for url with userinfo, got %v", err)
	}
	// 拒绝符号链接父目录
	realDir := filepath.Join(tmpDir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	linkDir := filepath.Join(tmpDir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink creation unsupported: %v", err)
	}
	if _, err := Download(context.Background(), "https://example.invalid/pkg.exe", filepath.Join(linkDir, "c.bin"), Config{}); !errors.Is(err, ErrFileIO) {
		t.Fatalf("expected ErrFileIO for symlink parent directory, got %v", err)
	}
}

// TestRateLimitBackoffAndCancelWake 验证 429 + Retry-After（整数秒与 HTTP-date）触发全局退避与并发减半，且取消 ctx 可立刻唤醒退避。
func TestRateLimitBackoffAndCancelWake(t *testing.T) {
	t.Run("ledger_halves_concurrency_per_backoff_epoch", func(t *testing.T) {
		ledger := newChunkLedger(2<<20, 256<<10, 6, 2, 0, 0)
		now := time.Now()
		// 同一退避窗口内并发触发多次 429 只减半一次：6 -> 3
		ledger.applyRateLimitBackoff(now, now.Add(2*time.Second))
		ledger.applyRateLimitBackoff(now.Add(10*time.Millisecond), now.Add(2*time.Second))
		if got := ledger.targetConcurrencyValue(); got != 3 {
			t.Fatalf("expected concurrency halved once 6->3, got %d", got)
		}
		// 退避窗口过后再遇 429 继续减半：3 -> 1
		later := now.Add(3 * time.Second)
		ledger.applyRateLimitBackoff(later, later.Add(2*time.Second))
		if got := ledger.targetConcurrencyValue(); got != 1 {
			t.Fatalf("expected concurrency halved 3->1 on next epoch, got %d", got)
		}
	})

	t.Run("429_retry_after_integer_and_http_date_recovers", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		var hit429 int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "bytes=0-0" {
				n := atomic.AddInt32(&hit429, 1)
				if n == 1 {
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				if n == 2 {
					w.Header().Set("Retry-After", time.Now().UTC().Add(2*time.Second).Format(http.TimeFormat))
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
			}
			serveByteRange(w, r, payload, `"rl-v1"`, "", nil)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "rl.bin")
		start := time.Now()
		res, err := Download(context.Background(), srv.URL+"/rl", dest, Config{
			BaseClient:     srv.Client(),
			MaxConnections: 4,
			RetryDelay:     20 * time.Millisecond,
			maxRetryAfter:  120 * time.Millisecond,
		})
		elapsed := time.Since(start)
		if err != nil || !res.UsedSegmented {
			t.Fatalf("expected recovery after 429 backoff: res=%+v err=%v", res, err)
		}
		if elapsed < 100*time.Millisecond {
			t.Fatalf("expected 429 Retry-After backoff wait >= 100ms, got %v", elapsed)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("429 recovery payload mismatch")
		}
	})

	t.Run("cancel_ctx_wakes_long_retry_after_immediately", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		entered429 := make(chan struct{})
		var once sync.Once
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-0" {
				serveByteRange(w, r, payload, `"rl-cancel"`, "", nil)
				return
			}
			defer once.Do(func() { close(entered429) })
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		tmpDir := t.TempDir()
		go func() {
			_, err := Download(ctx, srv.URL+"/rl", filepath.Join(tmpDir, "rl-cancel.bin"), Config{
				BaseClient:     srv.Client(),
				MaxConnections: 2,
			})
			done <- err
		}()

		<-entered429
		// 等待工作协程处理完 429 响应并真正阻塞进入全局退避等待分支
		time.Sleep(50 * time.Millisecond)
		startCancel := time.Now()
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected unwrapped context.Canceled, got %v", err)
			}
			var re *RetriesExhaustedError
			if errors.As(err, &re) {
				t.Fatalf("context.Canceled must not be wrapped in RetriesExhaustedError: %v", err)
			}
			if elapsed := time.Since(startCancel); elapsed > time.Second {
				t.Fatalf("cancel took too long to wake backoff: %v", elapsed)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for backoff cancel wakeup")
		}
		assertNoLeftoverTempFiles(t, tmpDir, "")
	})
}

// TestContextCancellationCleansUpWithoutRetry 验证下载中途取消外部 ctx 立即停止所有协程、原样透传 context.Canceled 且彻底清理临时文件。
func TestContextCancellationCleansUpWithoutRetry(t *testing.T) {
	payload := makeDeterministicPayload(2 << 20)
	chunkStarted := make(chan struct{})
	var startOnce sync.Once
	var reqCount int32
	release := make(chan struct{})
	defer close(release)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		if r.Header.Get("Range") == "bytes=0-0" {
			serveByteRange(w, r, payload, `"cancel-v1"`, "", nil)
			return
		}
		startOnce.Do(func() { close(chunkStarted) })
		w.Header().Set("ETag", `"cancel-v1"`)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-262143/%d", len(payload)))
		w.Header().Set("Content-Length", "262144")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[:4096])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "canceled.bin")
	errCh := make(chan error, 1)
	go func() {
		_, err := Download(ctx, srv.URL+"/cancel", dest, Config{
			BaseClient:     srv.Client(),
			MaxConnections: 4,
			RetryDelay:     5 * time.Second,
		})
		errCh <- err
	}()

	<-chunkStarted
	cancelAt := time.Now()
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		var te *TimeoutError
		var re *RetriesExhaustedError
		if errors.As(err, &te) || errors.As(err, &re) {
			t.Fatalf("parent cancellation must propagate unwrapped, got %T (%v)", err, err)
		}
		if elapsed := time.Since(cancelAt); elapsed > time.Second {
			t.Fatalf("cancellation took too long: %v", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("download did not stop promptly on context cancellation")
	}

	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("destination file should not exist after cancel")
	}
	assertNoLeftoverTempFiles(t, tmpDir, "")
}

// TestSingleStreamResumeSafetyAndCapped206 验证单流续传强校验器守卫、未请求 206 拒收、限长 206 续拉与超大 Content-Range 防溢出。
func TestSingleStreamResumeSafetyAndCapped206(t *testing.T) {
	t.Run("weak_or_missing_validator_resets_without_range", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			etag string
		}{
			{name: "weak_etag", etag: `W/"weak-v1"`},
			{name: "missing_validator", etag: ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				payload := makeDeterministicPayload(64 << 10)
				splitAt := len(payload) / 2
				var reqCount int32
				var attempt2Range atomic.Value
				var attempt2IfRange atomic.Value

				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := atomic.AddInt32(&reqCount, 1)
					if tc.etag != "" {
						w.Header().Set("ETag", tc.etag)
					}
					if n == 1 {
						w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write(payload[:splitAt])
						w.(http.Flusher).Flush()
						if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
							_ = conn.Close()
						}
						return
					}
					attempt2Range.Store(r.Header.Get("Range"))
					attempt2IfRange.Store(r.Header.Get("If-Range"))
					w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(payload)
				}))
				defer srv.Close()

				var sawReset atomic.Bool
				dest := filepath.Join(t.TempDir(), tc.name+".bin")
				res, err := Download(context.Background(), srv.URL+"/file", dest, Config{
					BaseClient:       srv.Client(),
					ExpectedSizeHint: int64(len(payload)),
					RetryDelay:       10 * time.Millisecond,
					OnProgress: func(p Progress) {
						if p.IsReset {
							sawReset.Store(true)
						}
					},
				})
				if err != nil || res.UsedSegmented || atomic.LoadInt32(&reqCount) != 2 {
					t.Fatalf("expected clean full retry without Range: res=%+v err=%v reqs=%d", res, err, reqCount)
				}
				if got, _ := attempt2Range.Load().(string); got != "" {
					t.Fatalf("expected no Range header without strong validator, got %q", got)
				}
				if got, _ := attempt2IfRange.Load().(string); got != "" {
					t.Fatalf("expected no If-Range header without strong validator, got %q", got)
				}
				if !sawReset.Load() {
					t.Fatal("expected IsReset progress event before full retry")
				}
				got, _ := os.ReadFile(dest)
				if !bytes.Equal(got, payload) {
					t.Fatal("downloaded payload mismatch after reset")
				}
			})
		}
	})

	t.Run("same_origin_206_drifted_etag_or_changed_total_resets", func(t *testing.T) {
		for _, mode := range []string{"drifted_etag", "changed_total"} {
			t.Run(mode, func(t *testing.T) {
				oldPayload := makeDeterministicPayload(64 << 10)
				newPayload := makeDeterministicPayload(80 << 10)
				for i := range newPayload {
					newPayload[i] ^= 0x33
				}
				splitAt := len(oldPayload) / 2
				var reqCount int32

				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := atomic.AddInt32(&reqCount, 1)
					switch n {
					case 1:
						w.Header().Set("ETag", `"v1"`)
						w.Header().Set("Content-Length", strconv.Itoa(len(oldPayload)))
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write(oldPayload[:splitAt])
						w.(http.Flusher).Flush()
						if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
							_ = conn.Close()
						}
					case 2:
						if r.Header.Get("Range") != fmt.Sprintf("bytes=%d-", splitAt) {
							t.Errorf("expected Range resume on attempt 2, got %q", r.Header.Get("Range"))
						}
						if mode == "drifted_etag" {
							w.Header().Set("ETag", `"v2"`)
							w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", splitAt, len(oldPayload)-1, len(oldPayload)))
							w.Header().Set("Content-Length", strconv.Itoa(len(oldPayload)-splitAt))
							w.WriteHeader(http.StatusPartialContent)
							_, _ = w.Write(oldPayload[splitAt:])
						} else {
							w.Header().Set("ETag", `"v1"`)
							w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", splitAt, len(newPayload)-1, len(newPayload)))
							w.Header().Set("Content-Length", strconv.Itoa(len(newPayload)-splitAt))
							w.WriteHeader(http.StatusPartialContent)
							_, _ = w.Write(newPayload[splitAt:])
						}
					default:
						if r.Header.Get("Range") != "" {
							t.Errorf("expected full GET without Range after 206 mismatch reset, got %q", r.Header.Get("Range"))
						}
						w.Header().Set("ETag", `"v2"`)
						w.Header().Set("Content-Length", strconv.Itoa(len(newPayload)))
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write(newPayload)
					}
				}))
				defer srv.Close()

				dest := filepath.Join(t.TempDir(), mode+".bin")
				_, err := Download(context.Background(), srv.URL+"/file", dest, Config{
					BaseClient:       srv.Client(),
					ExpectedSizeHint: int64(len(oldPayload)),
					RetryDelay:       10 * time.Millisecond,
				})
				if err != nil {
					t.Fatalf("expected reset recovery for %s, got %v", mode, err)
				}
				if got := atomic.LoadInt32(&reqCount); got != 3 {
					t.Fatalf("expected 3 requests for %s, got %d", mode, got)
				}
				got, _ := os.ReadFile(dest)
				if !bytes.Equal(got, newPayload) {
					t.Fatalf("payload mismatch for %s: expected clean newPayload without byte splicing", mode)
				}
			})
		}
	})

	t.Run("unsolicited_206_on_initial_get_rejected_immediately", func(t *testing.T) {
		var reqCount int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqCount, 1)
			w.Header().Set("Content-Range", "bytes 0-99/1000")
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(makeDeterministicPayload(100))
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		dest := filepath.Join(tmpDir, "unsolicited206.bin")
		_, err := Download(context.Background(), srv.URL+"/file", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: 1000,
			MaxAttempts:      3,
			RetryDelay:       10 * time.Millisecond,
		})
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusPartialContent {
			t.Fatalf("expected HTTPStatusError(206), got %T (%v)", err, err)
		}
		if got := atomic.LoadInt32(&reqCount); got != 1 {
			t.Fatalf("expected immediate rejection in 1 request, got %d", got)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("destination file must not exist on unsolicited 206")
		}
		assertNoLeftoverTempFiles(t, tmpDir, "")
	})

	t.Run("capped_206_resume_completes_full_payload", func(t *testing.T) {
		payload := makeDeterministicPayload(1000)
		var reqCount int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			w.Header().Set("ETag", `"capped-v1"`)
			switch n {
			case 1:
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload[:500])
				w.(http.Flusher).Flush()
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
			case 2:
				if r.Header.Get("Range") != "bytes=500-" {
					t.Errorf("attempt 2 unexpected Range: %q", r.Header.Get("Range"))
				}
				w.Header().Set("Content-Range", "bytes 500-699/1000")
				w.Header().Set("Content-Length", "200")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(payload[500:700])
			default:
				if r.Header.Get("Range") != "bytes=700-" {
					t.Errorf("attempt 3 unexpected Range: %q", r.Header.Get("Range"))
				}
				w.Header().Set("Content-Range", "bytes 700-999/1000")
				w.Header().Set("Content-Length", "300")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(payload[700:1000])
			}
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "capped.bin")
		res, err := Download(context.Background(), srv.URL+"/capped", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: 1000,
			MaxAttempts:      3,
			RetryDelay:       10 * time.Millisecond,
		})
		if err != nil || res.BytesWritten != 1000 || atomic.LoadInt32(&reqCount) != 3 {
			t.Fatalf("expected full 1000 bytes across 3 requests, got res=%+v err=%v reqs=%d", res, err, reqCount)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("capped 206 final payload mismatch")
		}
	})

	t.Run("capped_206_exhausted_attempts_does_not_finalize_truncated", func(t *testing.T) {
		payload := makeDeterministicPayload(1000)
		var reqCount int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			w.Header().Set("ETag", `"capped-short-v1"`)
			switch n {
			case 1:
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload[:500])
				w.(http.Flusher).Flush()
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
			default:
				w.Header().Set("Content-Range", "bytes 500-699/1000")
				w.Header().Set("Content-Length", "200")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(payload[500:700])
			}
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		dest := filepath.Join(tmpDir, "truncated.bin")
		_, err := Download(context.Background(), srv.URL+"/capped-short", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: 1000,
			MaxAttempts:      2,
			RetryDelay:       10 * time.Millisecond,
		})
		var retriesErr *RetriesExhaustedError
		if !errors.As(err, &retriesErr) {
			t.Fatalf("expected RetriesExhaustedError instead of truncated file, got %T (%v)", err, err)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("truncated file must not be finalized to destination")
		}
		assertNoLeftoverTempFiles(t, tmpDir, "")
	})

	t.Run("wildcard_content_range_max_int64_rejected_without_overflow", func(t *testing.T) {
		payload := makeDeterministicPayload(4096)
		var reqCount int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			w.Header().Set("ETag", `"wild-v1"`)
			if n == 1 {
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload[:1024])
				w.(http.Flusher).Flush()
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 1024-%d/*", math.MaxInt64))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[1024:])
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		dest := filepath.Join(tmpDir, "wild.bin")
		_, err := Download(context.Background(), srv.URL+"/wild", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: int64(len(payload)),
			MaxBytes:         1 << 20,
			RetryDelay:       10 * time.Millisecond,
		})
		var sizeErr *SizeLimitExceededError
		if !errors.As(err, &sizeErr) || !errors.Is(err, ErrSizeLimitExceeded) {
			t.Fatalf("expected SizeLimitExceededError on max-int64 Content-Range, got %T (%v)", err, err)
		}
		if sizeErr.Actual != math.MaxInt64 {
			t.Fatalf("expected Actual == MaxInt64, got %d", sizeErr.Actual)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("destination file must not exist after size limit rejection")
		}
		assertNoLeftoverTempFiles(t, tmpDir, "")
	})
}

// TestChunkLedgerTransientBackoff 验证非限流瞬态失败的分块按指数退避延后重领，且不阻塞其它待领分块。
func TestChunkLedgerTransientBackoff(t *testing.T) {
	ledger := newChunkLedger(512<<10, 256<<10, 2, 1, 100*time.Millisecond, 2*time.Second)
	base := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	// 槽位 0 领取分块 0 后遭遇非限流瞬态错误，应写入未来 notBefore
	c0 := ledger.claim(0, nil, base, nil)
	if c0.kind != claimWork || c0.chunkIndex != 0 {
		t.Fatalf("expected chunk 0, got %+v", c0)
	}
	aborted, allDone := ledger.releaseAttempt(0, c0.attemptID, outcomeTransientError, io.ErrUnexpectedEOF, 0, base)
	if aborted || allDone {
		t.Fatalf("expected chunk 0 requeued, got aborted=%v allDone=%v", aborted, allDone)
	}

	// 尚在退避期内时，其它未领取的分块 1 必须能立刻领取而不被阻塞
	c1 := ledger.claim(1, nil, base.Add(10*time.Millisecond), nil)
	if c1.kind != claimWork || c1.chunkIndex != 1 {
		t.Fatalf("expected pending chunk 1 claimed immediately while chunk 0 backs off, got %+v", c1)
	}

	// 所有待领分块都已发出且无可用对冲时，空闲槽位应收到针对分块 0 的 claimWaitBackoff
	waitClaim := ledger.claim(0, nil, base.Add(10*time.Millisecond), nil)
	if waitClaim.kind != claimWaitBackoff || !waitClaim.waitUntil.After(base.Add(10*time.Millisecond)) {
		t.Fatalf("expected claimWaitBackoff with future waitUntil, got %+v", waitClaim)
	}

	// 时钟推进至 waitUntil 后应立即重新领回分块 0
	retryClaim := ledger.claim(0, nil, waitClaim.waitUntil, nil)
	if retryClaim.kind != claimWork || retryClaim.chunkIndex != 0 {
		t.Fatalf("expected chunk 0 ready at waitUntil, got %+v", retryClaim)
	}
}

type countingListener struct {
	net.Listener
	accepts *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return conn, err
}

// TestPermanentTLSErrorFailsFast 验证面对不受信任的自签证书时在首次握手失败后立即中止，绝不重试。
func TestPermanentTLSErrorFailsFast(t *testing.T) {
	var accepts atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Listener = &countingListener{Listener: srv.Listener, accepts: &accepts}
	srv.StartTLS()
	defer srv.Close()

	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "untrusted.bin")
	start := time.Now()
	_, err := Download(context.Background(), srv.URL+"/pkg.exe", dest, Config{
		// 不注入 srv.Client()，强制使用系统默认根证书以触发不可恢复的 TLS 校验错误
		MaxAttempts: 3,
		RetryDelay:  500 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected TLS verification error against untrusted self-signed server")
	}
	if !isPermanentTLSError(err) {
		t.Fatalf("expected permanent TLS error, got %T (%v)", err, err)
	}
	var retriesErr *RetriesExhaustedError
	if errors.As(err, &retriesErr) {
		t.Fatalf("permanent TLS error must fail fast without RetriesExhaustedError, got %v", err)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("expected exactly 1 connection attempt without retry, got %d", got)
	}
	if elapsed >= 400*time.Millisecond {
		t.Fatalf("expected fast failure without retry sleep, took %v", elapsed)
	}
	assertNoLeftoverTempFiles(t, tmpDir, "")
}

// TestProbe416NonZeroDowngradesToSingleStream 验证非空文件探针收到 416 时同一次 attempt 降级为普通 GET 单流下载。
func TestProbe416NonZeroDowngradesToSingleStream(t *testing.T) {
	payload := makeDeterministicPayload(1200 << 10)
	var reqCount int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		if n == 1 {
			if r.Header.Get("Range") != "bytes=0-0" {
				t.Errorf("expected probe Range: bytes=0-0, got %q", r.Header.Get("Range"))
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(payload)))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if r.Header.Get("Range") != "" {
			t.Errorf("expected plain GET without Range after probe 416 downgrade, got %q", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "probe416.bin")
	res, err := Download(context.Background(), srv.URL+"/probe416", dest, Config{
		BaseClient:  srv.Client(),
		MaxAttempts: 1, // 证明在同一次 attempt 内降级且未耗尽重试预算
	})
	if err != nil || res.UsedSegmented || atomic.LoadInt32(&reqCount) != 2 {
		t.Fatalf("expected probe 416 downgrade to succeed in 2 requests, got res=%+v err=%v reqs=%d", res, err, reqCount)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, payload) {
		t.Fatal("probe 416 downgraded payload mismatch")
	}
}

// TestHTTP500RetryParity 验证探针、单流与分段分块遇到 HTTP 500 时均能瞬态重试恢复。
func TestHTTP500RetryParity(t *testing.T) {
	t.Run("single_stream_500_recovers", func(t *testing.T) {
		payload := makeDeterministicPayload(64 << 10)
		var reqCount int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&reqCount, 1) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "s500.bin")
		res, err := Download(context.Background(), srv.URL+"/s500", dest, Config{
			BaseClient:       srv.Client(),
			ExpectedSizeHint: int64(len(payload)),
			RetryDelay:       10 * time.Millisecond,
		})
		if err != nil || res.BytesWritten != int64(len(payload)) || atomic.LoadInt32(&reqCount) != 2 {
			t.Fatalf("expected single-stream HTTP 500 recovery in 2 requests, got res=%+v err=%v reqs=%d", res, err, reqCount)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("single-stream HTTP 500 recovered payload mismatch")
		}
	})

	t.Run("probe_and_segmented_500_recover", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		var probeFailed, chunkFailed atomic.Bool
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-0" && probeFailed.CompareAndSwap(false, true) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if r.Header.Get("Range") == "bytes=262144-524287" && chunkFailed.CompareAndSwap(false, true) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			serveByteRange(w, r, payload, `"seg-500-v1"`, "", nil)
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "seg500.bin")
		res, err := Download(context.Background(), srv.URL+"/seg500", dest, Config{
			BaseClient:     srv.Client(),
			MaxConnections: 4,
			RetryDelay:     10 * time.Millisecond,
		})
		if err != nil || !res.UsedSegmented {
			t.Fatalf("expected segmented HTTP 500 recovery, got res=%+v err=%v", res, err)
		}
		got, _ := os.ReadFile(dest)
		if !bytes.Equal(got, payload) {
			t.Fatal("segmented HTTP 500 recovered payload mismatch")
		}
	})
}

// TestTotalTimeoutAndChunk5xxExhaustion 验证慢滴流触发 TotalTimeout 返回 ErrTimeout，以及分片持续 500/503 耗尽重试且彻底清理临时文件。
func TestTotalTimeoutAndChunk5xxExhaustion(t *testing.T) {
	t.Run("slow_drip_total_timeout_returns_err_timeout", func(t *testing.T) {
		payload := makeDeterministicPayload(1 << 20)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "bytes=0-0" {
				serveByteRange(w, r, payload, `"drip-v1"`, "", nil)
				return
			}
			spec := strings.TrimPrefix(r.Header.Get("Range"), "bytes=")
			parts := strings.Split(spec, "-")
			start, _ := strconv.ParseInt(parts[0], 10, 64)
			end, _ := strconv.ParseInt(parts[1], 10, 64)
			slice := payload[start : end+1]
			w.Header().Set("ETag", `"drip-v1"`)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
			w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
			w.WriteHeader(http.StatusPartialContent)
			flusher, _ := w.(http.Flusher)
			// 持续慢速滴流，使单块假死超时不断被刷新，最终由硬总时限 TotalTimeout 终止
			for off := 0; off < len(slice); off += 32 {
				chunkEnd := min(off+32, len(slice))
				if _, err := w.Write(slice[off:chunkEnd]); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
				timer := time.NewTimer(15 * time.Millisecond)
				select {
				case <-r.Context().Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}))
		defer srv.Close()

		tmpDir := t.TempDir()
		dest := filepath.Join(tmpDir, "drip.bin")
		_, err := Download(context.Background(), srv.URL+"/drip", dest, Config{
			BaseClient:              srv.Client(),
			MaxConnections:          2,
			SingleStreamIdleTimeout: 5 * time.Second,
			ChunkStallTimeout:       5 * time.Second,
			TotalTimeout:            180 * time.Millisecond,
		})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("expected ErrTimeout on slow-drip TotalTimeout, got %T (%v)", err, err)
		}
		if errors.Is(err, context.Canceled) {
			t.Fatalf("TotalTimeout must not report context.Canceled, got %v", err)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatal("destination file must not exist after TotalTimeout")
		}
		assertNoLeftoverTempFiles(t, tmpDir, "")
	})

	t.Run("repeated_chunk_500_and_503_exhaust_retries", func(t *testing.T) {
		for _, code := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
			t.Run(fmt.Sprintf("http_%d", code), func(t *testing.T) {
				payload := makeDeterministicPayload(1 << 20)
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Range") == "bytes=0-0" {
						serveByteRange(w, r, payload, `"fail5xx-v1"`, "", nil)
						return
					}
					if r.Header.Get("Range") == "bytes=0-262143" {
						w.WriteHeader(code)
						return
					}
					serveByteRange(w, r, payload, `"fail5xx-v1"`, "", nil)
				}))
				defer srv.Close()

				tmpDir := t.TempDir()
				dest := filepath.Join(tmpDir, fmt.Sprintf("fail-%d.bin", code))
				_, err := Download(context.Background(), srv.URL+"/fail5xx", dest, Config{
					BaseClient:     srv.Client(),
					MaxConnections: 2,
					RetryDelay:     10 * time.Millisecond,
					maxRetryAfter:  50 * time.Millisecond,
				})
				var retriesErr *RetriesExhaustedError
				if !errors.As(err, &retriesErr) {
					t.Fatalf("expected RetriesExhaustedError for repeated HTTP %d, got %T (%v)", code, err, err)
				}
				var statusErr *HTTPStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != code {
					t.Fatalf("expected wrapped HTTPStatusError(%d), got %v", code, err)
				}
				if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
					t.Fatal("destination file must not exist after repeated 5xx exhaustion")
				}
				assertNoLeftoverTempFiles(t, tmpDir, "")
			})
		}
	})
}
