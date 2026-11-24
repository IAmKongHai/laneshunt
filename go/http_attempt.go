package laneshunt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// httpAttempt 统一封装探针与单流下载的单次 HTTP/1.1 请求句柄及其空闲看门狗定时器。
type httpAttempt struct {
	resp        *http.Response
	slot        *slotHTTPClient
	reqCancel   context.CancelFunc
	idleTimer   *time.Timer
	idleFired   *atomic.Bool
	finalURL    string
	crossOrigin bool
}

// close 释放本次请求的空闲定时器、上下文、响应体与独占连接池。
func (a *httpAttempt) close() {
	if a == nil {
		return
	}
	if a.idleTimer != nil {
		a.idleTimer.Stop()
	}
	if a.reqCancel != nil {
		a.reqCancel()
	}
	if a.resp != nil && a.resp.Body != nil {
		_ = a.resp.Body.Close()
	}
	a.slot.closeIdle()
}

func (a *httpAttempt) resetIdle(d time.Duration) {
	if a != nil && a.idleTimer != nil {
		a.idleTimer.Reset(d)
	}
}

func (a *httpAttempt) wasIdle() bool {
	return a != nil && a.idleFired != nil && a.idleFired.Load()
}

// startHTTPAttempt 发起一次带独立 HTTP/1.1 Transport 与空闲超时的 GET 请求。
// 若返回 fatalErr != nil 表示不可重试的致命错误；若返回 transientErr != nil 表示可重试的瞬态错误。
func (d *Downloader) startHTTPAttempt(
	parentCtx, totalCtx context.Context,
	rawURL, rangeHdr, ifRangeHdr string,
) (attempt *httpAttempt, fatalErr error, transientErr error) {
	var crossFlag atomic.Bool
	slot := newIsolatedHTTP1Client(
		d.cfg.BaseClient,
		d.cfg.RequireHTTPS(),
		d.cfg.MaxRedirects,
		d.cfg.SingleStreamIdleTimeout,
		&crossFlag,
	)

	reqCtx, reqCancel := context.WithCancel(totalCtx)
	idleFired := &atomic.Bool{}
	idleTimer := time.AfterFunc(d.cfg.SingleStreamIdleTimeout, func() {
		idleFired.Store(true)
		reqCancel()
	})

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		idleTimer.Stop()
		reqCancel()
		slot.closeIdle()
		return nil, err, nil
	}
	req.Header.Set("Accept-Encoding", "identity")
	if d.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", d.cfg.UserAgent)
	}
	if rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}
	if ifRangeHdr != "" {
		req.Header.Set("If-Range", ifRangeHdr)
	}

	resp, doErr := slot.client.Do(req)
	if doErr != nil {
		wasIdle := idleFired.Load()
		idleTimer.Stop()
		reqCancel()
		slot.closeIdle()
		fatal, transient := classifyRequestError(parentCtx, totalCtx, doErr, wasIdle)
		return nil, fatal, transient
	}

	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &httpAttempt{
		resp:        resp,
		slot:        slot,
		reqCancel:   reqCancel,
		idleTimer:   idleTimer,
		idleFired:   idleFired,
		finalURL:    finalURL,
		crossOrigin: crossFlag.Load(),
	}, nil, nil
}

// classifyRequestError 将请求或读流错误统一归类为不可重试致命错误或可重试瞬态错误。
func classifyRequestError(parentCtx, totalCtx context.Context, err error, idleFired bool) (fatalErr, transientErr error) {
	if parentCtx.Err() != nil {
		return classifyParentOrTotalErr(parentCtx, totalCtx, err), nil
	}
	if redirErr := extractRedirectError(err); redirErr != nil {
		return redirErr, nil
	}
	if isPermanentTLSError(err) {
		return err, nil
	}
	if totalCtx.Err() != nil {
		return &TimeoutError{Cause: totalCtx.Err()}, nil
	}
	if idleFired {
		return nil, &TimeoutError{Cause: err}
	}
	return nil, wrapIfTimeout(err)
}

// retryOrExhaust 在瞬态失败后检查重试预算；未耗尽时按 delay 等待（可被上下文中断）。
func retryOrExhaust(
	parentCtx, totalCtx context.Context,
	attempt, maxAttempts, attemptsUsed int,
	cause error,
	delay time.Duration,
) error {
	if attempt >= maxAttempts {
		return &RetriesExhaustedError{Attempts: attemptsUsed, Cause: cause}
	}
	if sleepErr := sleepWithContext(totalCtx, delay); sleepErr != nil {
		return classifyParentOrTotalErr(parentCtx, totalCtx, sleepErr)
	}
	return nil
}

// retryDelayForStatus 按状态码与 Retry-After 头计算本次瞬态错误应等待的退避时长。
func retryDelayForStatus(resp *http.Response, cfg Config) time.Duration {
	waitDelay := cfg.RetryDelay
	if isRateLimitOrGatewayStatus(resp.StatusCode) {
		if ra, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now(), cfg.maxRetryAfter); ok {
			waitDelay = ra
		}
	}
	return waitDelay
}

func classifyParentOrTotalErr(parentCtx, totalCtx context.Context, fallback error) error {
	if parentCtx.Err() != nil {
		if errors.Is(parentCtx.Err(), context.Canceled) {
			return context.Canceled
		}
		return &TimeoutError{Cause: parentCtx.Err()}
	}
	if totalCtx.Err() != nil {
		return &TimeoutError{Cause: totalCtx.Err()}
	}
	return fallback
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func extractRedirectError(err error) error {
	if errors.Is(err, ErrInsecureRedirect) {
		return ErrInsecureRedirect
	}
	if errors.Is(err, ErrTooManyRedirects) {
		return ErrTooManyRedirects
	}
	return nil
}

// wrapIfTimeout 将底层 context.DeadlineExceeded 或 net.Error 超时统一包装为 TimeoutError，便于调用方按 ErrTimeout 归类。
func wrapIfTimeout(err error) error {
	if err == nil {
		return nil
	}
	var te *TimeoutError
	if errors.As(err, &te) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &TimeoutError{Cause: err}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &TimeoutError{Cause: err}
	}
	return err
}

// isPermanentTLSError 判断是否为不可通过重试恢复的 TLS 证书校验失败。
func isPermanentTLSError(err error) bool {
	if err == nil {
		return false
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return true
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		return true
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}
	var sysRoots x509.SystemRootsError
	if errors.As(err, &sysRoots) {
		return true
	}
	var verifyErr *tls.CertificateVerificationError
	return errors.As(err, &verifyErr)
}
