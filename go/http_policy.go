package laneshunt

import (
	"crypto/tls"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// contentRange 表示解析后的 RFC 9110 Content-Range 字节范围信息。
type contentRange struct {
	isUnsatisfied bool
	start         int64
	end           int64
	total         int64
	hasTotal      bool
}

type validatorKind int

const (
	validatorNone validatorKind = iota
	validatorStrongETag
	validatorSafeLastModified
)

// lockedValidator 保存探针阶段锁定的强资源校验器，供后续所有分片及跨源续传复检。
type lockedValidator struct {
	kind  validatorKind
	value string
	lm    time.Time
}

// slotHTTPClient 封装单个 Worker 槽位独占的 HTTP/1.1 客户端与 Transport。
type slotHTTPClient struct {
	client    *http.Client
	transport *http.Transport
}

// closeIdle 关闭该槽位独占 Transport 的所有空闲连接，避免后台残留套接字。
func (s *slotHTTPClient) closeIdle() {
	if s != nil && s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

func isAllowedURL(u *url.URL, requireHTTPS bool) bool {
	if u == nil || u.Scheme == "" || u.Hostname() == "" || u.User != nil {
		return false
	}
	if requireHTTPS {
		return strings.EqualFold(u.Scheme, "https")
	}
	return strings.EqualFold(u.Scheme, "https") || strings.EqualFold(u.Scheme, "http")
}

// ValidateURL 校验下载地址的合法性、协议要求及禁止内嵌 userinfo。
func ValidateURL(rawURL string, requireHTTPS bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, ErrInsecureURL
	}
	u, err := url.Parse(trimmed)
	if err != nil || !isAllowedURL(u, requireHTTPS) {
		return nil, ErrInsecureURL
	}
	return u, nil
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}

// isSameOrigin 按 scheme + lower(host) + effectivePort 严格判定两个 URL 是否同源。
func isSameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

// NewSafeRedirectChecker 构建符合同源安全策略的 http.Client.CheckRedirect 回调。
// 该回调强制限制最大跳数、拒绝含 userinfo 的目标地址、在 requireHTTPS 为 true 时拦截降级至非 HTTPS，
// 并在跨源重定向时剥离 Authorization、Cookie、Referer 与 If-Range，同时保留 Range、Accept-Encoding 与 User-Agent。
func NewSafeRedirectChecker(requireHTTPS bool, maxRedirects int) func(req *http.Request, via []*http.Request) error {
	return newRedirectChecker(requireHTTPS, maxRedirects, nil)
}

func newRedirectChecker(requireHTTPS bool, maxRedirects int, crossOrigin *atomic.Bool) func(req *http.Request, via []*http.Request) error {
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return ErrTooManyRedirects
		}
		if !isAllowedURL(req.URL, requireHTTPS) {
			return ErrInsecureRedirect
		}
		if len(via) == 0 {
			return nil
		}

		origin := via[0]
		prev := via[len(via)-1]

		// 显式保留下载所需的 Range、Accept-Encoding 与 User-Agent 请求头
		for _, hdr := range []string{"Range", "Accept-Encoding", "User-Agent"} {
			if v := origin.Header.Get(hdr); v != "" {
				req.Header.Set(hdr, v)
			}
		}

		if !isSameOrigin(origin.URL, req.URL) || !isSameOrigin(prev.URL, req.URL) {
			if crossOrigin != nil {
				crossOrigin.Store(true)
			}
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Del("Referer")
			req.Header.Del("If-Range")
		} else {
			if v := origin.Header.Get("If-Range"); v != "" {
				req.Header.Set("If-Range", v)
			}
		}
		return nil
	}
}

// newIsolatedHTTP1Client 为单个槽位或探针克隆独立的 HTTP/1.1 Transport，
// 强制清除残留的 ALPN "h2" 协商列表以彻底杜绝 HTTP/2 单连接多路复用。
func newIsolatedHTTP1Client(base *http.Client, requireHTTPS bool, maxRedirects int, responseHeaderTimeout time.Duration, crossOrigin *atomic.Bool) *slotHTTPClient {
	checkRedirect := newRedirectChecker(requireHTTPS, maxRedirects, crossOrigin)

	var baseRT http.RoundTripper
	if base != nil && base.Transport != nil {
		baseRT = base.Transport
	} else {
		baseRT = http.DefaultTransport
	}

	if bt, ok := baseRT.(*http.Transport); ok && bt != nil {
		tr := bt.Clone()
		setHTTP1OnlyProtocols(tr)
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
			if tr.TLSClientConfig.MinVersion == 0 {
				tr.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		// 显式覆写 NextProtos，避免克隆已初始化的 http.DefaultTransport 时残留 "h2"
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		tr.DisableCompression = true
		tr.MaxIdleConns = 1
		tr.MaxIdleConnsPerHost = 1
		tr.MaxConnsPerHost = 0
		if responseHeaderTimeout > 0 {
			tr.ResponseHeaderTimeout = responseHeaderTimeout
		}
		return &slotHTTPClient{
			client: &http.Client{
				Transport:     tr,
				CheckRedirect: checkRedirect,
			},
			transport: tr,
		}
	}

	// 调用方注入了自定义非 *http.Transport 的 RoundTripper（如测试桩）时直接复用
	return &slotHTTPClient{
		client: &http.Client{
			Transport:     baseRT,
			CheckRedirect: checkRedirect,
		},
	}
}

func parseNonNegativeInt64(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// parseContentRange 严格按 RFC 9110 §14.4 解析 Content-Range 头。
func parseContentRange(header string) (contentRange, bool) {
	trimmed := strings.TrimSpace(header)
	if len(trimmed) < 6 || !strings.EqualFold(trimmed[:6], "bytes ") {
		return contentRange{}, false
	}
	spec := strings.TrimSpace(trimmed[6:])
	slash := strings.IndexByte(spec, '/')
	if slash <= 0 || slash != strings.LastIndexByte(spec, '/') {
		return contentRange{}, false
	}
	rangePart := spec[:slash]
	totalPart := spec[slash+1:]

	if rangePart == "*" {
		if totalPart == "*" {
			return contentRange{isUnsatisfied: true}, true
		}
		totalVal, ok := parseNonNegativeInt64(totalPart)
		if !ok {
			return contentRange{}, false
		}
		return contentRange{isUnsatisfied: true, total: totalVal, hasTotal: true}, true
	}

	dash := strings.IndexByte(rangePart, '-')
	if dash <= 0 || dash != strings.LastIndexByte(rangePart, '-') {
		return contentRange{}, false
	}
	startVal, ok := parseNonNegativeInt64(rangePart[:dash])
	if !ok {
		return contentRange{}, false
	}
	endVal, ok := parseNonNegativeInt64(rangePart[dash+1:])
	if !ok || endVal < startVal {
		return contentRange{}, false
	}

	if totalPart == "*" {
		return contentRange{start: startVal, end: endVal}, true
	}
	totalVal, ok := parseNonNegativeInt64(totalPart)
	if !ok || endVal >= totalVal {
		return contentRange{}, false
	}
	return contentRange{start: startVal, end: endVal, total: totalVal, hasTotal: true}, true
}

func isStrongETag(etag string) bool {
	etag = strings.TrimSpace(etag)
	if len(etag) < 2 {
		return false
	}
	if strings.HasPrefix(etag, "W/") || strings.HasPrefix(etag, "w/") {
		return false
	}
	return etag[0] == '"' && etag[len(etag)-1] == '"'
}

// extractStrongValidator 按 RFC 9110 §13.1.5 提取强校验器：
// 优先采用非弱 ETag；若无 ETag 则要求响应包含合法 Date 且 Date - Last-Modified >= 60s。
func extractStrongValidator(h http.Header) lockedValidator {
	if etag := strings.TrimSpace(h.Get("ETag")); etag != "" {
		if isStrongETag(etag) {
			return lockedValidator{
				kind:  validatorStrongETag,
				value: etag,
			}
		}
		return lockedValidator{kind: validatorNone}
	}

	lmRaw := strings.TrimSpace(h.Get("Last-Modified"))
	dateRaw := strings.TrimSpace(h.Get("Date"))
	if lmRaw == "" || dateRaw == "" {
		return lockedValidator{kind: validatorNone}
	}
	lmTime, err := http.ParseTime(lmRaw)
	if err != nil {
		return lockedValidator{kind: validatorNone}
	}
	dateTime, err := http.ParseTime(dateRaw)
	if err != nil {
		return lockedValidator{kind: validatorNone}
	}
	if dateTime.Sub(lmTime) >= 60*time.Second {
		return lockedValidator{
			kind:  validatorSafeLastModified,
			value: lmRaw,
			lm:    lmTime,
		}
	}
	return lockedValidator{kind: validatorNone}
}

// matchesResponse 校验后续分片或跨源续传响应是否与已锁定的强校验器严格一致。
func (v lockedValidator) matchesResponse(h http.Header) bool {
	switch v.kind {
	case validatorStrongETag:
		etag := strings.TrimSpace(h.Get("ETag"))
		return isStrongETag(etag) && etag == v.value
	case validatorSafeLastModified:
		if strings.TrimSpace(h.Get("ETag")) != "" {
			return false
		}
		lmRaw := strings.TrimSpace(h.Get("Last-Modified"))
		if lmRaw == "" {
			return false
		}
		if lmRaw == v.value {
			return true
		}
		if lmTime, err := http.ParseTime(lmRaw); err == nil && lmTime.Equal(v.lm) {
			return true
		}
		return false
	default:
		return false
	}
}

// isIdentityContentEncoding 判断响应 Content-Encoding 是否为空或仅包含 identity。
func isIdentityContentEncoding(h http.Header) bool {
	for _, raw := range h.Values("Content-Encoding") {
		for _, part := range strings.Split(raw, ",") {
			token := strings.TrimSpace(part)
			if token == "" {
				continue
			}
			if !strings.EqualFold(token, "identity") {
				return false
			}
		}
	}
	return true
}

// isMultipartByteranges 判断响应 Content-Type 是否为 multipart/byteranges。
func isMultipartByteranges(h http.Header) bool {
	ct := strings.TrimSpace(h.Get("Content-Type"))
	if ct == "" {
		return false
	}
	if mediaType, _, err := mime.ParseMediaType(ct); err == nil {
		return strings.EqualFold(mediaType, "multipart/byteranges")
	}
	return strings.HasPrefix(strings.ToLower(ct), "multipart/byteranges")
}

// parseRetryAfter 按 RFC 9110 §10.2.3 解析 Retry-After 头（支持非负整数秒或 HTTP-date），并封顶至 maxCap。
func parseRetryAfter(header string, now time.Time, maxCap time.Duration) (time.Duration, bool) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return 0, false
	}
	if secs, ok := parseNonNegativeInt64(trimmed); ok {
		if maxCap > 0 && secs > int64(maxCap/time.Second) {
			return maxCap, true
		}
		d := time.Duration(secs) * time.Second
		if maxCap > 0 && d > maxCap {
			return maxCap, true
		}
		return d, true
	}
	t, err := http.ParseTime(trimmed)
	if err != nil {
		return 0, false
	}
	d := t.Sub(now)
	if d < 0 {
		d = 0
	}
	if maxCap > 0 && d > maxCap {
		d = maxCap
	}
	return d, true
}

// isRateLimitOrGatewayStatus 判断是否为限流或网关拥塞状态码（需全局退避并在分段模式下并发减半）。
func isRateLimitOrGatewayStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// isRetryableServerStatus 判断是否为可瞬态重试的 5xx 服务端错误（非 502/503/504 时不触发并发减半）。
func isRetryableServerStatus(code int) bool {
	return code >= http.StatusInternalServerError && code < 600
}
