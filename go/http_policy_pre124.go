//go:build !go1.24

package laneshunt

import "net/http"

// setHTTP1OnlyProtocols 在 Go 1.22–1.23 上无需设置 Protocols，由 ForceAttemptHTTP2/TLSNextProto/NextProtos 保证仅走 HTTP/1.1。
func setHTTP1OnlyProtocols(_ *http.Transport) {}

// hasHTTP1OnlyProtocols 在 Go 1.22–1.23 上直接返回 true。
func hasHTTP1OnlyProtocols(_ *http.Transport) bool {
	return true
}
