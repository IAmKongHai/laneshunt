//go:build go1.24

package laneshunt

import "net/http"

// setHTTP1OnlyProtocols 在 Go 1.24+ 上显式通过 Transport.Protocols 仅启用 HTTP/1.1。
func setHTTP1OnlyProtocols(tr *http.Transport) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr.Protocols = protocols
}

// hasHTTP1OnlyProtocols 供单测校验 Transport.Protocols 是否处于仅 HTTP/1.1 状态。
func hasHTTP1OnlyProtocols(tr *http.Transport) bool {
	return tr.Protocols != nil && tr.Protocols.HTTP1() && !tr.Protocols.HTTP2()
}
