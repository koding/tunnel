package tunnel

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/cajax/mylittleproxy/proto"
	"github.com/koding/logging"
	"io"
	"net"
	"net/http"
	"net/url"
)

var (
	httpLog = logging.NewLogger("http")
)

// HTTPProxy forwards HTTP traffic.
//
// We take original request, replace host and protocol with target host and execute it. Returned data redirected to the yamux tunnel
// When connection to local server cannot be established proxy responds with http error message.
type HTTPProxy struct {
	// TargetHost defines the TCP address of the local server.
	// This is optional if you want to specify a single TCP address.
	TargetHost string

	// ErrorResp is custom response send to tunnel server when client cannot
	// establish connection to local server. If not set a default "no local server"
	// response is sent.
	ErrorResp *http.Response
	// Log is a custom logger that can be used for the proxy.
	// If not set a "http" logger is used.
	Log logging.Logger
}

// Proxy is a ProxyFunc.
func (p *HTTPProxy) Proxy(remote net.Conn, msg *proto.ControlMessage) {
	if msg.Protocol != proto.HTTP && msg.Protocol != proto.WS {
		panic("Proxy mismatch")
	}

	req, err := http.ReadRequest(bufio.NewReader(remote))

	p.patchRequest(req)

	res, err := http.DefaultClient.Do(req)

	fmt.Println(res, err)
	if err != nil {
		p.log().Warning("Failed remote request", req.URL.String(), err)
		p.sendError(remote)
		return
	}

	res.Write(remote)
	return
}

func (p *HTTPProxy) patchRequest(req *http.Request) {
	targetUrl, _ := url.Parse(p.TargetHost)
	path := req.URL.Path
	req.RequestURI = ""
	req.URL = targetUrl
	req.URL.Path = path
}

func (p *HTTPProxy) sendError(remote net.Conn) {
	var w = noLocalServer()
	if p.ErrorResp != nil {
		w = p.ErrorResp
	}

	buf := new(bytes.Buffer)
	w.Write(buf)
	if _, err := io.Copy(remote, buf); err != nil {
		var log = p.log()
		log.Debug("Copy in-mem response error: %s", err)
	}

	remote.Close()
}

func noLocalServer() *http.Response {
	body := bytes.NewBufferString("no local server")
	return &http.Response{
		Status:        http.StatusText(http.StatusServiceUnavailable),
		StatusCode:    http.StatusServiceUnavailable,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(body),
		ContentLength: int64(body.Len()),
	}
}

func (p *HTTPProxy) log() logging.Logger {
	if p.Log != nil {
		return p.Log
	}
	return httpLog
}
