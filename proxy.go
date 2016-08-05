package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sync"

	"github.com/koding/logging"
	"github.com/koding/tunnel/proto"
)

// Proxy is responsible for forwarding remote connection to local server and writing the response back.
type Proxy interface {
	Proxy(remote net.Conn, msg *proto.ControlMessage)
}

var (
	httpLog = logging.NewLogger("http")
	tpcLog  = logging.NewLogger("tcp")
)

// ProxyHTTP is Proxy implementation focused on forwarding HTTP traffic.
//
// When tunnel server requests a connection it's proxied to 127.0.0.1:incomingPort
// where incomingPort is control message LocalPort.
// Usually this is tunnel server's public exposed Port.
// This behaviour can be changed by setting LocalAddr or FetchLocalAddr.
// FetchLocalAddr takes precedence over LocalAddr.
//
// When connection to local server cannot be established proxy responds with http error message.
type ProxyHTTP struct {
	// LocalAddr defines the TCP address of the local server.
	// This is optional if you want to specify a single TCP address.
	LocalAddr string
	// FetchLocalAddr is used for looking up TCP address of the server.
	// This is optional if you want to specify a dynamic TCP address based on incommig port.
	FetchLocalAddr func(port int) (string, error)
	// ErrorResp is custom response send to tunnel server when client cannot
	// establish connection to local server. If not set a default "no local server"
	// response is sent.
	ErrorResp *http.Response
	// Log is a custom logger that can be used for the proxy.
	// If not set a "http" logger is used.
	Log logging.Logger
}

// Proxy proxies remote connection to local server.
func (p *ProxyHTTP) Proxy(remote net.Conn, msg *proto.ControlMessage) {
	if msg.Protocol != proto.HTTP && msg.Protocol != proto.WS {
		panic("Proxy mismatch")
	}

	var log = p.log()

	var port = msg.LocalPort
	if port == 0 {
		port = 80
	}

	var localAddr = fmt.Sprintf("127.0.0.1:%d", port)
	if p.LocalAddr != "" {
		localAddr = p.LocalAddr
	} else if p.FetchLocalAddr != nil {
		l, err := p.FetchLocalAddr(msg.LocalPort)
		if err != nil {
			log.Warning("Failed to get custom local address: %s", err)
			p.sendError(remote)
			return
		}
		localAddr = l
	}

	log.Debug("Dialing local server %q", localAddr)
	local, err := net.DialTimeout("tcp", localAddr, defaultTimeout)
	if err != nil {
		log.Error("Dialing local server %q failed: %s", localAddr, err)
		p.sendError(remote)
		return
	}

	Join(local, remote, log)
}

func (p *ProxyHTTP) sendError(remote net.Conn) {
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
}

func noLocalServer() *http.Response {
	body := bytes.NewBufferString("no local server")
	return &http.Response{
		Status:        http.StatusText(http.StatusServiceUnavailable),
		StatusCode:    http.StatusServiceUnavailable,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(body),
		ContentLength: int64(body.Len()),
	}
}

func (p *ProxyHTTP) log() logging.Logger {
	if p.Log != nil {
		return p.Log
	}
	return httpLog
}

// ProxyTCP is Proxy implementation for TCP streams.
//
// If port-based routing is used, LocalAddr or FetchLocalAddr field is required
// for tunneling to function properly.
// Otherwise you'll be forwarding traffic to random ports and this is usually not desired.
//
// If IP-based routing is used then tunnel server connection request is
// proxied to 127.0.0.1:incomingPort where incomingPort is control message LocalPort.
// Usually this is tunnel server's public exposed Port.
// This behaviour can be changed by setting LocalAddr or FetchLocalAddr.
// FetchLocalAddr takes precedence over LocalAddr.
type ProxyTCP struct {
	// LocalAddr defines the TCP address of the local server.
	// This is optional if you want to specify a single TCP address.
	LocalAddr string
	// FetchLocalAddr is used for looking up TCP address of the server.
	// This is optional if you want to specify a dynamic TCP address based on incommig port.
	FetchLocalAddr func(port int) (string, error)
	// Log is a custom logger that can be used for the proxy.
	// If not set a "tcp" logger is used.
	Log logging.Logger
}

// Proxy proxies remote connection to local server.
func (p *ProxyTCP) Proxy(remote net.Conn, msg *proto.ControlMessage) {
	if msg.Protocol != proto.TCP {
		panic("Proxy mismatch")
	}

	var log = p.log()

	var port = msg.LocalPort
	if port == 0 {
		log.Warning("TCP proxy to port 0")
	}

	var localAddr = fmt.Sprintf("127.0.0.1:%d", port)
	if p.LocalAddr != "" {
		localAddr = p.LocalAddr
	} else if p.FetchLocalAddr != nil {
		l, err := p.FetchLocalAddr(msg.LocalPort)
		if err != nil {
			log.Warning("Failed to get custom local address: %s", err)
			return
		}
		localAddr = l
	}

	log.Debug("Dialing local server: %q", localAddr)
	local, err := net.DialTimeout("tcp", localAddr, defaultTimeout)
	if err != nil {
		log.Error("Dialing local server %q failed: %s", localAddr, err)
		return
	}

	Join(local, remote, log)
}

func (p *ProxyTCP) log() logging.Logger {
	if p.Log != nil {
		return p.Log
	}
	return tpcLog
}

// Join copies data between local and remote connections.
// It reads one connection and writes to the other.
// It aims to provide a building block for custom Proxy implementations.
func Join(local, remote net.Conn, log logging.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)

	transfer := func(side string, dst, src net.Conn) {
		log.Debug("proxing %s -> %s", src.RemoteAddr(), dst.RemoteAddr())

		n, err := io.Copy(dst, src)
		if err != nil {
			log.Error("%s: copy error: %s", side, err)
		}

		if err := src.Close(); err != nil {
			log.Debug("%s: close error: %s", side, err)
		}

		// not for yamux streams, but for client to local server connections
		if d, ok := dst.(*net.TCPConn); ok {
			if err := d.CloseWrite(); err != nil {
				log.Debug("%s: closeWrite error: %s", side, err)
			}
		}

		wg.Done()
		log.Debug("done proxing %s -> %s: %d bytes", src.RemoteAddr(), dst.RemoteAddr(), n)
	}

	go transfer("remote to local", local, remote)
	go transfer("local to remote", remote, local)

	wg.Wait()
}

////////////////////
// ProxyOverwrite //
////////////////////

// ProxyOverwrite enables easy setting of different proxy functions for different
// transport protocols. Consider the following example:
//
//     tunnel.ProxyOverwrite{
//             HTTP: &tunnel.ProxyHTTP{
//                     LocalAddr: localAddr,
//             },
//             WS: &MyCustomWSProxy{},
//     }
//
// This code would result in a Proxy implementation that:
//
// * forwards all HTTP calls to localAddr
// * uses MyCustomWSProxy for web sockets
// * handles TCP using default implementation
type ProxyOverwrite struct {
	// HTTP is optional custom implementation of HTTP proxing.
	HTTP Proxy
	// TCP is optional custom implementation of TCP proxing.
	TCP Proxy
	// WS is optional custom implementation of web socket proxing.
	WS Proxy

	defaultHTTP ProxyHTTP
	defaultTCP  ProxyTCP
}

// Proxy selects appropriate Proxy method based on control message protocol.
// It proxy method for a given protocol was not ovewritten a default implementation
// would be used.
func (p *ProxyOverwrite) Proxy(remote net.Conn, msg *proto.ControlMessage) {
	switch msg.Protocol {
	case proto.HTTP:
		p.http(remote, msg)
	case proto.TCP:
		p.tcp(remote, msg)
	case proto.WS:
		p.ws(remote, msg)
	}
}

func (p *ProxyOverwrite) http(remote net.Conn, msg *proto.ControlMessage) {
	if p.HTTP != nil {
		p.HTTP.Proxy(remote, msg)
		return
	}

	p.defaultHTTP.Proxy(remote, msg)
}

func (p *ProxyOverwrite) tcp(remote net.Conn, msg *proto.ControlMessage) {
	if p.TCP != nil {
		p.TCP.Proxy(remote, msg)
		return
	}

	p.defaultTCP.Proxy(remote, msg)
}

func (p *ProxyOverwrite) ws(remote net.Conn, msg *proto.ControlMessage) {
	if p.WS != nil {
		p.WS.Proxy(remote, msg)
	}

	p.defaultHTTP.Proxy(remote, msg)
}
