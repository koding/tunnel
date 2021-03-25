package tunnel

import (
	"log"
	"net"

	"git.sequentialread.com/forest/threshold/tunnel-lib/proto"
)

// TCPProxy forwards TCP streams.
//
// the incoming ControlMessage will specify a service (string) and the TCPProxy will call FetchLocalAddr
// to determine which address to proxy to for that service name (for example, 127.0.0.1:8080 for fooService)
// or, it will fail/cancel if FetchLocalAddr returns an error.

type TCPProxy struct {

	// FetchLocalAddr is used for looking up TCP address of the services.
	FetchLocalAddr func(service string) (string, error)

	// Log is a custom logger that can be used for the proxy.
	// If not set a "tcp" logger is used.
	DebugLog bool
}

// Proxy is a ProxyFunc.
func (p *TCPProxy) Proxy(remote net.Conn, msg *proto.ControlMessage) {

	localAddr, err := p.FetchLocalAddr(msg.Service)
	if err != nil {
		log.Printf("TCPProxy.Proxy(): FetchLocalAddr('%s') returned %s.\n", msg.Service, err)
		return
	}

	//log.Debug("Dialing local server: %q", localAddr)
	//fmt.Printf("Dialing local server: %q\n\n", localAddr)
	local, err := net.DialTimeout("tcp", localAddr, defaultTimeout)
	if err != nil {
		log.Println("TCPProxy.Proxy(): Dialing local server %q failed: %s", localAddr, err)
		return
	}

	Join(local, remote, p.DebugLog)
}
