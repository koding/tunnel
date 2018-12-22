package tunnel

import (
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"git.sequentialread.com/forest/tunnel/tunnel-lib/proto"
)

// ProxyFunc is responsible for forwarding a remote connection to local server and writing the response back.
type ProxyFunc func(remote net.Conn, msg *proto.ControlMessage)

var (
	// DefaultProxyFuncs holds global default proxy functions for all transport protocols.
	DefaultProxyFuncs = ProxyFuncs{
		TCP: new(TCPProxy).Proxy,
	}
	// DefaultProxy is a ProxyFunc that uses DefaultProxyFuncs.
	DefaultProxy = Proxy(ProxyFuncs{})
)

// ProxyFuncs is a collection of ProxyFunc.
type ProxyFuncs struct {
	// TCP is custom implementation of TCP proxing.
	TCP ProxyFunc
}

// Proxy returns a ProxyFunc that uses custom function if provided, otherwise falls back to DefaultProxyFuncs.
func Proxy(p ProxyFuncs) ProxyFunc {
	return func(remote net.Conn, msg *proto.ControlMessage) {
		var f ProxyFunc
		f = DefaultProxyFuncs.TCP
		if p.TCP != nil {
			f = p.TCP
		}

		if f == nil {
			log.Printf("Proxy(): Could not determine proxy function for %v\n", msg)
			remote.Close()
		}

		f(remote, msg)
	}
}

// Join copies data between local and remote connections.
// It reads from one connection and writes to the other.
// It's a building block for ProxyFunc implementations.
func Join(local, remote net.Conn, debugLog bool) {
	var wg sync.WaitGroup
	wg.Add(2)

	transfer := func(side string, dst, src net.Conn) {
		if debugLog {
			log.Printf("Join(): proxying %s -> %s\n", src.RemoteAddr(), dst.RemoteAddr())
		}

		n, err := io.Copy(dst, src)
		// either the backend server being proxied,
		// or the client talking to the backend server through the proxy may close the connection at any time.
		// This is fine, and in that case we simply completely close and clean up this connection.
		if err != nil && !strings.Contains(err.Error(), "use of closed") {
			log.Printf("Join(): %s: copy error: %s\n", side, err)
		}

		if err := src.Close(); err != nil {
			if debugLog {
				log.Printf("Join(): %s: close error: %s\n", side, err)
			}
		}

		if err := dst.Close(); err != nil {
			if debugLog {
				log.Printf("Join(): %s: closeWrite error: %s\n", side, err)
			}
		}

		wg.Done()
		if debugLog {
			log.Printf("Join(): done proxying %s -> %s: %d bytes\n", src.RemoteAddr(), dst.RemoteAddr(), n)
		}
	}

	go transfer("remote to local", local, remote)
	go transfer("local to remote", remote, local)

	wg.Wait()
}
