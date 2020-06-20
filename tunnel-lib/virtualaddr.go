package tunnel

import (
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type ListenerInfo struct {
	//Send the HAProxy PROXY protocol v1 header to the proxy client before streaming TCP from the remote client.
	SendProxyProtocolv1 bool

	BackendPort              int
	AssociatedClientIdentity string
	HostnameGlob             string
}

type listener struct {
	net.Listener
	backends []ListenerInfo

	*vaddrOptions

	done int32

	// ips keeps track of registered clients for ip-based routing;
	// when last client is deleted from the ip routing map, we stop
	// listening on connections
	//ips map[string]struct{}
}

type vaddrOptions struct {
	connCh chan<- net.Conn
}

type vaddrStorage struct {
	*vaddrOptions

	listeners map[string]*listener
	//  ports     map[int]*listener // port-based routing: maps port number to identifier
	//	ips       map[string]*listener // ip-based routing: maps ip address to identifier

	mu sync.RWMutex
}

func newVirtualAddrs(opts *vaddrOptions) *vaddrStorage {
	return &vaddrStorage{
		vaddrOptions: opts,
		listeners:    make(map[string]*listener),
		//      ports:        make(map[int]*listener),
		//		ips:          make(map[string]*listener),
	}
}

func (l *listener) serve() {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("listener.serve(): failue listening on %q: %s\n", l.Addr(), err)
			return
		}

		if atomic.LoadInt32(&l.done) != 0 {
			log.Printf("listener.serve(): stopped serving %q", l.Addr())
			conn.Close()
			return
		}

		l.connCh <- conn
	}
}

func (l *listener) localAddr() string {
	if addr, ok := l.Listener.Addr().(*net.TCPAddr); ok {
		if addr.IP.Equal(net.IPv4zero) {
			return net.JoinHostPort("0.0.0.0", strconv.Itoa(addr.Port))
		}
	}
	return l.Addr().String()
}

func (l *listener) stop() {

	atomic.CompareAndSwapInt32(&l.done, 0, 1)

	l.Listener.Close()

	// WTF is this... why.....
	// --forest
	//
	// if atomic.CompareAndSwapInt32(&l.done, 0, 1) {
	// 	// stop is called when no more connections should be accepted by
	// 	// the user-provided listener; as we can't simple close the listener
	// 	// to not break the guarantee given by the (*Server).DeleteAddr
	// 	// method, we make a dummy connection to break out of serve loop.
	// 	// It is safe to make a dummy connection, as either the following
	// 	// dial will time out when the listener is busy accepting connections,
	// 	// or will get closed immadiately after idle listeners accepts connection
	// 	// and returns from the serve loop.
	// 	conn, err := net.DialTimeout("tcp", l.localAddr(), defaultTimeout)
	// 	if err == nil {
	// 		conn.Close()
	// 	}
	// }
}

func (vaddr *vaddrStorage) Add(ip net.IP, port int, hostnameGlob string, ident string, sendProxyProtocolv1 bool, backendPort int) error {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	listenAddress := fmt.Sprintf("%s:%d", ip, port)

	listener, ok := vaddr.listeners[listenAddress]
	if !ok {
		var err error
		listener, err = vaddr.newListener(ip, port)
		if err != nil {
			return err
		}
		vaddr.listeners[listenAddress] = listener
		go listener.serve()
	}

	listener.addHost(hostnameGlob, ident, sendProxyProtocolv1, backendPort)

	// vaddr.ports[mustPort(l)] = lis
	// if ip != nil {
	// 	lis.ips[ip.String()] = struct{}{}
	// 	vaddr.ips[ip.String()] = ident
	// } else {
	// 	vaddr.ports[mustPort(l)] = ident
	// }

	return nil
}

func (l *listener) addHost(hostnameGlob string, ident string, sendProxyProtocolv1 bool, backendPort int) {
	l.backends = append(l.backends, ListenerInfo{
		HostnameGlob:             hostnameGlob,
		AssociatedClientIdentity: ident,
		SendProxyProtocolv1:      sendProxyProtocolv1,
		BackendPort:              backendPort,
	})
}

func (l *listener) removeHost(hostnameGlob string) {
	newBackends := make([]ListenerInfo, 0)
	for _, b := range l.backends {
		if b.HostnameGlob != hostnameGlob {
			newBackends = append(newBackends, b)
		}
	}

	l.backends = newBackends
}

func (vaddr *vaddrStorage) Delete(ip net.IP, port int, hostnameGlob string) {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	listenAddress := fmt.Sprintf("%s:%d", ip, port)

	listener, ok := vaddr.listeners[listenAddress]
	if !ok {
		return
	}

	listener.removeHost(hostnameGlob)

	if len(listener.backends) == 0 {
		listener.stop()
		delete(vaddr.listeners, listenAddress)
	}

	// var stop bool

	// if ip != nil {
	// 	delete(lis.ips, ip.String())
	// 	delete(vaddr.ips, ip.String())

	// 	stop = len(lis.ips) == 0
	// } else {
	// 	delete(vaddr.ports, mustPort(l))

	// 	stop = true
	// }

	// // Only stop listening for connections when listener has clients
	// // registered to tunnel the connections to.
	// if stop {
	// 	lis.stop()
	// 	delete(vaddr.listeners, l)
	// }
}

func (vaddr *vaddrStorage) newListener(ip net.IP, port int) (*listener, error) {
	listenAddress := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	fmt.Printf("now listening on %s\n\n", listenAddress)

	netListener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, err
	}

	return &listener{
		Listener:     netListener,
		vaddrOptions: vaddr.vaddrOptions,
	}, nil
}

func (vaddr *vaddrStorage) HasIdentifier(identifier string) bool {
	for _, listener := range vaddr.listeners {
		for _, backend := range listener.backends {
			if backend.AssociatedClientIdentity == identifier {
				return true
			}
		}
	}
	// for _, id := range vaddr.ips {
	// 	if id == identifier {
	// 		return true
	// 	}
	// }
	return false
}

func (vaddr *vaddrStorage) getListenerInfo(conn net.Conn) (*ListenerInfo, string, []byte) {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	host, port, err := parseHostPort(conn.LocalAddr().String())
	if err != nil {
		log.Printf("vaddrStorage.getListenerInfo(): failed to get identifier for connection %q: %s", conn.LocalAddr(), err)
		return nil, "", make([]byte, 0)
	}

	for _, listener := range vaddr.listeners {
		listenerHost, listenerPort, err := parseHostPort(listener.localAddr())
		if err != nil {
			fmt.Printf("error parseHostPort on listener address: %s\n", err)
		}

		// fmt.Printf(
		// 	"host(%s) == listenerHost(%s), port(%d) == listenerPort(%d)\n\n",
		// 	host, listenerHost, port, listenerPort,
		// )

		listenHostMatches := listenerHost == host || listenerHost == "0.0.0.0" || listenerHost == "::"
		listenPortMatches := listenerPort == port

		if err == nil && listenHostMatches && listenPortMatches {

			//log.Printf("pre getHostnameFromSNI ")

			connectionHeader := make([]byte, 1024)
			n, err := conn.Read(connectionHeader)
			if err != nil && err != io.EOF {
				log.Printf("vaddrStorage.getListenerInfo(): failed to read header for connection %q: %s", conn.LocalAddr(), err)
				return nil, "", make([]byte, 0)
			}

			hostname, err := getHostnameFromSNI(connectionHeader[:n])

			// This will happen every time someone connects with a non-TLS protocol.
			// Its not a big deal, we can ignore it.
			// if err != nil {
			// 	log.Printf("vaddrStorage.getListenerInfo(): failed to get SNI for connection %q: %s\n", conn.LocalAddr(), err)
			// }

			//log.Printf("getHostnameFromSNI: %s\n", hostname)

			recordSpecificity := -10
			var mostSpecificMatchingBackend *ListenerInfo = nil
			for _, backend := range listener.backends {
				globToUse := backend.HostnameGlob
				if globToUse == "" {
					globToUse = "*"
				}
				numberOfPeriods := len(regexp.MustCompile(`\.`).FindAllString(globToUse, -1))
				numberOfGlobs := len(regexp.MustCompile(`\*+`).FindAllString(globToUse, -1))
				specificity := numberOfPeriods - numberOfGlobs
				if specificity > recordSpecificity && Glob(globToUse, hostname) {
					recordSpecificity = specificity
					mostSpecificMatchingBackend = &backend
				}
			}

			return mostSpecificMatchingBackend, hostname, connectionHeader[:n]
		}
	}

	return nil, "", make([]byte, 0)
}

// ---------------------------------------------------------------------------------------------

// https://github.com/ryanuber/go-glob/blob/master/glob.go

// The MIT License (MIT)

// Copyright (c) 2014 Ryan Uber

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// The character which is treated like a glob
const GLOB = "*"

// Glob will test a string pattern, potentially containing globs, against a
// subject string. The result is a simple true/false, determining whether or
// not the glob pattern matched the subject text.
func Glob(pattern, subj string) bool {
	// Empty pattern can only match empty subject
	if pattern == "" {
		return subj == pattern
	}

	// If the pattern _is_ a glob, it matches everything
	if pattern == GLOB {
		return true
	}

	parts := strings.Split(pattern, GLOB)

	if len(parts) == 1 {
		// No globs in pattern, so test for equality
		return subj == pattern
	}

	leadingGlob := strings.HasPrefix(pattern, GLOB)
	trailingGlob := strings.HasSuffix(pattern, GLOB)
	end := len(parts) - 1

	// Go over the leading parts and ensure they match.
	for i := 0; i < end; i++ {
		idx := strings.Index(subj, parts[i])

		switch i {
		case 0:
			// Check the first section. Requires special handling.
			if !leadingGlob && idx != 0 {
				return false
			}
		default:
			// Check that the middle parts match.
			if idx < 0 {
				return false
			}
		}

		// Trim evaluated text from subj as we loop over the pattern.
		subj = subj[idx+len(parts[i]):]
	}

	// Reached the last section. Requires special handling.
	return trailingGlob || strings.HasSuffix(subj, parts[end])
}
