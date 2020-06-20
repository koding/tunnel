package tunnel

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
)

type ListenerInfo struct {
	//Send the HAProxy PROXY protocol v1 header to the proxy client before streaming TCP from the remote client.
	SendProxyProtocolv1 bool

	BackendPort              int
	AssociatedClientIdentity string
	Hostname                 string
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

func (vaddr *vaddrStorage) Add(ip net.IP, port int, hostname string, ident string, sendProxyProtocolv1 bool, backendPort int) error {
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

	listener.addHost(hostname, ident, sendProxyProtocolv1, backendPort)

	// vaddr.ports[mustPort(l)] = lis
	// if ip != nil {
	// 	lis.ips[ip.String()] = struct{}{}
	// 	vaddr.ips[ip.String()] = ident
	// } else {
	// 	vaddr.ports[mustPort(l)] = ident
	// }

	return nil
}

func (l *listener) addHost(hostname string, ident string, sendProxyProtocolv1 bool, backendPort int) {
	l.backends = append(l.backends, ListenerInfo{
		Hostname:                 hostname,
		AssociatedClientIdentity: ident,
		SendProxyProtocolv1:      sendProxyProtocolv1,
		BackendPort:              backendPort,
	})
}

func (l *listener) removeHost(hostname string) {
	newBackends := make([]ListenerInfo, 0)
	for _, b := range l.backends {
		if b.Hostname != hostname {
			newBackends = append(newBackends, b)
		}
	}

	l.backends = newBackends
}

func (vaddr *vaddrStorage) Delete(ip net.IP, port int, hostname string) {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	listenAddress := fmt.Sprintf("%s:%d", ip, port)

	listener, ok := vaddr.listeners[listenAddress]
	if !ok {
		return
	}

	listener.removeHost(hostname)

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

func (vaddr *vaddrStorage) getListenerInfo(conn net.Conn) (*ListenerInfo, bool) {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	host, port, err := parseHostPort(conn.LocalAddr().String())
	if err != nil {
		log.Printf("vaddrStorage.getListenerInfo(): failed to get identifier for connection %q: %s", conn.LocalAddr(), err)
		return nil, false
	}

	for _, listener := range vaddr.listeners {
		listenerHost, listenerPort, err := parseHostPort(listener.localAddr())
		if err != nil {
			fmt.Printf("error parseHostPort on listener address: %s\n", err)
		}

		fmt.Printf(
			"host(%s) == listenerHost(%s), port(%d) == listenerPort(%d)\n\n",
			host, listenerHost, port, listenerPort,
		)

		if err == nil && (listenerHost == host || listenerHost == "0.0.0.0" || listenerHost == "::") && listenerPort == port {

			log.Printf("pre getHostnameFromSNI ")

			// TODO getHostnameFromSNI doesn't work -- it breaks the test when we uncomment it. Maybe we have to read the bytes
			// and then pass them along somehow??
			// hostname, err := getHostnameFromSNI(conn)
			// if err != nil {
			// 	log.Printf("failed to get SNI: %s\n", err)
			// }

			// log.Printf("getHostnameFromSNI: %s\n", hostname)

			// for _, backend := range listener.backends {
			// 	// TODO glob compare hostname and backend.Hostname

			// }

			return &(listener.backends[0]), true
		}
	}

	return nil, false

	// First lookup if there's a ip-based route, then try port-base one.
	// if ident, ok := vaddr.ips[ip]; ok {
	// 	return ident, true
	// }

	// listener, ok := vaddr.ports[port]
	// var listenerInfo *ListenerInfo
	// if ok {
	// 	listenerInfo = &(listener.ListenerInfo)
	// }
	// return listenerInfo, ok
}

// func mustPort(l net.Listener) int {
// 	_, port, err := parseHostPort(l.Addr().String())
// 	if err != nil {
// 		// This can happened when user passed custom type that
// 		// implements net.Listener, which returns ill-formed
// 		// net.Addr value.
// 		panic("ill-formed net.Addr: " + err.Error())
// 	}

// 	return port
// }
