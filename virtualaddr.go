package tunnel

import (
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
}

type listener struct {
	net.Listener
	ListenerInfo

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

	listeners map[net.Listener]*listener
	ports     map[int]*listener // port-based routing: maps port number to identifier
	//	ips       map[string]*listener // ip-based routing: maps ip address to identifier

	mu sync.RWMutex
}

func newVirtualAddrs(opts *vaddrOptions) *vaddrStorage {
	return &vaddrStorage{
		vaddrOptions: opts,
		listeners:    make(map[net.Listener]*listener),
		ports:        make(map[int]*listener),
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
	if addr, ok := l.Addr().(*net.TCPAddr); ok {
		if addr.IP.Equal(net.IPv4zero) {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port))
		}
	}
	return l.Addr().String()
}

func (l *listener) stop() {
	if atomic.CompareAndSwapInt32(&l.done, 0, 1) {
		// stop is called when no more connections should be accepted by
		// the user-provided listener; as we can't simple close the listener
		// to not break the guarantee given by the (*Server).DeleteAddr
		// method, we make a dummy connection to break out of serve loop.
		// It is safe to make a dummy connection, as either the following
		// dial will time out when the listener is busy accepting connections,
		// or will get closed immadiately after idle listeners accepts connection
		// and returns from the serve loop.
		conn, err := net.DialTimeout("tcp", l.localAddr(), defaultTimeout)
		if err == nil {
			conn.Close()
		}
	}
}

func (vaddr *vaddrStorage) Add(l net.Listener, ip net.IP, ident string, sendProxyProtocolv1 bool, backendPort int) {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	lis, ok := vaddr.listeners[l]
	if !ok {
		lis = vaddr.newListener(l, ident, sendProxyProtocolv1, backendPort)
		vaddr.listeners[l] = lis
		go lis.serve()
	}

	vaddr.ports[mustPort(l)] = lis
	// if ip != nil {
	// 	lis.ips[ip.String()] = struct{}{}
	// 	vaddr.ips[ip.String()] = ident
	// } else {
	// 	vaddr.ports[mustPort(l)] = ident
	// }
}

func (vaddr *vaddrStorage) Delete(l net.Listener, ip net.IP) {
	vaddr.mu.Lock()
	defer vaddr.mu.Unlock()

	lis, ok := vaddr.listeners[l]
	if !ok {
		return
	}

	lis.stop()
	delete(vaddr.ports, mustPort(l))
	delete(vaddr.listeners, l)

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

func (vaddr *vaddrStorage) newListener(l net.Listener, clientIdentity string, sendProxyProtocolv1 bool, backendPort int) *listener {
	return &listener{
		Listener: l,
		ListenerInfo: ListenerInfo{
			AssociatedClientIdentity: clientIdentity,
			SendProxyProtocolv1:      sendProxyProtocolv1,
			BackendPort:              backendPort,
		},
		vaddrOptions: vaddr.vaddrOptions,
		//ips:          make(map[string]struct{}),
	}
}

func (vaddr *vaddrStorage) HasIdentifier(identifier string) bool {
	for _, listener := range vaddr.ports {
		if listener.AssociatedClientIdentity == identifier {
			return true
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

	_, port, err := parseHostPort(conn.LocalAddr().String())
	if err != nil {
		log.Printf("vaddrStorage.getListenerInfo(): failed to get identifier for connection %q: %s", conn.LocalAddr(), err)
		return nil, false
	}

	// First lookup if there's a ip-based route, then try port-base one.
	// if ident, ok := vaddr.ips[ip]; ok {
	// 	return ident, true
	// }

	listener, ok := vaddr.ports[port]
	var listenerInfo *ListenerInfo
	if ok {
		listenerInfo = &(listener.ListenerInfo)
	}
	return listenerInfo, ok
}

func mustPort(l net.Listener) int {
	_, port, err := parseHostPort(l.Addr().String())
	if err != nil {
		// This can happened when user passed custom type that
		// implements net.Listener, which returns ill-formed
		// net.Addr value.
		panic("ill-formed net.Addr: " + err.Error())
	}

	return port
}
