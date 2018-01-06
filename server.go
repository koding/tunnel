// Package tunnel is a server/client package that enables to proxy public
// connections to your local machine over a tunnel connection from the local
// machine to the public server.
package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/koding/logging"
	"github.com/koding/tunnel/proto"

	"github.com/hashicorp/yamux"
)

var (
	errNoClientSession = errors.New("no client session established")
	defaultTimeout     = 10 * time.Second
)

// Server is responsible for proxying public connections to the client over a
// tunnel connection. It also listens to control messages from the client.
type Server struct {
	// pending contains the channel that is associated with each new tunnel request.
	pending map[string]chan net.Conn
	// pendingMu protects the pending map.
	pendingMu sync.Mutex

	// sessions contains a session per virtual host.
	// Sessions provides multiplexing over one connection.
	sessions map[string]*yamux.Session
	// sessionsMu protects sessions.
	sessionsMu sync.Mutex

	// controls contains the control connection from the client to the server.
	controls *controls

	// virtualHosts is used to map public hosts to remote clients.
	//virtualHosts vhostStorage

	// virtualAddrs.
	virtualAddrs *vaddrStorage

	// connCh is used to publish accepted connections for tcp tunnels.
	connCh chan net.Conn

	// onConnectCallbacks contains client callbacks called when control
	// session is established for a client with given identifier.
	onConnectCallbacks *callbacks

	// onDisconnectCallbacks contains client callbacks called when control
	// session is closed for a client with given identifier.
	onDisconnectCallbacks *callbacks

	// states represents current clients' connections state.
	states map[string]ClientState
	// statesMu protects states.
	statesMu sync.RWMutex
	// stateCh notifies receiver about client state changes.
	stateCh chan<- *ClientStateChange

	// yamuxConfig is passed to new yamux.Session's
	yamuxConfig *yamux.Config

	sendProxyProtocolv1 bool

	log logging.Logger
}

// ServerConfig defines the configuration for the Server
type ServerConfig struct {
	// StateChanges receives state transition details each time client
	// connection state changes. The channel is expected to be sufficiently
	// buffered to keep up with event pace.
	//
	// If nil, no information about state transitions are dispatched
	// by the library.
	StateChanges chan<- *ClientStateChange

	// Debug enables debug mode, enable only if you want to debug the server
	Debug bool

	//Send the HAProxy PROXY protocol v1 header to the proxy client before streaming TCP from the remote client.
	SendProxyProtocolv1 bool

	// Log defines the logger. If nil a default logging.Logger is used.
	Log logging.Logger

	// YamuxConfig defines the config which passed to every new yamux.Session. If nil
	// yamux.DefaultConfig() is used.
	YamuxConfig *yamux.Config
}

// NewServer creates a new Server. The defaults are used if config is nil.
func NewServer(cfg *ServerConfig) (*Server, error) {
	yamuxConfig := yamux.DefaultConfig()
	if cfg.YamuxConfig != nil {
		if err := yamux.VerifyConfig(cfg.YamuxConfig); err != nil {
			return nil, err
		}

		yamuxConfig = cfg.YamuxConfig
	}

	log := newLogger("tunnel-server", cfg.Debug)
	if cfg.Log != nil {
		log = cfg.Log
	}

	connCh := make(chan net.Conn)

	opts := &vaddrOptions{
		connCh: connCh,
		log:    log,
	}

	s := &Server{
		pending:               make(map[string]chan net.Conn),
		sessions:              make(map[string]*yamux.Session),
		onConnectCallbacks:    newCallbacks("OnConnect"),
		onDisconnectCallbacks: newCallbacks("OnDisconnect"),
		virtualAddrs:          newVirtualAddrs(opts),
		controls:              newControls(),
		states:                make(map[string]ClientState),
		stateCh:               cfg.StateChanges,
		yamuxConfig:           yamuxConfig,
		connCh:                connCh,
		log:                   log,
		sendProxyProtocolv1:   cfg.SendProxyProtocolv1,
	}

	go s.serveTCP()

	return s, nil
}

// ServeHTTP is a tunnel that creates an http/websocket tunnel between a
// public connection and the client connection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// if the user didn't add the control and tunnel handler manually, we'll
	// going to infer and call the respective path handlers.
	switch path.Clean(r.URL.Path) + "/" {
	case proto.ControlPath:
		s.checkConnect(s.controlHandler).ServeHTTP(w, r)
		return
	}

	http.Error(w, "404 not found", http.StatusNotFound)
}

func (s *Server) serveTCP() {
	for conn := range s.connCh {
		go s.serveTCPConn(conn)
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	err := s.handleTCPConn(conn)
	if err != nil {
		s.log.Warning("failed to serve %q: %s", conn.RemoteAddr(), err)
		conn.Close()
	}
}

func (s *Server) handleTCPConn(conn net.Conn) error {
	ident, ok := s.virtualAddrs.getIdent(conn)
	if !ok {
		return fmt.Errorf("no virtual address available for %s", conn.LocalAddr())
	}

	_, port, err := parseHostPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}

	stream, err := s.dial(ident, proto.TCP, port)
	if err != nil {
		return err
	}

	if s.sendProxyProtocolv1 {
		remoteHost, remotePort, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			return err
		}
		localHost, localPort, err := net.SplitHostPort(conn.LocalAddr().String())
		if err != nil {
			return err
		}
		proxyNetwork := "TCP4"
		if strings.Contains(localHost, ":") {
			proxyNetwork = "TCP6"
		}

		stream.Write([]byte(fmt.Sprintf("PROXY %s %s %s %s %s\r\n", proxyNetwork, remoteHost, localHost, remotePort, localPort)))
	}

	disconnectedChan := make(chan bool)

	go s.proxy(disconnectedChan, conn, stream, "from proxy-client to client")
	go s.proxy(disconnectedChan, stream, conn, "from client to proxy-client")

	// Once one member of this conversation has disconnected, we should end the conversation for all parties.
	<-disconnectedChan

	return nonil(stream.Close(), conn.Close())
}

func (s *Server) proxy(disconnectedChan chan bool, dst, src net.Conn, side string) {
	defer (func() { disconnectedChan <- true })()

	s.log.Debug("tunneling %s -> %s (%s)", src.RemoteAddr(), dst.RemoteAddr(), side)
	n, err := io.Copy(dst, src)
	s.log.Debug("tunneled %d bytes %s -> %s (%s): %v", n, src.RemoteAddr(), dst.RemoteAddr(), side, err)
}

func (s *Server) dial(identifier string, p proto.Type, port int) (net.Conn, error) {
	control, ok := s.getControl(identifier)
	if !ok {
		return nil, errNoClientSession
	}

	session, err := s.getSession(identifier)
	if err != nil {
		return nil, err
	}

	msg := proto.ControlMessage{
		Action:    proto.RequestClientSession,
		Protocol:  p,
		LocalPort: port,
	}

	s.log.Debug("Sending control msg %+v", msg)

	// ask client to open a session to us, so we can accept it
	if err := control.send(msg); err != nil {
		// we might have several issues here, either the stream is closed, or
		// the session is going be shut down, the underlying connection might
		// be broken. In all cases, it's not reliable anymore having a client
		// session.
		control.Close()
		s.deleteControl(identifier)
		return nil, errNoClientSession
	}

	var stream net.Conn
	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}

	// if we don't receive anything from the client, we'll timeout
	s.log.Debug("Waiting for session accept")

	select {
	case err := <-async(acceptStream):
		return stream, err
	case <-time.After(defaultTimeout):
		return nil, errors.New("timeout getting session")
	}
}

// controlHandler is used to capture incoming tunnel connect requests into raw
// tunnel TCP connections.
func (s *Server) controlHandler(w http.ResponseWriter, r *http.Request) (ctErr error) {
	identifier := r.Header.Get(proto.ClientIdentifierHeader)
	ok := s.hasIdentifier(identifier)
	if !ok {
		return fmt.Errorf("no host associated for identifier %s. please use server.AddAddr()", identifier)
	}

	ct, ok := s.getControl(identifier)
	if ok {
		ct.Close()
		s.deleteControl(identifier)
		s.deleteSession(identifier)
		s.log.Warning("Control connection for %q already exists. This is a race condition and needs to be fixed on client implementation", identifier)
		return fmt.Errorf("control conn for %s already exist. \n", identifier)
	}

	s.log.Debug("Tunnel with identifier %s", identifier)

	hj, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("webserver doesn't support hijacking: %T", w)
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("hijack not possible: %s", err)
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 "+proto.Connected+"\n\n"); err != nil {
		return fmt.Errorf("error writing response: %s", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("error setting connection deadline: %s", err)
	}

	s.log.Debug("Creating control session")
	session, err := yamux.Server(conn, s.yamuxConfig)
	if err != nil {
		return err
	}
	s.addSession(identifier, session)

	var stream net.Conn

	// close and delete the session/stream if something goes wrong
	defer func() {
		if ctErr != nil {
			if stream != nil {
				stream.Close()
			}
			s.deleteSession(identifier)
		}
	}()

	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}

	// if we don't receive anything from the client, we'll timeout
	select {
	case err := <-async(acceptStream):
		if err != nil {
			return err
		}
	case <-time.After(time.Second * 10):
		return errors.New("timeout getting session")
	}

	s.log.Debug("Initiating handshake protocol")
	buf := make([]byte, len(proto.HandshakeRequest))
	if _, err := stream.Read(buf); err != nil {
		return err
	}

	if string(buf) != proto.HandshakeRequest {
		return fmt.Errorf("handshake aborted. got: %s", string(buf))
	}

	if _, err := stream.Write([]byte(proto.HandshakeResponse)); err != nil {
		return err
	}

	// setup control stream and start to listen to messages
	ct = newControl(stream)
	s.addControl(identifier, ct)
	go s.listenControl(ct)

	s.log.Debug("Control connection is setup")
	return nil
}

// listenControl listens to messages coming from the client.
func (s *Server) listenControl(ct *control) {
	s.onConnect(ct.identifier)

	for {
		var msg map[string]interface{}
		err := ct.dec.Decode(&msg)
		if err != nil {
			s.log.Debug("Closing client connection:  '%s'", ct.identifier)

			// close client connection so it reconnects again
			ct.Close()

			// don't forget to cleanup anything
			s.deleteControl(ct.identifier)
			s.deleteSession(ct.identifier)

			s.onDisconnect(ct.identifier, err)

			if err != io.EOF {
				s.log.Error("decode err: %s", err)
			}
			return
		}

		// right now we don't do anything with the messages, but because the
		// underlying connection needs to establihsed, we know when we have
		// disconnection(above), so we can cleanup the connection.
		s.log.Debug("msg: %s", msg)
	}
}

// OnConnect invokes a callback for client with given identifier,
// when it establishes a control session.
// After a client is connected, the associated function
// is also removed and needs to be added again.
func (s *Server) OnConnect(identifier string, fn func() error) {
	s.onConnectCallbacks.add(identifier, fn)
}

// onConnect sends notifications to listeners (registered in onConnectCallbacks
// or stateChanges chanel readers) when client connects.
func (s *Server) onConnect(identifier string) {
	if err := s.onConnectCallbacks.call(identifier); err != nil {
		s.log.Error("OnConnect: error calling callback for %q: %s", identifier, err)
	}

	s.changeState(identifier, ClientConnected, nil)
}

// OnDisconnect calls the function when the client connected with the
// associated identifier disconnects from the server.
// After a client is disconnected, the associated function
// is also removed and needs to be added again.
func (s *Server) OnDisconnect(identifier string, fn func() error) {
	s.onDisconnectCallbacks.add(identifier, fn)
}

// onDisconnect sends notifications to listeners (registered in onDisconnectCallbacks
// or stateChanges chanel readers) when client disconnects.
func (s *Server) onDisconnect(identifier string, err error) {
	if err := s.onDisconnectCallbacks.call(identifier); err != nil {
		s.log.Error("OnDisconnect: error calling callback for %q: %s", identifier, err)
	}

	s.changeState(identifier, ClientClosed, err)
}

func (s *Server) changeState(identifier string, state ClientState, err error) (prev ClientState) {
	s.statesMu.Lock()
	defer s.statesMu.Unlock()

	prev = s.states[identifier]
	s.states[identifier] = state

	if s.stateCh != nil {
		change := &ClientStateChange{
			Identifier: identifier,
			Previous:   prev,
			Current:    state,
			Error:      err,
		}

		select {
		case s.stateCh <- change:
		default:
			s.log.Warning("Dropping state change due to slow reader: %s", change)
		}
	}

	return prev
}

// // AddHost adds the given virtual host and maps it to the identifier.
// func (s *Server) AddHost(host, identifier string) {
// 	s.virtualHosts.AddHost(host, identifier)
// }

// // DeleteHost deletes the given virtual host. Once removed any request to this
// // host is denied.
// func (s *Server) DeleteHost(host string) {
// 	s.virtualHosts.DeleteHost(host)
// }

// AddAddr starts accepting connections on listener l, routing every connection
// to a tunnel client given by the identifier.
//
// When ip parameter is nil, all connections accepted from the listener are
// routed to the tunnel client specified by the identifier (port-based routing).
//
// When ip parameter is non-nil, only those connections are routed whose local
// address matches the specified ip (ip-based routing).
//
// If l listens on multiple interfaces it's desirable to call AddAddr multiple
// times with the same l value but different ip one.
func (s *Server) AddAddr(l net.Listener, ip net.IP, identifier string) {
	s.virtualAddrs.Add(l, ip, identifier)
}

// DeleteAddr stops listening for connections on the given listener.
//
// Upon return no more connections will be tunneled, but as the method does not
// close the listener, so any ongoing connection won't get interrupted.
func (s *Server) DeleteAddr(l net.Listener, ip net.IP) {
	s.virtualAddrs.Delete(l, ip)
}

func (s *Server) hasIdentifier(identifier string) bool {
	return s.virtualAddrs.HasIdentifier(identifier)
}

func (s *Server) addControl(identifier string, conn *control) {
	s.controls.addControl(identifier, conn)
}

func (s *Server) getControl(identifier string) (*control, bool) {
	return s.controls.getControl(identifier)
}

func (s *Server) deleteControl(identifier string) {
	s.controls.deleteControl(identifier)
}

func (s *Server) getSession(identifier string) (*yamux.Session, error) {
	s.sessionsMu.Lock()
	session, ok := s.sessions[identifier]
	s.sessionsMu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no session available for identifier: '%s'", identifier)
	}

	return session, nil
}

func (s *Server) addSession(identifier string, session *yamux.Session) {
	s.sessionsMu.Lock()
	s.sessions[identifier] = session
	s.sessionsMu.Unlock()
}

func (s *Server) deleteSession(identifier string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	session, ok := s.sessions[identifier]

	if !ok {
		return // nothing to delete
	}

	if session != nil {
		session.GoAway() // don't accept any new connection
		session.Close()
	}

	delete(s.sessions, identifier)
}

func copyHeader(dst, src http.Header) {
	for k, v := range src {
		vv := make([]string, len(v))
		copy(vv, v)
		dst[k] = vv
	}
}

// checkConnect checks whether the incoming request is HTTP CONNECT method.
func (s *Server) checkConnect(fn func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "405 must CONNECT\n", http.StatusMethodNotAllowed)
			return
		}

		if err := fn(w, r); err != nil {
			s.log.Error("Handler err: %v", err.Error())

			if identifier := r.Header.Get(proto.ClientIdentifierHeader); identifier != "" {
				s.onDisconnect(identifier, err)
			}

			http.Error(w, err.Error(), 502)
		}
	})
}

func parseHostPort(addr string) (string, int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}

	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, err
	}

	return host, int(n), nil
}

// headerContains is a copy of tokenListContainsValue from gorilla/websocket/util.go
func headerContains(header []string, value string) bool {
	for _, h := range header {
		for _, v := range strings.Split(h, ",") {
			if strings.EqualFold(strings.TrimSpace(v), value) {
				return true
			}
		}
	}

	return false
}

func nonil(err ...error) error {
	for _, e := range err {
		if e != nil {
			return e
		}
	}

	return nil
}

func newLogger(name string, debug bool) logging.Logger {
	log := logging.NewLogger(name)
	logHandler := logging.NewWriterHandler(os.Stderr)
	logHandler.Colorize = true
	log.SetHandler(logHandler)

	if debug {
		log.SetLevel(logging.DEBUG)
		logHandler.SetLevel(logging.DEBUG)
	}

	return log
}
