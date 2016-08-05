package proto

// ControlMessage is sent from server to client to establish tunneled connection.
type ControlMessage struct {
	Action    Action            `json:"action"`
	Protocol  TransportProtocol `json:"transportProtocol"`
	LocalPort int               `json:"localPort"`
}

// Action represents type of ControlMsg request.
type Action int

const (
	RequestClientSession Action = iota + 1
)

// TransportProtocol represents tunneled connection type.
type TransportProtocol int

const (
	HTTP TransportProtocol = iota + 1
	TCP
	WS
)
