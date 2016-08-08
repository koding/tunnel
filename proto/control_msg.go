package proto

// ControlMessage is sent from server to client to establish tunneled connection.
type ControlMessage struct {
	Action    Action `json:"action"`
	Protocol  Type   `json:"transportProtocol"`
	LocalPort int    `json:"localPort"`
}

// Action represents type of ControlMsg request.
type Action int

const (
	RequestClientSession Action = iota + 1
)

// Type represents tunneled connection type.
type Type int

const (
	HTTP Type = iota + 1
	TCP
	WS
)
