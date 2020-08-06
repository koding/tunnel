package proto

// ControlMessage is sent from server to client to establish tunneled connection.
type ControlMessage struct {
	Action  Action `json:"action"`
	Service string `json:"service"`
}

// Action represents type of ControlMsg request.
type Action int

// ControlMessage actions.
const (
	RequestClientSession Action = iota + 1
)
