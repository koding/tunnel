// Package proto defines tunnel client server communication protocol.
package proto

const (
	// DefaultControlPath is http.Handler url path for control connection.
	DefaultControlPath = "/_controlPath"

	// ClientIdentifierHeader is a header carrying information about tunnel identifier.
	ClientIdentifierHeader = "X-Tunnel-Identifier"

	// ClientIdentifierSignature is a header carrying salted SHA-1 hash of ClientIdentifierHeader
	ClientIdentifierSignature = "X-Tunnel-Signature"

	// control messages

	// Connected is message sent by server to client when control connection was established.
	Connected = "200 Connected to Tunnel"
	// HandshakeRequest is hello message sent by client to server.
	HandshakeRequest = "controlHandshake"
	// HandshakeResponse is response to HandshakeRequest sent by server to client.
	HandshakeResponse = "controlOk"
)

type ConnectionConfig struct {
	Http HTTPConfig `json:"http"`
	// TODO WS and TCP
}

type HTTPConfig struct {
	Domain  string            `json:"domain"`
	Target  string            `json:"target"`
	Rewrite []HTTPRewriteRule `json:"rewrite"`
}

type HTTPRewriteRule struct {
	From string `json:"from"`
	To   string `json:"to"`
}
