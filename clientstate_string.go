// Code generated by "stringer -type ClientState"; DO NOT EDIT

package mylittleproxy

import "fmt"

const _ClientState_name = "ClientUnknownClientStartedClientConnectingClientConnectedClientDisconnectedClientClosed"

var _ClientState_index = [...]uint8{0, 13, 26, 42, 57, 75, 87}

func (i ClientState) String() string {
	if i >= ClientState(len(_ClientState_index)-1) {
		return fmt.Sprintf("ClientState(%d)", i)
	}
	return _ClientState_name[_ClientState_index[i]:_ClientState_index[i+1]]
}
