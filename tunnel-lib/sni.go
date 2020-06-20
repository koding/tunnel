package tunnel

import (
	"errors"
	"fmt"
	"strings"
)

const tlsRecordTypeHandshake uint8 = 22
const tlsMessageTypeClientHello uint8 = 1
const tlsExtensionServerName uint16 = 0

func getHostnameFromSNI(buf []byte) (string, error) {

	if len(buf) < 5 {
		return "", fmt.Errorf("expected buffer byte length > 5, got %d", len(buf))
	}

	// tls record type
	if uint8(buf[0]) != tlsRecordTypeHandshake {
		return "", fmt.Errorf("expected tlsRecordTypeHandshake (%d), got %d", tlsRecordTypeHandshake, uint8(buf[0]))
	}

	// ssl major version
	// (see https://serverfault.com/questions/910177/what-is-the-meaning-of-the-values-of-the-protocols-field-from-get-tlsciphersuite)
	// TLS_VERSIONS = {
	//     # SSL
	//     2       0x0002: "SSL_2_0",
	//     768     0x0300: "SSL_3_0",
	//     # TLS:
	//     769     0x0301: "TLS_1_0",
	//     770     0x0302: "TLS_1_1",
	//     771     0x0303: "TLS_1_2",
	//     772     0x0304: "TLS_1_3",
	//     # DTLS
	//     256     0x0100: "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
	//     32528   0x7f10: "TLS_1_3_DRAFT_16",
	//     32530   0x7f12: "TLS_1_3_DRAFT_18",
	//     65279   0xfeff: "DTLS_1_0",
	//     65277   0xfefd: "DTLS_1_1",
	// }
	if uint8(buf[1]) != 3 {
		return "", fmt.Errorf("expected TLS/SSL Major Version 3, got %d", uint8(buf[1]))
	}

	// payload length
	//l := int(buf[3])<<16 + int(buf[4])

	//log.Printf("length: %d, got: %d", l, n)

	// handshake message type
	if uint8(buf[5]) != tlsMessageTypeClientHello {
		return "", fmt.Errorf("expected tlsMessageTypeClientHello (%d), got %d", tlsMessageTypeClientHello, uint8(buf[5]))
	}

	// parse client hello message
	msg := &clientHelloMsg{}

	// client hello message not include tls header, 5 bytes
	success := msg.unmarshal(buf[5:])
	if !success {
		return "", errors.New("could not unmarshal TLS clientHelloMsg structure")
	}

	return msg.serverName, nil
}

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// this following code is from $GOROOT/src/crypto/tls
// with the parts we don't need commented out

type clientHelloMsg struct {
	// raw                          []byte
	// vers                         uint16
	// random                       []byte
	// sessionID                    []byte
	// cipherSuites                 []uint16
	// compressionMethods           []uint8
	// nextProtoNeg                 bool
	serverName string
	// ocspStapling                 bool
	// scts                         bool
	// supportedCurves              []CurveID
	// supportedPoints              []uint8
	// ticketSupported              bool
	// sessionTicket                []uint8
	// signatureAndHashes           []signatureAndHash
	// secureRenegotiation          []byte
	// secureRenegotiationSupported bool
	// alpnProtocols                []string
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}

	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return false
	}

	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	//numCipherSuites := cipherSuiteLen / 2
	// m.cipherSuites = make([]uint16, numCipherSuites)
	// for i := 0; i < numCipherSuites; i++ {
	// 	m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	// 	if m.cipherSuites[i] == scsvRenegotiation {
	// 		m.secureRenegotiationSupported = true
	// 	}
	// }
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	// if len(data) < 1+compressionMethodsLen {
	// 	return false
	// }
	// m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	// m.nextProtoNeg = false
	m.serverName = ""
	// m.ocspStapling = false
	// m.ticketSupported = false
	// m.sessionTicket = nil
	// m.signatureAndHashes = nil
	// m.alpnProtocols = nil
	// m.scts = false

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case tlsExtensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return false
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.serverName = string(d[:nameLen])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(m.serverName, ".") {
						return false
					}
					break
				}
				d = d[nameLen:]
			}
			// case extensionNextProtoNeg:
			// 	if length > 0 {
			// 		return false
			// 	}
			// 	m.nextProtoNeg = true
			// case extensionStatusRequest:
			// 	m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
			// case extensionSupportedCurves:
			// 	// http://tools.ietf.org/html/rfc4492#section-5.5.1
			// 	if length < 2 {
			// 		return false
			// 	}
			// 	l := int(data[0])<<8 | int(data[1])
			// 	if l%2 == 1 || length != l+2 {
			// 		return false
			// 	}
			// 	numCurves := l / 2
			// 	m.supportedCurves = make([]CurveID, numCurves)
			// 	d := data[2:]
			// 	for i := 0; i < numCurves; i++ {
			// 		m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
			// 		d = d[2:]
			// 	}
			// case extensionSupportedPoints:
			// 	// http://tools.ietf.org/html/rfc4492#section-5.5.2
			// 	if length < 1 {
			// 		return false
			// 	}
			// 	l := int(data[0])
			// 	if length != l+1 {
			// 		return false
			// 	}
			// 	m.supportedPoints = make([]uint8, l)
			// 	copy(m.supportedPoints, data[1:])
			// case extensionSessionTicket:
			// 	// http://tools.ietf.org/html/rfc5077#section-3.2
			// 	m.ticketSupported = true
			// 	m.sessionTicket = data[:length]
			// case extensionSignatureAlgorithms:
			// 	// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			// 	if length < 2 || length&1 != 0 {
			// 		return false
			// 	}
			// 	l := int(data[0])<<8 | int(data[1])
			// 	if l != length-2 {
			// 		return false
			// 	}
			// 	n := l / 2
			// 	d := data[2:]
			// 	m.signatureAndHashes = make([]signatureAndHash, n)
			// 	for i := range m.signatureAndHashes {
			// 		m.signatureAndHashes[i].hash = d[0]
			// 		m.signatureAndHashes[i].signature = d[1]
			// 		d = d[2:]
			// 	}
			// case extensionRenegotiationInfo:
			// 	if length == 0 {
			// 		return false
			// 	}
			// 	d := data[:length]
			// 	l := int(d[0])
			// 	d = d[1:]
			// 	if l != len(d) {
			// 		return false
			// 	}

			// 	m.secureRenegotiation = d
			// 	m.secureRenegotiationSupported = true
			// case extensionALPN:
			// 	if length < 2 {
			// 		return false
			// 	}
			// 	l := int(data[0])<<8 | int(data[1])
			// 	if l != length-2 {
			// 		return false
			// 	}
			// 	d := data[2:length]
			// 	for len(d) != 0 {
			// 		stringLen := int(d[0])
			// 		d = d[1:]
			// 		if stringLen == 0 || stringLen > len(d) {
			// 			return false
			// 		}
			// 		m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
			// 		d = d[stringLen:]
			// 	}
			// case extensionSCT:
			// 	m.scts = true
			// 	if length != 0 {
			// 		return false
			// 	}
		}
		data = data[length:]
	}

	return true
}
