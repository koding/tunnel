package main

import (
	"fmt"
	"net"

	proxyproto "github.com/armon/go-proxyproto"
)

func main() {
	// Create a listener
	tcpListener, err := net.Listen("tcp", ":9001")
	if err != nil {
		panic(err)
	}

	fmt.Print("Listener: I am listening on port 9001\n")

	// Wrap listener in a proxyproto listener
	proxyListener := &proxyproto.Listener{Listener: tcpListener}
	for {
		conn, err := proxyListener.Accept()
		if err != nil {
			panic(err)
		}
		go acceptConnection(conn)

	}

}

func acceptConnection(conn net.Conn) {
	fmt.Printf("Listener: Someone connected from: %s\r\n", conn.RemoteAddr().String())
	buffer := make([]byte, 4096, 4096)
	bytesRead := 0
	var err error
	for done := false; !done; done = bytesRead > 0 {
		bytesRead, err = conn.Read(buffer)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("Listener: read %d bytes\n", bytesRead)
	fmt.Printf("Listener: the sender sent: %s\n", string(buffer[:bytesRead]))
	fmt.Print("Listener: I am going to respond with \"asd\"\n")
	conn.Write([]byte("asd"))
	err = conn.Close()
	if err != nil {
		panic(err)
	}
	fmt.Println("Listener: conn.Close()")
}
