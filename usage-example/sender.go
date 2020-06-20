package main

import (
	"fmt"
	"net"
	//"crypto/tls"
)

func main() {

	conn, err := net.Dial("tcp", "localhost:9000")
	// conn, err := tls.Dial("tcp", "localhost:9000", &tls.Config{
	// 	InsecureSkipVerify: true,
	// })
	if err != nil {
		panic(err)
	}

	fmt.Printf("Sender: I am dialing localhost:9000 from %s\n", conn.LocalAddr())

	sent, err := conn.Write([]byte("Hello ! Hello! \n"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Sender: sent %d bytes\n", sent)

	buffer := make([]byte, 4096, 4096)
	bytesRead := 0
	for done := false; !done; done = bytesRead > 0 {
		bytesRead, err = conn.Read(buffer)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("Sender: read %d bytes\n", bytesRead)
	fmt.Printf("Sender: Response from listener was: %s\n", string(buffer[:bytesRead]))

	//conn.Close()
}
