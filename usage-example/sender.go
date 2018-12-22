package main

import (
	"fmt"
	"net"
)

func main() {

	fmt.Println("Sender: I am dialing localhost:9000")

	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		panic(err)
	}
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
