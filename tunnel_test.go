package tunnel

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

type testEnv struct {
	server         *Server
	client         *Client
	remoteListener net.Listener
	localListener  net.Listener
}

func (t *testEnv) Close() {
	log.Println("test: Closing client connection")
	if t.client != nil {
		t.client.Close()
	}

	log.Println("test: Closing local listener")
	if t.localListener != nil {
		t.localListener.Close()
	}

	log.Println("test: Closing remote listener")
	if t.remoteListener != nil {
		t.remoteListener.Close()
	}

}

func singleTestEnvironment(serverAddr, localAddr string) (*testEnv, error) {
	var identifier = "123abc"

	tunnelServer, _ := NewServer(&ServerConfig{
		Debug: true,
	})
	tunnelServer.AddHost(serverAddr, identifier)

	muxer := http.NewServeMux()
	muxer.Handle("/", tunnelServer)
	server := http.Server{Handler: muxer}

	remoteListener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := server.Serve(remoteListener); err != nil {
			log.Printf("remote listener: '%s'\n", err)
		}
	}()

	tunnelClient, _ := NewClient(&ClientConfig{
		Identifier: identifier,
		ServerAddr: serverAddr,
		LocalAddr:  localAddr,
		Debug:      true,
	})
	go tunnelClient.Start()
	<-tunnelClient.StartNotify()

	localListener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := http.Serve(localListener, echo()); err != nil {
			log.Printf("local listener: '%s'\n", err)
		}
	}()

	return &testEnv{
		server:         tunnelServer,
		client:         tunnelClient,
		remoteListener: remoteListener,
		localListener:  localListener,
	}, nil
}

func TestSingleRequest(t *testing.T) {
	var (
		serverAddr = "127.0.0.1:7000"
		localAddr  = "127.0.0.1:5000"
	)

	tenv, err := singleTestEnvironment(serverAddr, localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tenv.Close()

	msg := "hello"
	res, err := makeRequest(serverAddr, msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != msg {
		t.Errorf("Expecting %s, got %s", msg, res)
	}
}

// func TestMultipleRequest(t *testing.T) {
// 	var (
// 		serverAddr = "127.0.0.1:7000"
// 		localAddr  = "127.0.0.1:5000"
// 	)
//
// 	tenv, err := singleTestEnvironment(serverAddr, localAddr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer tenv.Close()
//
// 	// make a request to tunnelserver, this should be tunneled to local server
// 	var wg sync.WaitGroup
// 	for i := 0; i < 10; i++ {
// 		wg.Add(1)
//
// 		go func(i int) {
// 			defer wg.Done()
// 			msg := "hello" + strconv.Itoa(i)
// 			res, err := makeRequest(serverAddr, msg)
// 			if err != nil {
// 				t.Errorf("make request: %s", err)
// 			}
//
// 			if res != msg {
// 				t.Errorf("Expecting %s, got %s", msg, res)
// 			}
// 		}(i)
// 	}
//
// 	wg.Wait()
// }
//
func makeRequest(serverAddr, msg string) (string, error) {
	resp, err := http.Get("http://" + serverAddr + "/?echo=" + msg)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(res), nil
}

func echo() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("echo")
		io.WriteString(w, msg)
	})
}

func timeoutEcho() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second * 2)
		msg := r.URL.Query().Get("echo")
		io.WriteString(w, msg)
	})
}

// func TestTimeout(t *testing.T) {
// 	// setup tunnelserver
// 	server, _ := NewServer(&ServerConfig{
// 		Debug: true,
// 	})
// 	server.AddHost(serverAddr, identifier)
//
// 	m := http.NewServeMux()
// 	m.Handle("/", server)
// 	s := http.Server{Handler: m}
//
// 	var err error
// 	listener, err = net.Listen("tcp", serverAddr)
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	go func() {
// 		err = s.Serve(listener)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 	}()
//
// 	time.Sleep(time.Second)
//
// 	// setup tunnelclient
// 	client, _ := NewClient(&ClientConfig{
// 		Identifier: identifier,
// 		ServerAddr: serverAddr,
// 		LocalAddr:  localAddr,
// 		Debug:      true,
// 	})
// 	go client.Start()
//
// 	// start local server to be tunneled
// 	go http.ListenAndServe(localAddr, timeoutEcho())
//
// 	time.Sleep(time.Second)
//
// 	done := make(chan bool, 0)
// 	go func() {
// 		res, err := makeRequest("hello")
// 		if err != nil {
// 			t.Errorf("make request: %s", err)
// 		}
// 		fmt.Printf("res = %+v\n", res)
// 		close(done)
// 	}()
//
// 	<-done
// }
