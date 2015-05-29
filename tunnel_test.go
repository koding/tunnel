package tunnel

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
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
	if t.client != nil {
		t.client.Close()
	}

	if t.remoteListener != nil {
		t.remoteListener.Close()
	}

	if t.localListener != nil {
		t.localListener.Close()
	}
}

func singleTestEnvironment() (*testEnv, error) {
	var identifier = "123abc"

	tunnelServer, _ := NewServer(&ServerConfig{Debug: true})
	remoteServer := http.Server{Handler: tunnelServer}
	remoteListener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	tunnelServer.AddHost(remoteListener.Addr().String(), identifier)

	go func() {
		if err := remoteServer.Serve(remoteListener); err != nil {
			log.Printf("remote listener: '%s'\n", err)
		}
	}()

	localListener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	tunnelClient, _ := NewClient(&ClientConfig{
		Identifier: identifier,
		ServerAddr: remoteListener.Addr().String(),
		LocalAddr:  localListener.Addr().String(),
		Debug:      true,
	})
	go tunnelClient.Start()
	<-tunnelClient.StartNotify()

	localServer := http.Server{Handler: echo()}
	go func() {
		if err := localServer.Serve(localListener); err != nil {
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

func TestMultipleRequest(t *testing.T) {
	tenv, err := singleTestEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	defer tenv.Close()

	// make a request to tunnelserver, this should be tunneled to local server
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			msg := "hello" + strconv.Itoa(i)
			res, err := makeRequest(tenv.remoteListener.Addr().String(), msg)
			if err != nil {
				t.Errorf("make request: %s", err)
			}

			if res != msg {
				t.Errorf("Expecting %s, got %s", msg, res)
			}
		}(i)
	}

	wg.Wait()
	tenv.Close()
}

func TestSingleRequest(t *testing.T) {
	tenv, err := singleTestEnvironment()
	if err != nil {
		t.Fatal(err)
	}

	msg := "hello"
	res, err := makeRequest(tenv.remoteListener.Addr().String(), msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != msg {
		t.Errorf("Expecting %s, got %s", msg, res)
	}
	tenv.Close()
}

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
