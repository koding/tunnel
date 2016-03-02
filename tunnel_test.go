package tunnel_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/koding/tunnel/tunneltest"
)

func init() {
	rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
}

func echo(tt *tunneltest.TunnelTest, echo string) (string, error) {
	req := tt.Request("http", url.Values{"echo": []string{echo}})
	if req == nil {
		return "", fmt.Errorf(`tunnel "http" does not exist`)
	}

	req.Close = rand.Int()%2 == 0

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	p, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bytes.TrimSpace(p)), nil
}

func handlerEchoHTTP(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, r.URL.Query().Get("echo"))
}

func handlerLatencyEchoHTTP(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Duration(rand.Intn(2000)) * time.Millisecond)
	handlerEchoHTTP(w, r)
}

func handlerEchoTCP(conn net.Conn) {
	io.Copy(bufio.NewWriter(conn), bufio.NewReader(conn))
}

func singleHTTP(handler interface{}) map[string]*tunneltest.Tunnel {
	return map[string]*tunneltest.Tunnel{
		"http": {
			Type:      tunneltest.TypeHTTP,
			LocalAddr: "127.0.0.1:0",
			Handler:   handler,
		},
	}
}

func TestMultipleRequest(t *testing.T) {
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	// make a request to tunnelserver, this should be tunneled to local server
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			msg := "hello" + strconv.Itoa(i)
			res, err := echo(tt, msg)
			if err != nil {
				t.Errorf("make request: %s", err)
			}

			if res != msg {
				t.Errorf("Expecting %s, got %s", msg, res)
			}
		}(i)
	}

	wg.Wait()
}

func TestMultipleLatencyRequest(t *testing.T) {
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerLatencyEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	// make a request to tunnelserver, this should be tunneled to local server
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func(i int) {
			msg := "hello" + strconv.Itoa(i)
			res, err := echo(tt, msg)
			if err != nil {
				t.Errorf("make request: %s", err)
			}

			if res != msg {
				t.Errorf("Expecting %s, got %s", msg, res)
			}
			wg.Done()
		}(i)
	}

	wg.Wait()
}

func TestReconnectClient(t *testing.T) {
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	msg := "hello"
	res, err := echo(tt, msg)
	if err != nil {
		t.Fatalf("make request: %s", err)
	}

	if res != msg {
		t.Fatalf("expecting '%s', got '%s'", msg, res)
	}

	client := tt.Clients["http"]

	// close client, and start it again
	client.Close()

	go client.Start()
	<-client.StartNotify()

	msg = "helloagain"
	res, err = echo(tt, msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != msg {
		t.Errorf("expecting '%s', got '%s'", msg, res)
	}
}

func TestNoClient(t *testing.T) {
	const expectedErr = "no client session established"
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	// close client, this is the main point of the test
	if err := tt.Clients["http"].Close(); err != nil {
		t.Fatal(err)
	}

	msg := "hello"
	res, err := echo(tt, msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != expectedErr {
		t.Errorf("Expecting '%s', got '%s'", expectedErr, res)
	}
}

func TestNoLocalServer(t *testing.T) {
	const expectedErr = "no local server"
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	// close local listener, this is the main point of the test
	tt.Listeners["http"][0].Close()

	msg := "hello"
	res, err := echo(tt, msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != expectedErr {
		t.Errorf("Expecting %s, got %s", expectedErr, res)
	}
}

func TestSingleRequest(t *testing.T) {
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	msg := "hello"
	res, err := echo(tt, msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != msg {
		t.Errorf("Expecting %s, got %s", msg, res)
	}
}

func TestSingleLatencyRequest(t *testing.T) {
	t.Parallel()

	tt, err := tunneltest.Serve(singleHTTP(handlerLatencyEchoHTTP))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()

	// wait til the environment is ready, just for test
	time.Sleep(time.Second * 2)

	msg := "hello"
	res, err := echo(tt, msg)
	if err != nil {
		t.Errorf("make request: %s", err)
	}

	if res != msg {
		t.Errorf("Expecting %s, got %s", msg, res)
	}
}
