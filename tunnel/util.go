package tunnel

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cajax/mylittleproxy/proto"

	"github.com/cenkalti/backoff"
)

// async is a helper function to convert a blocking function to a function
// returning an error. Useful for plugging function closures into select and co
func async(fn func() error) <-chan error {
	errChan := make(chan error, 0)
	go func() {
		select {
		case errChan <- fn():
		default:
		}

		close(errChan)
	}()

	return errChan
}

type expBackoff struct {
	mu sync.Mutex
	bk *backoff.ExponentialBackOff
}

func newForeverBackoff() *expBackoff {
	eb := &expBackoff{
		bk: backoff.NewExponentialBackOff(),
	}
	eb.bk.MaxElapsedTime = 0 // never stops
	return eb
}

func (eb *expBackoff) NextBackOff() time.Duration {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	return eb.bk.NextBackOff()
}

func (eb *expBackoff) Reset() {
	eb.mu.Lock()
	eb.bk.Reset()
	eb.mu.Unlock()
}

type callbacks struct {
	mu    sync.Mutex
	name  string
	funcs map[string]func() error
}

func newCallbacks(name string) *callbacks {
	return &callbacks{
		name:  name,
		funcs: make(map[string]func() error),
	}
}

func (c *callbacks) add(identifier string, fn func() error) {
	c.mu.Lock()
	c.funcs[identifier] = fn
	c.mu.Unlock()
}

func (c *callbacks) pop(identifier string) (func() error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fn, ok := c.funcs[identifier]
	if !ok {
		return nil, nil // nop
	}

	delete(c.funcs, identifier)

	if fn == nil {
		return nil, fmt.Errorf("nil callback set for %q client", identifier)
	}

	return fn, nil
}

func (c *callbacks) call(identifier string) error {
	fn, err := c.pop(identifier)
	if err != nil {
		return err
	}

	if fn == nil {
		return nil // nop
	}

	return fn()
}

// Returns server control url as a string. Reads scheme and remote address from connection.
func controlURL(conn net.Conn) string {
	return fmt.Sprint(scheme(conn), "://", conn.RemoteAddr(), proto.ControlPath)
}

func scheme(conn net.Conn) (scheme string) {
	switch conn.(type) {
	case *tls.Conn:
		scheme = "https"
	default:
		scheme = "http"
	}

	return
}

func signIdentifier(id string, key string) string {
	// TODO replace with asymmetric encryption
	sha := sha1.New()
	sha.Write([]byte(id + ":" + key))
	return base64.URLEncoding.EncodeToString(sha.Sum(nil))
}

func checkIdentifierSignature(id string, key string, signature string) bool {
	return signature == signIdentifier(id, key)
}

func GetConfig(configPath *string, config any) error {
	configFile, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	// defer the closing of our configFile so that we can parse it later on
	defer configFile.Close()

	configBytes, err := io.ReadAll(configFile)
	if err != nil {
		return err
	}

	err = json.Unmarshal(configBytes, &config)
	return nil
}

func GetExecutableDir() string {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	return exPath
}
