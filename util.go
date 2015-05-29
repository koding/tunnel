package tunnel

import "io"

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

// nopCloser wraps a io.ReadWriter with a no-op Close method to convert it to a
// io.ReadWriteCloser. It's basically the same as ioutil.NopCloser but accepts
// io.ReadWriter instead of io.Reader.
type nopCloser struct {
	io.ReadWriter
}

func (nopCloser) Close() error { return nil }
