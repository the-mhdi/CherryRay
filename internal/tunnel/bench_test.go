package tunnel

import (
	"io"
	"net"
	"testing"

	"github.com/the-mhdi/muxocket"
)

// benchChannels returns two ends of a channel over a loopback TCP session.
func benchChannels(b *testing.B) (*muxocket.Channel, *muxocket.Channel) {
	c1, c2 := tcpPair(b)
	s1 := muxocket.NewSession(c1, nil)
	s2 := muxocket.NewSession(c2, nil)
	b.Cleanup(func() { s1.Close(); s2.Close() })
	x, err := s1.OpenChannel("b")
	if err != nil {
		b.Fatal(err)
	}
	y, err := s2.OpenChannel("b")
	if err != nil {
		b.Fatal(err)
	}
	return x, y
}

func benchSecure(b *testing.B, x, y *muxocket.Channel) (Conn, Conn) {
	hello, err := NewClientHello()
	if err != nil {
		b.Fatal(err)
	}
	var srv *SecureConn
	var serr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := ReadOpen(y)
		if err != nil {
			serr = err
			return
		}
		srv, serr = ServerHandshake(y, req, nil)
	}()
	hdr, err := WriteOpen(x, ModeStream, CipherChaCha20Poly1305, hello)
	if err != nil {
		b.Fatal(err)
	}
	cli, err := ClientHandshake(x, CipherChaCha20Poly1305, hdr, hello, nil)
	<-done
	if err != nil || serr != nil {
		b.Fatal(err, serr)
	}
	return cli, srv
}

// benchJoin measures JoinStream relaying a local TCP connection into the
// tunnel (up) or out of it (down).
func benchJoin(b *testing.B, secure, up bool) {
	x, y := benchChannels(b)
	var near, far Conn = x, y
	if secure {
		near, far = benchSecure(b, x, y)
	}
	app, local := tcpPair(b)
	go JoinStream(near, local)

	const chunk = 32 << 10
	buf := make([]byte, chunk)
	b.SetBytes(chunk)
	b.ResetTimer()
	done := make(chan int64)
	if up {
		go func() { n, _ := io.Copy(io.Discard, far); done <- n }()
		for i := 0; i < b.N; i++ {
			if _, err := app.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		_ = app.CloseWrite()
	} else {
		go func() { n, _ := io.Copy(io.Discard, app); done <- n }()
		for i := 0; i < b.N; i++ {
			if _, err := far.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		_ = far.CloseWrite()
	}
	if n := <-done; n != int64(b.N)*chunk {
		b.Fatalf("relayed %d of %d bytes", n, int64(b.N)*chunk)
	}
}

func BenchmarkJoinStream_Up(b *testing.B)         { benchJoin(b, false, true) }
func BenchmarkJoinStream_Down(b *testing.B)       { benchJoin(b, false, false) }
func BenchmarkJoinStream_SecureUp(b *testing.B)   { benchJoin(b, true, true) }
func BenchmarkJoinStream_SecureDown(b *testing.B) { benchJoin(b, true, false) }

// BenchmarkHTTPConnRead is the per-Read cost the -http wrapper adds once
// the header is done.
func BenchmarkHTTPConnRead(b *testing.B) {
	a, c := tcpPair(b)
	w := wrapHTTP(c, nil)
	go func() {
		_, _ = a.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		buf := make([]byte, 32<<10)
		for {
			if _, err := a.Write(buf); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 32<<10)
	b.SetBytes(32 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := io.ReadFull(w, buf); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	a.Close()
}

var _ net.Conn = (*httpTCPConn)(nil)
