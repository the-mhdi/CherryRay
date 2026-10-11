package tunnel

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/the-mhdi/muxocket"
)

func TestHTTP_RequestAndResponseHeaders(t *testing.T) {
	c := &HTTPConfig{
		Hosts:   []string{"cdn.example.com"},
		Paths:   []string{"/video/1.mp4"},
		Headers: []string{"User-Agent: test-agent/1.0", "Pragma:", "X-Extra: yes"},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	req := string(c.Request("ignored"))
	for _, want := range []string{
		"GET /video/1.mp4 HTTP/1.1\r\n", "\r\nHost: cdn.example.com\r\n",
		"\r\nUser-Agent: test-agent/1.0\r\n", "\r\nX-Extra: yes\r\n", "\r\nAccept-Encoding: gzip, deflate\r\n",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("request lacks %q:\n%s", want, req)
		}
	}
	if strings.Contains(req, "Pragma") || strings.Count(req, "User-Agent") != 1 {
		t.Errorf("header override/removal failed:\n%s", req)
	}
	if !strings.HasPrefix(req, "GET ") || !strings.HasSuffix(req, "\r\n\r\n") || strings.Count(req, "\r\n\r\n") != 1 {
		t.Errorf("malformed request:\n%q", req)
	}
	// Default Host is the given server host.
	if r := string((&HTTPConfig{}).Request("srv.example:8080")); !strings.Contains(r, "\r\nHost: srv.example:8080\r\n") || !strings.HasPrefix(r, "GET / HTTP/1.1\r\n") {
		t.Errorf("defaults: %q", r)
	}

	resp := string((&HTTPConfig{Status: "206 Partial Content", Headers: []string{"Server: nginx"}}).Response())
	if !strings.HasPrefix(resp, "HTTP/1.1 206 Partial Content\r\n") || !strings.Contains(resp, "\r\nServer: nginx\r\n") ||
		!strings.Contains(resp, "\r\nDate: ") || !strings.HasSuffix(resp, "\r\n\r\n") {
		t.Errorf("response: %q", resp)
	}
	if err := checkResponse([]byte(strings.TrimSuffix(resp, "\r\n\r\n"))); err != nil {
		t.Error(err)
	}
	if err := checkResponse([]byte("HTTP/1.1 404 Not Found")); err == nil {
		t.Error("404 accepted")
	}
	if err := checkResponse([]byte("SSH-2.0-OpenSSH")); err == nil {
		t.Error("non-HTTP accepted")
	}
}

func TestHTTP_Validate(t *testing.T) {
	bad := []HTTPConfig{
		{Method: "GE T"}, {Hosts: []string{"a b"}}, {Paths: []string{"nopath"}}, {Paths: []string{"/a b"}},
		{Headers: []string{"NoColon"}}, {Headers: []string{"Bad Name: v"}}, {Headers: []string{"Host: x"}},
		{Headers: []string{"X: a\r\nY: b"}}, {Status: "404 Not Found"}, {Status: "OK"},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v: accepted", c)
		}
	}
	good := HTTPConfig{Method: "POST", Hosts: []string{"a.example", "b.example:8443"}, Paths: []string{"/", "/q?x=1"},
		Headers: []string{"Cookie: a=b; c=d"}, Status: "302 Found"}
	if err := good.Validate(); err != nil {
		t.Error(err)
	}
}

func TestHTTP_CheckRequest(t *testing.T) {
	srv := &HTTPConfig{Hosts: []string{"Cdn.Example.com"}, Paths: []string{"/a", "/b?k=v"}}
	req := func(line, host string) []byte {
		h := line + "\r\nUser-Agent: x"
		if host != "" {
			h += "\r\nHost: " + host
		}
		return []byte(h)
	}
	for _, tc := range []struct {
		head []byte
		want string
	}{
		{req("GET /a HTTP/1.1", "cdn.example.com"), ""},
		{req("GET /a?anything HTTP/1.1", "cdn.example.com:443"), ""}, // query ignored, port stripped
		{req("POST /b?k=v HTTP/1.0", "CDN.EXAMPLE.COM"), ""},
		{req("GET /b HTTP/1.1", "cdn.example.com"), "404 Not Found"}, // entry with ? must match fully
		{req("GET /c HTTP/1.1", "cdn.example.com"), "404 Not Found"},
		{req("GET /a HTTP/1.1", "evil.example"), "404 Not Found"},
		{req("GET /a HTTP/1.1", ""), "400 Bad Request"},
		{req("GET /a HTTP/2", "cdn.example.com"), "400 Bad Request"},
		{req("GET /a", "cdn.example.com"), "400 Bad Request"},
		{[]byte("GET /a HTTP/1.1\r\ngarbage"), "400 Bad Request"},
	} {
		if got := srv.CheckRequest(tc.head); got != tc.want {
			t.Errorf("%q: got %q want %q", tc.head, got, tc.want)
		}
	}
	if got := (&HTTPConfig{Method: "GET"}).CheckRequest(req("PUT / HTTP/1.1", "x")); got != "405 Method Not Allowed" {
		t.Errorf("method check: %q", got)
	}
	if got := (&HTTPConfig{}).CheckRequest(req("PUT /any HTTP/1.1", "any")); got != "" {
		t.Errorf("open server rejected: %q", got)
	}
}

func TestHTTP_ReadHead(t *testing.T) {
	msg := "HTTP/1.1 200 OK\r\nA: b\r\n\r\nPAYLOAD"
	for name, r := range map[string]io.Reader{
		"whole":   strings.NewReader(msg),
		"1-byte":  iotest.OneByteReader(strings.NewReader(msg)),
		"halfway": iotest.HalfReader(strings.NewReader(msg)),
	} {
		head, rest, err := readHead(r)
		if err != nil || string(head) != "HTTP/1.1 200 OK\r\nA: b" {
			t.Fatalf("%s: head=%q err=%v", name, head, err)
		}
		more, _ := io.ReadAll(r)
		if got := string(rest) + string(more); got != "PAYLOAD" {
			t.Fatalf("%s: rest %q", name, got)
		}
	}
	if _, _, err := readHead(strings.NewReader("HTTP/1.1 200 OK\r\n")); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated: %v", err)
	}
	big := "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", maxHTTPHead) + "\r\n\r\n"
	if _, _, err := readHead(strings.NewReader(big)); err != errHTTPHeadTooLarge {
		t.Errorf("oversized: %v", err)
	}
	// Exactly at the limit is fine.
	fit := "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", maxHTTPHead-len("GET / HTTP/1.1\r\nX: ")) + "\r\n\r\n"
	if head, _, err := readHead(strings.NewReader(fit)); err != nil || len(head) != maxHTTPHead {
		t.Errorf("at limit: len=%d err=%v", len(head), err)
	}
}

// tcpPair returns a connected TCP pair.
func tcpPair(t testing.TB) (*net.TCPConn, *net.TCPConn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-ch
	t.Cleanup(func() { a.Close(); b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

func TestHTTP_StreamWireFormat(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	tr := Transport{Network: "tcp", Address: l.Addr().String()}
	if err := tr.SetHTTP(&HTTPConfig{Paths: []string{"/p"}, Headers: []string{"X-T: 1"}}); err != nil {
		t.Fatal(err)
	}
	dial, err := tr.Dialer("", 2*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // every (re)dial sends its own header
		got := make(chan string, 1)
		go func() {
			s, err := l.Accept()
			if err != nil {
				got <- err.Error()
				return
			}
			defer s.Close()
			head, rest, err := readHead(s)
			if err != nil {
				got <- err.Error()
				return
			}
			// Response and payload in one write: the client must split them.
			_, _ = s.Write(append((&HTTPConfig{}).Response(), "pong"...))
			buf := make([]byte, 4)
			copy(buf, rest)
			if len(rest) < 4 {
				_, _ = io.ReadFull(s, buf[len(rest):])
			}
			got <- string(head) + "|" + string(buf)
		}()
		c, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := c.(*httpTCPConn); !ok {
			t.Fatalf("plain TCP wrapped as %T; writev would be lost", c)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		r := <-got
		host := tr.Address
		if !strings.HasPrefix(r, "GET /p HTTP/1.1\r\nHost: "+host+"\r\n") || !strings.Contains(r, "\r\nX-T: 1") || !strings.HasSuffix(r, "|ping") {
			t.Fatalf("server saw %q", r)
		}
		b, err := io.ReadAll(io.LimitReader(c, 4))
		if err != nil || string(b) != "pong" {
			t.Fatalf("client read %q, %v", b, err)
		}
		c.Close()
	}
}

func TestHTTP_ServerAcceptsAndRejects(t *testing.T) {
	cfg := &HTTPConfig{Paths: []string{"/ok"}, Headers: []string{"Server: nginx"}}
	for _, tc := range []struct {
		path, status string
	}{{"/ok", "200 OK"}, {"/nope", "404 Not Found"}} {
		a, b := tcpPair(t)
		srv := wrapHTTP(b, cfg)
		// Request and stream data in one segment.
		go func() { _, _ = a.Write([]byte("GET " + tc.path + " HTTP/1.1\r\nHost: x\r\n\r\nhello")) }()
		buf := make([]byte, 5)
		_, err := io.ReadFull(srv, buf)
		if tc.status == "200 OK" {
			if err != nil || string(buf) != "hello" {
				t.Fatalf("accepted: %q %v", buf, err)
			}
			if _, err := srv.Write([]byte("world")); err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("bad path accepted")
		} else {
			srv.Close()
		}
		head, rest, err := readHead(a)
		if err != nil || !strings.HasPrefix(string(head), "HTTP/1.1 "+tc.status+"\r\n") {
			t.Fatalf("%s: response %q %v", tc.path, head, err)
		}
		if tc.status == "200 OK" {
			if !strings.Contains(string(head), "\r\nServer: nginx") {
				t.Errorf("custom response header missing: %q", head)
			}
			more := make([]byte, 5-len(rest))
			_, _ = io.ReadFull(a, more)
			if s := string(rest) + string(more); s != "world" {
				t.Errorf("stream after response: %q", s)
			}
		}
	}

	// Non-HTTP garbage gets no 200 and an error.
	a, b := tcpPair(t)
	srv := wrapHTTP(b, &HTTPConfig{})
	go func() { _, _ = a.Write([]byte("\x16\x03\x01garbage\r\n\r\n")); _ = a.CloseWrite() }()
	if _, err := srv.Read(make([]byte, 10)); err == nil {
		t.Fatal("garbage accepted")
	}
	if head, _, _ := readHead(a); !strings.HasPrefix(string(head), "HTTP/1.1 400") {
		t.Errorf("garbage answered %q", head)
	}
}

// WriteTo promoted from *net.TCPConn must not bypass header stripping.
func TestHTTP_WriteToStripsHeader(t *testing.T) {
	a, b := tcpPair(t)
	c := wrapHTTP(a, nil)
	go func() {
		_, _ = b.Write([]byte("HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody-bytes"))
		_ = b.CloseWrite()
	}()
	var out bytes.Buffer
	if _, err := io.Copy(&out, c); err != nil || out.String() != "body-bytes" {
		t.Fatalf("got %q, %v", out.String(), err)
	}
}

// muxocket end to end over -http, plain TCP and TLS, with a silent client
// connected first to show Accept isn't blocked by a header that never comes.
func TestHTTP_MuxocketEndToEnd(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "tls"}[useTLS], func(t *testing.T) {
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var l net.Listener = raw
			var ccfg *tls.Config
			if useTLS {
				scfg, pin, _, err := ServerTLS("", "", "", raw.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				l = tls.NewListener(l, scfg)
				if ccfg, err = ClientTLS(ClientTLSOptions{Pin: pin, SNI: "front.example"}); err != nil {
					t.Fatal(err)
				}
			}
			scfg := &HTTPConfig{Hosts: []string{"front.example", "cdn.example"}, Paths: []string{"/s"}}
			ln, err := muxocket.Listen(HTTPListener(l, scfg), muxocket.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			silent, err := net.Dial("tcp", raw.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer silent.Close()

			go func() {
				for {
					sess, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						ch, err := sess.OpenChannel("echo")
						if err != nil {
							return
						}
						_, _ = io.Copy(ch, ch)
						_ = ch.CloseWrite()
					}()
				}
			}()

			tr := Transport{Network: "tcp", Address: raw.Addr().String()}
			ccl := &HTTPConfig{Paths: []string{"/s"}}
			if !useTLS {
				ccl.Hosts = []string{"cdn.example"} // with TLS the Host defaults to the SNI
			}
			if err := tr.SetHTTP(ccl); err != nil {
				t.Fatal(err)
			}
			dial, err := tr.Dialer("", 5*time.Second, ccfg)
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			var first net.Conn
			counting := func() (net.Conn, error) {
				c, err := dial()
				if err == nil && dials.Add(1) == 1 {
					first = c
				}
				return c, err
			}
			sess, err := muxDial(counting)
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			ch, err := sess.OpenChannel("echo")
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 1<<20)
			for i := range data {
				data[i] = byte(i * 7)
			}
			half := len(data) / 2
			broken := make(chan struct{})
			go func() {
				_, _ = ch.Write(data[:half])
				<-broken
				_, _ = ch.Write(data[half:])
				_ = ch.CloseWrite()
			}()
			got := make([]byte, half)
			if _, err := io.ReadFull(ch, got); err != nil {
				t.Fatal(err)
			}
			// Break the transport: muxocket redials (a new connection, which
			// must carry its own HTTP header) and resumes the session.
			_ = first.Close()
			close(broken)
			rest, err := io.ReadAll(ch)
			got = append(got, rest...)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("echo: %d bytes, %v", len(got), err)
			}
			if dials.Load() < 2 {
				t.Errorf("transport was not redialed (%d dials)", dials.Load())
			}

			// A client with the wrong path is turned away.
			bad := Transport{Network: "tcp", Address: raw.Addr().String()}
			_ = bad.SetHTTP(&HTTPConfig{Paths: []string{"/wrong"}, Hosts: []string{"cdn.example"}})
			bdial, _ := bad.Dialer("", 2*time.Second, ccfg)
			if s, err := muxDial(bdial); err == nil {
				s.Close()
				t.Fatal("wrong path accepted")
			}
		})
	}
}

func muxDial(dial func() (net.Conn, error)) (*muxocket.Session, error) {
	c, err := dial()
	if err != nil {
		return nil, err
	}
	d := &muxocket.Dialer{HandshakeTimeout: 5 * time.Second, Redial: dial}
	s, err := d.Dial(c)
	if err != nil {
		c.Close()
	}
	return s, err
}

func TestHTTP_TransportRestrictions(t *testing.T) {
	for _, tr := range []Transport{{Network: "udp", Address: "x:1"}, {Network: "ip4:253", Address: "1.2.3.4"}} {
		if err := tr.SetHTTP(&HTTPConfig{}); err == nil {
			t.Errorf("%s: -http accepted", tr.Network)
		}
	}
	tr := Transport{Network: "tcp", Address: "x:1"}
	if err := tr.SetHTTP(nil); err != nil || tr.HTTP != nil {
		t.Error("nil config should be a no-op")
	}
}

func TestHTTP_Flags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	get := HTTPFlags(fs, false)
	if err := fs.Parse([]string{"-http", "-http-host", "a.example, b.example", "-http-path", "/x",
		"-http-header", "User-Agent: u", "-http-header", "X: y"}); err != nil {
		t.Fatal(err)
	}
	c, err := get()
	if err != nil || len(c.Hosts) != 2 || c.Hosts[1] != "b.example" || len(c.Headers) != 2 || c.Method != "GET" {
		t.Fatalf("%+v %v", c, err)
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	get = HTTPFlags(fs, true)
	_ = fs.Parse([]string{"-http-path", "/x"})
	if _, err := get(); err == nil {
		t.Error("-http-path without -http accepted")
	}
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	get = HTTPFlags(fs, true)
	_ = fs.Parse(nil)
	if c, err := get(); c != nil || err != nil {
		t.Errorf("disabled: %v %v", c, err)
	}
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	get = HTTPFlags(fs, true)
	_ = fs.Parse([]string{"-http", "-http-status", "500 Oops"})
	if _, err := get(); err == nil {
		t.Error("bad status accepted")
	}
}
