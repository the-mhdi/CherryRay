package tunnel

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/the-mhdi/muxocket"
)

func TestParseEndpoint(t *testing.T) {
	good := map[string]Endpoint{
		"tcp//127.0.0.1:443":     {"tcp", "127.0.0.1:443"},
		"TCP://[::1]:22":         {"tcp", "[::1]:22"},
		"unix///run/app.sock":    {"unix", "/run/app.sock"},
		"udp//1.1.1.1:53":        {"udp", "1.1.1.1:53"},
		"ip4:253//10.0.0.2":      {"ip4:253", "10.0.0.2"},
		"unixgram///tmp/log.sk":  {"unixgram", "/tmp/log.sk"},
		"ip6:icmp//fd00::1":      {"ip6:icmp", "fd00::1"},
		"tcp6//[2001:db8::1]:80": {"tcp6", "[2001:db8::1]:80"},
	}
	for in, want := range good {
		got, err := ParseEndpoint(in)
		if err != nil || got != want {
			t.Errorf("ParseEndpoint(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "127.0.0.1:443", "tcp//", "sctp//x:1", "ip4:999//1.2.3.4", "//x"} {
		if _, err := ParseEndpoint(in); err == nil {
			t.Errorf("ParseEndpoint(%q) accepted", in)
		}
	}
}

func TestParseTransport(t *testing.T) {
	if _, err := ParseTransport("", "", "", true); err == nil {
		t.Error("no transport accepted")
	}
	if _, err := ParseTransport(":1", ":2", "", true); err == nil {
		t.Error("two transports accepted")
	}
	tr, err := ParseTransport("", "", "ip4:253", true)
	if err != nil || tr.Address != "0.0.0.0" {
		t.Errorf("server -ip without address: %v %v", tr, err)
	}
	if _, err := ParseTransport("", "", "ip4:253", false); err == nil {
		t.Error("client -ip without address accepted")
	}
	tr, _ = ParseTransport("", "", "ip4:253@10.0.0.1", false)
	if tr.Network != "ip4:253" || tr.Address != "10.0.0.1" || tr.DefaultMTU() != 1476 {
		t.Errorf("got %+v mtu %d", tr, tr.DefaultMTU())
	}
}

func sessionPair(t *testing.T) (*muxocket.Session, *muxocket.Session) {
	c1, c2 := net.Pipe()
	s1 := muxocket.NewSession(c1, nil)
	s2 := muxocket.NewSession(c2, nil)
	t.Cleanup(func() { s1.Close(); s2.Close() })
	return s1, s2
}

func TestOpenHandshake(t *testing.T) {
	var buf bytes.Buffer
	_, _ = WriteOpen(&buf, ModeDatagram, CipherNone, nil)
	if r, err := ReadOpen(&buf); err != nil || r.Mode != ModeDatagram || r.Cipher != CipherNone {
		t.Fatal(r, err)
	}
	if _, err := ReadOpen(bytes.NewReader([]byte("GET / HTTP/1.1"))); err != ErrBadOpen {
		t.Fatal("bad preamble accepted:", err)
	}
	buf.Reset()
	_ = WriteStatus(&buf, StatusDialFailed, "connection refused")
	if err := ReadStatus(&buf); err == nil || !bytes.Contains([]byte(err.Error()), []byte("connection refused")) {
		t.Fatal(err)
	}
}

// A request/response target that only answers after the client half-closes
// (like "printf req | nc -N"): JoinStream must propagate EOF both ways.
func TestJoinStream_HalfClose(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		req, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("got:"), req...))
		c.Close()
	}()

	s1, s2 := sessionPair(t)
	server, _ := s1.OpenChannel("t")
	client, _ := s2.OpenChannel("t")
	target, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go JoinStream(server, target)

	payload := make([]byte, 200<<10)
	_, _ = rand.Read(payload)
	go func() { _, _ = client.Write(payload); _ = client.CloseWrite() }()
	resp, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(resp, append([]byte("got:"), payload...)) {
		t.Fatalf("response %d bytes, err %v", len(resp), err)
	}
}

func TestJoinDatagram_FramingAndLinger(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond) // reply arrives after the client's EOF
			_, _ = pc.WriteTo(append([]byte("r:"), b[:n]...), a)
		}
	}()

	s1, s2 := sessionPair(t)
	server, _ := s1.OpenChannel("d")
	client, _ := s2.OpenChannel("d")
	target, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { JoinDatagram(server, target, time.Minute); close(done) }()

	msgs := [][]byte{[]byte("a"), {}, bytes.Repeat([]byte("z"), 1400)}
	for _, m := range msgs {
		if err := WriteFrame(client, m); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.CloseWrite() // "no more queries", replies must still arrive

	buf := make([]byte, 65535)
	for _, m := range msgs {
		p, err := ReadFrame(client, buf)
		if err != nil || !bytes.Equal(p, append([]byte("r:"), m...)) {
			t.Fatalf("reply %q, %v", p, err)
		}
	}
	select {
	case <-done: // flow ended DatagramLinger after the half-close
	case <-time.After(DatagramLinger + 3*time.Second):
		t.Fatal("datagram flow did not end after half-close")
	}
}

func TestIPFlowAddr(t *testing.T) {
	a := &FlowAddr{IP: net.ParseIP("10.0.0.2"), Flow: 7, net: "ip4:253"}
	if a.String() != "10.0.0.2:7" || a.Network() != "ip4:253" {
		t.Fatal(a.String(), a.Network())
	}
}

func securePair(t *testing.T, c Cipher, serverPSK, clientPSK PSK) (cli, srv *SecureConn, cerr, serr error) {
	t.Helper()
	s1, s2 := sessionPair(t)
	a, _ := s1.OpenChannel("e")
	b, _ := s2.OpenChannel("e")
	hello, err := NewClientHello()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := ReadOpen(b)
		if err != nil {
			serr = err
			return
		}
		srv, serr = ServerHandshake(b, req, serverPSK)
		if serr != nil {
			b.Close()
		}
	}()
	hdr, err := WriteOpen(a, ModeStream, c, hello)
	if err != nil {
		t.Fatal(err)
	}
	cli, cerr = ClientHandshake(a, c, hdr, hello, clientPSK)
	if cerr != nil {
		a.Close() // as muxclient does; the server stops waiting for our MAC
	}
	<-done
	return
}

func TestSecure_AllCiphers(t *testing.T) {
	psk, _, _ := LoadPSK("", "correct horse battery staple")
	for c := CipherNone + 1; c < cipherMax; c++ {
		t.Run(c.String(), func(t *testing.T) {
			cli, srv, cerr, serr := securePair(t, c, psk, psk)
			if cerr != nil || serr != nil {
				t.Fatal(cerr, serr)
			}
			payload := make([]byte, 100<<10) // several records
			_, _ = rand.Read(payload)
			go func() { _, _ = cli.Write(payload); _ = cli.CloseWrite() }()
			got, err := io.ReadAll(srv)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("got %d bytes, %v", len(got), err)
			}
			go func() { _, _ = srv.Write([]byte("pong")); _ = srv.CloseWrite() }()
			got, err = io.ReadAll(cli)
			if err != nil || string(got) != "pong" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestSecure_WrongPSKRejected(t *testing.T) {
	k1, _, _ := LoadPSK("", "alpha")
	k2, _, _ := LoadPSK("", "bravo")
	_, _, cerr, _ := securePair(t, CipherAES256GCM, k1, k2)
	if cerr != ErrAuth {
		t.Fatalf("client accepted a server with another PSK: %v", cerr)
	}
	// Client without PSK against a PSK server: the server must refuse.
	// (The client notices first - the server's MAC doesn't verify - and
	// hangs up, so the server sees the channel end instead of a MAC.)
	cli, srv, cerr, serr := securePair(t, CipherChaCha20Poly1305, k1, nil)
	if cli != nil || srv != nil || cerr != ErrAuth || serr == nil {
		t.Fatalf("handshake without the PSK succeeded: client %v, server %v", cerr, serr)
	}
}

// A plain FIN (or a dropped tail) must not look like a clean end of stream,
// and modified ciphertext must be rejected.
func TestSecure_TruncationAndTampering(t *testing.T) {
	cli, srv, cerr, serr := securePair(t, CipherChaCha20Poly1305, nil, nil)
	if cerr != nil || serr != nil {
		t.Fatal(cerr, serr)
	}
	_, _ = cli.Write([]byte("hello"))
	_ = cli.ch.CloseWrite() // FIN without the authenticated close record
	got, err := io.ReadAll(srv)
	if string(got) != "hello" || err == nil {
		t.Fatalf("truncation not detected: %q %v", got, err)
	}

	cli, srv, _, _ = securePair(t, CipherAES128GCM, nil, nil)
	cli.wmu.Lock()
	n := 1 + 3 + cli.waead.Overhead()
	rec := make([]byte, 2+n)
	binary.BigEndian.PutUint16(rec, uint16(n))
	rec[2] = recData
	copy(rec[3:], "abc")
	setNonce(cli.wnonce, cli.wctr)
	cli.waead.Seal(rec[2:2], cli.wnonce, rec[2:6], rec[:2])
	rec[5] ^= 1 // flip a ciphertext bit
	_, _ = cli.ch.Write(rec)
	cli.wmu.Unlock()
	if _, err := srv.Read(make([]byte, 10)); err != ErrAuth {
		t.Fatalf("tampered record accepted: %v", err)
	}
}

func TestJoinMessages_Unixpacket(t *testing.T) {
	path := t.TempDir() + "/seq.sock"
	l, err := net.Listen("unixpacket", path)
	if err != nil {
		t.Skip("unixpacket unsupported:", err)
	}
	defer l.Close()
	go func() { // echo server keeping message boundaries
		c, err := l.Accept()
		if err != nil {
			return
		}
		b := make([]byte, 65536)
		for {
			n, err := c.Read(b)
			if err != nil {
				c.Close()
				return
			}
			_, _ = c.Write(append([]byte("m:"), b[:n]...))
		}
	}()
	s1, s2 := sessionPair(t)
	server, _ := s1.OpenChannel("p")
	client, _ := s2.OpenChannel("p")
	target, err := Endpoint{Network: "unixpacket", Address: path}.Dial(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go JoinMessages(server, target)
	buf := make([]byte, 65535)
	for _, m := range []string{"one", "two", string(bytes.Repeat([]byte("x"), 30000))} {
		_ = WriteFrame(client, []byte(m))
		p, err := ReadFrame(client, buf)
		if err != nil || string(p) != "m:"+m {
			t.Fatalf("got %d bytes, %v", len(p), err)
		}
	}
	_ = client.CloseWrite()
	if _, err := ReadFrame(client, buf); err != io.EOF {
		t.Fatalf("want EOF after target closed, got %v", err)
	}
}

func TestTLS_PinnedSelfSigned(t *testing.T) {
	scfg, pin, generated, err := ServerTLS("", "", "", "127.0.0.1:0")
	if err != nil || !generated {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", scfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	tr := Transport{Network: "tcp", Address: l.Addr().String()}
	for _, tc := range []struct {
		pin string
		ok  bool
	}{{pin, true}, {strings.Repeat("ab", 32), false}} {
		ccfg, err := ClientTLS(ClientTLSOptions{Pin: tc.pin})
		if err != nil {
			t.Fatal(err)
		}
		dial, _ := tr.Dialer("", 2*time.Second, ccfg)
		c, err := dial()
		if (err == nil) != tc.ok {
			t.Fatalf("pin %s: err=%v", tc.pin[:8], err)
		}
		if c != nil {
			c.Close()
		}
	}
	// Without a pin or CA the self-signed certificate must be rejected.
	ccfg, _ := ClientTLS(ClientTLSOptions{})
	dial, _ := tr.Dialer("", 2*time.Second, ccfg)
	if c, err := dial(); err == nil {
		c.Close()
		t.Fatal("unverified self-signed certificate accepted")
	}
}

func TestTLS_VersionsAndSNI(t *testing.T) {
	scfgFor := func(ver string, sni []string) (*tls.Config, string) {
		min, max, err := ParseTLSVersion(ver)
		if err != nil {
			t.Fatal(err)
		}
		cfg, pin, _, err := ServerTLSWith(ServerTLSOptions{ListenAddr: "127.0.0.1:0", MinVersion: min, MaxVersion: max, SNI: sni})
		if err != nil {
			t.Fatal(err)
		}
		return cfg, pin
	}
	serve := func(cfg *tls.Config) (string, func()) {
		l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(c, c); c.Close() }()
			}
		}()
		return l.Addr().String(), func() { l.Close() }
	}
	for _, tc := range []struct {
		name           string
		srvVer, cliVer string
		srvSNI         []string
		cliSNI         string
		ok             bool
		want           uint16
	}{
		{"default 1.3", "", "", nil, "", true, tls.VersionTLS13},
		{"1.2 only both", "1.2-1.2", "1.2-1.2", nil, "", true, tls.VersionTLS12},
		{"1.1 only both", "1.1-1.1", "1.1-1.1", nil, "", true, tls.VersionTLS11},
		{"server 1.1+, client 1.3", "1.1", "", nil, "", true, tls.VersionTLS13},
		{"server 1.1+, client 1.1-1.2", "1.1", "1.1-1.2", nil, "", true, tls.VersionTLS12},
		{"server 1.3, client 1.2 only", "", "1.2-1.2", nil, "", false, 0},
		{"sni match", "", "", []string{"cdn.example.com"}, "CDN.example.com", true, tls.VersionTLS13},
		{"sni mismatch", "", "", []string{"cdn.example.com"}, "other.example.com", false, 0},
		{"sni missing", "", "", []string{"cdn.example.com"}, "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scfg, pin := scfgFor(tc.srvVer, tc.srvSNI)
			addr, stop := serve(scfg)
			defer stop()
			min, max, err := ParseTLSVersion(tc.cliVer)
			if err != nil {
				t.Fatal(err)
			}
			ccfg, err := ClientTLS(ClientTLSOptions{Pin: pin, SNI: tc.cliSNI, MinVersion: min, MaxVersion: max})
			if err != nil {
				t.Fatal(err)
			}
			dial, _ := Transport{Network: "tcp", Address: addr}.Dialer("", 2*time.Second, ccfg)
			c, err := dial()
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v, want ok=%v", err, tc.ok)
			}
			if c == nil {
				return
			}
			defer c.Close()
			if v := c.(*tls.Conn).ConnectionState().Version; v != tc.want {
				t.Fatalf("negotiated %s, want %s", tls.VersionName(v), tls.VersionName(tc.want))
			}
		})
	}
	for _, bad := range []string{"1.0", "2", "1.3-1.2", "x"} {
		if _, _, err := ParseTLSVersion(bad); err == nil {
			t.Errorf("ParseTLSVersion(%q) accepted", bad)
		}
	}
}

// -sni and -tls-servername differ: SNI is what the server sees, the
// certificate is verified against -tls-servername with the CA.
func TestTLS_SNIDiffersFromVerifiedName(t *testing.T) {
	scfg, _, _, err := ServerTLSWith(ServerTLSOptions{ListenAddr: "127.0.0.1:0", SNI: []string{"front.example"}})
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	inner := scfg.GetConfigForClient
	scfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		seen = h.ServerName
		return inner(h)
	}
	leaf, _ := x509.ParseCertificate(scfg.Certificates[0].Certificate[0])
	caFile := t.TempDir() + "/ca.pem"
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600)
	l, err := tls.Listen("tcp", "127.0.0.1:0", scfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	tr := Transport{Network: "tcp", Address: l.Addr().String()}
	for _, tc := range []struct {
		verify string
		ok     bool
	}{{"localhost", true}, {"front.example", true}, {"wrong.example", false}} {
		ccfg, err := ClientTLS(ClientTLSOptions{CA: caFile, SNI: "front.example", ServerName: tc.verify})
		if err != nil {
			t.Fatal(err)
		}
		dial, _ := tr.Dialer("", 2*time.Second, ccfg)
		c, err := dial()
		if (err == nil) != tc.ok {
			t.Fatalf("verify %s: err=%v", tc.verify, err)
		}
		if c != nil {
			c.Close()
		}
		if seen != "front.example" {
			t.Fatalf("server saw SNI %q", seen)
		}
	}
}
