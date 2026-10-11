package tunnel

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseALPN(t *testing.T) {
	for in, want := range map[string][]string{
		"":                    {},
		"none":                {},
		" NONE ":              {},
		"h2":                  {"h2"},
		"h2, http/1.1":        {"h2", "http/1.1"},
		DefaultALPN:           {"muxtun/1"},
		"x-custom/2,acme-tls": {"x-custom/2", "acme-tls"},
	} {
		got, err := ParseALPN(in)
		if err != nil || got == nil || len(got) != len(want) {
			t.Errorf("%q: %v, %v", in, got, err)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q: %v", in, got)
			}
		}
	}
	for _, bad := range []string{"h2,,http/1.1", "h2,none", "h2,h2", string(make([]byte, 256))} {
		if _, err := ParseALPN(bad); err == nil {
			t.Errorf("%q accepted", bad[:min(len(bad), 12)])
		}
	}
}

// alpnHandshake runs one TLS handshake and returns the negotiated protocol.
func alpnHandshake(t *testing.T, server, client []string) (string, error) {
	t.Helper()
	scfg, pin, _, err := ServerTLSWith(ServerTLSOptions{ListenAddr: "127.0.0.1:0", ALPN: server})
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", scfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		_, _ = io.Copy(io.Discard, c)
		c.Close()
	}()
	ccfg, err := ClientTLS(ClientTLSOptions{Pin: pin, ALPN: client})
	if err != nil {
		t.Fatal(err)
	}
	tr := Transport{Network: "tcp", Address: l.Addr().String()}
	dial, _ := tr.Dialer("", 2*time.Second, ccfg)
	c, err := dial()
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.(*tls.Conn).ConnectionState().NegotiatedProtocol, nil
}

func TestTLS_ALPN(t *testing.T) {
	none := []string{}
	for _, tc := range []struct {
		name           string
		server, client []string
		want           string
		fail           bool
	}{
		{"default", nil, nil, "muxtun/1", false},
		{"browser-like", []string{"h2", "http/1.1"}, []string{"h2", "http/1.1"}, "h2", false},
		{"server preference wins", []string{"http/1.1", "h2"}, []string{"h2", "http/1.1"}, "http/1.1", false},
		{"partial overlap", []string{"h2"}, []string{"spdy/3", "h2"}, "h2", false},
		{"no overlap refused", []string{"h2"}, []string{"muxtun/1"}, "", true},
		{"client sends none", []string{"h2"}, none, "", false},
		{"server none", none, []string{"h2"}, "", false},
		{"both none", none, none, "", false},
	} {
		got, err := alpnHandshake(t, tc.server, tc.client)
		if (err != nil) != tc.fail || got != tc.want {
			t.Errorf("%s: negotiated %q, err %v", tc.name, got, err)
		}
	}
}

// The ClientHello must carry exactly the configured list (or no ALPN).
func TestTLS_ALPNOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		client []string
		want   []string
	}{{nil, []string{"muxtun/1"}}, {[]string{"h2", "http/1.1"}, []string{"h2", "http/1.1"}}, {[]string{}, nil}} {
		got := make(chan []string, 1)
		scfg, _, _, _ := ServerTLSWith(ServerTLSOptions{ListenAddr: "127.0.0.1:0"})
		scfg = scfg.Clone()
		scfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			got <- h.SupportedProtos
			return nil, nil
		}
		a, b := net.Pipe()
		go func() { _ = tls.Server(b, scfg).Handshake(); b.Close() }()
		ccfg, _ := ClientTLS(ClientTLSOptions{Insecure: true, ALPN: tc.client})
		ccfg.ServerName = "x"
		go func() { _ = tls.Client(a, ccfg).Handshake(); a.Close() }()
		p := <-got
		if len(p) != len(tc.want) {
			t.Fatalf("client %v: ClientHello offered %v", tc.client, p)
		}
		for i := range p {
			if p[i] != tc.want[i] {
				t.Fatalf("client %v: ClientHello offered %v", tc.client, p)
			}
		}
	}
}
