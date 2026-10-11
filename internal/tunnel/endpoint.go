// Package tunnel contains the pieces shared by muxserver and muxclient:
// endpoint/transport parsing, the per-channel open handshake, and the
// stream/datagram pumps between a muxocket.Channel and a local socket.
package tunnel

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Endpoint is a local or remote socket written as NETWORK//ADDRESS, e.g.
//
//	tcp//127.0.0.1:443   tcp6//[::1]:22   udp//1.1.1.1:53
//	unix///run/app.sock  unixgram///tmp/log.sock  unixpacket///run/seq.sock
//	ip4:253//10.0.0.2    ip6:253//fd00::2
//
// "NETWORK://ADDRESS" is accepted too.
type Endpoint struct {
	Network string
	Address string
}

func ParseEndpoint(s string) (Endpoint, error) {
	i := strings.Index(s, "//")
	if i <= 0 {
		return Endpoint{}, fmt.Errorf("endpoint %q: want NETWORK//ADDRESS (e.g. tcp//127.0.0.1:443)", s)
	}
	e := Endpoint{Network: strings.ToLower(strings.TrimSuffix(s[:i], ":")), Address: s[i+2:]}
	if e.Address == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q: empty address", s)
	}
	switch e.Network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix", "unixgram", "unixpacket":
	default:
		if _, err := parseIPNetwork(e.Network); err != nil {
			return Endpoint{}, fmt.Errorf("endpoint %q: %w", s, err)
		}
	}
	return e, nil
}

func (e Endpoint) String() string { return e.Network + "//" + e.Address }

// Packet reports whether the endpoint is message oriented (datagrams or
// unixpacket).
// Packet endpoints carry each datagram over the channel as a 2-byte
// big-endian length followed by the payload (the same framing as DNS over
// TCP); stream endpoints carry raw bytes.
func (e Endpoint) Packet() bool {
	return strings.HasPrefix(e.Network, "udp") || strings.HasPrefix(e.Network, "ip") ||
		e.Network == "unixgram" || e.Network == "unixpacket"
}

// Seqpacket reports a connection-oriented message socket (unixpacket): it is
// accepted/dialed like a stream but keeps message boundaries.
func (e Endpoint) Seqpacket() bool { return e.Network == "unixpacket" }

// parseIPNetwork validates "ip4:PROTO" / "ip6:PROTO" / "ip:PROTO".
func parseIPNetwork(n string) (string, error) {
	fam, proto, ok := strings.Cut(n, ":")
	if !ok || (fam != "ip" && fam != "ip4" && fam != "ip6") {
		return "", fmt.Errorf("unknown network %q", n)
	}
	bad := fmt.Errorf("bad IP protocol %q (number 0-255 or name like icmp)", proto)
	if p, err := strconv.Atoi(proto); err == nil {
		if p < 0 || p > 255 {
			return "", bad
		}
	} else if _, err := net.ResolveIPAddr(fam+":"+proto, ""); err != nil {
		return "", bad
	}
	return n, nil
}

// Dial connects to the endpoint.
func (e Endpoint) Dial(timeout time.Duration) (net.Conn, error) {
	if e.Network == "unixgram" {
		return dialUnixgram(e.Address)
	}
	return net.DialTimeout(e.Network, e.Address, timeout)
}

// unixgram replies need a bound local address; bind a temporary one and
// remove it when the conn is closed.
type unixgramConn struct {
	*net.UnixConn
	path string
}

func (c *unixgramConn) Close() error {
	err := c.UnixConn.Close()
	_ = os.Remove(c.path)
	return err
}

func dialUnixgram(addr string) (net.Conn, error) {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	local := filepath.Join(os.TempDir(), "muxtun-"+hex.EncodeToString(rnd[:])+".sock")
	c, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: local, Net: "unixgram"},
		&net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	return &unixgramConn{UnixConn: c, path: local}, nil
}

// ReadPacket reads one datagram. For raw IPv4 sockets ReadFrom strips the
// IP header (Read would not).
func ReadPacket(c net.Conn, buf []byte) (int, error) {
	if pc, ok := c.(net.PacketConn); ok {
		n, _, err := pc.ReadFrom(buf)
		return n, err
	}
	if u, ok := c.(*unixgramConn); ok {
		n, _, err := u.ReadFrom(buf)
		return n, err
	}
	return c.Read(buf)
}

// ---------------------------------------------------------------------------
// Mux transport (-tcp / -udp / -ip)
// ---------------------------------------------------------------------------

// Transport is the network the multiplexer itself runs over.
type Transport struct {
	Network string // "tcp", "udp", "ip4:PROTO"/"ip6:PROTO", or "rawspoof"
	Address string // host:port for tcp/udp, IP for raw ip, peer real IP for rawspoof
	// Spoof is set for the -raw spoofing transport; it carries the forged
	// source, accepted sources and optional FakeTCP settings.
	Spoof *SpoofOptions
	// HTTP, if set, disguises every transport connection as HTTP/1.1
	// (-http). Only for tcp (plain or TLS) and rawspoof with FakeTCP; use
	// SetHTTP to set it.
	HTTP *HTTPConfig
}

// SetHTTP enables the HTTP header camouflage on the transport.
func (t *Transport) SetHTTP(c *HTTPConfig) error {
	if c == nil {
		return nil
	}
	switch {
	case t.Spoof != nil && t.Spoof.FakeTCP:
		o := *t.Spoof
		o.HTTP = c
		t.Spoof = &o
	case t.Spoof != nil || t.Network != "tcp":
		return errors.New("-http needs -tcp (optionally with -tls) or -raw -faketcp")
	}
	t.HTTP = c
	return nil
}

// ParseTransport takes the -tcp, -udp and -ip flag values; exactly one must
// be set. The -ip form is "ip4:PROTO@ADDRESS" or "ip6:PROTO@ADDRESS"
// (ADDRESS may be omitted on the server to bind all addresses).
func ParseTransport(tcp, udp, ip string, server bool) (Transport, error) {
	set := 0
	for _, v := range []string{tcp, udp, ip} {
		if v != "" {
			set++
		}
	}
	if set != 1 {
		return Transport{}, errors.New("specify exactly one of -tcp, -udp or -ip")
	}
	switch {
	case tcp != "":
		return Transport{Network: "tcp", Address: tcp}, nil
	case udp != "":
		return Transport{Network: "udp", Address: udp}, nil
	}
	netw, addr, _ := strings.Cut(ip, "@")
	if _, err := parseIPNetwork(netw); err != nil || netw[:3] == "ip:" {
		return Transport{}, fmt.Errorf("-ip %q: want ip4:PROTO@ADDR or ip6:PROTO@ADDR", ip)
	}
	if addr == "" {
		if !server {
			return Transport{}, fmt.Errorf("-ip %q: missing @ADDRESS", ip)
		}
		if strings.HasPrefix(netw, "ip6") {
			addr = "::"
		} else {
			addr = "0.0.0.0"
		}
	}
	return Transport{Network: netw, Address: addr}, nil
}

func (t Transport) IsStream() bool { return t.Network == "tcp" }

func (t Transport) String() string { return t.Network + " " + t.Address }

// DefaultMTU is the largest datagram payload that avoids IP fragmentation
// on a 1500-byte link: minus IP (20/40) and UDP (8) or flow-shim (4)
// headers. It is the MTU value to pass to muxocket.ListenPacket.
func (t Transport) DefaultMTU() int {
	v6 := strings.HasPrefix(t.Network, "ip6")
	if t.Network == "udp" {
		host, _, err := net.SplitHostPort(t.Address)
		ip := net.ParseIP(host)
		// Unknown / dual-stack bind: assume IPv6 (smaller, always safe).
		v6 = err != nil || ip == nil || ip.To4() == nil
		if v6 {
			return 1500 - 40 - 8
		}
		return 1500 - 20 - 8
	}
	if t.Spoof != nil {
		// The forged IP/TCP headers and the flow shim are all part of the
		// 1500-byte link MTU that muxocket must fit its payload inside.
		return 1500 - t.Spoof.Overhead()
	}
	// Raw IP: the flow shim header (see ipflow.go) is part of the payload.
	if v6 {
		return 1500 - 40 - ipShimLen
	}
	return 1500 - 20 - ipShimLen
}

// Dialer returns a function that opens a new transport connection,
// optionally from a fixed local IP (needed for raw IP on a single host).
// tlsCfg (only for tcp) wraps every connection in TLS.
func (t Transport) Dialer(localIP string, timeout time.Duration, tlsCfg *tls.Config) (func() (net.Conn, error), error) {
	if tlsCfg != nil && t.Network != "tcp" {
		return nil, errors.New("TLS needs the -tcp transport (use -encryption for -udp/-ip)")
	}
	if t.Spoof != nil {
		return func() (net.Conn, error) { return DialSpoof(*t.Spoof) }, nil
	}
	d := net.Dialer{Timeout: timeout}
	if localIP != "" {
		ip := net.ParseIP(localIP)
		if ip == nil {
			return nil, fmt.Errorf("-local %q is not an IP address", localIP)
		}
		switch {
		case t.Network == "tcp":
			d.LocalAddr = &net.TCPAddr{IP: ip}
		case t.Network == "udp":
			d.LocalAddr = &net.UDPAddr{IP: ip}
		default:
			d.LocalAddr = &net.IPAddr{IP: ip}
		}
	}
	if strings.HasPrefix(t.Network, "ip") {
		return func() (net.Conn, error) {
			c, err := dialIPFlow(&d, t.Network, t.Address)
			if err == nil {
				TuneDatagramSocket(c.(*ipFlowConn).c)
			}
			return c, err
		}, nil
	}
	if tlsCfg != nil {
		return t.withHTTP(func() (net.Conn, error) {
			c, err := tls.DialWithDialer(&d, "tcp", t.Address, tlsCfg) // timeout covers the TLS handshake
			if err != nil {
				return nil, err
			}
			if tc, ok := c.NetConn().(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
				_ = tc.SetKeepAlive(true)
			}
			return c, nil
		}, tlsCfg.ServerName, timeout), nil
	}
	return t.withHTTP(func() (net.Conn, error) {
		c, err := d.Dial(t.Network, t.Address)
		if err == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
				_ = tc.SetKeepAlive(true)
			}
			TuneDatagramSocket(c)
		}
		return c, err
	}, "", timeout), nil
}

// withHTTP makes dial send the -http request header on every new
// connection (including muxocket's resumption redials). The Host header
// defaults to sni, else the host of the server address.
func (t Transport) withHTTP(dial func() (net.Conn, error), sni string, timeout time.Duration) func() (net.Conn, error) {
	cfg := t.HTTP
	if cfg == nil || t.Network != "tcp" {
		return dial
	}
	host := sni
	if host == "" {
		host = t.Address
		if h, port, err := net.SplitHostPort(t.Address); err == nil && (port == "80" || port == "443") {
			host = h
		}
	}
	return func() (net.Conn, error) {
		c, err := dial()
		if err != nil {
			return nil, err
		}
		if timeout > 0 {
			_ = c.SetWriteDeadline(time.Now().Add(timeout))
		}
		hc, err := ClientHTTP(c, cfg, host)
		if err != nil {
			c.Close()
			return nil, err
		}
		_ = c.SetWriteDeadline(time.Time{})
		return hc, nil
	}
}

// DatagramSocketBuffer is requested for UDP/raw IP transport sockets. The
// kernel defaults (~200 KiB) are smaller than one session window, so bursts
// were dropped by the kernel and had to be recovered by retransmission. The
// kernel caps the value at net.core.rmem_max / wmem_max.
const DatagramSocketBuffer = 4 << 20

// TuneDatagramSocket enlarges the socket buffers of UDP and IP sockets.
func TuneDatagramSocket(c any) {
	type bufferSetter interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	switch c.(type) {
	case *net.UDPConn, *net.IPConn:
		b := c.(bufferSetter)
		_ = b.SetReadBuffer(DatagramSocketBuffer)
		_ = b.SetWriteBuffer(DatagramSocketBuffer)
	}
}
