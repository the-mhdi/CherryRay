package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"crypto/rand"
)

// Raw IP has no ports. Without them the server can't tell two sessions from
// the same client IP apart (they would share one byte stream and corrupt
// each other), and every raw socket on the client host receives a copy of
// every reply. So each datagram on the -ip transport starts with a 4-byte
// shim header, a minimal "port":
//
//	'M' dir flowID(2, big endian)    dir: 'X' client->server, 'Y' server->client
//
// The client picks a random flow ID per transport connection; the server
// treats (source IP, flow ID) as the peer address. Datagrams without the
// magic (other users of the same IP protocol number) are ignored.
const ipShimLen = 4

// The second magic byte encodes the direction. On a single host the
// kernel hands every raw socket a copy of every packet of its protocol,
// including the ones it sent itself, so without it the client parsed its
// own handshake request as the server's reply ("malformed responder
// handshake") and the server answered its own replies.
var (
	magicToServer = [2]byte{'M', 'X'}
	magicToClient = [2]byte{'M', 'Y'}
)

// FlowAddr is a raw-IP peer address: source IP plus flow ID.
type FlowAddr struct {
	IP   net.IP
	Flow uint16
	net  string
}

func (a *FlowAddr) Network() string { return a.net }
func (a *FlowAddr) String() string {
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Flow)))
}

var shimPool = sync.Pool{New: func() any { b := make([]byte, 65535+ipShimLen); return &b }}

// ---------------------------------------------------------------------------
// server side
// ---------------------------------------------------------------------------

type ipFlowListener struct {
	c   *net.IPConn
	net string
}

// ListenIPFlows opens a raw IP socket (needs CAP_NET_RAW) that speaks the
// flow shim. MTU budgets must subtract IPShimOverhead.
func ListenIPFlows(network, address string) (net.PacketConn, error) {
	addr, err := net.ResolveIPAddr(network, address)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenIP(network, addr)
	if err != nil {
		return nil, err
	}
	TuneDatagramSocket(c)
	return &ipFlowListener{c: c, net: network}, nil
}

// IPShimOverhead is the per-datagram cost of the raw IP flow shim.
const IPShimOverhead = ipShimLen

func (l *ipFlowListener) ReadFrom(b []byte) (int, net.Addr, error) {
	pb := shimPool.Get().(*[]byte)
	defer shimPool.Put(pb)
	for {
		n, a, err := l.c.ReadFrom(*pb) // strips the IPv4 header
		if err != nil {
			return 0, nil, err
		}
		p := (*pb)[:n]
		if n < ipShimLen || p[0] != magicToServer[0] || p[1] != magicToServer[1] || n-ipShimLen > len(b) {
			continue
		}
		ip := a.(*net.IPAddr).IP
		return copy(b, p[ipShimLen:]), &FlowAddr{IP: ip, Flow: binary.BigEndian.Uint16(p[2:4]), net: l.net}, nil
	}
}

func (l *ipFlowListener) WriteTo(b []byte, addr net.Addr) (int, error) {
	fa, ok := addr.(*FlowAddr)
	if !ok {
		return 0, fmt.Errorf("ipflow: unexpected address type %T", addr)
	}
	pb := shimPool.Get().(*[]byte)
	defer shimPool.Put(pb)
	if len(b)+ipShimLen > len(*pb) {
		return 0, errors.New("ipflow: datagram too large")
	}
	p := (*pb)[:ipShimLen+len(b)]
	p[0], p[1] = magicToClient[0], magicToClient[1]
	binary.BigEndian.PutUint16(p[2:4], fa.Flow)
	copy(p[ipShimLen:], b)
	if _, err := l.c.WriteTo(p, &net.IPAddr{IP: fa.IP}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (l *ipFlowListener) Close() error                       { return l.c.Close() }
func (l *ipFlowListener) LocalAddr() net.Addr                { return l.c.LocalAddr() }
func (l *ipFlowListener) SetDeadline(t time.Time) error      { return l.c.SetDeadline(t) }
func (l *ipFlowListener) SetReadDeadline(t time.Time) error  { return l.c.SetReadDeadline(t) }
func (l *ipFlowListener) SetWriteDeadline(t time.Time) error { return l.c.SetWriteDeadline(t) }

// ---------------------------------------------------------------------------
// client side
// ---------------------------------------------------------------------------

// ipFlowConn is a connected raw IP conn with a random flow ID. It
// deliberately does not implement net.PacketConn, so muxocket reads through
// Read (which filters by flow ID) instead of ReadFrom.
type ipFlowConn struct {
	c    *net.IPConn
	flow uint16
}

func dialIPFlow(d *net.Dialer, network, address string) (net.Conn, error) {
	c, err := d.Dial(network, address)
	if err != nil {
		return nil, err
	}
	var id [2]byte
	_, _ = rand.Read(id[:])
	return &ipFlowConn{c: c.(*net.IPConn), flow: binary.BigEndian.Uint16(id[:])}, nil
}

func (c *ipFlowConn) Read(b []byte) (int, error) {
	pb := shimPool.Get().(*[]byte)
	defer shimPool.Put(pb)
	for {
		n, _, err := c.c.ReadFrom(*pb) // ReadFrom strips the IPv4 header, Read doesn't
		if err != nil {
			return 0, err
		}
		p := (*pb)[:n]
		if n < ipShimLen || p[0] != magicToClient[0] || p[1] != magicToClient[1] ||
			binary.BigEndian.Uint16(p[2:4]) != c.flow || n-ipShimLen > len(b) {
			continue // another flow's reply, or not ours at all
		}
		return copy(b, p[ipShimLen:]), nil
	}
}

func (c *ipFlowConn) Write(b []byte) (int, error) {
	pb := shimPool.Get().(*[]byte)
	defer shimPool.Put(pb)
	if len(b)+ipShimLen > len(*pb) {
		return 0, errors.New("ipflow: datagram too large")
	}
	p := (*pb)[:ipShimLen+len(b)]
	p[0], p[1] = magicToServer[0], magicToServer[1]
	binary.BigEndian.PutUint16(p[2:4], c.flow)
	copy(p[ipShimLen:], b)
	if _, err := c.c.Write(p); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ipFlowConn) Close() error                       { return c.c.Close() }
func (c *ipFlowConn) LocalAddr() net.Addr                { return c.c.LocalAddr() }
func (c *ipFlowConn) RemoteAddr() net.Addr               { return c.c.RemoteAddr() }
func (c *ipFlowConn) SetDeadline(t time.Time) error      { return c.c.SetDeadline(t) }
func (c *ipFlowConn) SetReadDeadline(t time.Time) error  { return c.c.SetReadDeadline(t) }
func (c *ipFlowConn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }
