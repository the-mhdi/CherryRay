//go:build linux

package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Spoofing raw-IP transport (-raw), a two-way IP-spoofing tunnel in the
// spirit of Candy-Spoof: every packet both ends send carries a forged
// source address, and each end only accepts packets whose source is on its
// whitelist. It needs CAP_NET_RAW (or root) and is IPv4 only.
//
// Addressing is point to point and fixed in advance, because a spoofed
// source cannot be answered by reflection:
//
//	           client                         server
//	  real IP   (the host's own)      -raw-peer (client real IP)
//	  -raw-peer (server real IP)       real IP  (the host's own)
//	  -spoof-src CS  (forged source)  -spoof-src SS  (forged source)
//	  -accept-src SS (peer's forge)   -accept-src CS (peer's forge)
//
// On the wire:
//
//	client -> server  IP(src=CS dst=server-real)  [TCP]  shim  payload
//	server -> client  IP(src=SS dst=client-real)  [TCP]  shim  payload
//
// The 4-byte flow shim (see ipflow.go) demultiplexes sessions and, through
// its direction byte, stops a host from parsing its own packets. Without
// -faketcp the payload rides directly in an IP packet of -raw-proto; with
// -faketcp it rides inside a crafted TCP segment so the flow looks like
// ordinary TCP to a censor.

// TCP flag bits, for -faketcp-flags.
const (
	tcpFIN = 1 << 0
	tcpSYN = 1 << 1
	tcpRST = 1 << 2
	tcpPSH = 1 << 3
	tcpACK = 1 << 4
	tcpURG = 1 << 5
)

var tcpFlagNames = []struct {
	bit  uint8
	name string
}{
	{tcpFIN, "FIN"}, {tcpSYN, "SYN"}, {tcpRST, "RST"},
	{tcpPSH, "PSH"}, {tcpACK, "ACK"}, {tcpURG, "URG"},
}

// Sequence-number progression for -faketcp-seq-incr.
const (
	seqPayload = iota // += payload length (what a real TCP sender does)
	seqPacket         // += 1 per packet
	seqNone           // stay at the starting value
)

// SpoofOptions configures the -raw transport. All IPs are IPv4.
type SpoofOptions struct {
	Proto   int    // IP protocol number for raw mode (ignored with FakeTCP, which is always 6)
	FakeTCP bool   // wrap payloads in crafted TCP segments
	SrcIP   net.IP // forged source stamped on every outgoing packet (-spoof-src)
	DstIP   net.IP // real IP of the peer, the true destination (-raw-peer)
	Accept  []net.IP

	// FakeTCP tuning.
	Flags   uint8
	Seq     uint32
	SeqIncr int
	SPort   uint16 // our TCP source port
	DPort   uint16 // peer's TCP port (our destination)

	// HTTP enables the -http camouflage (FakeTCP only): the first packets
	// of a flow carry an HTTP request (client) or response (server) header
	// at the start of the TCP payload. MTU is the link packet size the
	// header must fit in (0: 1500); a packet too large to take the header
	// is sent without it.
	HTTP *HTTPConfig
	MTU  int
}

// ParseTCPFlags turns "PSH,ACK" (or "psh|ack", spaces allowed) into a bit
// set. An empty string is an error; use "none" for no flags.
func ParseTCPFlags(s string) (uint8, error) {
	if strings.TrimSpace(s) == "" {
		return 0, errors.New("-faketcp-flags: empty (use e.g. PSH,ACK or none)")
	}
	var f uint8
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '|' || r == ' ' || r == '+' }) {
		p := strings.ToUpper(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		if p == "NONE" {
			return 0, nil
		}
		ok := false
		for _, fn := range tcpFlagNames {
			if fn.name == p {
				f |= fn.bit
				ok = true
				break
			}
		}
		if !ok {
			return 0, fmt.Errorf("-faketcp-flags %q: unknown flag (want FIN,SYN,RST,PSH,ACK,URG or none)", part)
		}
	}
	return f, nil
}

// TCPFlagString renders a flag set as "PSH,ACK" (or "none").
func TCPFlagString(f uint8) string {
	var names []string
	for _, fn := range tcpFlagNames {
		if f&fn.bit != 0 {
			names = append(names, fn.name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// ParseSeqIncr parses -faketcp-seq-incr.
func ParseSeqIncr(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "payload":
		return seqPayload, nil
	case "packet":
		return seqPacket, nil
	case "none", "fixed":
		return seqNone, nil
	}
	return 0, fmt.Errorf("-faketcp-seq-incr %q: want payload, packet or none", s)
}

// ParseIPv4List parses a comma-separated list of IPv4 addresses.
func ParseIPv4List(s string) ([]net.IP, error) {
	var out []net.IP
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("%q is not an IPv4 address", p)
		}
		out = append(out, ip.To4())
	}
	return out, nil
}

// SpoofOverhead is the per-datagram cost before the muxocket payload: IP
// header, optional TCP header, and the flow shim.
func (o SpoofOptions) Overhead() int {
	h := 20 + ipShimLen
	if o.FakeTCP {
		h += 20
	}
	return h
}

// Describe is a short human-readable summary for logs.
func (o SpoofOptions) Describe() string {
	mode := "raw ip proto " + strconv.Itoa(o.Proto)
	if o.FakeTCP {
		mode = fmt.Sprintf("faketcp %d->%d flags=%s seq=%d", o.SPort, o.DPort, TCPFlagString(o.Flags), o.Seq)
	}
	acc := "any"
	if len(o.Accept) > 0 {
		var s []string
		for _, ip := range o.Accept {
			s = append(s, ip.String())
		}
		sort.Strings(s)
		acc = strings.Join(s, ",")
	}
	if o.HTTP != nil {
		mode += " +http"
	}
	return fmt.Sprintf("%s, src=%s dst=%s accept=%s", mode, o.SrcIP, o.DstIP, acc)
}

func (o SpoofOptions) validate() error {
	if o.SrcIP == nil || o.SrcIP.To4() == nil {
		return errors.New("-spoof-src must be an IPv4 address")
	}
	if o.DstIP == nil || o.DstIP.To4() == nil {
		return errors.New("-raw-peer must be an IPv4 address")
	}
	if o.HTTP != nil && !o.FakeTCP {
		return errors.New("-http over -raw needs -faketcp")
	}
	if o.FakeTCP {
		if o.SPort == 0 || o.DPort == 0 {
			return errors.New("-faketcp needs -faketcp-sport and -faketcp-dport")
		}
	} else if o.Proto < 0 || o.Proto > 255 || o.Proto == 6 {
		return errors.New("-raw-proto must be 0-255 and not 6 (6 is -faketcp)")
	}
	for _, ip := range o.Accept {
		if ip.To4() == nil {
			return errors.New("-accept-src must be IPv4 addresses")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// packet codec
// ---------------------------------------------------------------------------

type spoofCodec struct {
	o        SpoofOptions
	src, dst [4]byte
	accept   map[[4]byte]bool

	mu   sync.Mutex // guards the TX counters below
	ipID uint16
	seq  uint32
	ack  uint32
}

func newCodec(o SpoofOptions) (*spoofCodec, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	c := &spoofCodec{o: o, seq: o.Seq}
	copy(c.src[:], o.SrcIP.To4())
	copy(c.dst[:], o.DstIP.To4())
	if len(o.Accept) > 0 {
		c.accept = make(map[[4]byte]bool, len(o.Accept))
		for _, ip := range o.Accept {
			var k [4]byte
			copy(k[:], ip.To4())
			c.accept[k] = true
		}
	}
	var r [6]byte
	_, _ = rand.Read(r[:])
	c.ipID = binary.BigEndian.Uint16(r[0:2])
	c.ack = binary.BigEndian.Uint32(r[2:6]) // plausible ACK for the disguise
	return c, nil
}

// build frames payload into a full IP packet with a forged source.
func (c *spoofCodec) build(payload []byte, magic [2]byte, flow uint16) []byte {
	return c.buildWith(nil, payload, magic, flow)
}

// buildWith is build with an optional -http header placed at the start of
// the TCP payload, before the flow shim.
func (c *spoofCodec) buildWith(prefix, payload []byte, magic [2]byte, flow uint16) []byte {
	ihl := 20
	thl := 0
	if c.o.FakeTCP {
		thl = 20
	}
	total := ihl + thl + len(prefix) + ipShimLen + len(payload)
	pkt := make([]byte, total)

	c.mu.Lock()
	id := c.ipID
	c.ipID++
	seq := c.seq
	switch c.o.SeqIncr {
	case seqPayload:
		c.seq += uint32(len(prefix) + ipShimLen + len(payload))
	case seqPacket:
		c.seq++
	}
	ack := c.ack
	c.mu.Unlock()

	// IPv4 header.
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	proto := byte(c.o.Proto)
	if c.o.FakeTCP {
		binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Don't Fragment, like real TCP
		proto = unix.IPPROTO_TCP
	}
	pkt[8] = 64 // TTL
	pkt[9] = proto
	copy(pkt[12:16], c.src[:])
	copy(pkt[16:20], c.dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:ihl])) // kernel recomputes, but be correct

	off := ihl
	if c.o.FakeTCP {
		t := pkt[off : off+thl]
		binary.BigEndian.PutUint16(t[0:2], c.o.SPort)
		binary.BigEndian.PutUint16(t[2:4], c.o.DPort)
		binary.BigEndian.PutUint32(t[4:8], seq)
		binary.BigEndian.PutUint32(t[8:12], ack)
		t[12] = 5 << 4 // data offset 5 (20 bytes), no options
		t[13] = c.o.Flags
		binary.BigEndian.PutUint16(t[14:16], 65535) // window
		binary.BigEndian.PutUint16(t[18:20], 0)     // urgent ptr
		off += thl
	}

	// Optional HTTP header, flow shim, payload.
	off += copy(pkt[off:], prefix)
	pkt[off] = magic[0]
	pkt[off+1] = magic[1]
	binary.BigEndian.PutUint16(pkt[off+2:off+4], flow)
	copy(pkt[off+4:], payload)

	if c.o.FakeTCP {
		binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18],
			tcpChecksum(c.src[:], c.dst[:], pkt[ihl:]))
	}
	return pkt
}

// parse validates an inbound IP packet and returns the muxocket payload and
// the sender's flow ID. ok is false for anything that is not ours.
func (c *spoofCodec) parse(pkt []byte, magic [2]byte) (payload []byte, flow uint16, ok bool) {
	payload, _, flow, ok = c.parseHTTP(pkt, magic)
	return payload, flow, ok
}

// parseHTTP is parse that also returns the -http header (without the final
// CRLF CRLF) if the packet carried one.
func (c *spoofCodec) parseHTTP(pkt []byte, magic [2]byte) (payload, head []byte, flow uint16, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, nil, 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, nil, 0, false
	}
	if c.accept != nil {
		var s [4]byte
		copy(s[:], pkt[12:16])
		if !c.accept[s] {
			return nil, nil, 0, false
		}
	}
	body := pkt[ihl:]
	if c.o.FakeTCP {
		if pkt[9] != unix.IPPROTO_TCP || len(body) < 20 {
			return nil, nil, 0, false
		}
		// Only our port pair; sport/dport are swapped relative to our TX.
		if binary.BigEndian.Uint16(body[0:2]) != c.o.DPort ||
			binary.BigEndian.Uint16(body[2:4]) != c.o.SPort {
			return nil, nil, 0, false
		}
		dataOff := int(body[12]>>4) * 4
		if dataOff < 20 || len(body) < dataOff {
			return nil, nil, 0, false
		}
		body = body[dataOff:]
	} else if int(pkt[9]) != c.o.Proto {
		return nil, nil, 0, false
	}
	if c.o.HTTP != nil && len(body) >= 2 && (body[0] != magic[0] || body[1] != magic[1]) {
		var rest []byte
		if head, rest, ok = splitHead(body); !ok {
			return nil, nil, 0, false
		}
		body = rest
	}
	if len(body) < ipShimLen || body[0] != magic[0] || body[1] != magic[1] {
		return nil, nil, 0, false
	}
	return body[ipShimLen:], head, binary.BigEndian.Uint16(body[2:4]), true
}

func ipChecksum(h []byte) uint16 { return onesComplement(h, nil) }

func tcpChecksum(src, dst, tcp []byte) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	return onesComplement(pseudo[:], tcp)
}

func onesComplement(a, b []byte) uint16 {
	var sum uint32
	add := func(p []byte) {
		for i := 0; i+1 < len(p); i += 2 {
			sum += uint32(p[i])<<8 | uint32(p[i+1])
		}
		if len(p)%2 == 1 {
			sum += uint32(p[len(p)-1]) << 8
		}
	}
	add(a)
	add(b)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---------------------------------------------------------------------------
// socket / net.Conn + net.PacketConn
// ---------------------------------------------------------------------------

// spoofConn is one forged-source raw socket. It satisfies both net.Conn
// (client: fixed flow) and net.PacketConn (server: flow per peer address).
type spoofConn struct {
	f      *os.File
	rc     syscall.RawConn
	codec  *spoofCodec
	server bool
	flow   uint16 // client flow (client mode only)
	rxMag  [2]byte
	txMag  [2]byte
	rbuf   []byte
	http   *spoofHTTP // -http camouflage state, nil without it
}

// spoofHTTP is the -http state of one raw socket.
type spoofHTTP struct {
	cfg    *HTTPConfig
	maxPkt int // link packet size a header-carrying packet must fit in

	// client: the request header for this flow, stamped on every packet
	// until the first packet from the server arrives.
	req      []byte
	answered atomic.Bool

	// server: flows that sent a valid request header.
	mu        sync.Mutex
	flows     map[uint16]*httpFlow
	lastPrune time.Time
}

type httpFlow struct {
	resp      []byte // response header, stamped until the client confirms
	confirmed bool   // the client sent a packet without the request header
	last      time.Time
}

// httpFlowTTL is how long the server remembers an idle -http flow.
const httpFlowTTL = 30 * time.Minute

func newSpoofHTTP(o SpoofOptions) *spoofHTTP {
	if o.HTTP == nil {
		return nil
	}
	mtu := o.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	return &spoofHTTP{cfg: o.HTTP, maxPkt: mtu - o.Overhead()}
}

func (h *spoofHTTP) fits(prefix, payload []byte) bool {
	return len(prefix)+len(payload) <= h.maxPkt
}

// admit decides whether the server takes a packet of flow fl that carried
// head (nil: no header). A flow must open with a valid request header;
// after that headerless packets confirm the client got our response.
func (h *spoofHTTP) admit(fl uint16, head []byte) bool {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	f := h.flows[fl]
	if head != nil {
		if h.cfg.CheckRequest(head) != "" {
			return false
		}
		if f == nil {
			h.prune(now)
			f = &httpFlow{resp: h.cfg.Response()}
			h.flows[fl] = f
		}
		f.last = now
		return true
	}
	if f == nil {
		return false
	}
	f.confirmed = true
	f.last = now
	return true
}

func (h *spoofHTTP) prune(now time.Time) {
	if len(h.flows) < 1024 || now.Sub(h.lastPrune) < time.Minute {
		return
	}
	h.lastPrune = now
	for k, f := range h.flows {
		if now.Sub(f.last) > httpFlowTTL {
			delete(h.flows, k)
		}
	}
}

// responseFor returns the header to stamp on a packet to flow fl, if any.
func (h *spoofHTTP) responseFor(fl uint16) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if f := h.flows[fl]; f != nil && !f.confirmed {
		return f.resp
	}
	return nil
}

func openRawSocket(o SpoofOptions) (*spoofConn, error) {
	proto := o.Proto
	if o.FakeTCP {
		proto = unix.IPPROTO_TCP
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, fmt.Errorf("raw socket (need CAP_NET_RAW/root): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, DatagramSocketBuffer)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, DatagramSocketBuffer)
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	codec, err := newCodec(o)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "muxspoof")
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &spoofConn{f: f, rc: rc, codec: codec, rbuf: make([]byte, 65535)}, nil
}

// spoofClientConn is the client side. Like ipFlowConn it deliberately
// implements only net.Conn (Read/Write), never net.PacketConn, so muxocket
// reads through Read — which filters by this client's flow ID — instead of
// ReadFrom.
type spoofClientConn struct{ s *spoofConn }

// DialSpoof opens the client side: a fixed random flow, sending with the
// client magic and accepting replies with the server magic.
func DialSpoof(o SpoofOptions) (net.Conn, error) {
	s, err := openRawSocket(o)
	if err != nil {
		return nil, err
	}
	var id [2]byte
	_, _ = rand.Read(id[:])
	s.flow = binary.BigEndian.Uint16(id[:])
	s.txMag, s.rxMag = magicToServer, magicToClient
	if s.http = newSpoofHTTP(o); s.http != nil {
		s.http.req = o.HTTP.Request(o.DstIP.String())
	}
	return &spoofClientConn{s: s}, nil
}

func (c *spoofClientConn) Read(b []byte) (int, error)         { return c.s.Read(b) }
func (c *spoofClientConn) Write(b []byte) (int, error)        { return c.s.Write(b) }
func (c *spoofClientConn) Close() error                       { return c.s.Close() }
func (c *spoofClientConn) LocalAddr() net.Addr                { return c.s.LocalAddr() }
func (c *spoofClientConn) RemoteAddr() net.Addr               { return c.s.RemoteAddr() }
func (c *spoofClientConn) SetDeadline(t time.Time) error      { return c.s.SetDeadline(t) }
func (c *spoofClientConn) SetReadDeadline(t time.Time) error  { return c.s.SetReadDeadline(t) }
func (c *spoofClientConn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

// ListenSpoof opens the server side: it reads client packets and replies to
// the (single) configured peer, using the flow ID to tell sessions apart.
func ListenSpoof(o SpoofOptions) (net.PacketConn, error) {
	s, err := openRawSocket(o)
	if err != nil {
		return nil, err
	}
	s.server = true
	s.txMag, s.rxMag = magicToClient, magicToServer
	if s.http = newSpoofHTTP(o); s.http != nil {
		s.http.flows = make(map[uint16]*httpFlow)
	}
	return s, nil
}

func (s *spoofConn) recv() (payload, head []byte, flow uint16, err error) {
	for {
		var n int
		var rerr error
		cerr := s.rc.Read(func(fd uintptr) bool {
			n, _, rerr = unix.Recvfrom(int(fd), s.rbuf, 0)
			return rerr != unix.EAGAIN && rerr != unix.EWOULDBLOCK
		})
		if cerr != nil {
			return nil, nil, 0, cerr
		}
		if rerr != nil {
			if rerr == unix.EINTR {
				continue
			}
			return nil, nil, 0, rerr
		}
		if p, h, fl, ok := s.codec.parseHTTP(s.rbuf[:n], s.rxMag); ok {
			return p, h, fl, nil
		}
	}
}

func (s *spoofConn) send(prefix, payload []byte, flow uint16) error {
	pkt := s.codec.buildWith(prefix, payload, s.txMag, flow)
	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], s.codec.dst[:])
	var werr error
	cerr := s.rc.Write(func(fd uintptr) bool {
		werr = unix.Sendto(int(fd), pkt, 0, sa)
		return werr != unix.EAGAIN && werr != unix.EWOULDBLOCK
	})
	if cerr != nil {
		return cerr
	}
	return werr
}

// net.Conn (client).
func (s *spoofConn) Read(b []byte) (int, error) {
	for {
		p, head, fl, err := s.recv()
		if err != nil {
			return 0, err
		}
		if fl != s.flow { // another session's reply on this host
			continue
		}
		if s.http != nil {
			if head != nil && checkResponse(head) != nil {
				continue
			}
			s.http.answered.Store(true) // stop stamping the request
		}
		return copy(b, p), nil
	}
}

func (s *spoofConn) Write(b []byte) (int, error) {
	var prefix []byte
	if h := s.http; h != nil && !h.answered.Load() && h.fits(h.req, b) {
		prefix = h.req
	}
	if err := s.send(prefix, b, s.flow); err != nil {
		return 0, err
	}
	return len(b), nil
}

// net.PacketConn (server).
func (s *spoofConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p, head, fl, err := s.recv()
		if err != nil {
			return 0, nil, err
		}
		if s.http != nil && !s.http.admit(fl, head) {
			continue // not (yet) a valid -http flow
		}
		n := copy(b, p)
		return n, &FlowAddr{IP: append(net.IP(nil), s.codec.o.DstIP.To4()...), Flow: fl, net: "rawspoof"}, nil
	}
}

func (s *spoofConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	fa, ok := addr.(*FlowAddr)
	if !ok {
		return 0, fmt.Errorf("spoof: unexpected address type %T", addr)
	}
	var prefix []byte
	if h := s.http; h != nil {
		if r := h.responseFor(fa.Flow); r != nil && h.fits(r, b) {
			prefix = r
		}
	}
	if err := s.send(prefix, b, fa.Flow); err != nil {
		return 0, err
	}
	return len(b), nil
}

type spoofAddr struct{ ip net.IP }

// Network returns an "ip4" family so muxocket's transport adapter treats the
// spoofing transport as the raw-IP datagram transport it is (whole-datagram
// framing), not a byte stream.
func (a spoofAddr) Network() string { return "ip4:rawspoof" }
func (a spoofAddr) String() string  { return a.ip.String() }

func (s *spoofConn) LocalAddr() net.Addr  { return spoofAddr{s.codec.o.SrcIP} }
func (s *spoofConn) RemoteAddr() net.Addr { return spoofAddr{s.codec.o.DstIP} }

func (s *spoofConn) Close() error                       { return s.f.Close() }
func (s *spoofConn) SetDeadline(t time.Time) error      { return s.f.SetDeadline(t) }
func (s *spoofConn) SetReadDeadline(t time.Time) error  { return s.f.SetReadDeadline(t) }
func (s *spoofConn) SetWriteDeadline(t time.Time) error { return s.f.SetWriteDeadline(t) }
