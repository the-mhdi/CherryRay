//go:build linux

package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestParseTCPFlags(t *testing.T) {
	cases := map[string]uint8{
		"PSH,ACK":     tcpPSH | tcpACK,
		"syn":         tcpSYN,
		"ACK|PSH|URG": tcpACK | tcpPSH | tcpURG,
		"fin, rst":    tcpFIN | tcpRST,
		"none":        0,
	}
	for in, want := range cases {
		got, err := ParseTCPFlags(in)
		if err != nil || got != want {
			t.Errorf("ParseTCPFlags(%q) = %d,%v want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "xyz", "ACK,NOPE"} {
		if _, err := ParseTCPFlags(bad); err == nil {
			t.Errorf("ParseTCPFlags(%q) accepted", bad)
		}
	}
	if s := TCPFlagString(tcpPSH | tcpACK); s != "PSH,ACK" {
		t.Errorf("TCPFlagString = %q", s)
	}
	if s := TCPFlagString(0); s != "none" {
		t.Errorf("TCPFlagString(0) = %q", s)
	}
}

func TestParseSeqIncrAndIPList(t *testing.T) {
	for in, want := range map[string]int{"": seqPayload, "payload": seqPayload, "packet": seqPacket, "none": seqNone, "fixed": seqNone} {
		if got, err := ParseSeqIncr(in); err != nil || got != want {
			t.Errorf("ParseSeqIncr(%q)=%d,%v", in, got, err)
		}
	}
	if _, err := ParseSeqIncr("weekly"); err == nil {
		t.Error("ParseSeqIncr accepted junk")
	}
	ips, err := ParseIPv4List("10.0.0.1, 10.0.0.2")
	if err != nil || len(ips) != 2 {
		t.Fatalf("ParseIPv4List: %v %v", ips, err)
	}
	if _, err := ParseIPv4List("::1"); err == nil {
		t.Error("ParseIPv4List accepted IPv6")
	}
}

func baseOpts(fake bool) SpoofOptions {
	o := SpoofOptions{
		FakeTCP: fake, Proto: 253,
		SrcIP:  net.IPv4(10, 0, 0, 1).To4(),
		DstIP:  net.IPv4(10, 0, 0, 2).To4(),
		Accept: []net.IP{net.IPv4(10, 0, 0, 1).To4()},
	}
	if fake {
		o.Flags = tcpPSH | tcpACK
		o.SPort, o.DPort = 443, 8080
		o.Seq = 1000
		o.SeqIncr = seqPayload
	}
	return o
}

func TestCodecRoundTrip(t *testing.T) {
	for _, fake := range []bool{false, true} {
		o := baseOpts(fake)
		c, err := newCodec(o)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello spoofed world")
		pkt := c.build(msg, magicToServer, 0x1234)

		// IP header checksum must verify.
		if onesComplement(pkt[:20], nil) != 0 {
			t.Error("bad IP checksum")
		}
		if fake {
			if pkt[9] != 6 {
				t.Errorf("proto = %d, want 6 (TCP)", pkt[9])
			}
			// TCP checksum over header+data must verify against pseudo-header.
			if tcpChecksum(pkt[12:16], pkt[16:20], pkt[20:]) != 0 {
				t.Error("bad TCP checksum")
			}
		} else if pkt[9] != 253 {
			t.Errorf("proto = %d, want 253", pkt[9])
		}
		if !bytes.Equal(pkt[12:16], o.SrcIP) || !bytes.Equal(pkt[16:20], o.DstIP) {
			t.Error("forged addresses not stamped")
		}

		// A peer with the mirrored magic parses it back.
		peerOpts := o
		peerOpts.SrcIP, peerOpts.DstIP = o.DstIP, o.SrcIP
		peerOpts.Accept = []net.IP{o.SrcIP}
		if fake {
			peerOpts.SPort, peerOpts.DPort = o.DPort, o.SPort
		}
		pc, _ := newCodec(peerOpts)
		got, flow, ok := pc.parse(pkt, magicToServer)
		if !ok || flow != 0x1234 || !bytes.Equal(got, msg) {
			t.Fatalf("parse failed: ok=%v flow=%x got=%q", ok, flow, got)
		}
	}
}

func TestCodecWhitelistAndMagic(t *testing.T) {
	o := baseOpts(false)
	c, _ := newCodec(o)
	pkt := c.build([]byte("x"), magicToServer, 7)

	// Receiver that accepts only a different source drops it.
	ro := o
	ro.Accept = []net.IP{net.IPv4(203, 0, 113, 9).To4()}
	rc, _ := newCodec(ro)
	if _, _, ok := rc.parse(pkt, magicToServer); ok {
		t.Error("packet from non-whitelisted source accepted")
	}
	// Wrong direction magic is rejected (host seeing its own packet).
	rc2, _ := newCodec(o)
	if _, _, ok := rc2.parse(pkt, magicToClient); ok {
		t.Error("wrong-direction magic accepted")
	}
	// Wrong protocol number dropped.
	pkt[9] = 254
	if _, _, ok := rc2.parse(pkt, magicToServer); ok {
		t.Error("wrong proto accepted")
	}
}

func TestCodecSeqProgression(t *testing.T) {
	o := baseOpts(true)
	o.Seq = 5000
	for _, tc := range []struct {
		incr int
		want []uint32
	}{
		{seqNone, []uint32{5000, 5000, 5000}},
		{seqPacket, []uint32{5000, 5001, 5002}},
	} {
		oo := o
		oo.SeqIncr = tc.incr
		c, _ := newCodec(oo)
		for i, want := range tc.want {
			pkt := c.build([]byte("ab"), magicToServer, 1)
			seq := uint32(pkt[24])<<24 | uint32(pkt[25])<<16 | uint32(pkt[26])<<8 | uint32(pkt[27])
			if seq != want {
				t.Errorf("incr=%d packet %d: seq=%d want=%d", tc.incr, i, seq, want)
			}
		}
	}
	// payload mode advances by shim+len each time.
	oo := o
	oo.SeqIncr = seqPayload
	c, _ := newCodec(oo)
	p1 := c.build([]byte("abc"), magicToServer, 1) // advances by 4+3
	p2 := c.build([]byte("de"), magicToServer, 1)
	s1 := uint32(p1[24])<<24 | uint32(p1[25])<<16 | uint32(p1[26])<<8 | uint32(p1[27])
	s2 := uint32(p2[24])<<24 | uint32(p2[25])<<16 | uint32(p2[26])<<8 | uint32(p2[27])
	if s1 != 5000 || s2 != 5000+uint32(ipShimLen+3) {
		t.Errorf("payload seq: %d then %d", s1, s2)
	}
}

func TestBuildSpoofTransport(t *testing.T) {
	tr, err := BuildSpoofTransport(RawFlags{
		Enable: true, SrcIP: "10.0.0.1", PeerIP: "10.0.0.2",
		AcceptSrc: "10.0.0.1", Proto: 253, SeqIncr: "payload", Flags: "PSH,ACK",
	})
	if err != nil || tr.Spoof == nil || tr.Network != "rawspoof" {
		t.Fatalf("transport: %+v err=%v", tr, err)
	}
	if tr.DefaultMTU() != 1500-24 {
		t.Errorf("raw MTU = %d", tr.DefaultMTU())
	}
	ft, err := BuildSpoofTransport(RawFlags{
		Enable: true, SrcIP: "10.0.0.1", PeerIP: "10.0.0.2",
		FakeTCP: true, Flags: "SYN", SeqIncr: "none", SPort: 443, DPort: 80, Seq: -1,
	})
	if err != nil || ft.DefaultMTU() != 1500-44 {
		t.Fatalf("faketcp transport: mtu=%d err=%v", ft.DefaultMTU(), err)
	}
	for _, bad := range []RawFlags{
		{Enable: true, SrcIP: "nope", PeerIP: "10.0.0.2"},
		{Enable: true, SrcIP: "10.0.0.1", PeerIP: "10.0.0.2", Proto: 6},
		{Enable: true, SrcIP: "10.0.0.1", PeerIP: "10.0.0.2", FakeTCP: true, Flags: "PSH", SeqIncr: "payload"}, // no ports
	} {
		if _, err := BuildSpoofTransport(bad); err == nil {
			t.Errorf("BuildSpoofTransport(%+v) accepted", bad)
		}
	}
}

func TestCodecHTTPPrefix(t *testing.T) {
	cfg := &HTTPConfig{Paths: []string{"/live"}}
	o := baseOpts(true)
	o.HTTP = cfg
	c, err := newCodec(o)
	if err != nil {
		t.Fatal(err)
	}
	peerOpts := o
	peerOpts.SrcIP, peerOpts.DstIP = o.DstIP, o.SrcIP
	peerOpts.Accept = []net.IP{o.SrcIP}
	peerOpts.SPort, peerOpts.DPort = o.DPort, o.SPort
	pc, _ := newCodec(peerOpts)

	req := cfg.Request("10.0.0.2")
	msg := []byte("muxocket handshake")
	pkt := c.buildWith(req, msg, magicToServer, 0x4242)
	// The TCP payload starts with the HTTP request, as a DPI box sees it.
	if !bytes.HasPrefix(pkt[40:], []byte("GET /live HTTP/1.1\r\n")) {
		t.Fatalf("TCP payload starts %q", pkt[40:60])
	}
	if tcpChecksum(pkt[12:16], pkt[16:20], pkt[20:]) != 0 {
		t.Error("bad TCP checksum")
	}
	got, head, flow, ok := pc.parseHTTP(pkt, magicToServer)
	if !ok || flow != 0x4242 || !bytes.Equal(got, msg) || !bytes.HasPrefix(head, []byte("GET /live ")) {
		t.Fatalf("parse: ok=%v flow=%x got=%q head=%q", ok, flow, got, head)
	}
	if cfg.CheckRequest(head) != "" {
		t.Error("own request rejected")
	}
	// Sequence numbers advance over the header too, like real TCP.
	before := c.seq
	c.buildWith(req, msg, magicToServer, 1)
	if c.seq-before != uint32(len(req)+ipShimLen+len(msg)) {
		t.Errorf("seq advanced %d", c.seq-before)
	}
	// Headerless packets still parse.
	if got, head, _, ok := pc.parseHTTP(c.build(msg, magicToServer, 1), magicToServer); !ok || head != nil || !bytes.Equal(got, msg) {
		t.Error("headerless packet rejected")
	}
	// Without -http a header-carrying packet is not ours.
	plain := peerOpts
	plain.HTTP = nil
	np, _ := newCodec(plain)
	if _, _, ok := np.parse(pkt, magicToServer); ok {
		t.Error("codec without -http accepted an HTTP-prefixed packet")
	}
	// Garbage instead of a header (no CRLF CRLF) is dropped.
	if _, _, _, ok := pc.parseHTTP(c.buildWith([]byte("GET / HTTP/1.1\r\nHost: x\r\n"), msg, magicToServer, 1), magicToServer); ok {
		t.Error("unterminated header accepted")
	}
}

func TestSpoofHTTPFlowState(t *testing.T) {
	o := baseOpts(true)
	o.HTTP = &HTTPConfig{Paths: []string{"/ok"}}
	h := newSpoofHTTP(o)
	h.flows = make(map[uint16]*httpFlow)
	good := []byte("GET /ok HTTP/1.1\r\nHost: a")
	bad := []byte("GET /no HTTP/1.1\r\nHost: a")

	if h.admit(1, nil) {
		t.Fatal("unknown flow without header admitted")
	}
	if h.admit(1, bad) || h.responseFor(1) != nil {
		t.Fatal("bad request admitted")
	}
	if !h.admit(1, good) {
		t.Fatal("valid request rejected")
	}
	r := h.responseFor(1)
	if !bytes.HasPrefix(r, []byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatalf("response %q", r)
	}
	if !h.admit(1, good) || !bytes.Equal(h.responseFor(1), r) {
		t.Fatal("retransmitted request: response must stay the same")
	}
	if h.responseFor(2) != nil {
		t.Fatal("response for unknown flow")
	}
	if !h.admit(1, nil) {
		t.Fatal("established flow's headerless packet dropped")
	}
	if h.responseFor(1) != nil {
		t.Fatal("still stamping after the client confirmed")
	}
	if h.admit(1, bad) {
		t.Fatal("bad header on an established flow admitted")
	}

	// Header only where it fits in the link MTU.
	payload := make([]byte, h.maxPkt-len(r))
	if !h.fits(r, payload) || h.fits(r, append(payload, 0)) {
		t.Errorf("fits: maxPkt=%d", h.maxPkt)
	}
	if h.maxPkt != 1500-o.Overhead() {
		t.Errorf("maxPkt %d", h.maxPkt)
	}

	// Idle flows are pruned once the table is large.
	old := time.Now().Add(-2 * httpFlowTTL)
	for i := 0; i < 1100; i++ {
		h.flows[uint16(100+i)] = &httpFlow{last: old}
	}
	h.lastPrune = time.Time{}
	h.admit(9, good)
	if len(h.flows) != 2 { // flows 1 and 9
		t.Errorf("after prune: %d flows", len(h.flows))
	}
}

func TestSpoofHTTPNeedsFakeTCP(t *testing.T) {
	o := baseOpts(false)
	o.HTTP = &HTTPConfig{}
	if _, err := newCodec(o); err == nil {
		t.Error("-http without -faketcp accepted")
	}
	tr := Transport{Network: "rawspoof", Spoof: &o}
	if err := tr.SetHTTP(&HTTPConfig{}); err == nil {
		t.Error("SetHTTP on raw without faketcp accepted")
	}
	f := baseOpts(true)
	tr = Transport{Network: "rawspoof", Spoof: &f}
	if err := tr.SetHTTP(&HTTPConfig{}); err != nil || tr.Spoof.HTTP == nil || f.HTTP != nil {
		t.Errorf("SetHTTP faketcp: %v (must set a copy)", err)
	}
}
