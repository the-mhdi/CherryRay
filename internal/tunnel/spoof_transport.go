package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// RawFlags holds the raw command-line values for the -raw spoofing
// transport, before parsing. Both muxserver and muxclient fill it from
// their flags and call BuildSpoofTransport.
type RawFlags struct {
	Enable    bool
	SrcIP     string // -spoof-src: forged source on outgoing packets
	PeerIP    string // -raw-peer: the peer's real IP (true destination)
	AcceptSrc string // -accept-src: comma-separated IPs we accept as source
	Proto     int    // -raw-proto: IP protocol number (plain raw mode)
	FakeTCP   bool   // -faketcp
	Flags     string // -faketcp-flags
	Seq       int64  // -faketcp-seq, -1 means random
	SeqIncr   string // -faketcp-seq-incr
	SPort     int    // -faketcp-sport
	DPort     int    // -faketcp-dport
}

// BuildSpoofTransport validates the flags and returns the matching
// Transport. mtuNote is a short string for logs.
func BuildSpoofTransport(f RawFlags) (Transport, error) {
	o := SpoofOptions{Proto: f.Proto, FakeTCP: f.FakeTCP}

	o.SrcIP = net.ParseIP(f.SrcIP)
	o.DstIP = net.ParseIP(f.PeerIP)
	if o.SrcIP == nil || o.SrcIP.To4() == nil {
		return Transport{}, fmt.Errorf("-spoof-src %q: want an IPv4 address", f.SrcIP)
	}
	if o.DstIP == nil || o.DstIP.To4() == nil {
		return Transport{}, fmt.Errorf("-raw-peer %q: want the peer's real IPv4 address", f.PeerIP)
	}
	o.SrcIP = o.SrcIP.To4()
	o.DstIP = o.DstIP.To4()

	accept, err := ParseIPv4List(f.AcceptSrc)
	if err != nil {
		return Transport{}, fmt.Errorf("-accept-src: %w", err)
	}
	o.Accept = accept

	if f.FakeTCP {
		if o.Flags, err = ParseTCPFlags(f.Flags); err != nil {
			return Transport{}, err
		}
		if o.SeqIncr, err = ParseSeqIncr(f.SeqIncr); err != nil {
			return Transport{}, err
		}
		if f.SPort <= 0 || f.SPort > 65535 {
			return Transport{}, fmt.Errorf("-faketcp-sport %d: want 1-65535", f.SPort)
		}
		if f.DPort <= 0 || f.DPort > 65535 {
			return Transport{}, fmt.Errorf("-faketcp-dport %d: want 1-65535", f.DPort)
		}
		o.SPort = uint16(f.SPort)
		o.DPort = uint16(f.DPort)
		if f.Seq < 0 {
			var b [4]byte
			_, _ = rand.Read(b[:])
			o.Seq = binary.BigEndian.Uint32(b[:])
		} else {
			o.Seq = uint32(f.Seq)
		}
	} else {
		if f.Proto < 0 || f.Proto > 255 {
			return Transport{}, fmt.Errorf("-raw-proto %d: want 0-255", f.Proto)
		}
		if f.Proto == 6 {
			return Transport{}, fmt.Errorf("-raw-proto 6 is TCP; use -faketcp for crafted TCP")
		}
	}

	return Transport{Network: "rawspoof", Address: o.DstIP.String(), Spoof: &o}, nil
}
