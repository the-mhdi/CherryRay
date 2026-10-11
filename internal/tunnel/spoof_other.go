//go:build !linux

package tunnel

import (
	"errors"
	"net"
)

// The -raw spoofing transport relies on Linux raw sockets (SOCK_RAW with
// IP_HDRINCL) and is unavailable on other platforms.

var errSpoofUnsupported = errors.New("-raw spoofing transport is Linux-only")

type SpoofOptions struct {
	Proto   int
	FakeTCP bool
	SrcIP   net.IP
	DstIP   net.IP
	Accept  []net.IP
	Flags   uint8
	Seq     uint32
	SeqIncr int
	SPort   uint16
	DPort   uint16
	HTTP    *HTTPConfig
	MTU     int
}

func (o SpoofOptions) Overhead() int {
	h := 24
	if o.FakeTCP {
		h += 20
	}
	return h
}
func (o SpoofOptions) Describe() string { return "raw spoofing (unsupported on this OS)" }

func ParseTCPFlags(string) (uint8, error)              { return 0, errSpoofUnsupported }
func TCPFlagString(uint8) string                       { return "" }
func ParseSeqIncr(string) (int, error)                 { return 0, errSpoofUnsupported }
func ParseIPv4List(string) ([]net.IP, error)           { return nil, errSpoofUnsupported }
func DialSpoof(SpoofOptions) (net.Conn, error)         { return nil, errSpoofUnsupported }
func ListenSpoof(SpoofOptions) (net.PacketConn, error) { return nil, errSpoofUnsupported }
