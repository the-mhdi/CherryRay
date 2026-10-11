package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/the-mhdi/muxocket"
)

const (
	copyBufSize = 32 << 10
	maxDatagram = 65535
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, maxDatagram+2); return &b }}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }

// copyStream copies until EOF (returns nil) or an error. It goes through
// io.CopyBuffer so *muxocket.Channel's ReadFrom/WriteTo (which read into
// and write out of the channel's own buffers, saving a copy per chunk) and
// the socket fast paths are used; the pooled buffer is only the fallback.
func copyStream(dst io.Writer, src io.Reader) error {
	pb := getBuf()
	defer putBuf(pb)
	_, err := io.CopyBuffer(dst, src, (*pb)[:copyBufSize])
	return err
}

type closeWriter interface{ CloseWrite() error }

// JoinStream pumps bytes both ways between ch and a stream conn, with proper
// half-close: EOF on one side becomes CloseWrite on the other, so
// request/response protocols that shut down their write side still get
// their answer. Returns when both directions are done.
func JoinStream(ch Conn, conn io.ReadWriteCloser) {
	join(ch, conn, copyStream, copyStream)
}

// JoinMessages is JoinStream for connection-oriented message sockets
// (unixpacket / SOCK_SEQPACKET): every message becomes one frame on the
// channel and every frame one message, with the same half-close handling.
// Zero-length messages can't be carried: on SEQPACKET sockets they are
// indistinguishable from end-of-stream.
func JoinMessages(ch Conn, conn io.ReadWriteCloser) {
	join(ch, conn, copyMessagesToFrames, copyFramesToMessages)
}

func join(ch Conn, conn io.ReadWriteCloser, up, down func(io.Writer, io.Reader) error) {
	var wg sync.WaitGroup
	wg.Add(2)
	abort := func() { _ = ch.Close(); _ = conn.Close() }

	go func() { // local -> channel
		defer wg.Done()
		if err := up(ch, conn); err != nil {
			abort()
			return
		}
		_ = ch.CloseWrite()
	}()
	go func() { // channel -> local
		defer wg.Done()
		if err := down(conn, ch); err != nil {
			abort()
			return
		}
		if cw, ok := conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = conn.Close() // no half-close available (e.g. stdout)
		}
	}()
	wg.Wait()
	_ = ch.Close()
	_ = conn.Close()
}

// copyMessagesToFrames reads whole messages from src (one per Read) and
// frames them onto dst.
func copyMessagesToFrames(dst io.Writer, src io.Reader) error {
	pb := getBuf()
	defer putBuf(pb)
	for {
		// Read behind 2 bytes of headroom so the frame is sent in place.
		n, err := src.Read((*pb)[2 : 2+maxDatagram])
		if n > 0 {
			if werr := WriteFramed(dst, (*pb)[:2+n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// copyFramesToMessages writes each frame from src as one message to dst.
func copyFramesToMessages(dst io.Writer, src io.Reader) error {
	pb := getBuf()
	defer putBuf(pb)
	for {
		p, err := ReadFrame(src, *pb)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(p) == 0 {
			continue // would read as EOF on the other side
		}
		if _, err := dst.Write(p); err != nil {
			return err
		}
	}
}

// WriteFrame sends one datagram over the channel as len(2) || payload, in a
// single Write so frames never interleave.
func WriteFrame(ch io.Writer, payload []byte) error {
	if len(payload) > maxDatagram {
		return errors.New("tunnel: datagram too large")
	}
	pb := getBuf()
	defer putBuf(pb)
	b := (*pb)[:2+len(payload)]
	copy(b[2:], payload)
	return WriteFramed(ch, b)
}

// WriteFramed is WriteFrame for a datagram that already sits behind 2
// bytes of headroom: b[2:] is the payload and b[:2] is overwritten with its
// length, so no copy is needed.
func WriteFramed(ch io.Writer, b []byte) error {
	if len(b) < 2 || len(b)-2 > maxDatagram {
		return errors.New("tunnel: datagram too large")
	}
	binary.BigEndian.PutUint16(b, uint16(len(b)-2))
	_, err := ch.Write(b)
	return err
}

// ReadFrame reads one framed datagram into buf (len >= 65535).
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf[:n], nil
}

// DatagramLinger is how long JoinDatagram keeps relaying replies after the
// channel peer has half-closed (no more datagrams will come from it), e.g.
// "printf query | muxclient" against a UDP DNS server.
const DatagramLinger = 2 * time.Second

// JoinDatagram pumps datagrams between ch (framed) and a connected packet
// conn. Datagram flows have no end-of-stream, so the flow ends after idle
// without traffic in either direction, DatagramLinger after the peer
// half-closed the channel, when the peer closes the channel, or on error.
func JoinDatagram(ch Conn, conn net.Conn, idle time.Duration) {
	var last atomic.Int64
	var peerEOF atomic.Bool
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	timeout := func() time.Duration {
		if peerEOF.Load() && (idle <= 0 || idle > DatagramLinger) {
			return DatagramLinger
		}
		return idle
	}
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); _ = ch.Close(); _ = conn.Close() }) }

	go func() { // channel -> local
		pb := getBuf()
		defer putBuf(pb)
		for {
			p, err := ReadFrame(ch, *pb)
			if err == io.EOF {
				// Peer won't send more; keep relaying replies for a while.
				peerEOF.Store(true)
				touch()
				_ = conn.SetReadDeadline(time.Now().Add(DatagramLinger))
				return
			}
			if err != nil {
				stop()
				return
			}
			touch()
			if _, err := conn.Write(p); err != nil && !isTransient(err) {
				stop()
				return
			}
		}
	}()

	pb := getBuf()
	defer putBuf(pb)
	for { // local -> channel
		if t := timeout(); t > 0 {
			_ = conn.SetReadDeadline(time.Unix(0, last.Load()).Add(t))
		}
		n, err := ReadPacket(conn, (*pb)[2:])
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if t := timeout(); t > 0 && time.Since(time.Unix(0, last.Load())) < t {
					continue // the other direction was active
				}
				break
			}
			if isTransient(err) {
				continue
			}
			break
		}
		touch()
		if err := WriteFramed(ch, (*pb)[:2+n]); err != nil {
			break
		}
	}
	stop()
	<-done
}

// isTransient: e.g. ECONNREFUSED from an ICMP port-unreachable on a
// connected UDP socket; the flow should survive it.
func isTransient(err error) bool {
	var ne *net.OpError
	if errors.As(err, &ne) && !ne.Timeout() {
		var se *os.SyscallError
		return errors.As(err, &se)
	}
	return false
}

// AwaitDone waits for the channel to finish (peer closed, everything
// acknowledged) so closing the session afterwards loses nothing.
func AwaitDone(ch *muxocket.Channel, max time.Duration) {
	select {
	case <-ch.Done():
	case <-time.After(max):
	}
}
