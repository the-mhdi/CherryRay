package tunnel

import (
	"errors"
	"fmt"
	"io"
)

// Per-channel open handshake.
//
// muxocket has no "open channel" frame, so the server can't tell which of its
// channels a client is about to use, and server-speaks-first protocols (SSH,
// SMTP, ...) would never start if the server waited for client data. The
// client therefore starts every channel with an OPEN request, and the server
// answers with a status before any payload:
//
//	client -> server:  'M' 'X' 'T' version(1)=2 mode(1) cipher(1) [client hello]
//	server -> client:  status(1) msgLen(1) msg(msgLen)
//
// mode: 0 = stream, 1 = messages (datagrams/seqpacket). With cipher != 0 the
// encryption handshake (secure.go) follows and the final status is sent
// encrypted. The server only dials the forward target after OPEN (and
// authentication), and the client learns about dial failures instead of
// seeing a silent EOF.
const (
	openVersion = 2

	ModeStream   byte = 0
	ModeDatagram byte = 1

	StatusOK         byte = 0
	StatusDialFailed byte = 1
	StatusBadRequest byte = 2
	StatusForbidden  byte = 3
)

var ErrBadOpen = errors.New("tunnel: malformed channel open request (client/server version mismatch?)")

// Conn is a channel-like byte stream with half-close: *muxocket.Channel or
// an encrypted *SecureConn.
type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// OpenRequest is a parsed OPEN.
type OpenRequest struct {
	Mode   byte
	Cipher Cipher
	Hello  []byte // client key share when Cipher != CipherNone
	header []byte
}

func openHeader(mode byte, c Cipher) []byte {
	return []byte{'M', 'X', 'T', openVersion, mode, byte(c)}
}

// WriteOpen sends OPEN. hello is required when c != CipherNone; the
// returned header is needed by ClientHandshake.
func WriteOpen(w io.Writer, mode byte, c Cipher, hello *ClientHello) ([]byte, error) {
	h := openHeader(mode, c)
	msg := h
	if c != CipherNone {
		msg = append(append([]byte(nil), h...), hello.Bytes...)
	}
	_, err := w.Write(msg)
	return h, err
}

// ReadOpen reads OPEN. An unknown cipher yields a request with that cipher
// and no hello; the caller refuses it.
func ReadOpen(r io.Reader) (*OpenRequest, error) {
	var b [6]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	if b[0] != 'M' || b[1] != 'X' || b[2] != 'T' || b[3] != openVersion || b[4] > ModeDatagram {
		return nil, ErrBadOpen
	}
	req := &OpenRequest{Mode: b[4], Cipher: Cipher(b[5]), header: append([]byte(nil), b[:]...)}
	if req.Cipher != CipherNone && req.Cipher < cipherMax {
		req.Hello = make([]byte, clientHelloLn)
		if _, err := io.ReadFull(r, req.Hello); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func WriteStatus(w io.Writer, code byte, msg string) error {
	if len(msg) > 255 {
		msg = msg[:255]
	}
	buf := make([]byte, 0, 2+len(msg))
	buf = append(buf, code, byte(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

// ReadStatus returns nil if the server accepted the channel.
func ReadStatus(r io.Reader) error {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return fmt.Errorf("reading channel status: %w", err)
	}
	msg := make([]byte, h[1])
	if _, err := io.ReadFull(r, msg); err != nil {
		return fmt.Errorf("reading channel status: %w", err)
	}
	if h[0] != StatusOK {
		return fmt.Errorf("server refused channel (code %d): %s", h[0], msg)
	}
	return nil
}
