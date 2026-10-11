package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// End-to-end channel encryption (-encryption).
//
// Each channel runs its own handshake right after the OPEN request, so every
// tunnelled connection gets fresh keys (forward secrecy) no matter which
// transport carries the session. The muxocket frame headers (channel ID,
// offsets) stay visible; payload, the server's status message and the end of
// the stream are protected.
//
// Key exchange: hybrid X25519 + ML-KEM-768 (the same construction as TLS's
// X25519MLKEM768), so recorded traffic stays safe even against a future
// quantum computer as long as either primitive holds.
//
// Authentication: with a pre-shared key (-psk / -psk-file / $MUXTUN_PSK) both
// sides prove knowledge of it with a MAC over the handshake transcript, which
// stops man-in-the-middle attacks and unauthorised clients. Without a PSK the
// channel is encrypted but unauthenticated.
//
// Key schedule: HKDF over the hybrid shared secret, salted with the stretched
// PSK, bound to a hash of the full transcript. ChaCha suites use BLAKE2b-256
// as the hash (as WireGuard pairs ChaCha20 with BLAKE2), AES suites
// SHA-256.
//
//	client -> server  OPEN(cipher)  x25519 pub(32) | ML-KEM-768 encaps key(1184) | random(32)
//	server -> client  status "accepted" (plaintext)
//	server -> client  x25519 pub(32) | ML-KEM ciphertext(1088) | random(32) | server MAC(32)
//	client -> server  client MAC(32)
//	both              AEAD records; the server's real status is the first one
//
// Record: len(2, big endian) | AEAD(type(1) | data), nonce = per-direction
// counter, the length is additional data. Type 1 is an authenticated end of
// stream, so an attacker can't truncate the stream with a forged FIN.

// Cipher identifies an AEAD suite; 0 is plaintext.
type Cipher byte

const (
	CipherNone Cipher = iota
	CipherChaCha20Poly1305
	CipherXChaCha20Poly1305
	CipherAES128GCM
	CipherAES256GCM
	cipherMax
)

type suite struct {
	name   string
	keyLen int
	aead   func(key []byte) (cipher.AEAD, error)
	hash   func() hash.Hash
}

func newBlake2b256() hash.Hash { h, _ := blake2b.New256(nil); return h }

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

var suites = map[Cipher]suite{
	CipherChaCha20Poly1305:  {"chacha20-poly1305", 32, chacha20poly1305.New, newBlake2b256},
	CipherXChaCha20Poly1305: {"xchacha20-poly1305", 32, chacha20poly1305.NewX, newBlake2b256},
	CipherAES128GCM:         {"aes-128-gcm", 16, gcm, sha256.New},
	CipherAES256GCM:         {"aes-256-gcm", 32, gcm, sha256.New},
}

func (c Cipher) String() string {
	if c == CipherNone {
		return "none"
	}
	if s, ok := suites[c]; ok {
		return s.name
	}
	return fmt.Sprintf("cipher(%d)", byte(c))
}

// CipherNames lists the accepted -encryption values.
func CipherNames() string {
	names := []string{"none"}
	for c := CipherNone + 1; c < cipherMax; c++ {
		names = append(names, c.String())
	}
	return strings.Join(names, ", ")
}

var cipherAliases = map[string]Cipher{
	"none": CipherNone, "off": CipherNone, "plain": CipherNone,
	"chacha20-poly1305": CipherChaCha20Poly1305, "chacha20": CipherChaCha20Poly1305, "chacha": CipherChaCha20Poly1305,
	"xchacha20-poly1305": CipherXChaCha20Poly1305, "xchacha20": CipherXChaCha20Poly1305, "xchacha": CipherXChaCha20Poly1305,
	"aes-128-gcm": CipherAES128GCM, "aes128": CipherAES128GCM, "aes128-gcm": CipherAES128GCM,
	"aes-256-gcm": CipherAES256GCM, "aes256": CipherAES256GCM, "aes256-gcm": CipherAES256GCM, "aes": CipherAES256GCM,
}

// ParseCipher parses one -encryption name.
func ParseCipher(s string) (Cipher, error) {
	c, ok := cipherAliases[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		hint := ""
		if strings.Contains(strings.ToLower(s), "blake") {
			hint = " (BLAKE2 is a hash, not a cipher; the chacha suites use it for key derivation)"
		}
		return 0, fmt.Errorf("unknown encryption %q%s; choose from %s", s, hint, CipherNames())
	}
	return c, nil
}

// CipherSet is the server's list of accepted ciphers.
type CipherSet map[Cipher]bool

// ParseCipherSet parses a comma-separated list; "all" means every AEAD suite.
func ParseCipherSet(list string) (CipherSet, error) {
	set := CipherSet{}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.EqualFold(item, "all") {
			for c := CipherNone + 1; c < cipherMax; c++ {
				set[c] = true
			}
			continue
		}
		c, err := ParseCipher(item)
		if err != nil {
			return nil, err
		}
		set[c] = true
	}
	if len(set) == 0 {
		return nil, errors.New("empty encryption list")
	}
	return set, nil
}

func (s CipherSet) String() string {
	var names []string
	for c := range s {
		names = append(names, c.String())
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// ---------------------------------------------------------------------------
// pre-shared key
// ---------------------------------------------------------------------------

// PSK is a stretched pre-shared key (nil: none).
type PSK []byte

// LoadPSK reads the key from -psk-file, -psk or $MUXTUN_PSK (in that order)
// and stretches it with PBKDF2-SHA256, so passphrases are costly to guess
// from a recorded handshake. Both sides must use the same secret.
func LoadPSK(file, value string) (PSK, string, error) {
	var secret []byte
	var src string
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, "", err
		}
		secret, src = []byte(strings.TrimRight(string(b), "\r\n")), "-psk-file"
	case value != "":
		secret, src = []byte(value), "-psk"
	case os.Getenv("MUXTUN_PSK") != "":
		secret, src = []byte(os.Getenv("MUXTUN_PSK")), "$MUXTUN_PSK"
	default:
		return nil, "", nil
	}
	if len(secret) == 0 {
		return nil, "", fmt.Errorf("%s: empty key", src)
	}
	k, err := pbkdf2.Key(sha256.New, string(secret), []byte("muxtun/psk/v1"), 200_000, 32)
	if err != nil {
		return nil, "", err
	}
	return PSK(k), src, nil
}

// ---------------------------------------------------------------------------
// handshake
// ---------------------------------------------------------------------------

const (
	x25519Len     = 32
	randLen       = 32
	macLen        = 32
	clientHelloLn = x25519Len + mlkem.EncapsulationKeySize768 + randLen
	serverHelloLn = x25519Len + mlkem.CiphertextSize768 + randLen + macLen
)

var ErrAuth = errors.New("tunnel: channel authentication failed (wrong or missing pre-shared key?)")

// ClientHello is the client's key-exchange state.
type ClientHello struct {
	Bytes []byte
	x     *ecdh.PrivateKey
	k     *mlkem.DecapsulationKey768
}

func NewClientHello() (*ClientHello, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, clientHelloLn)
	b = append(b, x.PublicKey().Bytes()...)
	b = append(b, k.EncapsulationKey().Bytes()...)
	r := make([]byte, randLen)
	_, _ = rand.Read(r)
	b = append(b, r...)
	return &ClientHello{Bytes: b, x: x, k: k}, nil
}

type keys struct {
	c2s, s2c   []byte
	macC, macS []byte
	th         []byte
}

func deriveKeys(s suite, open, ch, sh []byte, secret []byte, psk PSK) (*keys, error) {
	h := s.hash()
	h.Write([]byte("muxtun/v2 transcript"))
	h.Write(open)
	h.Write(ch)
	h.Write(sh)
	th := h.Sum(nil)
	salt := []byte(psk)
	if salt == nil {
		salt = []byte("muxtun/v2 no-psk")
	}
	km, err := hkdf.Key(s.hash, secret, salt, "muxtun/v2 keys "+string(th), 2*s.keyLen+2*macLen)
	if err != nil {
		return nil, err
	}
	return &keys{
		c2s: km[:s.keyLen], s2c: km[s.keyLen : 2*s.keyLen],
		macC: km[2*s.keyLen : 2*s.keyLen+macLen], macS: km[2*s.keyLen+macLen:],
		th: th,
	}, nil
}

func mac(s suite, key, th []byte, label string) []byte {
	m := hmac.New(s.hash, key)
	m.Write([]byte(label))
	m.Write(th)
	return m.Sum(nil)
}

// ServerHandshake runs the server side after OPEN was accepted. On
// ErrAuth the caller should drop the channel.
func ServerHandshake(rw Conn, req *OpenRequest, psk PSK) (*SecureConn, error) {
	s := suites[req.Cipher]
	if len(req.Hello) != clientHelloLn {
		return nil, ErrBadOpen
	}
	cx, err := ecdh.X25519().NewPublicKey(req.Hello[:x25519Len])
	if err != nil {
		return nil, ErrBadOpen
	}
	ek, err := mlkem.NewEncapsulationKey768(req.Hello[x25519Len : x25519Len+mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, ErrBadOpen
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	xs, err := x.ECDH(cx)
	if err != nil {
		return nil, ErrBadOpen // low-order point
	}
	ks, ct := ek.Encapsulate()

	sh := make([]byte, 0, serverHelloLn)
	sh = append(sh, x.PublicKey().Bytes()...)
	sh = append(sh, ct...)
	r := make([]byte, randLen)
	_, _ = rand.Read(r)
	sh = append(sh, r...)

	k, err := deriveKeys(s, req.header, req.Hello, sh, append(xs, ks...), psk)
	if err != nil {
		return nil, err
	}
	sh = append(sh, mac(s, k.macS, k.th, "server finished")...)
	if err := WriteStatus(rw, StatusOK, "handshake"); err != nil {
		return nil, err
	}
	if _, err := rw.Write(sh); err != nil {
		return nil, err
	}
	cm := make([]byte, macLen)
	if _, err := io.ReadFull(rw, cm); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(cm, mac(s, k.macC, k.th, "client finished")) != 1 {
		return nil, ErrAuth
	}
	return newSecureConn(rw, s, k.c2s, k.s2c)
}

// ClientHandshake completes the client side after OPEN (which carried
// hello.Bytes) was written.
func ClientHandshake(rw Conn, c Cipher, openHeader []byte, hello *ClientHello, psk PSK) (*SecureConn, error) {
	s := suites[c]
	if err := ReadStatus(rw); err != nil { // e.g. cipher not accepted
		return nil, err
	}
	sh := make([]byte, serverHelloLn)
	if _, err := io.ReadFull(rw, sh); err != nil {
		return nil, fmt.Errorf("reading server handshake: %w", err)
	}
	sx, err := ecdh.X25519().NewPublicKey(sh[:x25519Len])
	if err != nil {
		return nil, ErrAuth
	}
	xs, err := hello.x.ECDH(sx)
	if err != nil {
		return nil, ErrAuth
	}
	ks, err := hello.k.Decapsulate(sh[x25519Len : x25519Len+mlkem.CiphertextSize768])
	if err != nil {
		return nil, ErrAuth
	}
	body := sh[:serverHelloLn-macLen]
	k, err := deriveKeys(s, openHeader, hello.Bytes, body, append(xs, ks...), psk)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(sh[serverHelloLn-macLen:], mac(s, k.macS, k.th, "server finished")) != 1 {
		return nil, ErrAuth
	}
	if _, err := rw.Write(mac(s, k.macC, k.th, "client finished")); err != nil {
		return nil, err
	}
	return newSecureConn(rw, s, k.s2c, k.c2s)
}

// ---------------------------------------------------------------------------
// record layer
// ---------------------------------------------------------------------------

const (
	maxRecordData = 16 << 10
	recData       = 0
	recClose      = 1
)

// SecureConn encrypts a channel. Read and Write may run concurrently.
type SecureConn struct {
	ch Conn

	rmu    sync.Mutex
	raead  cipher.AEAD
	rnonce []byte
	rctr   uint64
	rbuf   []byte
	plain  []byte
	eof    bool
	rerr   error

	wmu    sync.Mutex
	waead  cipher.AEAD
	wnonce []byte
	wctr   uint64
	wbuf   []byte
	closed bool
}

func newSecureConn(ch Conn, s suite, rkey, wkey []byte) (*SecureConn, error) {
	ra, err := s.aead(rkey)
	if err != nil {
		return nil, err
	}
	wa, err := s.aead(wkey)
	if err != nil {
		return nil, err
	}
	max := 2 + 1 + maxRecordData + wa.Overhead()
	return &SecureConn{
		ch: ch, raead: ra, waead: wa,
		rnonce: make([]byte, ra.NonceSize()), wnonce: make([]byte, wa.NonceSize()),
		rbuf: make([]byte, max), wbuf: make([]byte, max),
	}, nil
}

func setNonce(n []byte, ctr uint64) {
	binary.BigEndian.PutUint64(n[len(n)-8:], ctr)
}

func (c *SecureConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.plain) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if c.eof {
			return 0, io.EOF
		}
		c.rerr = c.readRecord()
	}
	n := copy(b, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

func (c *SecureConn) readRecord() error {
	hdr := c.rbuf[:2]
	if _, err := io.ReadFull(c.ch, hdr); err != nil {
		if err == io.EOF {
			return fmt.Errorf("tunnel: encrypted stream truncated: %w", io.ErrUnexpectedEOF)
		}
		return err
	}
	n := int(binary.BigEndian.Uint16(hdr))
	if n < 1+c.raead.Overhead() || 2+n > len(c.rbuf) {
		return ErrAuth
	}
	ct := c.rbuf[2 : 2+n]
	if _, err := io.ReadFull(c.ch, ct); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	setNonce(c.rnonce, c.rctr)
	pt, err := c.raead.Open(ct[:0], c.rnonce, ct, hdr)
	if err != nil {
		return ErrAuth
	}
	c.rctr++
	switch pt[0] {
	case recData:
		c.plain = pt[1:]
	case recClose:
		c.eof = true
	default:
		return ErrAuth
	}
	return nil
}

// sealRecord encrypts the n plaintext bytes at buf[3:3+n] in place and
// returns the finished record. buf must have room for the AEAD tag.
func (c *SecureConn) sealRecord(buf []byte, typ byte, n int) []byte {
	l := 1 + n + c.waead.Overhead()
	binary.BigEndian.PutUint16(buf, uint16(l))
	buf[2] = typ
	setNonce(c.wnonce, c.wctr)
	c.wctr++
	c.waead.Seal(buf[2:2], c.wnonce, buf[2:3+n], buf[:2])
	return buf[:2+l]
}

func (c *SecureConn) writeRecord(typ byte, p []byte) error {
	copy(c.wbuf[3:], p)
	_, err := c.ch.Write(c.sealRecord(c.wbuf, typ, len(p)))
	return err
}

// ReadFrom implements io.ReaderFrom: data is read straight into a record
// buffer and sealed in place, saving Write's plaintext copy. The write
// lock is only held while a record is sealed and sent, never across
// r.Read, so Close can still send the close record meanwhile.
func (c *SecureConn) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 2+1+maxRecordData+c.waead.Overhead())
	var total int64
	for {
		n, err := r.Read(buf[3 : 3+maxRecordData])
		if n > 0 {
			c.wmu.Lock()
			if c.closed {
				c.wmu.Unlock()
				return total, io.ErrClosedPipe
			}
			_, werr := c.ch.Write(c.sealRecord(buf, recData, n))
			c.wmu.Unlock()
			if werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// WriteTo implements io.WriterTo: decrypted records are written to w
// directly from the record buffer instead of being copied out by Read.
// It returns nil at the authenticated end of stream.
func (c *SecureConn) WriteTo(w io.Writer) (int64, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var total int64
	for {
		for len(c.plain) == 0 {
			if c.rerr != nil {
				return total, c.rerr
			}
			if c.eof {
				return total, nil
			}
			c.rerr = c.readRecord()
		}
		n, err := w.Write(c.plain)
		total += int64(n)
		c.plain = c.plain[n:]
		if err != nil {
			return total, err
		}
	}
}

func (c *SecureConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(b) > 0 {
		p := b
		if len(p) > maxRecordData {
			p = p[:maxRecordData]
		}
		if err := c.writeRecord(recData, p); err != nil {
			return total, err
		}
		total += len(p)
		b = b[len(p):]
	}
	return total, nil
}

// CloseWrite sends the authenticated end-of-stream record, then half-closes
// the channel.
func (c *SecureConn) CloseWrite() error {
	c.wmu.Lock()
	if !c.closed {
		c.closed = true
		_ = c.writeRecord(recClose, nil)
	}
	c.wmu.Unlock()
	return c.ch.CloseWrite()
}

// Close ends the channel. Like muxocket's Channel.Close it ends our
// direction cleanly when possible; it never blocks behind a Write that is
// stuck on flow control (JoinStream's abort path relies on that).
func (c *SecureConn) Close() error {
	if c.wmu.TryLock() {
		if !c.closed {
			c.closed = true
			_ = c.writeRecord(recClose, nil)
		}
		c.wmu.Unlock()
	}
	return c.ch.Close()
}
