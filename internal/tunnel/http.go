package tunnel

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTP header camouflage (-http), in the spirit of Xray's "http" header
// obfuscation for raw TCP: the client starts every transport connection
// with a plausible HTTP/1.1 request header and the server answers with an
// HTTP response header; after that the connection carries the muxocket
// stream unchanged. It is camouflage for passive DPI, not security: it
// adds no secrecy or authentication (use -tls / -encryption for that).
//
//	client -> server   GET /path HTTP/1.1\r\nHost: ...\r\n...\r\n\r\n  muxocket...
//	server -> client   HTTP/1.1 200 OK\r\n...\r\n\r\n                  muxocket...
//
// Over -tls the header travels inside TLS. Over -raw -faketcp, where there
// is no byte stream, the header is put at the start of the crafted TCP
// payload of the first packets of a flow (see spoof.go): the client stamps
// the request on every packet until the server answers, and the server
// stamps the response on every packet until the client has received it.

// maxHTTPHead bounds the header we accept from the peer.
const maxHTTPHead = 8 << 10

// HTTPConfig configures the camouflage. On the client Hosts/Paths are the
// candidates picked at random per connection and Headers are request
// headers; on the server Hosts/Paths are the accepted values (empty: any)
// and Headers are response headers.
type HTTPConfig struct {
	Method  string   // request method (client), default GET
	Hosts   []string // client: Host header candidates; server: accepted Host values
	Paths   []string // client: request path candidates; server: accepted paths
	Headers []string // "Name: value" lines; override same-named defaults, "Name:" removes one
	Status  string   // response status (server), default "200 OK"
}

var defaultRequestHeaders = []string{
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Encoding: gzip, deflate",
	"Accept-Language: en-US,en;q=0.9",
	"Connection: keep-alive",
	"Pragma: no-cache",
}

var defaultResponseHeaders = []string{
	"Content-Type: application/octet-stream",
	"Transfer-Encoding: chunked",
	"Connection: keep-alive",
	"Pragma: no-cache",
}

// Validate checks the configuration for values that would break the
// header syntax.
func (c *HTTPConfig) Validate() error {
	if c.Method != "" && !isToken(c.Method) {
		return fmt.Errorf("-http-method %q: not an HTTP method token", c.Method)
	}
	for _, h := range c.Hosts {
		if h == "" || strings.ContainsAny(h, " \t\r\n/") {
			return fmt.Errorf("-http-host %q: not a host name", h)
		}
	}
	for _, p := range c.Paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " \t\r\n") {
			return fmt.Errorf("-http-path %q: must start with / and contain no spaces", p)
		}
	}
	for _, h := range c.Headers {
		name, _, ok := strings.Cut(h, ":")
		if !ok || !isToken(strings.TrimSpace(name)) || strings.ContainsAny(h, "\r\n") {
			return fmt.Errorf("-http-header %q: want \"Name: value\"", h)
		}
		if strings.EqualFold(strings.TrimSpace(name), "Host") {
			return fmt.Errorf("-http-header %q: use -http-host for the Host header", h)
		}
	}
	if c.Status != "" {
		code, _, _ := strings.Cut(c.Status, " ")
		if n, err := strconv.Atoi(code); err != nil || n < 200 || n > 399 || strings.ContainsAny(c.Status, "\r\n") {
			return fmt.Errorf("-http-status %q: want a 2xx or 3xx status such as \"200 OK\"", c.Status)
		}
	}
	return nil
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

// mergeHeaders applies user header lines on top of the defaults.
func mergeHeaders(defaults, user []string) []string {
	out := make([]string, 0, len(defaults)+len(user))
	override := make(map[string]bool, len(user))
	for _, h := range user {
		name, _, _ := strings.Cut(h, ":")
		override[strings.ToLower(strings.TrimSpace(name))] = true
	}
	for _, h := range defaults {
		name, _, _ := strings.Cut(h, ":")
		if !override[strings.ToLower(name)] {
			out = append(out, h)
		}
	}
	for _, h := range user {
		name, v, _ := strings.Cut(h, ":")
		if v = strings.TrimSpace(v); v != "" { // "Name:" only removes the default
			out = append(out, strings.TrimSpace(name)+": "+v)
		}
	}
	return out
}

func pick(list []string, def string) string {
	switch len(list) {
	case 0:
		return def
	case 1:
		return list[0]
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return list[0]
	}
	return list[n.Int64()]
}

// Request builds one request header; host is used when no -http-host was
// given.
func (c *HTTPConfig) Request(host string) []byte {
	method := c.Method
	if method == "" {
		method = "GET"
	}
	var b bytes.Buffer
	b.WriteString(method + " " + pick(c.Paths, "/") + " HTTP/1.1\r\n")
	b.WriteString("Host: " + pick(c.Hosts, host) + "\r\n")
	for _, h := range mergeHeaders(defaultRequestHeaders, c.Headers) {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// Response builds the server's response header.
func (c *HTTPConfig) Response() []byte {
	status := c.Status
	if status == "" {
		status = "200 OK"
	}
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	for _, h := range mergeHeaders(defaultResponseHeaders, c.Headers) {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Date: " + time.Now().UTC().Format(http1Date) + "\r\n\r\n")
	return b.Bytes()
}

const http1Date = "Mon, 02 Jan 2006 15:04:05 GMT"

// errorResponse is what the server sends before closing a connection whose
// request does not match, like an ordinary web server would.
func errorResponse(status string) []byte {
	body := status + "\n"
	return []byte("HTTP/1.1 " + status + "\r\nContent-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n" +
		"Date: " + time.Now().UTC().Format(http1Date) + "\r\n\r\n" + body)
}

var errHTTPHeadTooLarge = errors.New("http: header too large")

// CheckRequest validates a request header (without the final CRLF CRLF).
// It returns "" if the request is accepted, else the status to answer.
func (c *HTTPConfig) CheckRequest(head []byte) string {
	line, rest, _ := bytes.Cut(head, []byte("\r\n"))
	f := strings.Split(string(line), " ")
	if len(f) != 3 || !isToken(f[0]) || f[1] == "" || !strings.HasPrefix(f[2], "HTTP/1.") {
		return "400 Bad Request"
	}
	if c.Method != "" && f[0] != c.Method {
		return "405 Method Not Allowed"
	}
	if len(c.Paths) > 0 && !pathAllowed(c.Paths, f[1]) {
		return "404 Not Found"
	}
	host := ""
	for len(rest) > 0 {
		var l []byte
		l, rest, _ = bytes.Cut(rest, []byte("\r\n"))
		name, v, ok := bytes.Cut(l, []byte(":"))
		if !ok {
			return "400 Bad Request"
		}
		if strings.EqualFold(string(bytes.TrimSpace(name)), "Host") {
			host = string(bytes.TrimSpace(v))
		}
	}
	if host == "" {
		return "400 Bad Request" // HTTP/1.1 requires Host
	}
	if len(c.Hosts) > 0 && !hostAllowed(c.Hosts, host) {
		return "404 Not Found"
	}
	return ""
}

func pathAllowed(paths []string, target string) bool {
	path, _, _ := strings.Cut(target, "?")
	for _, p := range paths {
		if p == target || (!strings.Contains(p, "?") && p == path) {
			return true
		}
	}
	return false
}

func hostAllowed(hosts []string, host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	for _, a := range hosts {
		if strings.EqualFold(a, host) || strings.EqualFold(a, h) {
			return true
		}
	}
	return false
}

// checkResponse validates the status line of a response header.
func checkResponse(head []byte) error {
	line, _, _ := bytes.Cut(head, []byte("\r\n"))
	f := strings.SplitN(string(line), " ", 3)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") {
		return errors.New("http: malformed response from server")
	}
	code, err := strconv.Atoi(f[1])
	if err != nil || code < 200 || code > 399 {
		return fmt.Errorf("http: server answered %q", line)
	}
	return nil
}

var headEnd = []byte("\r\n\r\n")

// readHead reads from r until the end of an HTTP header. It returns the
// header without the final CRLF CRLF and any bytes read past it.
func readHead(r io.Reader) (head, rest []byte, err error) {
	buf := make([]byte, 0, 1024)
	scanned := 0
	for {
		if len(buf) == cap(buf) {
			if cap(buf) >= maxHTTPHead+len(headEnd) {
				return nil, nil, errHTTPHeadTooLarge
			}
			nb := make([]byte, len(buf), min(2*cap(buf), maxHTTPHead+len(headEnd)))
			copy(nb, buf)
			buf = nb
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if i := bytes.Index(buf[max(0, scanned-3):], headEnd); i >= 0 {
			i += max(0, scanned-3)
			return buf[:i], buf[i+4:], nil
		}
		scanned = len(buf)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, nil, err
		}
	}
}

// splitHead splits a packet payload that starts with an HTTP header.
func splitHead(b []byte) (head, rest []byte, ok bool) {
	if len(b) < 16 || b[0] < 'A' || b[0] > 'Z' {
		return nil, nil, false
	}
	lim := b
	if len(lim) > maxHTTPHead+len(headEnd) {
		lim = lim[:maxHTTPHead+len(headEnd)]
	}
	i := bytes.Index(lim, headEnd)
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+4:], true
}

// ---------------------------------------------------------------------------
// stream transport wrappers
// ---------------------------------------------------------------------------

// httpStream is the per-connection state shared by both wrapper types.
type httpStream struct {
	ready  atomic.Bool // fast path: header done, nothing buffered, no error
	mu     sync.Mutex
	server *HTTPConfig // nil on the client
	conn   net.Conn    // the wrapped connection
	done   bool        // the peer's header has been consumed
	err    error       // sticky error from the header exchange
	rest   []byte      // stream bytes read past the peer's header
}

// read strips the peer's header (and on the server, answers it) before the
// first byte of the stream is returned.
func (s *httpStream) read(b []byte) (int, error) {
	if s.ready.Load() {
		return s.conn.Read(b)
	}
	s.mu.Lock()
	if !s.done {
		s.handshake()
	}
	if s.err != nil {
		s.mu.Unlock()
		return 0, s.err
	}
	if len(s.rest) > 0 {
		n := copy(b, s.rest)
		s.rest = s.rest[n:]
		if len(s.rest) == 0 {
			s.rest = nil
			s.ready.Store(true)
		}
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()
	return s.conn.Read(b)
}

func (s *httpStream) handshake() {
	s.done = true
	head, rest, err := readHead(s.conn)
	if err != nil {
		if s.server != nil && err == errHTTPHeadTooLarge {
			_, _ = s.conn.Write(errorResponse("431 Request Header Fields Too Large"))
		}
		s.err = err
		return
	}
	if s.server == nil {
		s.err = checkResponse(head)
	} else if status := s.server.CheckRequest(head); status != "" {
		_, _ = s.conn.Write(errorResponse(status))
		s.err = fmt.Errorf("http: rejected request (%s)", status)
	} else if _, err := s.conn.Write(s.server.Response()); err != nil {
		s.err = err
	}
	if s.err == nil {
		if len(rest) > 0 {
			s.rest = append([]byte(nil), rest...)
		} else {
			s.ready.Store(true)
		}
	}
}

// writeTo serves io.WriterTo so a promoted (*net.TCPConn).WriteTo can't
// bypass the header stripping.
func (s *httpStream) writeTo(w io.Writer) (int64, error) {
	return io.Copy(w, readerFunc(s.read))
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

// httpTCPConn wraps a plain TCP connection. Embedding *net.TCPConn (not
// net.Conn) keeps its writev support, which net.Buffers — and so
// muxocket's batched frame writes — only use on the concrete type.
type httpTCPConn struct {
	*net.TCPConn
	s *httpStream
}

func (c *httpTCPConn) Read(b []byte) (int, error)         { return c.s.read(b) }
func (c *httpTCPConn) WriteTo(w io.Writer) (int64, error) { return c.s.writeTo(w) }

// httpConn wraps any other stream connection (e.g. *tls.Conn).
type httpConn struct {
	net.Conn
	s *httpStream
}

func (c *httpConn) Read(b []byte) (int, error)         { return c.s.read(b) }
func (c *httpConn) WriteTo(w io.Writer) (int64, error) { return c.s.writeTo(w) }

func wrapHTTP(c net.Conn, server *HTTPConfig) net.Conn {
	s := &httpStream{server: server, conn: c}
	if tc, ok := c.(*net.TCPConn); ok {
		return &httpTCPConn{TCPConn: tc, s: s}
	}
	return &httpConn{Conn: c, s: s}
}

// ClientHTTP sends the request header on a fresh transport connection and
// returns a conn that strips the server's response header from the stream.
// The request is written immediately, so the muxocket handshake follows it
// without waiting a round trip.
func ClientHTTP(c net.Conn, cfg *HTTPConfig, host string) (net.Conn, error) {
	if _, err := c.Write(cfg.Request(host)); err != nil {
		return nil, err
	}
	return wrapHTTP(c, nil), nil
}

// HTTPListener wraps a stream listener so every accepted connection must
// start with an HTTP request header matching cfg. Accept never blocks on
// a client: the header is read and answered lazily, on the first Read,
// which muxocket does inside its handshake (and handshake timeout).
func HTTPListener(l net.Listener, cfg *HTTPConfig) net.Listener {
	return &httpListener{Listener: l, cfg: cfg}
}

type httpListener struct {
	net.Listener
	cfg *HTTPConfig
}

func (l *httpListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return wrapHTTP(c, l.cfg), nil
}

// ---------------------------------------------------------------------------
// flags
// ---------------------------------------------------------------------------

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ", ") }
func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// HTTPFlags registers the -http* flags on fs. After fs.Parse, call the
// returned function to get the configuration (nil without -http).
func HTTPFlags(fs *flag.FlagSet, server bool) func() (*HTTPConfig, error) {
	enable := fs.Bool("http", false, "camouflage the transport as HTTP/1.1: requests/responses with fake headers (-tcp, -tls, -raw -faketcp)")
	var hostHelp, pathHelp, hdrHelp string
	var method, status *string
	if server {
		hostHelp = "comma-separated Host `names` to accept (-http; default: any)"
		pathHelp = "comma-separated request `paths` to accept (-http; default: any)"
		hdrHelp = "extra response header `\"Name: value\"`, repeatable; overrides a default, \"Name:\" removes it (-http)"
		status = fs.String("http-status", "200 OK", "response `status` (-http)")
		method = fs.String("http-method", "", "only accept this request `method` (-http; default: any)")
	} else {
		hostHelp = "comma-separated Host header `names`, one picked at random per connection (-http; default: -sni, else the server host)"
		pathHelp = "comma-separated request `paths`, one picked at random per connection (-http; default /)"
		hdrHelp = "extra request header `\"Name: value\"`, repeatable; overrides a default (e.g. User-Agent), \"Name:\" removes it (-http)"
		method = fs.String("http-method", "GET", "request `method` (-http)")
	}
	hosts := fs.String("http-host", "", hostHelp)
	paths := fs.String("http-path", "", pathHelp)
	var headers listFlag
	fs.Var(&headers, "http-header", hdrHelp)

	return func() (*HTTPConfig, error) {
		set := false
		fs.Visit(func(f *flag.Flag) {
			if strings.HasPrefix(f.Name, "http-") {
				set = true
			}
		})
		if !*enable {
			if set {
				return nil, errors.New("-http-* flags need -http")
			}
			return nil, nil
		}
		c := &HTTPConfig{Method: *method, Hosts: splitList(*hosts), Paths: splitList(*paths), Headers: headers}
		if status != nil {
			c.Status = *status
		}
		return c, c.Validate()
	}
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
