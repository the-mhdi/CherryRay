// Command CherryRayClient connects to a CherryRayServer and carries local traffic over
// one of its channels.
//
//	client -tcp server:7000 -channel ssh -listen tcp//127.0.0.1:2222
//	client -udp server:7000 -channel dns -listen udp//127.0.0.1:5353
//	client -ip ip4:253@203.0.113.7 -channel app -listen unix///tmp/app.sock
//	ssh -o ProxyCommand='client -tcp server:7000 -channel ssh' host
//	client -tcp server:443 -tls -tls-pin HEX -psk-file key.txt -channel ssh -listen tcp//127.0.0.1:2222
//	client -raw -spoof-src 88.0.0.2 -raw-peer SERVER_IP -accept-src 77.0.0.1 -psk-file key.txt -channel web -listen tcp//127.0.0.1:8080
//	client -tcp server:80 -http -http-host cdn.example.com -http-path /video -channel ssh -listen tcp//127.0.0.1:2222
//
// Every accepted local connection (or, for packet listeners, every local
// peer address) gets its own muxocket session, so connections never block
// each other and each one ends cleanly. Without -listen a single connection
// is carried over stdin/stdout.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/the-mhdi/cherryray/internal/tunnel"
	"github.com/the-mhdi/muxocket"
)

var (
	labelRE = regexp.MustCompile(`^[A-Za-z0-9]{1,6}$`)
	verbose bool
)

func vlogf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

type client struct {
	tr          tunnel.Transport
	redial      func() (net.Conn, error)
	label       string
	dialTimeout time.Duration
	idle        time.Duration
	cipher      tunnel.Cipher
	psk         tunnel.PSK
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stderr)
	var (
		tcpAddr     = flag.String("tcp", "", "connect to the server over TCP `host:port`")
		udpAddr     = flag.String("udp", "", "connect to the server over UDP `host:port`")
		ipAddr      = flag.String("ip", "", "connect over raw IP: `ip4:PROTO@ADDR` or ip6:PROTO@ADDR (needs CAP_NET_RAW)")
		localIP     = flag.String("local", "", "local source `IP` for the transport")
		rawSpoof    = flag.Bool("raw", false, "two-way IP-spoofing transport (Linux, needs CAP_NET_RAW): forge the source IP on every packet and accept only -accept-src")
		spoofSrc    = flag.String("spoof-src", "", "forged source `IP` stamped on packets we send (-raw)")
		rawPeer     = flag.String("raw-peer", "", "the server's real `IP` (the true destination) (-raw)")
		acceptSrc   = flag.String("accept-src", "", "comma-separated source `IPs` to accept; others are dropped (-raw; default: any)")
		rawProto    = flag.Int("raw-proto", 253, "IP protocol `number` for -raw packets (not 6; use -faketcp for TCP)")
		fakeTCP     = flag.Bool("faketcp", false, "wrap -raw packets in crafted TCP segments")
		ftFlags     = flag.String("faketcp-flags", "PSH,ACK", "TCP `flags` set on crafted segments: FIN,SYN,RST,PSH,ACK,URG or none")
		ftSeq       = flag.Int64("faketcp-seq", -1, "starting TCP sequence `number` (default: random)")
		ftSeqIncr   = flag.String("faketcp-seq-incr", "payload", "how the sequence advances: `payload`, packet or none")
		ftSport     = flag.Int("faketcp-sport", 0, "our TCP source `port` (-faketcp)")
		ftDport     = flag.Int("faketcp-dport", 0, "the server's TCP `port` (-faketcp)")
		label       = flag.String("channel", "tunnel", "server channel to use (1-6 letters/digits, case-insensitive)")
		listen      = flag.String("listen", "", "accept local traffic on `NET//ADDR` (tcp//, unix//, unixpacket//, udp//, unixgram//, ip4:N//); default: stdin/stdout")
		dialTimeout = flag.Duration("dial-timeout", 10*time.Second, "timeout for connecting to the server and opening the channel")
		idle        = flag.Duration("idle", 2*time.Minute, "end datagram flows after this long without traffic")
	)
	var (
		encryption = flag.String("encryption", "", "encrypt the channel end-to-end: "+tunnel.CipherNames()+" (default: chacha20-poly1305 if a PSK is set, else none)")
		pskFile    = flag.String("psk-file", "", "pre-shared key file, must match the server's (or set $MUXTUN_PSK)")
		pskValue   = flag.String("psk", "", "pre-shared key (visible in ps; prefer -psk-file or $MUXTUN_PSK)")
		useTLS     = flag.Bool("tls", false, "wrap the -tcp transport in TLS (1.3 unless -tlsversion)")
		tlsVersion = flag.String("tlsversion", "", "TLS `version`: 1.1, 1.2 or 1.3 = that version or newer; MIN-MAX (e.g. 1.2-1.2) for a range (default 1.3)")
		tlsALPN    = flag.String("alpn", tunnel.DefaultALPN, "ALPN `protocols` to offer, comma-separated in preference order (e.g. h2,http/1.1), or none to send no ALPN; must overlap the server's (-tls)")
		tlsSNI     = flag.String("sni", "", "server `name` sent in the TLS ClientHello (default: -tls-servername, else host from -tcp)")
		tlsPin     = flag.String("tls-pin", "", "trust exactly the server key with this SHA-256 `pin` (printed by muxserver)")
		tlsCA      = flag.String("tls-ca", "", "verify the server certificate against this CA `file` instead of the system roots")
		tlsName    = flag.String("tls-servername", "", "server name to verify (default: -sni, else host from -tcp)")
		tlsCert    = flag.String("tls-cert", "", "client certificate `file` for mutual TLS")
		tlsKey     = flag.String("tls-key", "", "client private key `file` for mutual TLS")
		tlsInsec   = flag.Bool("tls-insecure", false, "don't verify the server certificate (testing only)")
	)
	httpFlags := tunnel.HTTPFlags(flag.CommandLine, false)
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s (-tcp ADDR | -udp ADDR | -ip ip4:PROTO@ADDR) [-channel NAME] [-listen NET//ADDR] [flags]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() > 0 {
		fatalUsage("unexpected arguments: %v", flag.Args())
	}

	var err error
	var tr tunnel.Transport
	if *rawSpoof {
		if *tcpAddr != "" || *udpAddr != "" || *ipAddr != "" {
			fatalUsage("-raw replaces -tcp/-udp/-ip; don't combine them")
		}
		if tr, err = tunnel.BuildSpoofTransport(tunnel.RawFlags{
			Enable: true, SrcIP: *spoofSrc, PeerIP: *rawPeer, AcceptSrc: *acceptSrc,
			Proto: *rawProto, FakeTCP: *fakeTCP, Flags: *ftFlags, Seq: *ftSeq,
			SeqIncr: *ftSeqIncr, SPort: *ftSport, DPort: *ftDport,
		}); err != nil {
			fatalUsage("%v", err)
		}
	} else {
		if *spoofSrc != "" || *rawPeer != "" || *acceptSrc != "" || *fakeTCP {
			fatalUsage("-spoof-src/-raw-peer/-accept-src/-faketcp need -raw")
		}
		if tr, err = tunnel.ParseTransport(*tcpAddr, *udpAddr, *ipAddr, false); err != nil {
			fatalUsage("%v", err)
		}
	}
	httpCfg, err := httpFlags()
	if err != nil {
		fatalUsage("%v", err)
	}
	if err := tr.SetHTTP(httpCfg); err != nil {
		fatalUsage("%v", err)
	}
	if !labelRE.MatchString(*label) {
		fatalUsage("-channel %q: 1-6 letters or digits", *label)
	}
	psk, _, err := tunnel.LoadPSK(*pskFile, *pskValue)
	if err != nil {
		fatalUsage("%v", err)
	}
	cipher := tunnel.CipherNone
	switch {
	case *encryption != "":
		if cipher, err = tunnel.ParseCipher(*encryption); err != nil {
			fatalUsage("-encryption: %v", err)
		}
		if cipher == tunnel.CipherNone && psk != nil {
			fatalUsage("a pre-shared key needs -encryption other than none")
		}
	case psk != nil:
		cipher = tunnel.CipherChaCha20Poly1305
	}
	if cipher != tunnel.CipherNone && psk == nil {
		log.Printf("warning: no pre-shared key: the channel is encrypted but the server is not authenticated")
	}

	var tlsCfg *tls.Config
	if *useTLS {
		minV, maxV, err := tunnel.ParseTLSVersion(*tlsVersion)
		if err != nil {
			fatalUsage("%v", err)
		}
		alpn, err := tunnel.ParseALPN(*tlsALPN)
		if err != nil {
			fatalUsage("%v", err)
		}
		if tlsCfg, err = tunnel.ClientTLS(tunnel.ClientTLSOptions{
			CA: *tlsCA, ServerName: *tlsName, Pin: *tlsPin, Insecure: *tlsInsec,
			CertFile: *tlsCert, KeyFile: *tlsKey,
			SNI: *tlsSNI, MinVersion: minV, MaxVersion: maxV, ALPN: alpn,
		}); err != nil {
			fatalUsage("%v", err)
		}
		if minV < tls.VersionTLS12 {
			log.Printf("warning: -tlsversion allows %s, which is deprecated and weak", tunnel.TLSVersionName(minV))
		}
		if *tlsInsec && *tlsPin == "" {
			log.Printf("warning: -tls-insecure: server certificate not verified")
		}
	} else if *tlsPin != "" || *tlsCA != "" || *tlsName != "" || *tlsCert != "" || *tlsKey != "" || *tlsInsec || *tlsVersion != "" || *tlsSNI != "" || flagSet("alpn") {
		fatalUsage("-tls-*, -tlsversion, -sni and -alpn need -tls")
	}
	if *rawSpoof {
		log.Printf("raw spoofing transport: %s", tr.Spoof.Describe())
	}
	redial, err := tr.Dialer(*localIP, *dialTimeout, tlsCfg)
	if err != nil {
		fatalUsage("%v", err)
	}
	c := &client{tr: tr, redial: redial, label: strings.ToLower(*label), dialTimeout: *dialTimeout, idle: *idle, cipher: cipher, psk: psk}

	if *listen == "" {
		os.Exit(c.runStdio())
	}
	ep, err := tunnel.ParseEndpoint(*listen)
	if err != nil {
		fatalUsage("-listen: %v", err)
	}
	if ep.Packet() && !ep.Seqpacket() {
		err = c.runPacket(ep)
	} else {
		err = c.runStream(ep)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// flagSet reports whether the named flag was given on the command line.
func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func fatalUsage(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "CherryRayClient: "+format+"\n", args...)
	flag.Usage()
	os.Exit(2)
}

// connect establishes a new session and opens the channel. Datagram
// transports get a few handshake attempts because a single lost packet
// would otherwise fail the connection.
func (c *client) connect(mode byte) (*muxocket.Session, *muxocket.Channel, tunnel.Conn, error) {
	attempts := 1
	if !c.tr.IsStream() {
		attempts = 3
	}
	d := &muxocket.Dialer{
		HandshakeTimeout: c.dialTimeout / time.Duration(attempts),
		// Transparent reconnect + session resume if the transport breaks
		// (server restart of the socket, NAT rebinding, roaming client).
		Redial: func() (net.Conn, error) {
			vlogf("transport to %s lost, reconnecting", c.tr)
			return c.redial()
		},
	}
	var sess *muxocket.Session
	var err error
	for i := 0; i < attempts; i++ {
		var conn net.Conn
		if conn, err = c.redial(); err != nil {
			if strings.HasPrefix(c.tr.Network, "ip") && errors.Is(err, os.ErrPermission) {
				err = fmt.Errorf("%w (raw IP needs root or CAP_NET_RAW)", err)
			}
			return nil, nil, nil, fmt.Errorf("connect %s: %w", c.tr, err)
		}
		if sess, err = d.Dial(conn); err == nil {
			break
		}
		conn.Close()
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("handshake with %s: %w", c.tr, err)
	}

	ch, err := sess.OpenChannel(c.label)
	if err != nil {
		sess.Close()
		return nil, nil, nil, err
	}
	var hello *tunnel.ClientHello
	if c.cipher != tunnel.CipherNone {
		if hello, err = tunnel.NewClientHello(); err != nil {
			sess.Close()
			return nil, nil, nil, err
		}
	}
	hdr, err := tunnel.WriteOpen(ch, mode, c.cipher, hello)
	if err != nil {
		sess.Close()
		return nil, nil, nil, err
	}
	// Channel reads have no deadline; bound the handshake/status wait by
	// closing the session. An unknown channel name gets no answer at all,
	// hence the hint.
	t := time.AfterFunc(c.dialTimeout, func() { sess.Close() })
	var pipe tunnel.Conn = ch
	if c.cipher != tunnel.CipherNone {
		var sc *tunnel.SecureConn
		if sc, err = tunnel.ClientHandshake(ch, c.cipher, hdr, hello, c.psk); err == nil {
			pipe = sc
		}
	}
	if err == nil {
		err = tunnel.ReadStatus(pipe) // encrypted when a cipher is in use
		if err != nil && pipe != tunnel.Conn(ch) && !strings.Contains(err.Error(), "refused") {
			// The server drops the session when our "finished" MAC is wrong.
			err = fmt.Errorf("%w (server rejected the key exchange: pre-shared key mismatch?)", err)
		}
	}
	stopped := t.Stop()
	if err != nil {
		sess.Close()
		if !stopped {
			err = fmt.Errorf("no answer for channel %q within %v (does the server offer it?)", c.label, c.dialTimeout)
		}
		return nil, nil, nil, err
	}
	return sess, ch, pipe, nil
}

// finish waits for the channel to drain, then ends the session.
func finish(sess *muxocket.Session, ch *muxocket.Channel) {
	tunnel.AwaitDone(ch, 5*time.Second)
	_ = sess.Close()
}

// ---------------------------------------------------------------------------
// stdin/stdout
// ---------------------------------------------------------------------------

func (c *client) runStdio() int {
	sess, ch, pipe, err := c.connect(tunnel.ModeStream)
	if err != nil {
		log.Printf("CherryRayClient: %v", err)
		return 1
	}
	// Not JoinStream: a blocked read on stdin can't be interrupted, so we
	// can't wait for that direction once the remote side is finished.
	inDone := make(chan error, 1)
	go func() { // stdin -> channel; EOF half-closes the channel
		_, err := io.Copy(pipe, os.Stdin)
		if err == nil {
			err = pipe.CloseWrite()
		}
		inDone <- err
	}()
	_, outErr := io.Copy(os.Stdout, pipe) // channel -> stdout until EOF
	_ = os.Stdout.Close()
	if outErr != nil {
		log.Printf("CherryRayClient: %v", outErr)
		_ = sess.Close()
		return 1
	}
	// The remote side has finished sending. Keep forwarding stdin while it
	// can still be delivered (half-closed peers may keep reading).
	select {
	case err := <-inDone:
		if err != nil && !sess.IsClosed() {
			log.Printf("CherryRayClient: %v", err)
		}
	case <-ch.Done():
	case <-sess.Done():
	}
	finish(sess, ch)
	return 0
}

// ---------------------------------------------------------------------------
// connection listeners (tcp, unix, unixpacket)
// ---------------------------------------------------------------------------

func (c *client) runStream(ep tunnel.Endpoint) error {
	if ep.Network == "unix" || ep.Network == "unixpacket" {
		removeStaleSocket(ep.Address)
	}
	l, err := net.Listen(ep.Network, ep.Address)
	if err != nil {
		return err
	}
	onSignal(func() { l.Close() })
	log.Printf("listening on %s, forwarding to channel %q via %s", ep, c.label, c.tr)
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond) // e.g. EMFILE
			continue
		}
		go c.serveStream(conn, ep.Seqpacket())
	}
}

func (c *client) serveStream(conn net.Conn, seqpacket bool) {
	from := conn.RemoteAddr().String()
	if from == "" || from == "@" {
		from = "local peer"
	}
	mode := tunnel.ModeStream
	if seqpacket {
		mode = tunnel.ModeDatagram
	}
	sess, ch, pipe, err := c.connect(mode)
	if err != nil {
		log.Printf("%s: %v", from, err)
		conn.Close()
		return
	}
	vlogf("%s: connected to channel %q", from, c.label)
	start := time.Now()
	if seqpacket {
		tunnel.JoinMessages(pipe, conn) // one frame per message
	} else {
		tunnel.JoinStream(pipe, conn)
	}
	finish(sess, ch)
	vlogf("%s: closed after %v", from, time.Since(start).Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// packet listeners (udp, unixgram, raw ip)
// ---------------------------------------------------------------------------

// flow is the session carrying one local peer's datagrams.
type flow struct {
	peer  net.Addr
	queue chan []byte // datagrams waiting for the session to come up
	last  atomic.Int64
	ch    atomic.Pointer[muxocket.Channel]
}

const flowQueue = 64

func (c *client) runPacket(ep tunnel.Endpoint) error {
	if ep.Network == "unixgram" {
		removeStaleSocket(ep.Address)
	}
	pc, err := net.ListenPacket(ep.Network, ep.Address)
	if err != nil {
		return err
	}
	onSignal(func() { pc.Close() })
	log.Printf("listening on %s, forwarding to channel %q via %s", ep, c.label, c.tr)

	var mu sync.Mutex
	flows := map[string]*flow{}
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue // transient (e.g. ICMP errors on UDP)
		}
		key := ""
		if addr != nil {
			key = addr.String()
		}
		pkt := make([]byte, 2+n) // 2 bytes of headroom for tunnel.WriteFramed
		copy(pkt[2:], buf[:n])

		mu.Lock()
		f := flows[key]
		if f == nil {
			f = &flow{peer: addr, queue: make(chan []byte, flowQueue)}
			flows[key] = f
			go func() {
				c.serveFlow(pc, f)
				mu.Lock()
				delete(flows, key)
				mu.Unlock()
			}()
		}
		mu.Unlock()

		f.last.Store(time.Now().UnixNano())
		select {
		case f.queue <- pkt:
		default: // queue full while connecting / sender faster than the tunnel: drop, like a router would
		}
	}
}

func (c *client) serveFlow(pc net.PacketConn, f *flow) {
	name := "unnamed peer"
	if f.peer != nil && f.peer.String() != "" {
		name = f.peer.String()
	}
	sess, ch, pipe, err := c.connect(tunnel.ModeDatagram)
	if err != nil {
		log.Printf("%s: %v", name, err)
		return
	}
	vlogf("%s: new flow on channel %q", name, c.label)
	defer func() {
		_ = pipe.Close()
		finish(sess, ch)
		vlogf("%s: flow closed", name)
	}()

	stop := make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(stop) }) }

	go func() { // channel -> local peer
		defer end()
		buf := make([]byte, 65535)
		warned := false
		for {
			p, err := tunnel.ReadFrame(pipe, buf)
			if err != nil {
				return
			}
			f.last.Store(time.Now().UnixNano())
			if name == "unnamed peer" {
				if !warned {
					log.Printf("dropping replies: local unixgram sender has no bound address")
					warned = true
				}
				continue
			}
			_, _ = pc.WriteTo(p, f.peer)
		}
	}()

	tick := time.NewTicker(idleCheck(c.idle))
	defer tick.Stop()
	for {
		select {
		case p := <-f.queue:
			if err := tunnel.WriteFramed(pipe, p); err != nil {
				return
			}
		case <-tick.C:
			if c.idle > 0 && time.Since(time.Unix(0, f.last.Load())) > c.idle {
				vlogf("%s: idle for %v", name, c.idle)
				return
			}
		case <-stop:
			return
		case <-sess.Done():
			return
		}
	}
}

func idleCheck(idle time.Duration) time.Duration {
	if idle <= 0 || idle > 10*time.Second {
		return time.Second
	}
	return idle / 4
}

// ---------------------------------------------------------------------------

// removeStaleSocket deletes a leftover unix socket file (only if nothing is
// listening on it), so restarts don't fail with "address already in use".
func removeStaleSocket(path string) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return
	}
	for _, n := range []string{"unix", "unixgram", "unixpacket"} {
		if c, err := net.DialTimeout(n, path, time.Second); err == nil {
			c.Close()
			return // in use
		}
	}
	_ = os.Remove(path)
}

func onSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; fn() }()
}
