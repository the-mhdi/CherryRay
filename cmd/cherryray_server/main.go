// Command server accepts muxocket sessions over TCP, UDP or raw IP and
// forwards every channel to a local or remote target.
//
//	server -tcp :7000 -channels ssh=tcp//127.0.0.1:22,web=tcp//127.0.0.1:443
//	server -udp :7000 -channels dns -forward udp//1.1.1.1:53
//	server -ip ip4:253 -channels app -forward unix///run/app.sock
//	server -tcp :443 -tls -psk-file key.txt -encryption chacha20-poly1305 -channels ssh=tcp//127.0.0.1:22
//	server -raw -spoof-src 77.0.0.1 -raw-peer CLIENT_IP -accept-src 88.0.0.2 -psk-file key.txt -channels web=tcp//127.0.0.1:8080
//	server -tcp :80 -http -http-host cdn.example.com -http-path /video -channels ssh=tcp//127.0.0.1:22
//
// For every accepted session the server opens each channel named in
// -channels. A client uses one of them; when the client's first bytes (the
// OPEN request) arrive, the server dials that channel's target and pumps data
// both ways. Sessions are closed when their channels are finished, or after
// -open-timeout if the client never opens a channel.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/the-mhdi/cherryray/internal/tunnel"
	"github.com/the-mhdi/muxocket"
)

type channelSpec struct {
	label  string
	target tunnel.Endpoint
}

var (
	labelRE = regexp.MustCompile(`^[A-Za-z0-9]{1,6}$`)
	verbose bool
)

func vlogf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	var (
		tcpAddr     = flag.String("tcp", "", "listen for sessions on TCP `host:port`")
		udpAddr     = flag.String("udp", "", "listen for sessions on UDP `host:port`")
		ipAddr      = flag.String("ip", "", "listen on raw IP: `ip4:PROTO[@ADDR]` or ip6:PROTO[@ADDR] (needs CAP_NET_RAW)")
		channels    = flag.String("channels", "tunnel", "comma-separated channels opened in every session: `NAME[=NET//ADDR],...` (names: 1-6 letters/digits, case-insensitive)")
		forward     = flag.String("forward", "", "default target `NET//ADDR` for channels without one, e.g. tcp//127.0.0.1:443, udp//1.1.1.1:53, unix///run/x.sock, unixpacket///run/x.sock, ip4:253//10.0.0.2")
		mtu         = flag.Int("mtu", 0, "max IP payload size for -udp/-ip datagrams (default: 1472 IPv4 UDP, 1452 IPv6 UDP, 1480/1460 raw IP)")
		reliable    = flag.String("reliable", "auto", "retransmission/ordering: auto (on for -udp/-ip, off for -tcp), on, off")
		dialTimeout = flag.Duration("dial-timeout", 10*time.Second, "timeout for dialing a forward target")
		openTimeout = flag.Duration("open-timeout", 15*time.Second, "close sessions that open no channel within this time")
		idle        = flag.Duration("idle", 2*time.Minute, "end datagram flows (udp/unixgram/ip targets) after this long without traffic")
		rawSpoof    = flag.Bool("raw", false, "two-way IP-spoofing transport (Linux, needs CAP_NET_RAW): forge the source IP on every packet and accept only -accept-src")
		spoofSrc    = flag.String("spoof-src", "", "forged source `IP` stamped on packets we send (-raw)")
		rawPeer     = flag.String("raw-peer", "", "the client's real `IP` (the true destination) (-raw)")
		acceptSrc   = flag.String("accept-src", "", "comma-separated source `IPs` to accept; others are dropped (-raw; default: any)")
		rawProto    = flag.Int("raw-proto", 253, "IP protocol `number` for -raw packets (not 6; use -faketcp for TCP)")
		fakeTCP     = flag.Bool("faketcp", false, "wrap -raw packets in crafted TCP segments")
		ftFlags     = flag.String("faketcp-flags", "PSH,ACK", "TCP `flags` set on crafted segments: FIN,SYN,RST,PSH,ACK,URG or none")
		ftSeq       = flag.Int64("faketcp-seq", -1, "starting TCP sequence `number` (default: random)")
		ftSeqIncr   = flag.String("faketcp-seq-incr", "payload", "how the sequence advances: `payload`, packet or none")
		ftSport     = flag.Int("faketcp-sport", 0, "our TCP source `port` (-faketcp)")
		ftDport     = flag.Int("faketcp-dport", 0, "the client's TCP `port` (-faketcp)")
	)
	var (
		encryption = flag.String("encryption", "", "accepted channel ciphers, comma-separated: "+tunnel.CipherNames()+", or all (default: all, plus none unless a PSK is set)")
		pskFile    = flag.String("psk-file", "", "pre-shared key file authenticating encrypted channels (or set $MUXTUN_PSK)")
		pskValue   = flag.String("psk", "", "pre-shared key (visible in ps; prefer -psk-file or $MUXTUN_PSK)")
		useTLS     = flag.Bool("tls", false, "wrap the -tcp transport in TLS (1.3 unless -tlsversion)")
		tlsVersion = flag.String("tlsversion", "", "TLS `version`: 1.1, 1.2 or 1.3 = that version or newer; MIN-MAX (e.g. 1.2-1.2) for a range (default 1.3)")
		tlsALPN    = flag.String("alpn", tunnel.DefaultALPN, "ALPN `protocols` to accept, comma-separated in preference order (e.g. h2,http/1.1), or none; clients offering none of them are refused (-tls)")
		tlsSNI     = flag.String("sni", "", "accept only TLS clients sending one of these server `names` (comma-separated); also put in a generated certificate")
		tlsCert    = flag.String("tls-cert", "", "TLS certificate `file` (PEM); default: generate a self-signed one and print its pin")
		tlsKey     = flag.String("tls-key", "", "TLS private key `file` (PEM)")
		tlsCA      = flag.String("tls-client-ca", "", "require client certificates signed by this CA `file` (mutual TLS)")
	)
	httpFlags := tunnel.HTTPFlags(flag.CommandLine, true)
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s (-tcp ADDR | -udp ADDR | -ip ip4:PROTO[@ADDR]) [-channels LIST] [-forward NET//ADDR] [flags]\n\n", os.Args[0])
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
		if tr, err = tunnel.ParseTransport(*tcpAddr, *udpAddr, *ipAddr, true); err != nil {
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
	specs, err := parseChannels(*channels, *forward)
	if err != nil {
		fatalUsage("%v", err)
	}

	cfg := muxocket.DefaultConfig()
	switch *reliable {
	case "auto":
		cfg.Reliability = !tr.IsStream()
	case "on":
		cfg.Reliability = true
	case "off":
		cfg.Reliability = false
	default:
		fatalUsage("-reliable must be auto, on or off")
	}
	if !tr.IsStream() && !cfg.Reliability {
		log.Printf("warning: -reliable=off over %s: lost datagrams corrupt or stall channels", tr.Network)
	}

	psk, pskSrc, err := tunnel.LoadPSK(*pskFile, *pskValue)
	if err != nil {
		fatalUsage("%v", err)
	}
	var ciphers tunnel.CipherSet
	if *encryption == "" {
		ciphers, _ = tunnel.ParseCipherSet("all")
		if psk == nil {
			ciphers[tunnel.CipherNone] = true
		}
	} else if ciphers, err = tunnel.ParseCipherSet(*encryption); err != nil {
		fatalUsage("-encryption: %v", err)
	}
	if psk != nil && ciphers[tunnel.CipherNone] {
		fatalUsage("-encryption includes none, which would let clients bypass the pre-shared key")
	}
	if psk != nil {
		log.Printf("encrypted channels authenticated with the pre-shared key from %s", pskSrc)
	} else if len(ciphers) > 1 || !ciphers[tunnel.CipherNone] {
		log.Printf("warning: no pre-shared key: encrypted channels are not authenticated (man-in-the-middle possible), and anyone can connect")
	}

	var tlsCfg *tls.Config
	if *useTLS {
		if !tr.IsStream() {
			fatalUsage("-tls needs -tcp (TLS has no datagram mode here; use -encryption with -udp/-ip)")
		}
		var pin string
		var generated bool
		minV, maxV, err := tunnel.ParseTLSVersion(*tlsVersion)
		if err != nil {
			fatalUsage("%v", err)
		}
		sni, err := tunnel.ParseSNIList(*tlsSNI)
		if err != nil {
			fatalUsage("%v", err)
		}
		alpn, err := tunnel.ParseALPN(*tlsALPN)
		if err != nil {
			fatalUsage("%v", err)
		}
		if tlsCfg, pin, generated, err = tunnel.ServerTLSWith(tunnel.ServerTLSOptions{
			CertFile: *tlsCert, KeyFile: *tlsKey, ClientCA: *tlsCA, ListenAddr: tr.Address,
			MinVersion: minV, MaxVersion: maxV, SNI: sni, ALPN: alpn,
		}); err != nil {
			log.Fatalf("tls: %v", err)
		}
		if minV < tls.VersionTLS12 {
			log.Printf("warning: -tlsversion allows %s, which is deprecated and weak", tunnel.TLSVersionName(minV))
		}
		if minV != maxV {
			log.Printf("TLS: versions %s to %s", tunnel.TLSVersionName(minV), tunnel.TLSVersionName(maxV))
		} else {
			log.Printf("TLS: version %s only", tunnel.TLSVersionName(minV))
		}
		if len(sni) > 0 {
			log.Printf("TLS: accepting only SNI %s", strings.Join(sni, ", "))
		}
		if generated {
			log.Printf("TLS: generated a self-signed certificate (new on every start; use -tls-cert/-tls-key to keep it)")
		}
		log.Printf("TLS: clients connect with  -tls -tls-pin %s", pin)
	} else if *tlsCert != "" || *tlsKey != "" || *tlsCA != "" || *tlsVersion != "" || *tlsSNI != "" || flagSet("alpn") {
		fatalUsage("-tls-cert/-tls-key/-tls-client-ca/-tlsversion/-sni/-alpn need -tls")
	}

	ln, err := listen(tr, *mtu, cfg, tlsCfg)
	if err != nil {
		log.Fatalf("listen %s: %v", tr, err)
	}
	ln.TransparentResumption = true // a migrated client keeps its session

	for _, s := range specs {
		log.Printf("channel %q -> %s", s.label, s.target)
	}
	log.Printf("listening on %s %s (reliable=%v, tls=%v, http=%v, encryption=%s)", tr.Network, ln.Addr(), cfg.Reliability, tlsCfg != nil, tr.HTTP != nil, ciphers)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("shutting down")
		_ = ln.Close()
		os.Exit(0)
	}()

	srv := &server{specs: specs, dialTimeout: *dialTimeout, openTimeout: *openTimeout, idle: *idle, ciphers: ciphers, psk: psk}
	for {
		sess, err := ln.Accept()
		if err != nil {
			if errors.Is(err, muxocket.ErrListenerClosed) {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go srv.serve(sess)
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
	fmt.Fprintf(os.Stderr, "CherryRayServer: "+format+"\n", args...)
	flag.Usage()
	os.Exit(2)
}

func parseChannels(list, forward string) ([]channelSpec, error) {
	var def *tunnel.Endpoint
	if forward != "" {
		e, err := tunnel.ParseEndpoint(forward)
		if err != nil {
			return nil, fmt.Errorf("-forward: %w", err)
		}
		def = &e
	}
	seen := map[string]bool{}
	var specs []channelSpec
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, target, hasTarget := strings.Cut(item, "=")
		if !labelRE.MatchString(name) {
			return nil, fmt.Errorf("-channels: bad name %q (1-6 letters or digits)", name)
		}
		key := strings.ToLower(name) // channel IDs are case-insensitive
		if seen[key] {
			return nil, fmt.Errorf("-channels: duplicate name %q (names are case-insensitive)", name)
		}
		seen[key] = true
		s := channelSpec{label: key}
		switch {
		case hasTarget:
			e, err := tunnel.ParseEndpoint(target)
			if err != nil {
				return nil, fmt.Errorf("-channels %s: %w", name, err)
			}
			s.target = e
		case def != nil:
			s.target = *def
		default:
			return nil, fmt.Errorf("-channels: %q has no target; use NAME=NET//ADDR or set -forward", name)
		}
		specs = append(specs, s)
	}
	if len(specs) == 0 {
		return nil, errors.New("-channels: no channels given")
	}
	return specs, nil
}

func listen(tr tunnel.Transport, mtu int, cfg *muxocket.Config, tlsCfg *tls.Config) (*muxocket.Listener, error) {
	if tr.IsStream() {
		l, err := net.Listen("tcp", tr.Address)
		if err != nil {
			return nil, err
		}
		if tlsCfg != nil {
			l = tls.NewListener(l, tlsCfg) // handshake runs inside muxocket's handshake timeout
		}
		if tr.HTTP != nil {
			l = tunnel.HTTPListener(l, tr.HTTP) // header exchange also runs inside the handshake timeout
		}
		return muxocket.Listen(l, cfg)
	}
	if tr.Spoof != nil {
		opts := *tr.Spoof
		opts.MTU = mtu // link packet size for -http headers (0: 1500)
		if mtu == 0 {
			mtu = tr.DefaultMTU()
		} else {
			mtu -= tr.Spoof.Overhead()
		}
		pc, err := tunnel.ListenSpoof(opts)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				err = fmt.Errorf("%w (raw spoofing needs root or CAP_NET_RAW)", err)
			}
			return nil, err
		}
		ln, err := muxocket.ListenPacket(pc, mtu, cfg)
		if err != nil {
			pc.Close()
		}
		return ln, err
	}
	rawIP := strings.HasPrefix(tr.Network, "ip")
	switch {
	case mtu == 0:
		mtu = tr.DefaultMTU() // already excludes the raw-IP flow shim
	case rawIP:
		mtu -= tunnel.IPShimOverhead // -mtu is the IP payload; the shim is part of it
	}
	var pc net.PacketConn
	var err error
	if rawIP {
		pc, err = tunnel.ListenIPFlows(tr.Network, tr.Address)
	} else {
		pc, err = net.ListenPacket(tr.Network, tr.Address)
		if err == nil {
			tunnel.TuneDatagramSocket(pc)
		}
	}
	if err != nil {
		if rawIP && errors.Is(err, os.ErrPermission) {
			err = fmt.Errorf("%w (raw IP needs root or CAP_NET_RAW)", err)
		}
		return nil, err
	}
	ln, err := muxocket.ListenPacket(pc, mtu, cfg)
	if err != nil {
		pc.Close()
	}
	return ln, err
}

type server struct {
	specs       []channelSpec
	dialTimeout time.Duration
	openTimeout time.Duration
	idle        time.Duration
	ciphers     tunnel.CipherSet
	psk         tunnel.PSK
}

// sessionState tracks channel use so the session is closed once every
// channel the client opened has finished.
type sessionState struct {
	sess   *muxocket.Session
	mu     sync.Mutex
	active int
	used   bool
}

func (st *sessionState) begin() {
	st.mu.Lock()
	st.active++
	st.used = true
	st.mu.Unlock()
}

func (st *sessionState) end() {
	st.mu.Lock()
	st.active--
	last := st.active == 0
	st.mu.Unlock()
	if last {
		_ = st.sess.Close()
	}
}

func (srv *server) serve(sess *muxocket.Session) {
	peer := "?"
	if a := sess.RemoteAddr(); a != nil {
		peer = a.String()
	}
	vlogf("session %.8x from %s", sess.ID(), peer)
	st := &sessionState{sess: sess}

	for _, spec := range srv.specs {
		ch, err := sess.OpenChannel(spec.label)
		if err != nil {
			log.Printf("%s: open channel %q: %v", peer, spec.label, err)
			_ = sess.Close()
			return
		}
		go srv.handle(st, ch, spec, peer)
	}

	if srv.openTimeout > 0 {
		t := time.AfterFunc(srv.openTimeout, func() {
			st.mu.Lock()
			used := st.used
			st.mu.Unlock()
			if !used {
				vlogf("%s: no channel opened within %v, closing session", peer, srv.openTimeout)
				_ = sess.Close()
			}
		})
		defer t.Stop()
	}
	<-sess.Done()
	vlogf("session %.8x from %s closed", sess.ID(), peer)
}

func (srv *server) handle(st *sessionState, ch *muxocket.Channel, spec channelSpec, peer string) {
	refuse := func(code byte, msg string) {
		_ = tunnel.WriteStatus(ch, code, msg)
		_ = ch.Close()
		tunnel.AwaitDone(ch, 2*time.Second)
	}
	req, err := tunnel.ReadOpen(ch)
	if err != nil {
		if errors.Is(err, tunnel.ErrBadOpen) {
			log.Printf("%s: channel %q: %v", peer, spec.label, err)
			refuse(tunnel.StatusBadRequest, "bad open request (client/server version mismatch?)")
			_ = st.sess.Close()
		}
		return // session closed before the channel was used
	}
	st.begin()
	defer st.end()

	if !srv.ciphers[req.Cipher] {
		log.Printf("%s: channel %q: refused encryption %s", peer, spec.label, req.Cipher)
		refuse(tunnel.StatusForbidden, fmt.Sprintf("encryption %s not accepted; server accepts: %s", req.Cipher, srv.ciphers))
		return
	}
	var pipe tunnel.Conn = ch
	if req.Cipher != tunnel.CipherNone {
		// Bound the key exchange: a client that never sends its MAC must not
		// hold the session (and a goroutine) forever.
		var t *time.Timer
		if srv.openTimeout > 0 {
			t = time.AfterFunc(srv.openTimeout, func() { _ = st.sess.Close() })
		}
		sc, err := tunnel.ServerHandshake(ch, req, srv.psk)
		if t != nil && !t.Stop() && err == nil {
			err = errors.New("key exchange timed out")
		}
		if err != nil {
			log.Printf("%s: channel %q: %v", peer, spec.label, err)
			_ = ch.Close()
			_ = st.sess.Close() // failed authentication: drop the whole session
			return
		}
		pipe = sc
	}

	conn, err := spec.target.Dial(srv.dialTimeout)
	if err != nil {
		log.Printf("%s: channel %q: dial %s: %v", peer, spec.label, spec.target, err)
		_ = tunnel.WriteStatus(pipe, tunnel.StatusDialFailed, err.Error())
		_ = pipe.Close()
		tunnel.AwaitDone(ch, 2*time.Second)
		return
	}
	if err := tunnel.WriteStatus(pipe, tunnel.StatusOK, ""); err != nil {
		conn.Close()
		return
	}
	vlogf("%s: channel %q -> %s (client mode %d, encryption %s)", peer, spec.label, spec.target, req.Mode, req.Cipher)

	start := time.Now()
	// The target decides the wire format: message targets (udp, unixgram,
	// unixpacket, ip) exchange length-prefixed messages, stream targets raw
	// bytes. A datagram-mode client talking to a stream target therefore
	// sends DNS-over-TCP style framing, which is exactly what e.g. a TCP DNS
	// server expects.
	switch {
	case spec.target.Seqpacket():
		tunnel.JoinMessages(pipe, conn)
	case spec.target.Packet():
		tunnel.JoinDatagram(pipe, conn, srv.idle)
	default:
		tunnel.JoinStream(pipe, conn)
	}
	tunnel.AwaitDone(ch, 5*time.Second) // let the last bytes be acknowledged
	vlogf("%s: channel %q done after %v", peer, spec.label, time.Since(start).Round(time.Millisecond))
}
