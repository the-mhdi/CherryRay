package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// TLS for the -tcp transport. TLS 1.3 by default (-tlsversion allows 1.1
// and 1.2); the session (and with it every channel, header and handshake)
// runs inside it.

const alpn = "muxtun/1"

// DefaultALPN is the -alpn default.
const DefaultALPN = alpn

// ParseALPN parses -alpn: a comma-separated list of protocol IDs in
// preference order, e.g. "h2,http/1.1". "none" (or "") disables ALPN, so no
// extension is sent (client) or negotiated (server). The result is never
// nil, so an explicit "none" can be told apart from "use the default".
func ParseALPN(v string) ([]string, error) {
	protos := []string{}
	if t := strings.TrimSpace(v); t == "" || strings.EqualFold(t, "none") {
		return protos, nil
	}
	seen := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			return nil, fmt.Errorf("-alpn %q: empty protocol name", v)
		case len(p) > 255:
			return nil, fmt.Errorf("-alpn %q: protocol names are at most 255 bytes", v)
		case strings.EqualFold(p, "none"):
			return nil, fmt.Errorf("-alpn %q: \"none\" can't be combined with protocols", v)
		case seen[p]:
			return nil, fmt.Errorf("-alpn %q: duplicate %q", v, p)
		}
		seen[p] = true
		protos = append(protos, p)
	}
	return protos, nil
}

// nextProtos turns an ALPN option into tls.Config.NextProtos: nil means
// the default, an empty list no ALPN.
func nextProtos(o []string) []string {
	if o == nil {
		return []string{alpn}
	}
	if len(o) == 0 {
		return nil
	}
	return append([]string(nil), o...)
}

// PinOf returns the hex SHA-256 of a certificate's public key (SPKI), the
// value -tls-pin expects. It survives certificate renewal with the same key.
func PinOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func parsePin(p string) ([]byte, error) {
	p = strings.TrimPrefix(strings.TrimPrefix(p, "sha256:"), "sha256/")
	if b, err := hex.DecodeString(p); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(p); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("-tls-pin %q: want the 64-hex-digit SHA-256 printed by muxserver", p)
}

// ParseTLSVersion parses -tlsversion: "MIN" (that version or newer, like
// curl's --tlsv1.x) or "MIN-MAX". Versions are 1.1, 1.2 and 1.3; an empty
// value means 1.3 only.
func ParseTLSVersion(v string) (min, max uint16, err error) {
	one := func(s string) (uint16, error) {
		switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "tls") {
		case "1.1", "11":
			return tls.VersionTLS11, nil
		case "1.2", "12":
			return tls.VersionTLS12, nil
		case "1.3", "13":
			return tls.VersionTLS13, nil
		}
		return 0, fmt.Errorf("-tlsversion %q: want 1.1, 1.2 or 1.3, or a range such as 1.2-1.3", v)
	}
	if strings.TrimSpace(v) == "" {
		return tls.VersionTLS13, tls.VersionTLS13, nil
	}
	lo, hi, isRange := strings.Cut(v, "-")
	if min, err = one(lo); err != nil {
		return 0, 0, err
	}
	max = tls.VersionTLS13
	if isRange {
		if max, err = one(hi); err != nil {
			return 0, 0, err
		}
		if max < min {
			return 0, 0, fmt.Errorf("-tlsversion %q: maximum is below the minimum", v)
		}
	}
	return min, max, nil
}

// TLSVersionName is "TLS 1.2" etc., for logs.
func TLSVersionName(v uint16) string { return tls.VersionName(v) }

// ParseSNIList parses the server's -sni list (comma-separated host names).
func ParseSNIList(v string) ([]string, error) {
	var names []string
	for _, n := range strings.Split(v, ",") {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		if net.ParseIP(n) != nil {
			return nil, fmt.Errorf("-sni %q: an IP address is never sent as SNI, use a host name", n)
		}
		names = append(names, n)
	}
	if v != "" && len(names) == 0 {
		return nil, fmt.Errorf("-sni %q: no host names", v)
	}
	return names, nil
}

func loadPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificates found", file)
	}
	return pool, nil
}

// ServerTLSOptions are the server's -tls-* flags.
type ServerTLSOptions struct {
	CertFile, KeyFile string
	ClientCA          string   // enables mutual TLS
	ListenAddr        string   // its host goes into a generated certificate
	MinVersion        uint16   // 0 = TLS 1.3
	MaxVersion        uint16   // 0 = TLS 1.3
	SNI               []string // if set, only handshakes naming one of these are accepted
	// ALPN protocols the server accepts, in preference order (nil: muxtun/1,
	// empty: no ALPN). A client offering ALPN with none of them is refused.
	ALPN []string
}

// ServerTLS builds the server config with default options (TLS 1.3, no SNI
// restriction). See ServerTLSWith.
func ServerTLS(certFile, keyFile, clientCA, listenAddr string) (cfg *tls.Config, pin string, generated bool, err error) {
	return ServerTLSWith(ServerTLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCA: clientCA, ListenAddr: listenAddr})
}

// ServerTLSWith builds the server config. Without CertFile/KeyFile a
// self-signed ECDSA certificate is generated (covering the SNI names);
// generated reports that, and pin is what clients pass to -tls-pin.
func ServerTLSWith(o ServerTLSOptions) (cfg *tls.Config, pin string, generated bool, err error) {
	certFile, keyFile, clientCA := o.CertFile, o.KeyFile, o.ClientCA
	var cert tls.Certificate
	switch {
	case certFile != "" && keyFile != "":
		if cert, err = tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return nil, "", false, err
		}
	case certFile != "" || keyFile != "":
		return nil, "", false, errors.New("-tls-cert and -tls-key must be given together")
	default:
		if cert, err = selfSigned(o.ListenAddr, o.SNI); err != nil {
			return nil, "", false, err
		}
		generated = true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, "", false, err
	}
	min, max := versionsOrDefault(o.MinVersion, o.MaxVersion)
	cfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   min,
		MaxVersion:   max,
		NextProtos:   nextProtos(o.ALPN),
	}
	if len(o.SNI) > 0 {
		allowed := make(map[string]bool, len(o.SNI))
		for _, n := range o.SNI {
			allowed[n] = true
		}
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !allowed[strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))] {
				if hello.ServerName == "" {
					return nil, errors.New("tls: client sent no SNI")
				}
				return nil, fmt.Errorf("tls: SNI %q not accepted", hello.ServerName)
			}
			return nil, nil // keep cfg
		}
	}
	if clientCA != "" {
		pool, err := loadPool(clientCA)
		if err != nil {
			return nil, "", false, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, PinOf(leaf), generated, nil
}

func versionsOrDefault(min, max uint16) (uint16, uint16) {
	if min == 0 {
		min = tls.VersionTLS13
	}
	if max == 0 {
		max = tls.VersionTLS13
	}
	return min, max
}

func selfSigned(listenAddr string, sni []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName(sni)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string{"localhost"}, sni...),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if h, err := os.Hostname(); err == nil {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	if host, _, err := net.SplitHostPort(listenAddr); err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// ClientTLSOptions are the client's -tls-* flags.
type ClientTLSOptions struct {
	CA, ServerName, Pin string
	Insecure            bool
	CertFile, KeyFile   string // client certificate for mutual TLS
	SNI                 string // name sent in the ClientHello (default: ServerName, else host of the address)
	MinVersion          uint16 // 0 = TLS 1.3
	MaxVersion          uint16 // 0 = TLS 1.3
	// ALPN protocols offered in the ClientHello, in preference order (nil:
	// muxtun/1, empty: no ALPN extension).
	ALPN []string
}

// ClientTLS builds the client config. Verification: -tls-pin alone trusts
// exactly that key (works with the server's self-signed certificate);
// -tls-ca and/or system roots verify the chain and name; both may be
// combined. -tls-insecure disables verification (testing only).
//
// -sni sets the name sent in the ClientHello. The certificate is checked
// against -tls-servername if given, else against the SNI, else against the
// host from -tcp; so -sni and -tls-servername may differ.
func ClientTLS(o ClientTLSOptions) (*tls.Config, error) {
	if o.SNI != "" && net.ParseIP(o.SNI) != nil {
		return nil, fmt.Errorf("-sni %q: an IP address is never sent as SNI, use a host name", o.SNI)
	}
	min, max := versionsOrDefault(o.MinVersion, o.MaxVersion)
	verifyName := o.ServerName
	sni := o.SNI
	if sni == "" {
		sni = o.ServerName
	}
	if verifyName == "" {
		verifyName = o.SNI
	}
	cfg := &tls.Config{
		MinVersion: min,
		MaxVersion: max,
		NextProtos: nextProtos(o.ALPN),
		ServerName: sni, // empty: crypto/tls uses the host from the address
	}
	// Chain verification by crypto/tls checks cfg.ServerName; when the
	// verified name differs from the SNI we verify the chain ourselves.
	splitName := sni != "" && verifyName != "" && !strings.EqualFold(sni, verifyName)
	if o.CA != "" {
		pool, err := loadPool(o.CA)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if o.CertFile != "" || o.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	switch {
	case o.Pin != "":
		want, err := parsePin(o.Pin)
		if err != nil {
			return nil, err
		}
		checkPin := func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls: no server certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if string(got[:]) != string(want) {
				return fmt.Errorf("tls: server key pin mismatch (got %x)", got)
			}
			return nil
		}
		switch {
		case o.CA == "":
			cfg.InsecureSkipVerify = true // the pin replaces chain verification
			cfg.VerifyConnection = checkPin
		case splitName:
			cfg.InsecureSkipVerify = true
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if err := verifyChain(cs, cfg.RootCAs, verifyName); err != nil {
					return err
				}
				return checkPin(cs)
			}
		default:
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				// chain was verified by crypto/tls already
				return checkPin(cs)
			}
		}
	case o.Insecure:
		cfg.InsecureSkipVerify = true
	case splitName:
		cfg.InsecureSkipVerify = true // replaced by verifyChain against verifyName
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return verifyChain(cs, cfg.RootCAs, verifyName)
		}
	}
	return cfg, nil
}

// verifyChain does what crypto/tls does, but for a name other than the SNI.
func verifyChain(cs tls.ConnectionState, roots *x509.CertPool, name string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("tls: no server certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots, // nil = system roots
		Intermediates: inter,
		DNSName:       name,
	})
	if err != nil {
		return fmt.Errorf("tls: verifying certificate for %q: %w", name, err)
	}
	return nil
}

func commonName(sni []string) string {
	if len(sni) > 0 {
		return sni[0]
	}
	return "muxserver"
}
