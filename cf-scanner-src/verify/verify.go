// Package verify implements the VerifyPlugin interface and plugins.
// Architecture: design.md ③ verify plugin - pluggable CF endpoint detection.
package verify

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"
)

// ───────────────────────── 全局复用对象 ─────────────────────────
var (
	tlsCfg = &tls.Config{
		InsecureSkipVerify: true,
	}
	defaultDialer = &net.Dialer{Timeout: 2 * time.Second}
)

// ───────────────────────── Plugin interface ─────────────────────────
// Plugin is the interface every verify plugin implements.
type Plugin interface {
	Name() string
	// Decide probes the target and returns a result.
	// If the probe established a TLS connection (PASS or UNKNOWN but TLS worked),
	// the *tls.Conn is returned for reuse by the hybrid state machine.
	// Caller must close the conn when done.
	Decide(ctx context.Context, ip, port string, cfg *Config) (*Result, *tls.Conn)
}

// Config holds verify configuration.
type Config struct {
	SNI         string        // TLS SNI (default: cloudflare.com)
	Host        string        // HTTP Host header (default: www.cloudflare.com)
	ConnTimeout time.Duration // TCP connect timeout (default: 2s)
	TlsTimeout  time.Duration // TLS handshake timeout (default: 5s)
	HTTPTimeout time.Duration // HTTP read timeout (default: 5s)
	ProxyAddr   string        // SOCKS5 proxy (default: "" = direct)
	Method      string        // HTTP method (GET/HEAD/OPTIONS)
}

// ResultStatus indicates the verification outcome.
type ResultStatus int

const (
	PASS    ResultStatus = iota // confirmed CF endpoint
	FAIL                        // confirmed not CF
	UNKNOWN                     // probe failed (timeout/conn_error)
)

func (s ResultStatus) String() string {
	switch s {
	case PASS:
		return "PASS"
	case FAIL:
		return "FAIL"
	case UNKNOWN:
		return "UNKNOWN"
	}
	return "?"
}

// Extras carries TLS fingerprint fields collected during the handshake.
type Extras struct {
	TLSVersion string
	Cipher     string
	ALPN       string
}

// Result is the output of a verify plugin Decide() call.
type Result struct {
	Status     ResultStatus
	Reason     string // cert_match / cf_ray / timeout / conn_error / noncf
	Confidence string // high (CF-RAY + cert), mid (only CF-RAY), low (only cert)
	CertMatch  bool
	CfRay      string
	ServerHdr  string
	StatusCode int
	Extras     Extras
}

// extractTLSFingerprint reads TLS version, cipher, ALPN from connection state.
func extractTLSFingerprint(cs tls.ConnectionState) Extras {
	e := Extras{}
	switch cs.Version {
	case tls.VersionTLS13:
		e.TLSVersion = "TLS1.3"
	case tls.VersionTLS12:
		e.TLSVersion = "TLS1.2"
	case tls.VersionTLS11:
		e.TLSVersion = "TLS1.1"
	default:
		e.TLSVersion = "TLS?"
	}
	e.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	if len(cs.NegotiatedProtocol) > 0 {
		e.ALPN = cs.NegotiatedProtocol
	} else {
		e.ALPN = "-"
	}
	return e
}

// checkCert looks for "cloudflare" in the leaf certificate's subject org or DNSNames.
func checkCert(state tls.ConnectionState) bool {
	if len(state.PeerCertificates) == 0 {
		return false
	}
	cert := state.PeerCertificates[0]
	containsCF := func(s string) bool {
		return strings.Contains(strings.ToLower(s), "cloudflare")
	}
	if containsCF(cert.Subject.CommonName) {
		return true
	}
	for _, name := range cert.DNSNames {
		if containsCF(name) {
			return true
		}
	}
	// Also check Subject Organization
	for _, org := range cert.Subject.Organization {
		if containsCF(org) {
			return true
		}
	}
	return false
}

// dialTarget connects to the target. Direct by default; SOCKS5 when ProxyAddr is set.
func dialTarget(ctx context.Context, addr string, cfg *Config) (net.Conn, error) {
	if cfg.ProxyAddr != "" {
		return socksDial(ctx, cfg.ProxyAddr, addr)
	}
	return defaultDialer.DialContext(ctx, "tcp", addr)
}

// ───────────────────────── Plugin registry ─────────────────────────
var plugins = make(map[string]Plugin)

// Register adds a plugin to the global registry. Called from init().
func Register(p Plugin) {
	plugins[p.Name()] = p
}

// GetPlugin returns a plugin by name, or nil if not found.
func GetPlugin(name string) Plugin {
	return plugins[name]
}

// AvailablePlugins returns the list of registered plugin names.
func AvailablePlugins() []string {
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	return names
}

// ───────────────────────── SOCKS5 CONNECT (ported from original) ─────────────────────────
func socksDial(ctx context.Context, proxyAddr, dstAddr string) (net.Conn, error) {
	proxy, err := defaultDialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = proxy.SetDeadline(dl)
	}
	// greeting: ver=5, nmethods=1, no-auth(0)
	if _, err := proxy.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		proxy.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxy, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		proxy.Close()
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(dstAddr)
	if err != nil {
		proxy.Close()
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if e != nil || len(ips) == 0 {
			proxy.Close()
			return nil, err
		}
		ip = ips[0]
	}
	ip4 := ip.To4()
	if ip4 == nil {
		proxy.Close()
		return nil, err
	}
	var p uint16
	// parse port
	pp, _ := net.LookupPort("tcp", portStr)
	if pp > 0 {
		p = uint16(pp)
	} else {
		// manually convert
		var pi int
		for _, c := range portStr {
			pi = pi*10 + int(c-'0')
		}
		p = uint16(pi)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(p >> 8), byte(p & 0xff)}
	if _, err := proxy.Write(req); err != nil {
		proxy.Close()
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(proxy, hdr); err != nil || hdr[1] != 0x00 {
		proxy.Close()
		return nil, err
	}
	skip := 0
	switch hdr[3] {
	case 0x01:
		skip = 6
	case 0x03:
		l := []byte{0}
		io.ReadFull(proxy, l)
		skip = int(l[0]) + 2
	case 0x04:
		skip = 18
	default:
		proxy.Close()
		return nil, err
	}
	tail := make([]byte, skip)
	io.ReadFull(proxy, tail)
	_ = proxy.SetDeadline(time.Time{})
	return proxy, nil
}
