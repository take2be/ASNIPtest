package verify

import (
	"context"
	"crypto/tls"
	"time"
)

const pluginNameTLS = "tls"

func init() {
	Register(&TLSPlugin{})
}

// TLSPlugin implements TLS handshake + certificate check.
type TLSPlugin struct{}

func (p *TLSPlugin) Name() string { return pluginNameTLS }

func (p *TLSPlugin) Decide(ctx context.Context, ip, port string, cfg *Config) (*Result, *tls.Conn) {
	target := netJoinHostPort(ip, port)
	raw, err := dialTarget(ctx, target, cfg)
	if err != nil {
		return &Result{Status: UNKNOWN, Reason: "conn_error"}, nil
	}

	// TLS handshake with cloned config and per-connection SNI
	tlsCfgClone := tlsCfg.Clone()
	tlsCfgClone.ServerName = cfg.SNI

	tlsConn := tls.Client(raw, tlsCfgClone)
	_ = tlsConn.SetDeadline(time.Now().Add(cfg.TlsTimeout))

	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return &Result{Status: UNKNOWN, Reason: "timeout"}, nil
	}

	// Extract TLS fingerprint (zero-cost, handshake already done)
	extras := extractTLSFingerprint(tlsConn.ConnectionState())

	// Certificate check
	certMatch := checkCert(tlsConn.ConnectionState())

	if !certMatch {
		// TLS connected but cert doesn't indicate CF
		tlsConn.Close()
		return &Result{
			Status:     FAIL,
			Reason:     "noncf",
			Confidence: "low",
			CertMatch:  false,
			Extras:     extras,
		}, nil
	}

	// Cert matches → PASS with low confidence (HTTP may upgrade to high/mid)
	return &Result{
		Status:     PASS,
		Reason:     "cert_match",
		Confidence: "low",
		CertMatch:  true,
		Extras:     extras,
	}, tlsConn
}

func netJoinHostPort(ip, port string) string {
	return ip + ":" + port
}
