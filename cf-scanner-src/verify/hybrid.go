package verify

import (
	"context"
	"crypto/tls"
	"strings"
)

const pluginNameHybrid = "hybrid"

func init() {
	Register(&HybridPlugin{})
}

// HybridPlugin implements the hybrid state machine from design.md ③.3:
//
//   TLS decide()
//     ├─ PASS → return PASS (confidence=low/high via HTTP upgrade)
//     ├─ FAIL → return FAIL (non-CF, HTTP never overrides TLS FAIL)
//     └─ UNKNOWN → reuse the same socket (NO second TCP/TLS!) → HTTP decide()
//                     ├─ CF-RAY / Server:cloudflare → PASS (confidence=mid)
//                     └─ no CF indicators → FAIL
//
// Design rule A: TLS PASS/FAIL is final; HTTP only runs on UNKNOWN.
// Design rule B: HTTP NEVER re-handshakes TLS; it reuses the conn from TLS step.
type HybridPlugin struct{}

func (p *HybridPlugin) Name() string { return pluginNameHybrid }

func (p *HybridPlugin) Decide(ctx context.Context, ip, port string, cfg *Config) (*Result, *tls.Conn) {
	tlsRes, tlsConn := GetPlugin("tls").Decide(ctx, ip, port, cfg)

	switch tlsRes.Status {
	case PASS:
		// Cert matches CF → PASS. Try to upgrade confidence with HTTP on same conn.
		if tlsConn != nil {
			httpRes := GetPlugin("http").(*HTTPPlugin).Check(ctx, tlsConn, cfg)
			tlsConn.Close()
			if httpRes.Status == PASS {
				// Upgrade confidence
				conf := "low"
				if httpRes.CfRay != "" && strings.Contains(strings.ToLower(httpRes.ServerHdr), "cloudflare") {
					conf = "high"
				} else if httpRes.CfRay != "" {
					conf = "mid"
				}
				return &Result{
					Status:     PASS,
					Reason:     "cert_match+cf_ray",
					Confidence: conf,
					CertMatch:  true,
					CfRay:      httpRes.CfRay,
					ServerHdr:  httpRes.ServerHdr,
					StatusCode: httpRes.StatusCode,
					Extras:     tlsRes.Extras,
				}, nil
			}
		}
		// HTTP didn't confirm, but cert already says CF
		if tlsConn != nil {
			tlsConn.Close()
		}
		return tlsRes, nil

	case FAIL:
		// TLS connected but cert not CF → non-CF, final.
		if tlsConn != nil {
			tlsConn.Close()
		}
		return tlsRes, nil

	case UNKNOWN:
		// TLS failed (timeout/conn_error). If we still have a conn, try HTTP as last resort.
		if tlsConn != nil {
			httpRes := GetPlugin("http").(*HTTPPlugin).Check(ctx, tlsConn, cfg)
			tlsConn.Close()
			if httpRes.Status == PASS {
				return &Result{
					Status:     PASS,
					Reason:     "cf_ray",
					Confidence: "mid",
					CfRay:      httpRes.CfRay,
					ServerHdr:  httpRes.ServerHdr,
					StatusCode: httpRes.StatusCode,
				}, nil
			}
		}
		return &Result{Status: UNKNOWN, Reason: tlsRes.Reason}, nil

	default:
		if tlsConn != nil {
			tlsConn.Close()
		}
		return tlsRes, nil
	}
}
