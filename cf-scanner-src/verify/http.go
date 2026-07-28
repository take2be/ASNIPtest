package verify

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const pluginNameHTTP = "http"

func init() {
	Register(&HTTPPlugin{})
}

// HTTPPlugin sends an HTTP request on an existing TLS connection
// and checks the response for CF indicators (CF-RAY header, Server header).
// This plugin REUSES the TLS connection from the TLS plugin (no second handshake).
type HTTPPlugin struct{}

func (p *HTTPPlugin) Name() string { return pluginNameHTTP }

// Decide sends an HTTP request on the provided TLS connection.
// The conn must already be established (TLS handshake done).
func (p *HTTPPlugin) Decide(ctx context.Context, ip, port string, cfg *Config) (*Result, *tls.Conn) {
	return nil, nil // HTTPPlugin is never called standalone; it's used via HybridPlugin
}

// Check reuses an existing TLS connection to send an HTTP request and check headers.
// The caller is responsible for closing the conn.
func (p *HTTPPlugin) Check(ctx context.Context, tlsConn *tls.Conn, cfg *Config) *Result {
	_ = tlsConn.SetDeadline(time.Now().Add(cfg.HTTPTimeout))

	reqLine := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		cfg.Method, cfg.Host)

	if _, err := tlsConn.Write([]byte(reqLine)); err != nil {
		return &Result{Status: UNKNOWN, Reason: "http_write_error"}
	}

	// Lightweight header parsing: read until \r\n\r\n
	hdrBuf := make([]byte, 0, 2048)
	tmp := make([]byte, 256)
	statusCode := 0
	cfray := ""
	serverHdr := ""
	headerDone := false

	for !headerDone {
		_ = tlsConn.SetDeadline(time.Now().Add(cfg.HTTPTimeout))
		n, e := tlsConn.Read(tmp)
		if n > 0 {
			hdrBuf = append(hdrBuf, tmp[:n]...)
			if bytes.Contains(hdrBuf, []byte("\r\n\r\n")) {
				headerDone = true
			}
		}
		if e != nil {
			break
		}
		if len(hdrBuf) > 16384 {
			break
		}
	}

	// Parse status line
	headerText := string(hdrBuf)
	if idx := strings.Index(headerText, "\r\n"); idx > 0 {
		firstLine := headerText[:idx]
		if strings.HasPrefix(firstLine, "HTTP/") {
			parts := strings.SplitN(firstLine, " ", 3)
			if len(parts) >= 2 {
				statusCode, _ = strconv.Atoi(parts[1])
			}
		}
	}

	// Parse headers
	for _, line := range strings.Split(headerText, "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "cf-ray:") {
			cfray = strings.TrimSpace(line[len("cf-ray:"):])
		} else if strings.HasPrefix(lower, "server:") {
			serverHdr = strings.TrimSpace(line[len("server:"):])
		}
	}

	// Determine result based on headers
	if cfray != "" || strings.Contains(strings.ToLower(serverHdr), "cloudflare") {
		conf := "mid"
		if cfray != "" && strings.Contains(strings.ToLower(serverHdr), "cloudflare") {
			conf = "high"
		}
		return &Result{
			Status:     PASS,
			Reason:     "cf_ray",
			Confidence: conf,
			CertMatch:  false,
			CfRay:      cfray,
			ServerHdr:  serverHdr,
			StatusCode: statusCode,
		}
	}

	return &Result{Status: FAIL, Reason: "noncf"}
}
