// Package stats collects TLS fingerprint statistics during verification.
// Architecture: design.md ③.9 Statistics + AI review item 9.
// These stats are zero-cost because the handshake already completed.
package stats

import (
	"fmt"
	"sync/atomic"
	"sync"
)

// Collector aggregates TLS fingerprint statistics.
type Collector struct {
	total     atomic.Int64
	pass      atomic.Int64
	fail      atomic.Int64
	unknown   atomic.Int64
	tls13     atomic.Int64
	tls12     atomic.Int64
	tlsOther  atomic.Int64
	h2        atomic.Int64
	http11    atomic.Int64
	alpnOther atomic.Int64
	byReason  sync.Map // map[string]int64
	byConf    sync.Map // map[string]int64
}

// Record adds a verification result to the stats.
func (c *Collector) Record(status string, reason, confidence, tlsVer, alpn string) {
	c.total.Add(1)
	switch status {
	case "PASS":
		c.pass.Add(1)
	case "FAIL":
		c.fail.Add(1)
	default:
		c.unknown.Add(1)
	}

	// Reason distribution
	if v, ok := c.byReason.Load(reason); ok {
		c.byReason.Store(reason, v.(int64)+1)
	} else {
		c.byReason.Store(reason, int64(1))
	}

	// Confidence distribution
	if v, ok := c.byConf.Load(confidence); ok {
		c.byConf.Store(confidence, v.(int64)+1)
	} else {
		c.byConf.Store(confidence, int64(1))
	}

	// TLS version
	switch tlsVer {
	case "TLS1.3":
		c.tls13.Add(1)
	case "TLS1.2":
		c.tls12.Add(1)
	default:
		if tlsVer != "" {
			c.tlsOther.Add(1)
		}
	}

	// ALPN
	switch alpn {
	case "h2":
		c.h2.Add(1)
	case "http/1.1", "-":
		c.http11.Add(1)
	default:
		if alpn != "" {
			c.alpnOther.Add(1)
		}
	}
}

// Report returns a formatted summary string.
func (c *Collector) Report() string {
	total := c.total.Load()
	if total == 0 {
		return "no data"
	}
	pass := c.pass.Load()
	fail := c.fail.Load()
	unknown := c.unknown.Load()

	s := fmt.Sprintf("Total: %d | PASS: %d (%.1f%%) | FAIL: %d (%.1f%%) | UNKNOWN: %d (%.1f%%)\n",
		total, pass, pct(pass, total), fail, pct(fail, total), unknown, pct(unknown, total))

	// TLS version distribution
	t13 := c.tls13.Load()
	t12 := c.tls12.Load()
	to := c.tlsOther.Load()
	withTLS := t13 + t12 + to
	if withTLS > 0 {
		s += fmt.Sprintf("TLS: 1.3=%d(%.1f%%) 1.2=%d(%.1f%%) other=%d(%.1f%%)\n",
			t13, pct(t13, withTLS), t12, pct(t12, withTLS), to, pct(to, withTLS))
	}

	// ALPN distribution
	h2 := c.h2.Load()
	h11 := c.http11.Load()
	ao := c.alpnOther.Load()
	withALPN := h2 + h11 + ao
	if withALPN > 0 {
		s += fmt.Sprintf("ALPN: h2=%d(%.1f%%) http/1.1=%d(%.1f%%) other=%d(%.1f%%)\n",
			h2, pct(h2, withALPN), h11, pct(h11, withALPN), ao, pct(ao, withALPN))
	}

	// Reason distribution
	s += "\nReason breakdown:\n"
	c.byReason.Range(func(key, value any) bool {
		s += fmt.Sprintf("  %s: %d\n", key, value)
		return true
	})

	s += "\nConfidence breakdown:\n"
	c.byConf.Range(func(key, value any) bool {
		s += fmt.Sprintf("  %s: %d\n", key, value)
		return true
	})

	return s
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
