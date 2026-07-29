package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cf-scanner/output"
	"cf-scanner/queue"
	"cf-scanner/resume"
	"cf-scanner/stats"
	"cf-scanner/verify"
)

// ───────────────────────── CLI flags ─────────────────────────
var (
	inputFile    = flag.String("i", "", "输入文件，每行 IP 或 IP:port")
	outputFile   = flag.String("o", "", "输出文件（默认 cf_hits_<ts>.txt）")
	stateFile    = flag.String("state", "scanner.state", "断点续跑文件")
	concurrency  = flag.Int("c", 5000, "并发 worker 数（默认5000，上限20000）")
	connectTO    = flag.Duration("connect-timeout", 2*time.Second, "TCP 连接超时")
	timeout      = flag.Duration("timeout", 5*time.Second, "TLS/HTTP 总超时")
	sni          = flag.String("sni", "cloudflare.com", "TLS SNI")
	host         = flag.String("host", "www.cloudflare.com", "HTTP Host 头")
	proxyAddr    = flag.String("proxy", "", "SOCKS5 代理地址（默认空=直连；仅小规模<500并发用）")
	method       = flag.String("method", "GET", "HTTP 方法（GET/HEAD/OPTIONS，默认 GET）")
	formatOut    = flag.String("format", "csv", "输出格式 csv|json")
	fieldsOut    = flag.String("fields", "ip,port,colo,cfray,status,conf", "输出字段")
	rateLimit    = flag.Int("rate", 0, "令牌桶限速（每秒最大握手数，0=不限）")
	backpressure = flag.Bool("backpressure", false, "动态背压：队列积压或超时率>40%自动降速")
	logPath      = flag.String("log", "scanner.jsonl", "结构化日志 JSONL 路径")
	verifyMode   = flag.String("verify-mode", "hybrid", "验证插件 (tls/http/hybrid/api)")
	planDir      = flag.String("plan-dir", ".", "scan_plan.json 及 block 产物目录")
)

const maxConc = 20000

func main() {
	flag.Parse()

	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: cf-scanner -i ips.txt [-o hits.txt] [-c 5000]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Clamp concurrency
	if *concurrency < 1 {
		*concurrency = 1
	}
	if *concurrency > maxConc {
		*concurrency = maxConc
	}

	// Default output filename
	if *outputFile == "" {
		*outputFile = fmt.Sprintf("cf_hits_%s.txt", time.Now().Format("20060102_150405"))
	}

	// Plugin selection
	plugin := verify.GetPlugin(*verifyMode)
	if plugin == nil {
		fmt.Fprintf(os.Stderr, "未知验证插件: %s (可用: %s)\n", *verifyMode, strings.Join(verify.AvailablePlugins(), ", "))
		os.Exit(1)
	}
	fmt.Printf("Plugin: %s | SNI=%s Host=%s | conc=%d | mode=%s\n",
		plugin.Name(), *sni, *host, *concurrency, *verifyMode)

	egress := "direct"
	if *proxyAddr != "" {
		egress = "SOCKS5 " + *proxyAddr
	}
	fmt.Printf("Egress: %s\n", egress)
	fmt.Printf("Output: %s\n", *outputFile)

	// Verify config
	vcfg := &verify.Config{
		SNI:         *sni,
		Host:        *host,
		ConnTimeout: *connectTO,
		TlsTimeout:  *timeout,
		HTTPTimeout: *timeout,
		ProxyAddr:   *proxyAddr,
		Method:      *method,
	}

	// ── Resume: load checkpoint ──
	cp, err := resume.LoadCheckpoint(*stateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取断点文件 %s: %v\n", *stateFile, err)
		os.Exit(1)
	}
	skipCount := len(cp.Completed)
	if skipCount > 0 {
		fmt.Printf("Resume: %d already verified, skipping\n", skipCount)
	}

	// ── Count total lines ──
	total, err := countLines(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *inputFile, err)
		os.Exit(1)
	}
	fmt.Printf("Total IPs: %d\n", total)

	// ── Output writer ──
	w, err := output.NewWriter(*outputFile, *formatOut, *fieldsOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(1)
	}
	defer w.Close()

	// ── Log file ──
	var logF *os.File
	if *logPath != "" {
		logF, _ = os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if logF != nil {
			defer logF.Close()
		}
	}

	// ── Stats collector ──
	statsCol := &stats.Collector{}

	// ── Queue Manager with backpressure ──
	qm := queue.NewManager(*concurrency*2, queue.DefaultConfig(),
		func(ctx context.Context, jobs chan<- string) {
			produceLines(ctx, *inputFile, skipCount, jobs)
		})
	if !*backpressure {
		// Disable backpressure by using very high water marks
		qm = queue.NewManager(*concurrency*2,
			queue.Config{HighWater: 1 << 30, LowWater: 1 << 29, CheckInterval: 10 * time.Second},
			func(ctx context.Context, jobs chan<- string) {
				produceLines(ctx, *inputFile, skipCount, jobs)
			})
	}

	// ── Counter for state save ──
	var scannedTotal int64
	var completed sync.Map // key = "ip:port", value = true — for checkpoint file

	// ── Checkpoint timer goroutine (every 30s) ──
	checkpointTicker := time.NewTicker(30 * time.Second)
	defer checkpointTicker.Stop()
	checkpointDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-checkpointDone:
				return
			case <-checkpointTicker.C:
				// 30s checkpoint: write completed set to state file
				entries := make([]string, 0, 500)
				completed.Range(func(key, value any) bool {
					entries = append(entries, key.(string)+" 1")
					return true
				})
				if len(entries) > 0 {
					resume.SaveCheckpoint(*stateFile, entries)
				}
			}
		}
	}() // tracks total scanned (including resumed)

	// ── Token bucket ──
	var tb *time.Ticker
	if *rateLimit > 0 {
		tb = time.NewTicker(time.Second / time.Duration(*rateLimit))
	}

	// ── Wait group for workers ──
	var workerWG sync.WaitGroup

	// ── Start workers ──
	for i := 0; i < *concurrency; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for target := range qm.Jobs() {
				// Token bucket rate limiting
				if tb != nil {
					<-tb.C
				}

				ip, port, err := netSplitHostPort(target)
				if err != nil {
					qm.Done()
					continue
				}

				result, _ := plugin.Decide(context.Background(), ip, port, vcfg)
				qm.Done()

				// Record stats
				extras := result.Extras
				statsCol.Record(result.Status.String(), result.Reason, result.Confidence,
					extras.TLSVersion, extras.ALPN)

				// Record timeout for backpressure
				if result.Status == verify.UNKNOWN && result.Reason == "timeout" {
					qm.RecordTimeout()
				}

				// Write result
				if result.Status == verify.PASS {
					colo := extractColo(result.CfRay)
					cfray := result.CfRay
					if len(cfray) > 30 {
						cfray = cfray[:30]
					}
					w.Record(ip, port, colo, cfray,
						fmt.Sprintf("%d", result.StatusCode),
						result.Confidence, extras.TLSVersion, extras.Cipher, extras.ALPN)
				}

				atomic.AddInt64(&scannedTotal, 1)
				completed.Store(ip+":"+port, true)
				n := atomic.LoadInt64(&scannedTotal)

				// Periodic checkpoint (every 500)
				if n%500 == 0 {
					entries := make([]string, 0, 500)
					completed.Range(func(key, value any) bool {
						entries = append(entries, key.(string)+" 1")
						return true
					})
					if len(entries) > 0 {
						resume.SaveCheckpoint(*stateFile, entries)
					}
				}
			}
		}()
	}

	// ── Progress reporter ──
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				n := atomic.LoadInt64(&scannedTotal)
				elapsed := time.Since(start).Seconds()
				var rate int64
				if elapsed > 0 {
					rate = int64(float64(n) / elapsed)
				}

				// Write log entry
				if logF != nil {
					fmt.Fprintf(logF,
						`{"ts":"%s","stage":"verify","scanned":%d,"total":%d,"rate":%d}`+"\n",
						time.Now().Format(time.RFC3339), int64(skipCount)+n, total, rate)
				}

				fmt.Printf("\rScanned %d/%d (%.1f%%) | %d/s | hits=%d",
					int64(skipCount)+n, total,
					float64(int64(skipCount)+n)/float64(total)*100,
					rate, w.Count())
			}
		}
	}()

	// ── Signal handling ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted. Saving checkpoint...")
		entries := make([]string, 0, 500)
		completed.Range(func(key, value any) bool {
			entries = append(entries, key.(string)+" 1")
			return true
		})
		if len(entries) > 0 {
			resume.SaveCheckpoint(*stateFile, entries)
		}
		fmt.Println("Checkpoint saved. Exiting.")
		os.Exit(1)
	}()

	// ── Start ──
	workerWG.Wait()

	// Flush output
	w.Flush()
	close(done)
	close(checkpointDone)

	// Mark complete — clean up checkpoint state file
	os.Remove(*stateFile)

	fmt.Printf("\n\nDone! %d verified | %d hits\n", total, w.Count())

	// Final stats report
	fmt.Println("\n─── TLS Fingerprint Statistics ───")
	fmt.Print(statsCol.Report())

	// Clean up state file on normal completion
	os.Remove(*stateFile)
}

// ───────────────────────── Helpers ─────────────────────────

func countLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	// If last line has no newline, count it
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n, nil
}

func produceLines(ctx context.Context, path string, skip int, out chan<- string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	// Read all lines, skip the first `skip` lines
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i < skip {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case out <- line:
		}
	}
}

func netSplitHostPort(target string) (string, string, error) {
	idx := strings.LastIndex(target, ":")
	if idx < 0 {
		return target, "443", nil
	}
	return target[:idx], target[idx+1:], nil
}

func extractColo(cfray string) string {
	if cfray == "" {
		return ""
	}
	parts := strings.Split(cfray, "-")
	return parts[len(parts)-1]
}

func init() {
	// Ensure all verify plugins are registered
	_ = verify.GetPlugin("hybrid")
}
