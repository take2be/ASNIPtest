// Package output handles result writing (CSV/JSON).
// Architecture: design.md ⑥ output (initially for verify results,
// will be extended when ④⑤⑥ are added).
package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Writer writes results to a file with buffered I/O.
type Writer struct {
	f      *os.File
	bw     *bufio.Writer
	format string
	fields []string
	count  int
}

// NewWriter creates a new output writer.
// format: "csv" or "json"
// fields: comma-separated field list
func NewWriter(path string, format string, fields string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create output: %w", err)
	}

	w := &Writer{
		f:      f,
		bw:     bufio.NewWriterSize(f, 2*1024*1024), // 2MB buffer
		format: format,
		fields: strings.Split(fields, ","),
	}

	// Write CSV header
	if format == "csv" {
		w.bw.WriteString(strings.Join(w.fields, ",") + "\n")
	}

	return w, nil
}

// Record writes a single result record.
func (w *Writer) Record(ip, port, colo, cfray, status, conf, tlsVer, cipher, alpn string) error {
	var line string
	if w.format == "json" {
		m := map[string]string{
			"ip":      ip,
			"port":    port,
			"colo":    colo,
			"cfray":   cfray,
			"status":  status,
			"conf":    conf,
			"tls":     tlsVer,
			"cipher":  cipher,
			"alpn":    alpn,
		}
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		line = string(b)
	} else {
		// CSV: only output requested fields
		vals := make([]string, len(w.fields))
		for i, f := range w.fields {
			switch f {
			case "ip":
				vals[i] = ip
			case "port":
				vals[i] = port
			case "colo":
				vals[i] = colo
			case "cfray":
				vals[i] = cfray
			case "status":
				vals[i] = status
			case "conf":
				vals[i] = conf
			case "tls":
				vals[i] = tlsVer
			case "cipher":
				vals[i] = cipher
			case "alpn":
				vals[i] = alpn
			default:
				vals[i] = ""
			}
		}
		line = strings.Join(vals, ",")
	}

	_, err := w.bw.WriteString(line + "\n")
	if err != nil {
		return err
	}
	w.count++
	return nil
}

// Flush flushes the buffer to disk.
func (w *Writer) Flush() error {
	return w.bw.Flush()
}

// Close flushes and closes the file.
func (w *Writer) Close() error {
	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// Count returns the number of records written.
func (w *Writer) Count() int {
	return w.count
}
