// Package resume implements IP:Port-level checkpoint and scan plan management.
// Architecture: design.md ②.10 Resume mechanism (IP:Port level, not block level).
package resume

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Plan represents a scan plan (scan_plan.json).
type Plan struct {
	ResumeIdentity ResumeIdentity `json:"resume_identity"`
	RuntimeInfo    RuntimeInfo    `json:"runtime_info"`
}

// ResumeIdentity contains fields that force re-scan if changed.
type ResumeIdentity struct {
	ASN          string         `json:"asn"`
	CIDRSource   string         `json:"cidr_source"`
	PortsHash    string         `json:"ports_hash"`
	VerifyMethod string         `json:"verify_method"`
	ScanSchema   int            `json:"scan_schema"`
	VerifySchema int            `json:"verify_schema"`
	ResumeSchema int            `json:"resume_schema"`
	Blocks       []BlockMeta   `json:"blocks"`
}

// BlockMeta describes one block in the plan.
type BlockMeta struct {
	Index          int    `json:"index"`
	CIDRRange      Range  `json:"cidr_range"`
	BlockInputHash string `json:"block_input_hash"`
	CIDRsFile      string `json:"cidrs_file"`
}

// Range describes a range of indices.
type Range struct {
	StartIdx int `json:"start_idx"`
	EndIdx   int `json:"end_idx"`
}

// RuntimeInfo contains environment metadata (for info only, not resume logic).
type RuntimeInfo struct {
	CreatedAt     string `json:"created_at"`
	ToolVersion   string `json:"tool_version"`
	VerifyWorkers int    `json:"verify_workers"`
	Hostname      string `json:"hostname"`
}

// Checkpoint tracks completed tasks at IP:Port level.
// It reads .cf.tmp to build the set of already-verified targets.
type Checkpoint struct {
	Completed map[string]bool // key = "ip:port"
}

// LoadCheckpoint reads a .cf.tmp file and returns the set of verified targets.
// Each line format: "ip:port 0" or "ip:port 1"
func LoadCheckpoint(path string) (*Checkpoint, error) {
	cp := &Checkpoint{Completed: make(map[string]bool)}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cp, nil // no checkpoint yet
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			cp.Completed[fields[0]] = true
		}
	}
	return cp, scanner.Err()
}

// SaveCheckpoint atomically writes the checkpoint file (.cf.tmp.new → rename).
func SaveCheckpoint(path string, entries []string) error {
	tmpPath := path + ".new"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range entries {
		fmt.Fprintln(w, e)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.Close()
	return os.Rename(tmpPath, path)
}

// FinalizeCheckpoint renames .cf.tmp to .cf.txt for a completed block.
func FinalizeCheckpoint(tmpPath, finalPath string) error {
	return os.Rename(tmpPath, finalPath)
}

// NeedsRescan determines what needs to be done for a block:
//   -1 = block fully completed (skip)
//    0 = have .json but need verify
//    1 = need full scan + verify
func NeedsRescan(blockDir string, block BlockMeta) int {
	cfPath := filepath.Join(blockDir, fmt.Sprintf("block_%03d.cf.txt", block.Index))
	jsonPath := filepath.Join(blockDir, fmt.Sprintf("block_%03d.json", block.Index))

	if _, err := os.Stat(cfPath); err == nil {
		return -1 // completed
	}
	if _, err := os.Stat(jsonPath); err == nil {
		return 0 // have masscan results, need verify
	}
	return 1 // need full scan
}

// PortsHash computes a deterministic hash of a port list.
// Ports are sorted and deduplicated first.
func PortsHash(ports []int) string {
	sorted := make([]int, len(ports))
	copy(sorted, ports)
	sort.Ints(sorted)

	// Deduplicate
	uniq := sorted[:0]
	for i, p := range sorted {
		if i == 0 || p != sorted[i-1] {
			uniq = append(uniq, p)
		}
	}

	canonical := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(uniq)), ","), "[]")
	h := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", h[:8])
}
