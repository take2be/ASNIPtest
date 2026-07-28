// Package pipeline defines the Stage interface and Task type
// for chaining ②→③→[④]→[⑤]→⑥ in the future.
package pipeline

import "context"

// ResultStatus for VerifyResult.
type ResultStatus int

const (
	PASS   ResultStatus = iota // confirmed CF endpoint
	FAIL                       // confirmed not CF
	UNKNOWN                    // probe failed (timeout/conn_error)
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

// Extras carries TLS fingerprint fields collected during the same handshake.
type Extras struct {
	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
}

// VerifyResult is the output of stage ③.
type VerifyResult struct {
	Status     ResultStatus `json:"status"`
	Reason     string       `json:"reason"`     // cert_match / cf_ray / timeout / conn_error / noncf
	Confidence string       `json:"confidence"` // high / mid / low
	CertMatch  bool         `json:"cert_match"`
	CfRay      string       `json:"cf_ray,omitempty"`
	ServerHdr  string       `json:"server_hdr,omitempty"`
	StatusCode int          `json:"status_code"`
	Extras     Extras       `json:"extras,omitempty"`
}

// Task is the unit that flows through the pipeline.
// Stage ② sets Target; ③ sets VerifyResult;
// ④/⑤/⑥ will add their own fields in the future.
type Task struct {
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Target string `json:"target"` // "ip:port"

	// Block index for resume / tracking
	BlockIdx int `json:"block_idx,omitempty"`

	// Stage ③ output
	VerifyResult *VerifyResult `json:"verify_result,omitempty"`

	// Reserved for future stages
	// Stage ④: enrich result
	// Stage ⑤: speedtest result
}

// Stage is the interface every pipeline stage implements.
// Run reads tasks from input, processes them, and sends results to output.
// The stage must close output when it's done.
// Returning an error causes the pipeline to abort.
type Stage interface {
	Name() string
	Run(ctx context.Context, input <-chan *Task, output chan<- *Task) error
}

// Pipeline chains stages together.
type Pipeline struct {
	Stages []Stage
}

// Run executes the pipeline. Each stage's output feeds the next stage's input.
// The first stage receives tasks from source.
func (p *Pipeline) Run(ctx context.Context, source <-chan *Task) error {
	if len(p.Stages) == 0 {
		return nil
	}

	var prev <-chan *Task = source

	for _, stage := range p.Stages {
		next := make(chan *Task, 10000)
		go func(s Stage, in <-chan *Task, out chan<- *Task) {
			if err := s.Run(ctx, in, out); err != nil {
				return
			}
		}(stage, prev, next)
		prev = next
	}

	// Drain final output
	for range prev {
	}
	return nil
}
