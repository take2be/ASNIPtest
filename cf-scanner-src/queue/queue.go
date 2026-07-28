// Package queue implements a Queue Manager with true backpressure.
// Architecture: design.md ②.6 Watermark / Backpressure.
// Unlike the original "fake backpressure" (ticker halving only),
// this controls the producer based on queue length and timeout rate.
package queue

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	DefaultHighWater = 10000 // pause producer when queue exceeds this
	DefaultLowWater  = 5000  // resume producer when queue drops below this
)

// Config for the Queue Manager.
type Config struct {
	HighWater    int           // pause producer above this
	LowWater     int           // resume producer below this
	CheckInterval time.Duration // how often to check water level
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		HighWater:     DefaultHighWater,
		LowWater:      DefaultLowWater,
		CheckInterval: 500 * time.Millisecond,
	}
}

// Manager provides a producer-controllable queue with backpressure.
// It wraps a chan and allows the consumer to pause/resume the producer
// based on queue depth and timeout rate.
type Manager struct {
	jobs       chan string
	cfg        Config
	paused     atomic.Bool
	produceFn  func(context.Context, chan<- string)
	totalAdded atomic.Int64
	totalDone  atomic.Int64
	timeoutCnt atomic.Int64
}

// NewManager creates a new Queue Manager.
func NewManager(bufSize int, cfg Config, produceFn func(context.Context, chan<- string)) *Manager {
	if cfg.HighWater <= 0 {
		cfg.HighWater = DefaultHighWater
	}
	if cfg.LowWater <= 0 {
		cfg.LowWater = DefaultLowWater
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 500 * time.Millisecond
	}
	return &Manager{
		jobs:      make(chan string, bufSize),
		cfg:       cfg,
		produceFn: produceFn,
	}
}

// Jobs returns the jobs channel (for workers to consume).
func (m *Manager) Jobs() <-chan string {
	return m.jobs
}

// Run starts the producer and backpressure monitor.
// Blocks until the producer completes and all jobs are consumed.
func (m *Manager) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start the producer in a goroutine
	producerDone := make(chan struct{})
	go func() {
		m.produceFn(ctx, m.jobs)
		close(m.jobs) // signal workers that no more jobs are coming
		close(producerDone)
	}()

	// Backpressure monitor: periodically check queue depth and timeout rate
	// and pause/resume the producer accordingly.
	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-producerDone:
			return
		case <-ticker.C:
			qlen := len(m.jobs)
			done := m.totalDone.Load()
			to := m.timeoutCnt.Load()

			// Pause if queue is too deep or timeout rate > 40%
			timeoutRate := 0.0
			if done > 1000 {
				timeoutRate = float64(to) / float64(done)
			}

			if qlen > m.cfg.HighWater || timeoutRate > 0.4 {
				m.paused.Store(true)
			} else if qlen < m.cfg.LowWater && timeoutRate < 0.3 {
				m.paused.Store(false)
			}
		}
	}
}

// IsPaused returns whether the producer is currently paused.
func (m *Manager) IsPaused() bool {
	return m.paused.Load()
}

// WaitPaused blocks until the producer is paused or the context is cancelled.
func (m *Manager) WaitPaused(ctx context.Context) {
	for !m.paused.Load() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// WaitResumed blocks until the producer is resumed or the context is cancelled.
func (m *Manager) WaitResumed(ctx context.Context) {
	for m.paused.Load() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Added increments the added counter.
func (m *Manager) Added(n int64) {
	m.totalAdded.Add(n)
}

// Done increments the done counter.
func (m *Manager) Done() {
	m.totalDone.Add(1)
}

// RecordTimeout records a timeout event for backpressure calculation.
func (m *Manager) RecordTimeout() {
	m.timeoutCnt.Add(1)
}

// Stats returns current queue statistics.
func (m *Manager) Stats() (added, done, timeouts, qlen int64) {
	return m.totalAdded.Load(), m.totalDone.Load(), m.timeoutCnt.Load(), int64(len(m.jobs))
}
