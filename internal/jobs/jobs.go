// Package jobs runs Dropr's periodic maintenance (PLAN.md §6: every 5
// minutes): expired sessions, expired links with their blobs, incomplete
// uploads older than 24 h, expired download tokens and passkey ceremonies,
// and orphaned blob directories (FileTasks).
//
// Log retention (7 days, PLAN.md §7) is the job of the log collector: Dropr
// writes structured logs to stdout and keeps no log files.
package jobs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// DefaultInterval is the cleanup cadence.
const DefaultInterval = 5 * time.Minute

// Task is one maintenance step. It returns how many items it removed.
type Task struct {
	Name string
	Run  func(ctx context.Context) (int64, error)
}

// Runner executes tasks on a ticker.
type Runner struct {
	interval time.Duration
	log      *slog.Logger

	mu    sync.Mutex
	tasks []Task
}

// NewRunner returns a runner; interval <= 0 selects DefaultInterval.
func NewRunner(interval time.Duration, log *slog.Logger) *Runner {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if log == nil {
		log = slog.Default()
	}
	return &Runner{interval: interval, log: log.With("component", "jobs")}
}

// Add registers a task.
func (r *Runner) Add(t Task) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tasks = append(r.tasks, t)
}

// RunOnce executes every task once, continuing past failures, and returns
// the joined errors.
func (r *Runner) RunOnce(ctx context.Context) error {
	r.mu.Lock()
	tasks := append([]Task(nil), r.tasks...)
	r.mu.Unlock()
	var errs []error
	for _, t := range tasks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := t.Run(ctx)
		if err != nil {
			r.log.ErrorContext(ctx, "task failed", "task", t.Name, "err", err)
			errs = append(errs, err)
			continue
		}
		if n > 0 {
			r.log.InfoContext(ctx, "task done", "task", t.Name, "removed", n)
		}
	}
	return errors.Join(errs...)
}

// Run executes the tasks immediately and then every interval until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		_ = r.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
