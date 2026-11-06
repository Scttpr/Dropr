package jobs

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunner(t *testing.T) {
	t.Parallel()
	r := NewRunner(10*time.Millisecond, slog.New(slog.DiscardHandler))
	var ok, failed atomic.Int64
	r.Add(Task{Name: "fail", Run: func(context.Context) (int64, error) { failed.Add(1); return 0, errors.New("x") }})
	r.Add(Task{Name: "ok", Run: func(context.Context) (int64, error) { ok.Add(1); return 1, nil }})
	if err := r.RunOnce(t.Context()); err == nil || ok.Load() != 1 {
		t.Fatal("RunOnce must run every task and report failures")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	r.Run(ctx)
	if ok.Load() < 3 || failed.Load() != ok.Load() {
		t.Fatalf("ticker ran %d/%d", ok.Load(), failed.Load())
	}
}
