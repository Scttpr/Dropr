package server

import (
	"testing"
	"time"
)

func TestLimitsDownloads(t *testing.T) {
	t.Parallel()
	ptr := func(n int64) *int64 { return &n }
	val := func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	}
	cases := []struct {
		name         string
		l            limits
		in           *int64
		want         int64 // 0: no limit
		wantRejected bool
	}{
		{"no cap, none asked", limits{}, nil, 0, false},
		{"no cap, asked", limits{}, ptr(7), 7, false},
		{"no cap, above the hard cap", limits{}, ptr(1_000_000), 0, true},
		{"zero", limits{}, ptr(0), 0, true},
		{"default only", limits{defaultMaxDownloads: 3}, nil, 3, false},
		{"default, asked", limits{defaultMaxDownloads: 3}, ptr(9), 9, false},
		{"cap, none asked", limits{maxDownloads: 10}, nil, 10, false},
		{"cap and default, none asked", limits{maxDownloads: 10, defaultMaxDownloads: 4}, nil, 4, false},
		{"cap, within", limits{maxDownloads: 10}, ptr(10), 10, false},
		{"cap, above", limits{maxDownloads: 10}, ptr(11), 0, true},
	}
	for _, tc := range cases {
		got, e := tc.l.downloads(tc.in)
		if (e != nil) != tc.wantRejected || val(got) != tc.want {
			t.Errorf("%s: got %d, %v; want %d, rejected %v", tc.name, val(got), e, tc.want, tc.wantRejected)
		}
	}
}

func TestLimitsExpiry(t *testing.T) {
	t.Parallel()
	l := limits{defaultExpiry: "3d", expiries: map[string]time.Duration{"12h": 12 * time.Hour, "3d": 72 * time.Hour}}
	if d, e := l.expiry(""); e != nil || d != 72*time.Hour {
		t.Errorf("default: %v %v", d, e)
	}
	if d, e := l.expiry("12h"); e != nil || d != 12*time.Hour {
		t.Errorf("12h: %v %v", d, e)
	}
	if _, e := l.expiry("7d"); e == nil {
		t.Error("7d accepted though not a choice of this instance")
	}
}
