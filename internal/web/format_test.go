package web

import (
	"testing"
	"time"
)

func TestFormatBytesMatchesJS(t *testing.T) {
	t.Parallel()
	for n, want := range map[int64]string{
		0: "0 B", 1023: "1023 B", 1024: "1.00 KB", 1536: "1.50 KB", 10 * 1024: "10.0 KB",
		100 * 1024: "100 KB", 5 << 30: "5.00 GB", 73400320: "70.0 MB", -1: "–",
	} {
		if got := FormatBytes(n); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestFormatExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	for d, want := range map[int64]string{
		// Same table as web/test/format.test.ts (rounding up).
		-5: "Expired", 0: "Expired", 1: "Expires in 1 minute", 30: "Expires in 1 minute", 600: "Expires in 10 minutes",
		601: "Expires in 11 minutes", 3599: "Expires in 1 hour", 3600: "Expires in 1 hour", 3601: "Expires in 2 hours",
		86_399: "Expires in 1 day", 86_400: "Expires in 1 day", 86_401: "Expires in 2 days",
		6*86_400 + 100: "Expires in 7 days", 7*86_400 - 3: "Expires in 7 days", 7 * 86_400: "Expires in 7 days",
	} {
		if got := FormatExpiry(now.Unix()+d, now); got != want {
			t.Errorf("FormatExpiry(+%d) = %q, want %q", d, got, want)
		}
	}
}
