package web

import (
	"strconv"
	"time"
)

// FormatBytes renders a size in binary units labeled KB/MB/GB ("1.50 GB"),
// exactly like formatBytes in web/src/lib/format.ts so server-rendered and
// JS-rendered sizes agree.
func FormatBytes(n int64) string {
	if n < 0 {
		return "–"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	u := 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	digits := 2
	switch {
	case u == 0 || v >= 100:
		digits = 0
	case v >= 10:
		digits = 1
	}
	return strconv.FormatFloat(v, 'f', digits, 64) + " " + units[u]
}

// FormatExpiry renders "Expires in 7 days" for a Unix-seconds expiry. It
// rounds up to the largest unit that fits (minutes below an hour, hours below
// a day, days otherwise), so a fresh 7-day link reads "7 days" and a fresh
// 1-hour link "1 hour". Same rule as formatExpiry in web/src/lib/format.ts.
func FormatExpiry(expiresAt int64, now time.Time) string {
	s := expiresAt - now.Unix()
	plural := func(n int64, w string) string {
		if n == 1 {
			return "1 " + w
		}
		return strconv.FormatInt(n, 10) + " " + w + "s"
	}
	ceil := func(a, b int64) int64 { return (a + b - 1) / b }
	if s <= 0 {
		return "Expired"
	}
	if m := ceil(s, 60); m < 60 {
		return "Expires in " + plural(m, "minute")
	}
	if h := ceil(s, 3600); h < 24 {
		return "Expires in " + plural(h, "hour")
	}
	return "Expires in " + plural(ceil(s, 86_400), "day")
}
