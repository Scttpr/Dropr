package web

import (
	"strconv"
	"strings"
	"time"

	"github.com/scttpr/dropr/internal/i18n"
)

var byteUnits = map[i18n.Lang][]string{
	i18n.EN: {"B", "KB", "MB", "GB", "TB"},
	i18n.FR: {"o", "Ko", "Mo", "Go", "To"},
}

// FormatBytes renders a size in English (see FormatBytesIn).
func FormatBytes(n int64) string { return FormatBytesIn(i18n.EN, n) }

// FormatBytesIn renders a size in binary units labeled KB/MB/GB ("1.50 GB";
// French "1,50 Go", with a no-break space), exactly like formatBytes in
// web/src/lib/format.ts so server-rendered and JS-rendered sizes agree.
func FormatBytesIn(l i18n.Lang, n int64) string {
	if n < 0 {
		return "–"
	}
	units, ok := byteUnits[l]
	if !ok {
		units = byteUnits[i18n.EN]
	}
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
	num := strconv.FormatFloat(v, 'f', digits, 64)
	if l == i18n.FR {
		return strings.Replace(num, ".", ",", 1) + "\u00a0" + units[u]
	}
	return num + " " + units[u]
}

// FormatExpiry renders "Expires in 7 days" in English (see FormatExpiryIn).
func FormatExpiry(expiresAt int64, now time.Time) string {
	return FormatExpiryIn(i18n.EN, expiresAt, now)
}

// FormatExpiryIn renders "Expires in 7 days" for a Unix-seconds expiry. It
// rounds up to the largest unit that fits (minutes below an hour, hours below
// a day, days otherwise), so a fresh 7-day link reads "7 days" and a fresh
// 1-hour link "1 hour". Same rule and wording as formatExpiry in
// web/src/lib/format.ts.
func FormatExpiryIn(l i18n.Lang, expiresAt int64, now time.Time) string {
	s := expiresAt - now.Unix()
	ceil := func(a, b int64) int64 { return (a + b - 1) / b }
	if s <= 0 {
		return l.T("Expired")
	}
	var n int64
	var one, other string
	switch m, h := ceil(s, 60), ceil(s, 3600); {
	case m < 60:
		n, one, other = m, i18n.N("Expires in 1 minute"), i18n.N("Expires in %d minutes")
	case h < 24:
		n, one, other = h, i18n.N("Expires in 1 hour"), i18n.N("Expires in %d hours")
	default:
		n, one, other = ceil(s, 86_400), i18n.N("Expires in 1 day"), i18n.N("Expires in %d days")
	}
	if n == 1 {
		return l.T(one)
	}
	return l.T(other, n)
}
