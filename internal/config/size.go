package config

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Size units are binary (powers of 1024) whether written "GB" or "GiB", so
// the 100 GB hard cap equals the 3200 x 32 MiB part geometry of FORMAT.md.
const (
	KiB int64 = 1 << 10
	MiB int64 = 1 << 20
	GiB int64 = 1 << 30
	TiB int64 = 1 << 40

	// MaxFileSizeCap is the hard maximum file size (100 GiB).
	MaxFileSizeCap = 100 * GiB
)

var sizeUnits = []struct {
	suffix string
	mult   int64
}{
	// Longest suffixes first so "GiB" is not parsed as "B".
	{"KIB", KiB}, {"MIB", MiB}, {"GIB", GiB}, {"TIB", TiB},
	{"KB", KiB}, {"MB", MiB}, {"GB", GiB}, {"TB", TiB},
	{"K", KiB}, {"M", MiB}, {"G", GiB}, {"T", TiB},
	{"B", 1},
}

// ParseSize parses a non-negative byte size such as "5GB", "512MiB" or
// "1024". Only integer quantities are accepted.
func ParseSize(s string) (int64, error) {
	in := strings.ToUpper(strings.TrimSpace(s))
	if in == "" {
		return 0, errors.New("empty size")
	}
	mult := int64(1)
	for _, u := range sizeUnits {
		if strings.HasSuffix(in, u.suffix) {
			mult = u.mult
			in = strings.TrimSpace(strings.TrimSuffix(in, u.suffix))
			break
		}
	}
	if in == "" || strings.ContainsAny(in, "+-") {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	n, err := strconv.ParseInt(in, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("size %q overflows", s)
	}
	return n * mult, nil
}

// ParseDuration parses a Go duration ("15m", "1h30m") and additionally the
// day suffix "d" as a whole number of days ("7d"). Negative values are
// rejected.
func ParseDuration(s string) (time.Duration, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return 0, errors.New("empty duration")
	}
	if days, ok := strings.CutSuffix(in, "d"); ok {
		if strings.ContainsAny(days, "+-") {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n > int64(math.MaxInt64/(24*time.Hour)) {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(in)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("negative duration %q", s)
	}
	return d, nil
}
