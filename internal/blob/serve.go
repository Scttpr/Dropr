package blob

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrRange means a Range header is not exactly one satisfiable byte range.
var ErrRange = errors.New("blob: unsatisfiable range")

// ParseRange interprets a Range header for a representation of size bytes.
//
// Policy (ARCHITECTURE.md §3): an absent header selects the full content
// (ok=false). Otherwise the header must be one byte range, "bytes=a-b",
// "bytes=a-" or "bytes=-n", within the content; anything else (other units,
// several ranges, malformed or unsatisfiable ranges) is ErrRange and answered
// with 416. The returned range is [start, end] inclusive.
func ParseRange(h string, size int64) (start, end int64, ok bool, err error) {
	if h == "" {
		return 0, 0, false, nil
	}
	spec, found := strings.CutPrefix(h, "bytes=")
	if !found || size <= 0 {
		return 0, 0, false, ErrRange
	}
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, ",") {
		return 0, 0, false, ErrRange
	}
	first, last, found := strings.Cut(spec, "-")
	if !found {
		return 0, 0, false, ErrRange
	}
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)
	if first == "" {
		// Suffix range: the last n bytes.
		n, perr := parseDigits(last)
		if perr != nil || n == 0 {
			return 0, 0, false, ErrRange
		}
		return max(0, size-n), size - 1, true, nil
	}
	start, perr := parseDigits(first)
	if perr != nil || start >= size {
		return 0, 0, false, ErrRange
	}
	end = size - 1
	if last != "" {
		e, perr := parseDigits(last)
		if perr != nil || e < start {
			return 0, 0, false, ErrRange
		}
		end = min(e, size-1)
	}
	return start, end, true, nil
}

// parseDigits accepts only ASCII decimal digits (no sign, no spaces).
func parseDigits(s string) (int64, error) {
	if s == "" || len(s) > 19 {
		return 0, ErrRange
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrRange
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// DownloadName is the generic file name of every ciphertext download; the
// real name is encrypted and only known to the browser.
const DownloadName = "dropr-download.bin"

// WriteTimeout is how long one write may stall before the connection is
// dropped; the deadline slides forward while data flows.
const WriteTimeout = 2 * time.Minute

// ErrTooSlow means a transfer moved fewer than its minimum rate's worth of
// bytes during a whole RateWindow (audit L-4: trickling connections).
var ErrTooSlow = errors.New("blob: transfer too slow")

// RateWindow is the window over which a minimum transfer rate is enforced.
const RateWindow = 60 * time.Second

// rateCheck enforces a minimum average rate over consecutive windows.
type rateCheck struct {
	min   int64 // bytes per second; <= 0 disables the check
	now   func() time.Time
	start time.Time
	n     int64
}

func (c *rateCheck) add(n int) error {
	if c.min <= 0 {
		return nil
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	t := now()
	if c.start.IsZero() {
		c.start = t
	}
	c.n += int64(n)
	if el := t.Sub(c.start); el >= RateWindow {
		if c.n < c.min*int64(el/time.Second) {
			return ErrTooSlow
		}
		c.start, c.n = t, 0
	}
	return nil
}

// Planned returns how many body bytes Serve will send for req (0 for HEAD
// and for answers other than 200/206), so callers can account for them
// before serving.
func Planned(req *http.Request, size int64) int64 {
	if req.Method == http.MethodHead {
		return 0
	}
	start, end, partial, err := ParseRange(rangeHeader(req), size)
	switch {
	case err != nil:
		return 0
	case !partial:
		return size
	default:
		return end - start + 1
	}
}

func rangeHeader(req *http.Request) string {
	if req.Header.Get("If-Range") != "" {
		return ""
	}
	return req.Header.Get("Range")
}

// Serve writes the ciphertext from r (Size bytes) honoring a single Range,
// as an opaque attachment. It never emits Last-Modified or ETag. HEAD
// requests receive the headers only. A conditional If-Range (which cannot
// match, as no validator is ever sent) makes the full content be served, as
// RFC 9110 §13.1.5 requires. The body is abandoned (the connection then
// closes short of Content-Length) if the client reads slower than minRate
// bytes per second over a RateWindow (minRate <= 0 disables this). It returns
// the number of body bytes written.
func Serve(w http.ResponseWriter, req *http.Request, r *Reader, minRate int64) int64 {
	size := r.Size()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+DownloadName+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Accept-Ranges", "bytes")

	start, end, partial, err := ParseRange(rangeHeader(req), size)
	if err != nil {
		h.Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		_, _ = io.WriteString(w, "The requested range is not available.\n")
		return 0
	}
	status := http.StatusOK
	if !partial {
		start, end = 0, size-1
	} else {
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(size, 10))
	}
	length := end - start + 1
	h.Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(status)
	if req.Method == http.MethodHead {
		return 0
	}
	if _, err := r.Seek(start, io.SeekStart); err != nil {
		return 0
	}
	dw := &deadlineWriter{w: w, rc: http.NewResponseController(w), rate: rateCheck{min: minRate}}
	n, _ := io.CopyN(dw, r, length)
	return n
}

// deadlineWriter pushes the write deadline forward as data flows, so a
// 100 GB download is bounded by progress, not by total duration, and stops
// a client that drains slower than the minimum rate.
type deadlineWriter struct {
	w    io.Writer
	rc   *http.ResponseController
	last time.Time
	rate rateCheck
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	if now := time.Now(); now.Sub(d.last) > WriteTimeout/8 {
		_ = d.rc.SetWriteDeadline(now.Add(WriteTimeout))
		d.last = now
	}
	n, err := d.w.Write(p)
	if err == nil {
		err = d.rate.add(n)
	}
	return n, err
}

// ProgressReader wraps a request body and pushes the read and write
// deadlines forward while bytes arrive (uploads of one 32 MiB part over a
// slow link). The write deadline must slide too: HTTP/2 resets the stream
// when it passes, even mid-body, and HTTP/1.1 could not send the reply
// (audit 2026-11b L-1). Callers set a final write deadline once the body is
// read. With MinRate > 0 it fails with ErrTooSlow once a whole RateWindow
// brought fewer than MinRate bytes per second.
type ProgressReader struct {
	R       io.Reader
	RC      *http.ResponseController
	Timeout time.Duration
	MinRate int64 // bytes per second
	last    time.Time
	rate    rateCheck
}

// Read implements io.Reader.
func (p *ProgressReader) Read(b []byte) (int, error) {
	if now := time.Now(); now.Sub(p.last) > p.Timeout/8 {
		_ = p.RC.SetReadDeadline(now.Add(p.Timeout))
		_ = p.RC.SetWriteDeadline(now.Add(p.Timeout))
		p.last = now
	}
	n, err := p.R.Read(b)
	p.rate.min = p.MinRate
	if rerr := p.rate.add(n); rerr != nil && (err == nil || errors.Is(err, io.EOF)) {
		if errors.Is(err, io.EOF) {
			return n, err // the body is complete: too late to matter
		}
		return n, rerr
	}
	return n, err
}
