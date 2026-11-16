package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/scttpr/dropr/internal/httpx"
)

// logBuffer collects JSON log lines written concurrently by handlers.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// events returns the log lines that carry an event, in order.
func (b *logBuffer) events(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(b.String()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("log line is not JSON: %s", sc.Bytes())
		}
		if _, ok := line["event"]; ok {
			out = append(out, line)
		}
	}
	return out
}

func eventNames(evs []map[string]any) []string {
	names := make([]string, len(evs))
	for i, ev := range evs {
		names[i], _ = ev["event"].(string)
	}
	return names
}

// newLoggedEnv is a test env whose JSON logs land in the returned buffer.
func newLoggedEnv(t *testing.T, o testOpts) (*testEnv, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	// As in production (cmd/dropr): JSON, with the request ID added.
	o.logger = slog.New(httpx.ContextHandler(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return newTestEnvWith(t, o), logs
}

// assertAbsent fails if any capability or address shows up in the logs.
func assertAbsent(t *testing.T, logs *logBuffer, secrets map[string]string) {
	t.Helper()
	all := logs.String()
	for what, v := range secrets {
		if v != "" && strings.Contains(all, v) {
			t.Errorf("logs contain the %s %q", what, v)
		}
	}
}

// The share lifecycle logs exactly one event per owner action and counted
// download, with keyed references instead of IDs.
func TestShareEvents(t *testing.T) {
	t.Parallel()
	e, logs := newLoggedEnv(t, testOpts{})
	e.login()
	data := randBytes(int(smallSize))
	u := e.createShare(e.client, smallSize, map[string]any{"max_downloads": 2})
	e.uploadAll(u, data)
	if resp, b := e.finalize(u, 1); resp.StatusCode != http.StatusOK { // repeated: idempotent, silent
		t.Fatalf("finalize again: %d %s", resp.StatusCode, b)
	}
	anon := &http.Client{Transport: e.client.Transport}
	token := func() string {
		resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token: %d %s", resp.StatusCode, b)
		}
		var g downloadGrant
		mustJSON(t, b, &g)
		return g.Token
	}
	tok1 := token()
	if resp, _ := e.download(anon, tok1, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("download 1: %d", resp.StatusCode)
	}
	if resp, _ := e.download(anon, tok1, map[string]string{"Range": "bytes=10-"}); resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("resume: %d", resp.StatusCode)
	}
	tok2 := token()
	if resp, _ := e.download(anon, tok2, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("download 2: %d", resp.StatusCode)
	}
	// The link is exhausted: no token is issued any more.
	if resp, _ := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("token on exhausted link: %d", resp.StatusCode)
	}
	if resp, b := e.api(http.MethodDelete, "/api/shares/"+u.ShareID, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}

	evs := logs.events(t)
	want := []string{"auth.login", "share.created", "share.ready", "share.opened", "share.downloaded",
		"share.opened", "share.downloaded", "share.exhausted", "share.revoked"}
	if got := eventNames(evs); !slices.Equal(got, want) {
		t.Fatalf("events:\n got %v\nwant %v", got, want)
	}
	ref := e.s.refs.Link(u.ShareID)
	for _, ev := range evs[1:] {
		if ev["link"] != ref {
			t.Errorf("%s: link %v, want %s", ev["event"], ev["link"], ref)
		}
	}
	if c := evs[1]; c["max_downloads"] != 2.0 || c["size"] != float64(smallSize) || c["parts"] != 1.0 || c["expires_at"] == nil || c["user"] == nil {
		t.Errorf("share.created: %v", c)
	}
	if evs[2]["size"] != float64(smallSize) {
		t.Errorf("share.ready: %v", evs[2])
	}
	for i, n := range map[int]float64{4: 1, 6: 2} {
		if evs[i]["count"] != n || evs[i]["max_downloads"] != 2.0 || evs[i]["ip"] == nil || evs[i]["rid"] == nil {
			t.Errorf("share.downloaded %v: %v", n, evs[i])
		}
	}
	assertAbsent(t, logs, map[string]string{"share ID": u.ShareID, "upload ID": u.UploadID, "upload token": u.UploadToken,
		"download token 1": tok1, "download token 2": tok2, "client address": "127.0.0.1"})
}
