package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/auth/oidc/oidctest"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/jobs"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now().UTC()} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type upload struct {
	ShareID     string `json:"share_id"`
	UploadID    string `json:"upload_id"`
	UploadToken string `json:"upload_token"`
}

// meta is a sealed-metadata stand-in on the smallest padded length (audit
// 2026-11b L-8).
func meta() string { return b64t.EncodeToString(randBytes(padMin + blob.TagSize)) }

// smallSize is the ciphertext of a 1000-byte file (one part).
var smallSize = blob.CipherSize(1000)

func (e *testEnv) createShare(c *http.Client, size int64, extra map[string]any) upload {
	e.t.Helper()
	body := map[string]any{"size": size, "parts": blob.PartsFor(size), "meta": meta(), "expires_in": "1d"}
	for k, v := range extra {
		body[k] = v
	}
	resp, b := e.apiWith(c, http.MethodPost, "/api/shares", body, nil)
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("create share: %d %s", resp.StatusCode, b)
	}
	var u upload
	mustJSON(e.t, b, &u)
	return u
}

func (e *testEnv) putPart(u upload, n int, data []byte) (*http.Response, []byte) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(e.t.Context(), http.MethodPut, e.origin+"/upload/"+u.UploadID+"/part/"+strconv.Itoa(n), bytes.NewReader(data))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+u.UploadToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := (&http.Client{Transport: e.client.Transport}).Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *testEnv) bearer(u upload) map[string]string {
	return map[string]string{"Authorization": "Bearer " + u.UploadToken}
}

func (e *testEnv) finalize(u upload, parts int) (*http.Response, []byte) {
	e.t.Helper()
	return e.api(http.MethodPost, "/upload/"+u.UploadID+"/finalize", map[string]any{"parts": parts}, e.bearer(u))
}

// uploadAll uploads data as u and finalizes it.
func (e *testEnv) uploadAll(u upload, data []byte) {
	e.t.Helper()
	g, err := blob.NewGeometry(int64(len(data)), blob.PartsFor(int64(len(data))))
	if err != nil {
		e.t.Fatal(err)
	}
	for n := range g.Parts {
		off := int64(n) * blob.PartCipherSize
		if resp, b := e.putPart(u, n, data[off:off+g.PartSize(n)]); resp.StatusCode != http.StatusNoContent {
			e.t.Fatalf("put %d: %d %s", n, resp.StatusCode, b)
		}
	}
	if resp, b := e.finalize(u, g.Parts); resp.StatusCode != http.StatusOK {
		e.t.Fatalf("finalize: %d %s", resp.StatusCode, b)
	}
}

func (e *testEnv) blobDir(id string) string {
	return filepath.Join(e.s.blobs.Root(), id[0:2], id[2:4], id)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func (e *testEnv) download(c *http.Client, token string, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(e.t.Context(), http.MethodGet, e.origin+"/dl/"+token, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestShareFlow(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	anon := &http.Client{Transport: e.client.Transport}

	size := blob.CipherSize(blob.PartPlainSize + 5000) // two parts
	data := randBytes(int(size))
	u := e.createShare(e.client, size, map[string]any{"max_downloads": 2})
	p0, p1 := data[:blob.PartCipherSize], data[blob.PartCipherSize:]

	// Invisible until finalized.
	if resp, _ := e.do(http.MethodGet, "/s/"+u.ShareID, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unfinished share page: %d", resp.StatusCode)
	}
	if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unfinished share download: %d %s", resp.StatusCode, b)
	}

	// Out of order, resumable, idempotent.
	if resp, b := e.putPart(u, 1, p1); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put 1: %d %s", resp.StatusCode, b)
	}
	resp, b := e.api(http.MethodGet, "/upload/"+u.UploadID, nil, e.bearer(u))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"parts_present":[1]`) {
		t.Errorf("status: %s", b)
	}
	if resp, b := e.api(http.MethodGet, "/upload/"+u.UploadID, nil, nil); resp.StatusCode != http.StatusUnauthorized || errCode(b) != "bad_token" {
		t.Errorf("status without token: %d", resp.StatusCode)
	}
	if resp, b := e.finalize(u, 2); resp.StatusCode != http.StatusConflict || errCode(b) != "incomplete" {
		t.Errorf("early finalize: %d %s", resp.StatusCode, b)
	}
	e.putPart(u, 0, p0)
	if resp, _ := e.putPart(u, 1, p1); resp.StatusCode != http.StatusNoContent {
		t.Error("re-put")
	}
	_, b = e.api(http.MethodGet, "/upload/"+u.UploadID, nil, e.bearer(u))
	if !strings.Contains(string(b), `"parts_present":[0,1]`) {
		t.Errorf("status: %s", b)
	}
	if resp, b := e.finalize(u, 3); resp.StatusCode != http.StatusBadRequest || errCode(b) != "bad_parts" {
		t.Errorf("wrong parts: %d %s", resp.StatusCode, b)
	}
	resp, first := e.finalize(u, 2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize: %d %s", resp.StatusCode, first)
	}
	if resp, again := e.finalize(u, 2); resp.StatusCode != http.StatusOK || !bytes.Equal(again, first) {
		t.Errorf("finalize not idempotent: %d %s", resp.StatusCode, again)
	}
	if resp, b := e.putPart(u, 0, p0); resp.StatusCode != http.StatusConflict || errCode(b) != "already_complete" {
		t.Errorf("put after finalize: %d %s", resp.StatusCode, b)
	}

	// Visible now.
	_, b = e.api(http.MethodGet, "/api/shares", nil, nil)
	if !strings.Contains(string(b), `"id":"`+u.ShareID+`"`) || !strings.Contains(string(b), `"max_downloads":2`) {
		t.Errorf("list: %s", b)
	}
	resp, page := e.do(http.MethodGet, "/s/"+u.ShareID, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `data-share-id="`+u.ShareID+`"`) || !strings.Contains(page, `data-expires-at="`) {
		t.Errorf("share page: %d", resp.StatusCode)
	}

	// Three tokens issued while the count is 0; each first use counts once.
	tokens := make([]string, 3)
	for i := range tokens {
		resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil)
		var g struct {
			Token string
			Size  int64
			Parts int
			Meta  string
		}
		mustJSON(t, b, &g)
		if resp.StatusCode != http.StatusOK || g.Size != size || g.Parts != 2 || g.Meta == "" {
			t.Fatalf("token: %d %s", resp.StatusCode, b)
		}
		tokens[i] = g.Token
	}
	count := func() string {
		_, b := e.api(http.MethodGet, "/api/shares", nil, nil)
		i := bytes.Index(b, []byte(`"download_count":`))
		return string(b)[i+17 : i+18]
	}
	start := blob.PartCipherSize - 7
	resp, got := e.download(anon, tokens[0], map[string]string{"Range": "bytes=" + strconv.Itoa(start) + "-"})
	if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(got, data[start:]) ||
		resp.Header.Get("Content-Range") != "bytes "+strconv.Itoa(start)+"-"+strconv.FormatInt(size-1, 10)+"/"+strconv.FormatInt(size, 10) {
		t.Fatalf("range: %d %v", resp.StatusCode, resp.Header)
	}
	for k, v := range map[string]string{"Content-Type": "application/octet-stream", "Cache-Control": "no-store",
		"Cross-Origin-Resource-Policy": "same-origin", "Content-Disposition": `attachment; filename="dropr-download.bin"`} {
		if resp.Header.Get(k) != v {
			t.Errorf("%s = %q", k, resp.Header.Get(k))
		}
	}
	resp, _ = e.download(anon, tokens[0], map[string]string{"Range": "bytes=10-19"})
	if resp.StatusCode != http.StatusPartialContent || count() != "1" {
		t.Errorf("resume counted again: %s", count())
	}
	resp, got = e.download(anon, tokens[1], nil)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, data) || count() != "2" {
		t.Fatalf("full: %d count %s", resp.StatusCode, count())
	}
	if resp, b := e.download(anon, tokens[2], nil); resp.StatusCode != http.StatusGone || errCode(b) != "exhausted" {
		t.Errorf("first use past the limit: %d %s", resp.StatusCode, b)
	}
	if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusGone || errCode(b) != "exhausted" {
		t.Errorf("new token past the limit: %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.download(anon, tokens[0], map[string]string{"Range": "bytes=0-"}); resp.StatusCode != http.StatusPartialContent {
		t.Error("counted token stopped working")
	}
	if resp, page := e.do(http.MethodGet, "/s/"+u.ShareID, nil); resp.StatusCode != http.StatusGone || !strings.Contains(page, "download limit") ||
		strings.Contains(page, "data-share-id") {
		t.Errorf("exhausted page: %d", resp.StatusCode)
	}

	// Revoke deletes the blob.
	dir := e.blobDir(u.UploadID)
	if !exists(dir) {
		t.Fatal("blob dir missing")
	}
	if resp, _ := e.api(http.MethodDelete, "/api/shares/"+u.ShareID, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatal("revoke")
	}
	if exists(dir) {
		t.Error("revoke left the blob on disk")
	}
	if resp, _ := e.download(anon, tokens[0], nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("token after revoke: %d", resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodGet, "/s/"+u.ShareID, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("page after revoke: %d", resp.StatusCode)
	}

	// Canceling an unfinished share deletes its partial blob.
	u2 := e.createShare(e.client, smallSize, nil)
	e.putPart(u2, 0, randBytes(int(smallSize)))
	if resp, _ := e.api(http.MethodDelete, "/api/shares/"+u2.ShareID, nil, nil); resp.StatusCode != http.StatusNoContent || exists(e.blobDir(u2.UploadID)) {
		t.Errorf("cancel: %d", resp.StatusCode)
	}
	if resp, b := e.putPart(u2, 0, randBytes(int(smallSize))); resp.StatusCode != http.StatusNotFound {
		t.Errorf("put after cancel: %d %s", resp.StatusCode, b)
	}
}

func (o *owner) createRequest(body map[string]any) string {
	o.e.t.Helper()
	resp, b := o.e.apiWith(o.c, http.MethodPost, "/api/requests", body, nil)
	if resp.StatusCode != http.StatusCreated {
		o.e.t.Fatalf("create request: %d %s", resp.StatusCode, b)
	}
	var v struct {
		RequestID string `json:"request_id"`
	}
	mustJSON(o.e.t, b, &v)
	return v.RequestID
}

func (e *testEnv) createRequestFile(id string, size int64) (*http.Response, upload) {
	e.t.Helper()
	anon := &http.Client{Transport: e.client.Transport}
	resp, b := e.apiWith(anon, http.MethodPost, "/api/r/"+id+"/files", map[string]any{
		"size": size, "parts": blob.PartsFor(size), "meta": meta(), "wrapped_key": b64t.EncodeToString(randBytes(80)),
	}, nil)
	var u upload
	if resp.StatusCode == http.StatusCreated {
		mustJSON(e.t, b, &u)
	}
	return resp, u
}

func TestRequestFlow(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()
	reqBody := map[string]any{"expires_in": "7d", "max_files": 5, "max_bytes": 10 * smallSize, "single_use": false}
	id := o.createRequest(reqBody)
	label := b64t.EncodeToString(randBytes(minLabel))
	if resp, b := e.api(http.MethodPut, "/api/requests/"+id+"/label", map[string]any{"label_meta": label}, nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("label: %d %s", resp.StatusCode, b)
	}
	resp, page := e.do(http.MethodGet, "/r/"+id, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Alice Example") || !strings.Contains(page, `data-max-files="5"`) {
		t.Errorf("request page: %d %s", resp.StatusCode, page)
	}

	// Anonymous upload.
	data := randBytes(int(smallSize))
	resp, u := e.createRequestFile(id, smallSize)
	if resp.StatusCode != http.StatusCreated || u.ShareID != "" {
		t.Fatalf("request file: %d", resp.StatusCode)
	}
	if _, b := e.api(http.MethodGet, "/api/inbox", nil, nil); strings.Contains(string(b), u.UploadID) || strings.Count(string(b), `"id"`) != 0 {
		t.Errorf("unfinished file listed: %s", b)
	}
	e.uploadAll(u, data)

	// Inbox: the owner lists and downloads.
	_, b := e.api(http.MethodGet, "/api/inbox", nil, nil)
	var inbox struct {
		Inbox []struct {
			ID         string `json:"id"`
			RequestID  string `json:"request_id"`
			Size       int64  `json:"size"`
			WrappedKey string `json:"wrapped_key"`
		}
	}
	mustJSON(t, b, &inbox)
	if len(inbox.Inbox) != 1 || inbox.Inbox[0].RequestID != id || inbox.Inbox[0].Size != smallSize {
		t.Fatalf("inbox: %s", b)
	}
	fileID := inbox.Inbox[0].ID
	_, b = e.api(http.MethodGet, "/api/requests", nil, nil)
	if !strings.Contains(string(b), `"files_received":1`) || !strings.Contains(string(b), `"label_meta":"`+label+`"`) {
		t.Errorf("requests: %s", b)
	}
	resp, b = e.api(http.MethodPost, "/api/inbox/"+fileID+"/download", map[string]any{}, nil)
	var g struct{ Token string }
	mustJSON(t, b, &g)
	if resp.StatusCode != http.StatusOK || g.Token == "" {
		t.Fatalf("inbox token: %d %s", resp.StatusCode, b)
	}
	anon := &http.Client{Transport: e.client.Transport}
	if resp, _ := e.download(anon, g.Token, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("inbox token without session: %d", resp.StatusCode)
	}
	if resp, got := e.download(e.client, g.Token, nil); resp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Errorf("inbox download: %d", resp.StatusCode)
	}

	// Delete the file: row and blob go.
	if resp, _ := e.api(http.MethodDelete, "/api/inbox/"+fileID, nil, nil); resp.StatusCode != http.StatusNoContent || exists(e.blobDir(u.UploadID)) {
		t.Errorf("delete inbox file: %d", resp.StatusCode)
	}

	// Single use: closes after the first finalized file.
	single := o.createRequest(map[string]any{"expires_in": "1h", "max_files": 3, "max_bytes": 3 * smallSize, "single_use": true})
	if resp, page := e.do(http.MethodGet, "/r/"+single, nil); resp.StatusCode != http.StatusOK || !strings.Contains(page, `data-max-files="1"`) {
		t.Errorf("single-use page offers more than one file: %d", resp.StatusCode)
	}
	_, u1 := e.createRequestFile(single, smallSize)
	_, u2 := e.createRequestFile(single, smallSize) // already reserved: may still finish
	e.uploadAll(u1, randBytes(int(smallSize)))
	if resp, _ := e.createRequestFile(single, smallSize); resp.StatusCode != http.StatusGone {
		t.Errorf("single-use link still open: %d", resp.StatusCode)
	}
	e.uploadAll(u2, randBytes(int(smallSize)))
	if resp, page := e.do(http.MethodGet, "/r/"+single, nil); resp.StatusCode != http.StatusGone || strings.Contains(page, "data-request-id") {
		t.Errorf("closed page: %d", resp.StatusCode)
	}

	// Revoking a request link deletes the files it received.
	if resp, _ := e.api(http.MethodDelete, "/api/requests/"+single, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatal("revoke request")
	}
	if exists(e.blobDir(u1.UploadID)) || exists(e.blobDir(u2.UploadID)) {
		t.Error("revoked request left blobs")
	}
	if resp, _ := e.do(http.MethodGet, "/r/"+single, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoked page: %d", resp.StatusCode)
	}
}

func TestRequestCapsUnderConcurrency(t *testing.T) {
	t.Parallel()
	clk := newClock()
	e := newTestEnvWith(t, testOpts{now: clk.Now})
	o := e.newOwner()
	byFiles := o.createRequest(map[string]any{"max_files": 3, "max_bytes": 100 * smallSize})
	byBytes := o.createRequest(map[string]any{"max_files": 10, "max_bytes": 2 * smallSize})

	race := func(id string) (ok int) {
		var (
			wg sync.WaitGroup
			mu sync.Mutex
		)
		for range 8 {
			wg.Go(func() {
				resp, _ := e.createRequestFile(id, smallSize)
				mu.Lock()
				defer mu.Unlock()
				switch resp.StatusCode {
				case http.StatusCreated:
					ok++
				case http.StatusConflict:
				default:
					t.Errorf("unexpected %d", resp.StatusCode)
				}
			})
		}
		wg.Wait()
		return ok
	}
	if n := race(byFiles); n != 3 {
		t.Errorf("max_files=3 admitted %d", n)
	}
	if n := race(byBytes); n != 2 {
		t.Errorf("max_bytes=2 files admitted %d", n)
	}

	// Abandoned uploads give their reservation back when collected.
	clk.Advance(jobs.StaleUploadAge + time.Minute)
	if err := e.runJobs(clk.Now); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.createRequestFile(byFiles, smallSize); resp.StatusCode != http.StatusCreated {
		t.Errorf("reservation not released: %d", resp.StatusCode)
	}
}

func TestQuotaAndDiskSpace(t *testing.T) {
	t.Parallel()
	var avail uint64 = 1 << 40
	var mu sync.Mutex
	e := newTestEnvWith(t, testOpts{
		extraConfig: "[limits]\nuser_quota = \"3000B\"",
		diskUsage: func(string) (uint64, uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			return avail, 2 << 40, nil
		},
	})
	o := e.newOwner()
	e.createShare(e.client, smallSize, nil)
	e.createShare(e.client, smallSize, nil)
	resp, b := e.api(http.MethodPost, "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta()}, nil)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || errCode(b) != "quota_exceeded" {
		t.Errorf("quota: %d %s", resp.StatusCode, b)
	}
	// Request-link uploads count against the owner too.
	id := o.createRequest(map[string]any{"max_files": 5, "max_bytes": 5 * smallSize})
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("request quota: %d", resp.StatusCode)
	}
	mu.Lock()
	avail = 1 << 30 // below the automatic headroom of 5% of 2 TiB
	mu.Unlock()
	resp, b = e.api(http.MethodPost, "/api/shares", map[string]any{"size": blob.CipherSize(10), "parts": 1, "meta": meta()}, nil)
	if resp.StatusCode != http.StatusInsufficientStorage || errCode(b) != "disk_full" {
		t.Errorf("disk: %d %s", resp.StatusCode, b)
	}
}

func TestUploadValidation(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	u := e.createShare(e.client, smallSize, nil)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		hdr    map[string]string
		status int
		code   string
	}{
		{"bad geometry", "POST", "/api/shares", map[string]any{"size": 65568, "parts": 1, "meta": meta()}, nil, 400, "invalid_size"},
		{"parts mismatch", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 2, "meta": meta()}, nil, 400, "invalid_size"},
		{"too large", "POST", "/api/shares", map[string]any{"size": blob.CipherSize(6 << 30), "parts": blob.PartsFor(blob.CipherSize(6 << 30)), "meta": meta()}, nil, 413, "too_large"},
		{"over cap", "POST", "/api/shares", map[string]any{"size": blob.MaxCipherSize + 1, "parts": 3201, "meta": meta()}, nil, 413, "too_large"},
		{"meta too long", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": b64t.EncodeToString(make([]byte, 2*maxMetaPadded+blob.TagSize))}, nil, 400, "bad_request"},
		{"meta not padded", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": b64t.EncodeToString(make([]byte, 200+blob.TagSize))}, nil, 400, "bad_request"},
		{"meta too short", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": b64t.EncodeToString(make([]byte, 16))}, nil, 400, "bad_request"},
		{"bad expiry", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta(), "expires_in": "2d"}, nil, 400, "bad_request"},
		{"max_downloads 0", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta(), "max_downloads": 0}, nil, 400, "bad_request"},
		{"unknown field", "POST", "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta(), "x": 1}, nil, 400, "bad_request"},
		{"not json", "POST", "/api/shares", []byte(`{"size":1}`), map[string]string{"Content-Type": "text/plain"}, 400, "bad_request"},
		{"trailing data", "POST", "/api/shares", []byte(`{} {}`), nil, 400, "bad_request"},
		{"body limit", "POST", "/api/shares", []byte(`{"meta":"` + strings.Repeat("A", 17<<10) + `"}`), nil, 413, ""},
		{"wrapped key length", "POST", "/api/r/AAAAAAAAAAAAAAAAAAAAAA/files", map[string]any{"size": smallSize, "parts": 1, "meta": meta(), "wrapped_key": b64t.EncodeToString(make([]byte, 79))}, nil, 400, "bad_request"},
		{"request file too large", "POST", "/api/r/AAAAAAAAAAAAAAAAAAAAAA/files", map[string]any{"size": blob.CipherSize(6 << 30), "parts": blob.PartsFor(blob.CipherSize(6 << 30)), "meta": meta(), "wrapped_key": b64t.EncodeToString(make([]byte, 80))}, nil, 413, "too_large"},
		{"unknown request link", "POST", "/api/r/AAAAAAAAAAAAAAAAAAAAAA/files", map[string]any{"size": smallSize, "parts": 1, "meta": meta(), "wrapped_key": b64t.EncodeToString(make([]byte, 80))}, nil, 404, "not_found"},
		{"request max_files 0", "POST", "/api/requests", map[string]any{"max_files": 0, "max_bytes": 100}, nil, 400, "bad_request"},
		{"wrong token", "GET", "/upload/" + u.UploadID, nil, map[string]string{"Authorization": "Bearer " + strings.Repeat("A", 43)}, 401, "bad_token"},
		{"malformed token", "GET", "/upload/" + u.UploadID, nil, map[string]string{"Authorization": "Bearer x"}, 401, "bad_token"},
		{"unknown upload", "GET", "/upload/AAAAAAAAAAAAAAAAAAAAAA", nil, e.bearer(u), 404, "not_found"},
		{"part out of range", "PUT", "/upload/" + u.UploadID + "/part/1", make([]byte, smallSize), e.bearer(u), 400, "bad_part"},
		{"part leading zero", "PUT", "/upload/" + u.UploadID + "/part/00", make([]byte, smallSize), e.bearer(u), 400, "bad_part"},
		{"wrong part size", "PUT", "/upload/" + u.UploadID + "/part/0", make([]byte, smallSize-1), e.bearer(u), 400, "wrong_part_size"},
		{"part body limit", "PUT", "/upload/" + u.UploadID + "/part/0", make([]byte, blob.PartCipherSize+1), e.bearer(u), 413, ""},
		{"bad dl token", "GET", "/dl/nope", nil, nil, 404, "not_found"},
		{"unknown dl token", "GET", "/dl/" + strings.Repeat("A", 43), nil, nil, 404, "not_found"},
	}
	for _, c := range cases {
		resp, b := e.api(c.method, c.path, c.body, c.hdr)
		if resp.StatusCode != c.status || (c.code != "" && errCode(b) != c.code) {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, b)
		}
	}

	// A chunked body (no Content-Length) of the wrong size stores nothing.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, e.origin+"/upload/"+u.UploadID+"/part/0",
		io.MultiReader(bytes.NewReader(make([]byte, smallSize)), strings.NewReader("extra")))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+u.UploadToken)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || errCode(b) != "wrong_part_size" {
		t.Errorf("chunked oversize: %d %s", resp.StatusCode, b)
	}
	if _, b := e.api(http.MethodGet, "/upload/"+u.UploadID, nil, e.bearer(u)); !strings.Contains(string(b), `"parts_present":[]`) {
		t.Errorf("bad part stored: %s", b)
	}
}

func TestOwnerIsolation(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	a := e.newOwner()
	share := e.createShare(e.client, smallSize, nil)
	e.uploadAll(share, randBytes(int(smallSize)))
	reqID := a.createRequest(map[string]any{"max_files": 2, "max_bytes": 2 * smallSize})
	_, f := e.createRequestFile(reqID, smallSize)
	e.uploadAll(f, randBytes(int(smallSize)))
	_, b := e.api(http.MethodGet, "/api/inbox", nil, nil)
	var inbox struct{ Inbox []struct{ ID string } }
	mustJSON(t, b, &inbox)
	_, b = e.api(http.MethodPost, "/api/inbox/"+inbox.Inbox[0].ID+"/download", map[string]any{}, nil)
	var g struct{ Token string }
	mustJSON(t, b, &g)

	// Bob: another account.
	e.op.Set(func(k *oidctest.Knobs) { k.Subject = "bob-456" })
	bob := e.newClient()
	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, "/api/shares/" + share.ShareID},
		{http.MethodDelete, "/api/requests/" + reqID},
		{http.MethodDelete, "/api/inbox/" + inbox.Inbox[0].ID},
		{http.MethodPost, "/api/inbox/" + inbox.Inbox[0].ID + "/download"},
	} {
		if resp, b := e.apiWith(bob, c.method, c.path, map[string]any{}, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("bob %s %s: %d %s", c.method, c.path, resp.StatusCode, b)
		}
	}
	if resp, _ := e.apiWith(bob, http.MethodPut, "/api/requests/"+reqID+"/label", map[string]any{"label_meta": b64t.EncodeToString(randBytes(minLabel))}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bob label: %d", resp.StatusCode)
	}
	for _, p := range []string{"/api/shares", "/api/requests", "/api/inbox"} {
		if _, b := e.apiWith(bob, http.MethodGet, p, nil, nil); strings.Contains(string(b), `"id"`) {
			t.Errorf("bob sees %s: %s", p, b)
		}
	}
	// Alice's inbox token needs Alice's session.
	if resp, _ := e.download(bob, g.Token, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bob with alice's inbox token: %d", resp.StatusCode)
	}
	// Alice's things are intact.
	if !exists(e.blobDir(share.UploadID)) || !exists(e.blobDir(f.UploadID)) {
		t.Error("isolation breach deleted files")
	}
}

func TestExpiryDeletesBlobs(t *testing.T) {
	t.Parallel()
	clk := newClock()
	e := newTestEnvWith(t, testOpts{now: clk.Now})
	o := e.newOwner()
	share := e.createShare(e.client, smallSize, map[string]any{"expires_in": "1h"})
	e.uploadAll(share, randBytes(int(smallSize)))
	reqID := o.createRequest(map[string]any{"expires_in": "1h", "max_files": 2, "max_bytes": 2 * smallSize})
	_, f := e.createRequestFile(reqID, smallSize)
	e.uploadAll(f, randBytes(int(smallSize)))
	long := e.createShare(e.client, smallSize, map[string]any{"expires_in": "30d"})
	e.uploadAll(long, randBytes(int(smallSize)))

	clk.Advance(time.Hour + time.Second)
	anon := &http.Client{Transport: e.client.Transport}
	if resp, page := e.do(http.MethodGet, "/s/"+share.ShareID, nil); resp.StatusCode != http.StatusGone || !strings.Contains(page, "This link has expired.") {
		t.Errorf("expired page: %d", resp.StatusCode)
	}
	if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+share.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusGone || errCode(b) != "expired" {
		t.Errorf("expired token: %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.createRequestFile(reqID, smallSize); resp.StatusCode != http.StatusGone {
		t.Errorf("expired request upload: %d", resp.StatusCode)
	}
	if err := e.runJobs(clk.Now); err != nil {
		t.Fatal(err)
	}
	if exists(e.blobDir(share.UploadID)) || exists(e.blobDir(f.UploadID)) {
		t.Error("expired links left blobs")
	}
	if !exists(e.blobDir(long.UploadID)) {
		t.Error("live share deleted")
	}
	if resp, _ := e.do(http.MethodGet, "/s/"+share.ShareID, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("purged page: %d", resp.StatusCode)
	}
}

// An expired request link takes its files with it at once: they disappear
// from the inbox and its counts, and can no longer be downloaded, even
// before the cleanup job deletes them.
func TestExpiredRequestHidesFilesBeforeCleanup(t *testing.T) {
	t.Parallel()
	clk := newClock()
	e := newTestEnvWith(t, testOpts{now: clk.Now})
	start := clk.Now()
	o := e.newOwner()
	reqID := o.createRequest(map[string]any{"expires_in": "1h", "max_files": 2, "max_bytes": 2 * smallSize})
	_, f := e.createRequestFile(reqID, smallSize)
	e.uploadAll(f, randBytes(int(smallSize)))
	_, b := e.api(http.MethodGet, "/api/inbox", nil, nil)
	var inbox struct{ Inbox []struct{ ID string } }
	mustJSON(t, b, &inbox)
	if len(inbox.Inbox) != 1 {
		t.Fatalf("inbox: %s", b)
	}
	fileID := inbox.Inbox[0].ID
	_, b = e.api(http.MethodPost, "/api/inbox/"+fileID+"/download", map[string]any{}, nil)
	var g struct{ Token string }
	mustJSON(t, b, &g)
	if resp, _ := e.download(e.client, g.Token, map[string]string{"Range": "bytes=0-0"}); resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("inbox download while live: %d", resp.StatusCode)
	}

	// Stay active (30 min session idle timeout) and keep the token in use
	// (1 h idle) while the link runs out.
	for range 4 {
		clk.Advance(16 * time.Minute)
		if resp, _ := e.api(http.MethodGet, "/api/requests", nil, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("session lost: %d", resp.StatusCode)
		}
		if clk.Now().Before(start.Add(time.Hour)) {
			if resp, _ := e.download(e.client, g.Token, map[string]string{"Range": "bytes=0-0"}); resp.StatusCode != http.StatusPartialContent {
				t.Fatalf("inbox download while live: %d", resp.StatusCode)
			}
		}
	}
	if _, b := e.api(http.MethodGet, "/api/inbox", nil, nil); !strings.Contains(string(b), `"inbox":[]`) {
		t.Errorf("expired link's file listed: %s", b)
	}
	if resp, b := e.api(http.MethodPost, "/api/inbox/"+fileID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("token for an expired link's file: %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.download(e.client, g.Token, nil); resp.StatusCode != http.StatusGone {
		t.Errorf("earlier token after the link expired: %d", resp.StatusCode)
	}
	if _, page := e.do(http.MethodGet, "/", nil); !strings.Contains(page, `Received files (<span id="inbox-count">0</span>)`) {
		t.Error("dashboard counts the expired link's file")
	}
	if _, page := e.do(http.MethodGet, "/inbox", nil); !strings.Contains(page, `data-count="0"`) {
		t.Error("inbox page counts the expired link's file")
	}
	if !exists(e.blobDir(f.UploadID)) {
		t.Fatal("the file was swept: the test no longer covers the window before cleanup")
	}
}

func TestStaleUploadsCollected(t *testing.T) {
	t.Parallel()
	clk := newClock()
	e := newTestEnvWith(t, testOpts{now: clk.Now})
	e.newOwner()
	u := e.createShare(e.client, blob.CipherSize(blob.PartPlainSize+1), map[string]any{"expires_in": "30d"})
	e.putPart(u, 1, randBytes(17))
	clk.Advance(23 * time.Hour)
	runner := e.runner(clk.Now)
	_ = runner.RunOnce(context.Background())
	if !exists(e.blobDir(u.UploadID)) {
		t.Fatal("collected too early")
	}
	clk.Advance(2 * time.Hour)
	if resp, b := e.putPart(u, 1, randBytes(17)); resp.StatusCode != http.StatusGone || errCode(b) != "expired" {
		t.Errorf("put after 24h: %d %s", resp.StatusCode, b)
	}
	_ = runner.RunOnce(context.Background())
	if exists(e.blobDir(u.UploadID)) {
		t.Error("stale upload left on disk")
	}
	if resp, _ := e.api(http.MethodGet, "/upload/"+u.UploadID, nil, e.bearer(u)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("stale upload still known: %d", resp.StatusCode)
	}
}

func TestCSRFOnStateChangingEndpoints(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	u := e.createShare(e.client, smallSize, nil)
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/shares"}, {"DELETE", "/api/shares/" + u.ShareID}, {"POST", "/api/s/" + u.ShareID + "/download"},
		{"POST", "/api/requests"}, {"DELETE", "/api/requests/" + id}, {"PUT", "/api/requests/" + id + "/label"},
		{"POST", "/api/r/" + id + "/files"}, {"POST", "/api/inbox/" + id + "/download"}, {"DELETE", "/api/inbox/" + id},
		{"PUT", "/upload/" + u.UploadID + "/part/0"}, {"POST", "/upload/" + u.UploadID + "/finalize"},
	} {
		for _, hdr := range []map[string]string{
			{"Sec-Fetch-Site": "cross-site"},
			{"Sec-Fetch-Site": "", "Origin": "https://evil.example"},
			{"Sec-Fetch-Site": ""},
		} {
			resp, _ := e.api(c.method, c.path, map[string]any{}, hdr)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s %v: %d", c.method, c.path, hdr, resp.StatusCode)
			}
		}
	}
	// The share was not revoked by the blocked DELETE.
	if _, b := e.api(http.MethodGet, "/upload/"+u.UploadID, nil, e.bearer(u)); !strings.Contains(string(b), "parts_present") {
		t.Error("blocked request had an effect")
	}
}

func TestDLFallbackAndServiceWorker(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	resp, body := e.do(http.MethodGet, "/_dl/AAAAAAAAAAAAAAAAAAAAAA", nil)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "could not start") {
		t.Errorf("/_dl: %d", resp.StatusCode)
	}
}

// runner returns a job runner with the file cleanup tasks of e on clock now.
func (e *testEnv) runner(now func() time.Time) *jobs.Runner {
	r := jobs.NewRunner(0, slog.New(slog.DiscardHandler))
	for _, t := range jobs.FileTasks(e.s.store, e.s.blobs, now) {
		r.Add(t)
	}
	return r
}

func (e *testEnv) runJobs(now func() time.Time) error {
	return e.runner(now).RunOnce(context.Background())
}
