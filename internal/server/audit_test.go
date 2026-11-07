package server

// Regression tests for the findings of the 2026-11 internal security audit.

import (
	"bytes"
	"errors"
	"io"
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
	"github.com/scttpr/dropr/internal/store"
)

// pendingPut starts a part PUT whose body the test feeds through w; the
// response arrives on the returned channel.
func (e *testEnv) pendingPut(u upload, n int, size int64) (w *io.PipeWriter, done <-chan *http.Response) {
	e.t.Helper()
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(e.t.Context(), http.MethodPut, e.origin+"/upload/"+u.UploadID+"/part/"+strconv.Itoa(n), pr)
	req.ContentLength = size
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+u.UploadToken)
	ch := make(chan *http.Response, 1)
	go func() {
		resp, err := (&http.Client{Transport: e.client.Transport}).Do(req)
		if err != nil {
			ch <- nil
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		ch <- resp
	}()
	return pw, ch
}

// L-3: a part PUT that was already streaming when the upload got finalized
// must not replace data in the now complete blob.
func TestPartPutRacingFinalize(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	u := e.createShare(e.client, smallSize, nil)
	original := randBytes(int(smallSize))
	if resp, b := e.putPart(u, 0, original); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: %d %s", resp.StatusCode, b)
	}
	// A second PUT of part 0 starts and stalls half-way.
	replacement := randBytes(int(smallSize))
	pw, done := e.pendingPut(u, 0, smallSize)
	if _, err := pw.Write(replacement[:smallSize/2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if resp, b := e.finalize(u, 1); resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize: %d %s", resp.StatusCode, b)
	}
	// The late body completes after finalize.
	if _, err := pw.Write(replacement[smallSize/2:]); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	resp := <-done
	if resp == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("late part: %v", resp)
	}
	got, err := os.ReadFile(filepath.Join(e.blobDir(u.UploadID), "part00000"))
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("a part written after finalize replaced the complete blob's data")
	}
}

// I-2: finalize of an upload whose row was deleted between the checks
// (revocation, stale-upload collection) is not reported as a success.
func TestFinalizeDeletedUpload(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	u := e.createShare(e.client, smallSize, nil)
	up, err := e.s.store.UploadByID(t.Context(), u.UploadID)
	if err != nil {
		t.Fatal(err)
	}
	if resp, b := e.api(http.MethodDelete, "/api/shares/"+u.ShareID, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}
	if err := e.s.store.CompleteUpload(t.Context(), up, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("complete a deleted upload: %v", err)
	}
	if resp, _ := e.finalize(u, 1); resp.StatusCode != http.StatusNotFound {
		t.Errorf("finalize a revoked upload: %d", resp.StatusCode)
	}
	// An already complete upload stays idempotent.
	v := e.createShare(e.client, smallSize, nil)
	e.uploadAll(v, randBytes(int(smallSize)))
	up, _ = e.s.store.UploadByID(t.Context(), v.UploadID)
	if err := e.s.store.CompleteUpload(t.Context(), up, time.Now()); !errors.Is(err, store.ErrComplete) {
		t.Errorf("complete twice: %v", err)
	}
}

// L-2: one counted download token cannot serve unlimited full downloads.
// It may serve at most store.TokenByteBudget bytes (resumes included).
func TestDownloadTokenByteBudget(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	anon := &http.Client{Transport: e.client.Transport}
	u := e.createShare(e.client, smallSize, map[string]any{"max_downloads": 1})
	data := randBytes(int(smallSize))
	e.uploadAll(u, data)
	_, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil)
	var g struct{ Token string }
	mustJSON(t, b, &g)

	budget := store.TokenByteBudget(smallSize)
	served := int64(0)
	// HEAD requests serve nothing and cost nothing.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodHead, e.origin+"/dl/"+g.Token, nil)
	if resp, err := anon.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("head: %v %v", resp, err)
	}
	// A resume (Range) costs only what it serves.
	resp, got := e.download(anon, g.Token, map[string]string{"Range": "bytes=500-"})
	if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(got, data[500:]) {
		t.Fatalf("resume: %d", resp.StatusCode)
	}
	served += smallSize - 500
	full := 0
	for served+smallSize <= budget {
		resp, got := e.download(anon, g.Token, nil)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
			t.Fatalf("full download %d within the budget: %d", full+1, resp.StatusCode)
		}
		served += smallSize
		full++
	}
	if full > 2 {
		t.Errorf("%d full downloads with one max_downloads=1 token", full)
	}
	resp, b = e.download(anon, g.Token, nil)
	if resp.StatusCode != http.StatusGone || errCode(b) != "token_used" {
		t.Fatalf("past the budget: %d %s", resp.StatusCode, b)
	}
	// The rest of the budget still serves a small resume.
	if left := budget - served; left > 0 {
		resp, _ = e.download(anon, g.Token, map[string]string{"Range": "bytes=" + strconv.FormatInt(smallSize-left, 10) + "-"})
		if resp.StatusCode != http.StatusPartialContent {
			t.Errorf("resume within the remaining budget: %d", resp.StatusCode)
		}
	}
	// And the share's single download is spent: no new token.
	if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusGone || errCode(b) != "exhausted" {
		t.Errorf("new token: %d %s", resp.StatusCode, b)
	}
}

// L-4: concurrent part uploads and downloads are capped per client address
// (and in total); a freed slot can be reused.
func TestTransferStreamCap(t *testing.T) {
	t.Parallel()
	e := newTestEnvWith(t, testOpts{extraConfig: "[limits]\nmax_transfers = 10\nmax_transfers_per_ip = 2\n"})
	e.newOwner()
	u := e.createShare(e.client, blob.CipherSize(blob.PartPlainSize+1000), nil) // 2 parts
	w0, done0 := e.pendingPut(u, 0, blob.PartCipherSize)
	w1, done1 := e.pendingPut(u, 1, blob.CipherSize(blob.PartPlainSize+1000)-blob.PartCipherSize)
	_, _ = w0.Write([]byte{1})
	_, _ = w1.Write([]byte{1})
	deadline := time.Now().Add(5 * time.Second)
	for e.s.streams.Active() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	resp, b := e.putPart(u, 1, randBytes(10))
	if resp.StatusCode != http.StatusTooManyRequests || errCode(b) != "too_many_transfers" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("third concurrent transfer: %d %s", resp.StatusCode, b)
	}
	_ = w1.CloseWithError(errors.New("client gone"))
	<-done1
	for e.s.streams.Active() > 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if resp, b := e.putPart(u, 1, randBytes(10)); resp.StatusCode != http.StatusBadRequest || errCode(b) != "wrong_part_size" {
		t.Errorf("transfer after a slot was freed: %d %s", resp.StatusCode, b)
	}
	_ = w0.CloseWithError(errors.New("client gone"))
	<-done0
}

// L-6: the free-space check counts what the uploads in progress still have
// to write, so concurrent uploads cannot each pass against the same space.
func TestDiskSpaceCountsInflightUploads(t *testing.T) {
	t.Parallel()
	const headroom = 1024
	var mu sync.Mutex
	avail := uint64(headroom + 2*smallSize + smallSize/2)
	e := newTestEnvWith(t, testOpts{
		extraConfig: "[limits]\ndisk_headroom = \"1KB\"\n",
		diskUsage: func(string) (uint64, uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			return avail, 1 << 40, nil
		},
	})
	e.newOwner()
	a := e.createShare(e.client, smallSize, nil)
	e.createShare(e.client, smallSize, nil)
	resp, b := e.api(http.MethodPost, "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta()}, nil)
	if resp.StatusCode != http.StatusInsufficientStorage || errCode(b) != "disk_full" {
		t.Fatalf("third upload while two are reserved: %d %s", resp.StatusCode, b)
	}
	// Writing a's data moves it from "reserved" to "used" (the probe sees
	// less free space), so the check stays as strict; finalizing ends the
	// reservation.
	e.uploadAll(a, randBytes(int(smallSize)))
	mu.Lock()
	avail -= uint64(smallSize)
	mu.Unlock()
	if resp, b := e.api(http.MethodPost, "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta()}, nil); resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("after a's data landed: %d %s", resp.StatusCode, b)
	}
	mu.Lock()
	avail += uint64(smallSize) // a deleted by its owner, say
	mu.Unlock()
	if resp, b := e.api(http.MethodPost, "/api/shares", map[string]any{"size": smallSize, "parts": 1, "meta": meta()}, nil); resp.StatusCode != http.StatusCreated {
		t.Errorf("after the reservation ended: %d %s", resp.StatusCode, b)
	}
}

// I-3: when revalidation finds the owner's role withdrawn, their request
// links stop accepting uploads (and say so) until they sign in again with
// the role.
func TestRequestLinkClosedWhenOwnerLosesRole(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()
	id := o.createRequest(map[string]any{"max_files": 5, "max_bytes": 5 * smallSize})
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload while active: %d", resp.StatusCode)
	}

	e.op.Set(func(k *oidctest.Knobs) { k.RefreshClaims = map[string]any{"name": "Alice Example", "roles": []any{}} })
	// Make the session due for revalidation.
	if _, err := e.s.store.DB().W.ExecContext(t.Context(), `UPDATE sessions SET revalidated_at = revalidated_at - 3600`); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.api(http.MethodGet, "/api/requests", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revalidation without the role kept the session: %d", resp.StatusCode)
	}
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusGone {
		t.Errorf("upload after the owner lost the role: %d", resp.StatusCode)
	}
	if resp, page := e.do(http.MethodGet, "/r/"+id, nil); resp.StatusCode != http.StatusGone || strings.Contains(page, "data-request-id") {
		t.Errorf("request page after the owner lost the role: %d", resp.StatusCode)
	}

	// Signing in again with the role reopens the link.
	e.op.Set(func(k *oidctest.Knobs) { k.RefreshClaims = nil })
	e.login()
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusCreated {
		t.Errorf("upload after the owner signed in again: %d", resp.StatusCode)
	}
}

// I-8: responses ServeMux generates itself (path-cleaning redirects) carry
// the security headers, since the mux runs inside the header middleware.
// Only answers net/http writes before any handler runs (malformed request
// lines, 431) cannot; see docs/THREAT_MODEL.md.
func TestMuxGeneratedResponsesHaveHeaders(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	c := &http.Client{Transport: e.client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, e.origin+"/assets/../login", nil)
	req.URL.Opaque = "/assets/../login" // keep the dot segments
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 3 || resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("mux redirect: %d %v", resp.StatusCode, resp.Header)
	}
}
