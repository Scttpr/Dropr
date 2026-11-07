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

// userID returns the ID of the env's only account.
func (e *testEnv) userID() string {
	e.t.Helper()
	users, err := e.s.store.ListUsers(e.t.Context())
	if err != nil || len(users) != 1 {
		e.t.Fatalf("users: %d %v", len(users), err)
	}
	return users[0].ID
}

// dueForRevalidation makes every session due for revalidation.
func (e *testEnv) dueForRevalidation() {
	e.t.Helper()
	if _, err := e.s.store.DB().W.ExecContext(e.t.Context(), `UPDATE sessions SET revalidated_at = revalidated_at - 3600`); err != nil {
		e.t.Fatal(err)
	}
}

// 2026-11b L-2: when revalidation finds the owner's role withdrawn, their
// share links expire at once (page, download token, uploads in progress)
// and stay expired after the owner signs in again.
func TestSharesExpireWhenOwnerLosesRole(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	anon := &http.Client{Transport: e.client.Transport}
	done := e.createShare(e.client, smallSize, nil)
	e.uploadAll(done, randBytes(int(smallSize)))
	pending := e.createShare(e.client, smallSize, nil)
	if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+done.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("download token while active: %d %s", resp.StatusCode, b)
	}

	e.op.Set(func(k *oidctest.Knobs) { k.RefreshClaims = map[string]any{"name": "Alice Example", "roles": []any{}} })
	e.dueForRevalidation()
	if resp, _ := e.api(http.MethodGet, "/api/shares", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revalidation without the role kept the session: %d", resp.StatusCode)
	}
	expired := func(when string) {
		t.Helper()
		if resp, page := e.do(http.MethodGet, "/s/"+done.ShareID, nil); resp.StatusCode != http.StatusGone || strings.Contains(page, "data-share-id") {
			t.Errorf("share page %s: %d", when, resp.StatusCode)
		}
		if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+done.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusGone || errCode(b) != "expired" {
			t.Errorf("download token %s: %d %s", when, resp.StatusCode, b)
		}
		if resp, b := e.putPart(pending, 0, randBytes(int(smallSize))); resp.StatusCode != http.StatusGone || errCode(b) != "expired" {
			t.Errorf("part upload %s: %d %s", when, resp.StatusCode, b)
		}
		if resp, b := e.finalize(pending, 1); resp.StatusCode != http.StatusGone || errCode(b) != "expired" {
			t.Errorf("finalize %s: %d %s", when, resp.StatusCode, b)
		}
	}
	expired("after the owner lost the role")
	var tokens int
	if err := e.s.store.DB().R.QueryRowContext(t.Context(), `SELECT count(*) FROM dl_tokens`).Scan(&tokens); err != nil || tokens != 0 {
		t.Errorf("download tokens left: %d %v", tokens, err)
	}

	// Signing in again does not bring the shares back; new ones work.
	e.op.Set(func(k *oidctest.Knobs) { k.RefreshClaims = nil })
	e.login()
	expired("after the owner signed in again")
	e.createShare(e.client, smallSize, nil)
}

// 2026-11b L-2: a transient failure of the provider ends the session but
// is not a loss of access: share links keep serving.
func TestSharesSurviveTransientRevalidationFailure(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	anon := &http.Client{Transport: e.client.Transport}
	u := e.createShare(e.client, smallSize, nil)
	e.uploadAll(u, randBytes(int(smallSize)))

	e.op.Set(func(k *oidctest.Knobs) { k.TokenEndpointDown = true })
	e.dueForRevalidation()
	if resp, _ := e.api(http.MethodGet, "/api/shares", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revalidation against a down provider kept the session: %d", resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodGet, "/s/"+u.ShareID, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("share page after a transient failure: %d", resp.StatusCode)
	}
	if resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+u.ShareID+"/download", map[string]any{}, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("download token after a transient failure: %d %s", resp.StatusCode, b)
	}
	if active, err := e.s.store.AccountActive(t.Context(), e.userID()); err != nil || !active {
		t.Errorf("account marked inactive by a transient failure: %v %v", active, err)
	}
}

// 2026-11b L-3: a disabled owner cannot sign in, and their request links
// stay closed until `dropr user enable`.
func TestDisabledOwner(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()
	id := o.createRequest(map[string]any{"max_files": 5, "max_bytes": 5 * smallSize})
	uid := e.userID()
	if _, _, err := e.s.store.DisableUser(t.Context(), uid, time.Now()); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.api(http.MethodGet, "/api/requests", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("session of a disabled user: %d", resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodGet, "/auth/login", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("login of a disabled user: %d", resp.StatusCode)
	}
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusGone {
		t.Errorf("request upload while disabled: %d", resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodGet, "/r/"+id, nil); resp.StatusCode != http.StatusGone {
		t.Errorf("request page while disabled: %d", resp.StatusCode)
	}
	if _, err := e.s.store.EnableUser(t.Context(), uid); err != nil {
		t.Fatal(err)
	}
	e.login()
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusCreated {
		t.Errorf("request upload after enable: %d", resp.StatusCode)
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

// Regression tests for the findings of the 2026-11b audit.

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *testEnv) partClaims() int {
	e.s.parts.mu.Lock()
	defer e.s.parts.mu.Unlock()
	return len(e.s.parts.m)
}

// M-1: a newer PUT of a part stops the one still receiving it (a client
// retry after a dropped connection), so one part never holds two slots.
func TestPartPutSupersedesOlderPut(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.newOwner()
	u := e.createShare(e.client, smallSize, nil)
	pw, done := e.pendingPut(u, 0, smallSize)
	if _, err := pw.Write(randBytes(int(smallSize / 2))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.partClaims() == 1 })
	data := randBytes(int(smallSize))
	if resp, b := e.putPart(u, 0, data); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("newer put: %d %s", resp.StatusCode, b)
	}
	_ = pw.Close()
	if resp := <-done; resp != nil && resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("superseded put: %d", resp.StatusCode)
	}
	got, err := os.ReadFile(filepath.Join(e.blobDir(u.UploadID), "part00000"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("the newer part was not stored")
	}
	waitFor(t, func() bool { return e.partClaims() == 0 && e.s.capStreams.Active() == 0 })
}

// M-1: one upload holds at most maxStreamsPerCapability transfer slots,
// whatever the per-address cap allows.
func TestStreamCapPerUpload(t *testing.T) {
	t.Parallel()
	e := newTestEnvWith(t, testOpts{diskUsage: func(string) (uint64, uint64, error) { return 1 << 50, 1 << 51, nil }})
	e.newOwner()
	parts := maxStreamsPerCapability + 1
	u := e.createShare(e.client, blob.CipherSize(int64(parts)*blob.PartPlainSize), nil)
	var writers []*io.PipeWriter
	var dones []<-chan *http.Response
	for n := range maxStreamsPerCapability {
		w, d := e.pendingPut(u, n, blob.PartCipherSize)
		_, _ = w.Write([]byte{1})
		writers, dones = append(writers, w), append(dones, d)
	}
	waitFor(t, func() bool { return e.s.capStreams.Active() == maxStreamsPerCapability })
	w, d := e.pendingPut(u, parts-1, blob.PartCipherSize)
	if resp := <-d; resp == nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("one stream past the per-upload cap: %v", resp)
	}
	_ = w.Close()
	// Another upload from the same address is not affected.
	v := e.createShare(e.client, smallSize, nil)
	if resp, b := e.putPart(v, 0, randBytes(int(smallSize))); resp.StatusCode != http.StatusNoContent {
		t.Errorf("other upload: %d %s", resp.StatusCode, b)
	}
	for i, w := range writers {
		_ = w.CloseWithError(errors.New("client gone"))
		<-dones[i]
	}
}

// I6: the space check runs only for a live request link, so an unknown link
// answers 404 whatever the disk state.
func TestRequestFileSpaceCheckAfterLink(t *testing.T) {
	t.Parallel()
	e := newTestEnvWith(t, testOpts{diskUsage: func(string) (uint64, uint64, error) { return 0, 1 << 40, nil }})
	e.newOwner()
	if resp, _ := e.createRequestFile("AAAAAAAAAAAAAAAAAAAAAA", smallSize); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown link on a full disk: %d", resp.StatusCode)
	}
	// Creating the link itself is refused below the headroom (M-3)...
	if resp, b := e.api(http.MethodPost, "/api/requests", map[string]any{"max_files": 1, "max_bytes": smallSize}, nil); resp.StatusCode != http.StatusInsufficientStorage || errCode(b) != "disk_full" {
		t.Errorf("request link on a full disk: %d %s", resp.StatusCode, b)
	}
	// ...so make one directly to check the upload answer.
	id := "BBBBBBBBBBBBBBBBBBBBBB"
	if _, err := e.s.store.DB().W.ExecContext(t.Context(), `INSERT INTO requests (id, owner_id, expires_at, max_files, max_bytes, created_at)
		SELECT ?, id, ?, 1, ?, ? FROM users`, id, time.Now().Add(time.Hour).Unix(), smallSize, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.createRequestFile(id, smallSize); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("live link on a full disk: %d", resp.StatusCode)
	}
}

// M-3: the owner write API is rate limited per user, with JSON 429 and
// Retry-After; reads are not.
func TestOwnerWritesRateLimited(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()
	id := o.createRequest(map[string]any{"max_files": 1, "max_bytes": smallSize})
	label := map[string]any{"label_meta": b64t.EncodeToString(randBytes(176))}
	var resp *http.Response
	var b []byte
	for range 400 {
		resp, b = e.api(http.MethodPut, "/api/requests/"+id+"/label", label, nil)
		if resp.StatusCode != http.StatusNoContent {
			break
		}
	}
	if resp.StatusCode != http.StatusTooManyRequests || errCode(b) != "rate_limited" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("owner writes not limited: %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.api(http.MethodGet, "/api/requests", nil, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("read after the write limit: %d", resp.StatusCode)
	}
}

// A01-2: an inbox token used without the owner's session spends nothing,
// and I1: a share download that serves nothing (416) does not count.
func TestDownloadChecksBeforeSpending(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()
	anon := &http.Client{Transport: e.client.Transport}
	id := o.createRequest(map[string]any{"max_files": 1, "max_bytes": smallSize})
	_, u := e.createRequestFile(id, smallSize)
	data := randBytes(int(smallSize))
	e.uploadAll(u, data)
	_, b := e.api(http.MethodGet, "/api/inbox", nil, nil)
	var inbox struct{ Inbox []struct{ ID string } }
	mustJSON(t, b, &inbox)
	_, b = e.api(http.MethodPost, "/api/inbox/"+inbox.Inbox[0].ID+"/download", map[string]any{}, nil)
	var g struct{ Token string }
	mustJSON(t, b, &g)
	for range 5 {
		if resp, _ := e.download(anon, g.Token, nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("inbox token without a session: %d", resp.StatusCode)
		}
	}
	if resp, got := e.download(e.client, g.Token, nil); resp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("owner after refused uses: %d", resp.StatusCode)
	}

	s := e.createShare(e.client, smallSize, map[string]any{"max_downloads": 1})
	e.uploadAll(s, data)
	token := func() string {
		resp, b := e.apiWith(anon, http.MethodPost, "/api/s/"+s.ShareID+"/download", map[string]any{}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("share token: %d %s", resp.StatusCode, b)
		}
		var g struct{ Token string }
		mustJSON(t, b, &g)
		return g.Token
	}
	if resp, _ := e.download(anon, token(), map[string]string{"Range": "bytes=99999999-"}); resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("unsatisfiable range: %d", resp.StatusCode)
	}
	if resp, got := e.download(anon, token(), nil); resp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("the single download after a 416: %d", resp.StatusCode)
	}
}
