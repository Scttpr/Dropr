package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/store"
)

// Sentinels of the part commit check.
var (
	errPartLate = errors.New("server: part arrived after finalize")
	errPartGone = errors.New("server: upload deleted while its part arrived")
)

const (
	// partReadTimeout bounds a stall while a part body arrives; it slides
	// with progress.
	partReadTimeout = 2 * time.Minute
	// UploadMaxAge is how long an upload may stay incomplete (PLAN.md §4).
	UploadMaxAge = 24 * time.Hour
)

// bearer returns the syntactically valid bearer secret of r, if any.
func bearer(r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !ids.ValidSecret(tok) {
		return "", false
	}
	return tok, true
}

// upload authenticates an upload request: the upload must exist and be
// attached to a link, and the bearer token must match its hash (compared in
// constant time). It answers and returns nil on failure.
func (s *Server) upload(w http.ResponseWriter, r *http.Request) (*store.Upload, blob.Geometry) {
	id := r.PathValue("upload_id")
	tok, ok := bearer(r)
	if !ids.Valid(id) {
		httpx.WriteError(w, errUploadUnknown)
		return nil, blob.Geometry{}
	}
	if !ok {
		httpx.WriteError(w, errBadToken)
		return nil, blob.Geometry{}
	}
	u, err := s.store.UploadByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errUploadUnknown)
		return nil, blob.Geometry{}
	} else if err != nil {
		s.apiError(w, r, "load upload", err)
		return nil, blob.Geometry{}
	}
	if !u.CheckToken(ids.Hash(tok)) {
		httpx.WriteError(w, errBadToken)
		return nil, blob.Geometry{}
	}
	g, err := blob.NewGeometry(u.Size, u.Parts)
	if err != nil {
		s.apiError(w, r, "stored geometry", err)
		return nil, blob.Geometry{}
	}
	return u, g
}

// uploadOpen reports whether parts may still be written or finalized: the
// upload is younger than 24 h and its link has not expired.
func (s *Server) uploadOpen(w http.ResponseWriter, u *store.Upload) bool {
	now := s.now()
	if now.Sub(u.CreatedAt) >= UploadMaxAge {
		httpx.WriteError(w, errUploadExpired)
		return false
	}
	if !u.ExpiresAt.After(now) {
		httpx.WriteError(w, errExpired)
		return false
	}
	return true
}

// parsePartNumber accepts a canonical decimal (no sign, no leading zeros).
func parsePartNumber(s string) (int, bool) {
	if s == "" || len(s) > 4 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// handlePutPart stores one ciphertext part. The body must be exactly the
// part's size: a wrong Content-Length is refused before reading, and a body
// that turns out shorter or longer is discarded without replacing anything.
// Re-sending a part replaces it.
func (s *Server) handlePutPart(w http.ResponseWriter, r *http.Request) {
	u, g := s.upload(w, r)
	if u == nil {
		return
	}
	if u.Complete {
		httpx.WriteError(w, errUploadDone)
		return
	}
	if !s.uploadOpen(w, u) {
		return
	}
	n, ok := parsePartNumber(r.PathValue("n"))
	want := g.PartSize(n)
	if !ok || want < 0 {
		httpx.WriteError(w, errBadPart)
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != want {
		httpx.WriteError(w, errPartSize)
		return
	}
	body := &blob.ProgressReader{R: r.Body, RC: http.NewResponseController(w), Timeout: partReadTimeout, MinRate: s.minRate()}
	// The body may take minutes to arrive: re-check, under the blob's lock
	// that finalize also takes, that the upload is still open right before
	// the part is renamed into place (audit L-3).
	err := s.blobs.WritePartIf(r.Context(), u.ID, n, want, body, func(ctx context.Context) error {
		cur, err := s.store.UploadByID(ctx, u.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return errPartGone
		case err != nil:
			return err
		case cur.Complete:
			return errPartLate
		}
		return nil
	})
	var mbe *http.MaxBytesError
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, errPartLate):
		httpx.WriteError(w, errUploadDone)
	case errors.Is(err, errPartGone):
		httpx.WriteError(w, errUploadUnknown)
	case errors.Is(err, blob.ErrTooSlow):
		s.log.InfoContext(r.Context(), "part upload too slow; aborted", "err", err)
		httpx.WriteError(w, errTooSlow)
	case errors.Is(err, blob.ErrPartSize):
		httpx.WriteError(w, errPartSize)
	case errors.As(err, &mbe):
		httpx.WriteError(w, errPartSize)
	case errors.Is(err, blob.ErrNoSpace):
		s.log.ErrorContext(r.Context(), "disk full while writing a part", "err", err)
		httpx.WriteError(w, errDiskFull)
	default:
		// Most likely the client went away mid-body.
		s.log.InfoContext(r.Context(), "part write failed", "err", err)
		httpx.WriteError(w, errBadRequest)
	}
}

type uploadStatus struct {
	PartsPresent []int `json:"parts_present"`
	Complete     bool  `json:"complete"`
}

// handleUploadStatus lists the parts already stored, for resuming.
func (s *Server) handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	u, g := s.upload(w, r)
	if u == nil {
		return
	}
	present, err := s.blobs.Present(u.ID, g)
	if err != nil {
		s.apiError(w, r, "list parts", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, uploadStatus{PartsPresent: present, Complete: u.Complete})
}

type finalized struct {
	UploadID string `json:"upload_id"`
	Complete bool   `json:"complete"`
}

// handleFinalize checks that every part is stored with its exact size and
// marks the upload complete, which makes the share or inbox entry visible.
// Finalizing a complete upload again answers the same success.
func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	u, g := s.upload(w, r)
	if u == nil {
		return
	}
	var body finalizeRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Parts != g.Parts {
		httpx.WriteError(w, errBadParts)
		return
	}
	ok := finalized{UploadID: u.ID, Complete: true}
	if u.Complete {
		httpx.WriteJSON(w, http.StatusOK, ok)
		return
	}
	if !s.uploadOpen(w, u) {
		return
	}
	// Under the blob's lock, so no part write can land between the check and
	// the state change (audit L-3).
	err := s.blobs.Locked(r.Context(), u.ID, func(ctx context.Context) error {
		if err := s.blobs.Verify(u.ID, g); err != nil {
			return err
		}
		return s.store.CompleteUpload(ctx, u, s.now())
	})
	switch {
	case err == nil, errors.Is(err, store.ErrComplete):
		httpx.WriteJSON(w, http.StatusOK, ok)
	case errors.Is(err, blob.ErrIncomplete):
		httpx.WriteError(w, errIncomplete)
	case errors.Is(err, store.ErrNotFound):
		// Deleted meanwhile (revoked, or collected as stale): audit I-2.
		httpx.WriteError(w, errUploadUnknown)
	default:
		s.apiError(w, r, "complete upload", err)
	}
}

// handleDownload serves the ciphertext a download token grants, with single
// Range support. The first GET of a share token counts one download; later
// requests with the same token (Range resumes) do not, but every token may
// serve at most store.TokenByteBudget bytes in total (410 token_used
// afterwards, audit L-2). Inbox tokens also require the owner's session.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	if !ids.ValidSecret(tok) {
		httpx.WriteError(w, errLinkUnknown)
		return
	}
	ctx := r.Context()
	hash := ids.Hash(tok)
	t, err := s.store.UseDownloadToken(ctx, hash, r.Method == http.MethodGet, func(size int64) int64 { return blob.Planned(r, size) }, s.now())
	if e := storeError(err); e != nil {
		httpx.WriteError(w, e)
		return
	} else if err != nil {
		s.apiError(w, r, "download token", err)
		return
	}
	if t.ShareID == "" {
		sess := session.FromContext(ctx)
		if sess == nil || sess.UserID() != t.OwnerID {
			httpx.WriteError(w, errNotFound)
			return
		}
	}
	rd, err := s.blobs.Open(t.BlobID, blob.Geometry{Size: t.Size, Parts: t.Parts})
	if err != nil {
		s.apiError(w, r, "open blob", err)
		return
	}
	defer func() { _ = rd.Close() }()
	sent := blob.Serve(w, r, rd, s.minRate())
	if err := s.store.RefundDownloadToken(context.WithoutCancel(ctx), hash, t.Reserved-sent); err != nil {
		s.log.ErrorContext(ctx, "refund download token", "err", err)
	}
}

// minRate is the minimum transfer rate (bytes per second over
// blob.RateWindow) of part uploads and downloads; 0 disables the check.
func (s *Server) minRate() int64 { return s.cfg.Limits.MinTransferRateBytes }
