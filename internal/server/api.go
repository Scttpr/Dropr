package server

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/store"
)

var b64 = base64.RawURLEncoding.Strict()

// Opaque field bounds (FORMAT.md §5, §8.6; ARCHITECTURE.md §2).
const (
	minMeta       = blob.TagSize + 1 // sealed JSON: at least one byte plus the tag
	maxMeta       = 4096             // decoded, tag included
	wrappedKeyLen = 80               // HPKE enc(32) || ct(48)
	minLabel      = 32 + blob.TagSize + 1
	maxLabel      = 512
	// Request link caps.
	maxRequestFiles  = 1000
	maxShareDownload = 999_999
)

// API errors, in plain language (ARCHITECTURE.md §3 "Error codes").
var (
	errUnauthenticated = httpx.Errorf(http.StatusUnauthorized, "unauthenticated", "Your session has expired. Please sign in again.")
	errLocked          = httpx.Errorf(http.StatusForbidden, "locked", "Unlock your inbox with your passkey first.")
	errBadRequest      = httpx.Errorf(http.StatusBadRequest, "bad_request", "The request was not accepted. Please reload the page and try again.")
	errInvalidSize     = httpx.Errorf(http.StatusBadRequest, "invalid_size", "The file size does not match its parts. Please try again.")
	errTooLarge        = httpx.Errorf(http.StatusRequestEntityTooLarge, "too_large", "This file is too large.")
	errBodyTooLarge    = httpx.Errorf(http.StatusRequestEntityTooLarge, "too_large", "The request is too large.")
	errQuota           = httpx.Errorf(http.StatusRequestEntityTooLarge, "quota_exceeded", "There is not enough storage space left for this file.")
	errDiskFull        = httpx.Errorf(http.StatusInsufficientStorage, "disk_full", "The server is out of disk space. Please try again later.")
	errLinkUnknown     = httpx.Errorf(http.StatusNotFound, "not_found", msgLinkUnknown)
	errNotFound        = httpx.Errorf(http.StatusNotFound, "not_found", "This item does not exist or was deleted.")
	errExpired         = httpx.Errorf(http.StatusGone, "expired", msgLinkExpired)
	errExhausted       = httpx.Errorf(http.StatusGone, "exhausted", msgLinkExhausted)
	errClosed          = httpx.Errorf(http.StatusGone, "closed", msgLinkClosed)
	errFull            = httpx.Errorf(http.StatusConflict, "link_full", "This link cannot accept this file: it has reached its file or size limit.")
	errUploadUnknown   = httpx.Errorf(http.StatusNotFound, "not_found", "This upload does not exist or was canceled.")
	errBadToken        = httpx.Errorf(http.StatusUnauthorized, "bad_token", "This upload link is not valid. Please start the upload again.")
	errUploadExpired   = httpx.Errorf(http.StatusGone, "expired", "This upload has expired. Please start again.")
	errUploadDone      = httpx.Errorf(http.StatusConflict, "already_complete", "This upload is already finished.")
	errBadPart         = httpx.Errorf(http.StatusBadRequest, "bad_part", "This part number is not valid for this file.")
	errPartSize        = httpx.Errorf(http.StatusBadRequest, "wrong_part_size", "This part does not have the expected size.")
	errBadParts        = httpx.Errorf(http.StatusBadRequest, "bad_parts", "The number of parts does not match this file.")
	errIncomplete      = httpx.Errorf(http.StatusConflict, "incomplete", "Some parts of the file are missing. The upload will resume.")
	errTokenSpent      = httpx.Errorf(http.StatusGone, "token_used", "This download link has been used up. Reload the page to download again.")
	errTooSlow         = httpx.Errorf(http.StatusRequestTimeout, "too_slow", "The connection is too slow. The upload will retry.")
	errInternal        = httpx.Errorf(http.StatusInternalServerError, "internal", "Something went wrong on the server. Please try again.")
)

func (s *Server) apiError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.ErrorContext(r.Context(), what, "err", err)
	httpx.WriteError(w, errInternal)
}

// apiSession returns the session or answers 401. With unlocked set it also
// requires a passkey unlock (403 "locked").
func (s *Server) apiSession(w http.ResponseWriter, r *http.Request, unlocked bool) *session.Session {
	sess := session.FromContext(r.Context())
	if sess == nil {
		httpx.WriteError(w, errUnauthenticated)
		return nil
	}
	if unlocked && !s.sessions.IsUnlocked(sess) {
		httpx.WriteError(w, errLocked)
		return nil
	}
	return sess
}

// decode strictly decodes a JSON body, answering 400/413/415 on failure.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := httpx.DecodeJSON(r, v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			httpx.WriteError(w, errBodyTooLarge)
		} else {
			httpx.WriteError(w, errBadRequest)
		}
		return false
	}
	return true
}

// decodeEmpty accepts an empty body or an empty JSON object.
func decodeEmpty(w http.ResponseWriter, r *http.Request) bool {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteError(w, errBodyTooLarge)
		return false
	}
	if len(b) == 0 {
		return true
	}
	var v struct{}
	if err := httpx.DecodeJSONBytesFrom(bytesReader(b), &v); err != nil {
		httpx.WriteError(w, errBadRequest)
		return false
	}
	return true
}

// limits are the instance limits request validation depends on.
type limits struct {
	maxFileSize   int64 // plaintext bytes
	defaultExpiry string
}

func (s *Server) limits() limits {
	return limits{maxFileSize: s.cfg.Limits.MaxFileSizeBytes, defaultExpiry: s.cfg.Limits.DefaultExpiry}
}

func expiry(in, def string) (time.Duration, *httpx.APIError) {
	if in == "" {
		in = def
	}
	d, ok := config.ExpiryDuration(in)
	if !ok {
		return 0, errBadRequest
	}
	return d, nil
}

// fileGeometry validates a declared ciphertext size and part count against
// the format and the instance file size limit.
func fileGeometry(size int64, parts int, l limits) (blob.Geometry, *httpx.APIError) {
	g, err := blob.NewGeometry(size, parts)
	if err != nil {
		if size > blob.MaxCipherSize {
			return blob.Geometry{}, errTooLarge
		}
		return blob.Geometry{}, errInvalidSize
	}
	if g.Plain() > l.maxFileSize {
		return blob.Geometry{}, errTooLarge
	}
	return g, nil
}

func opaque(s string, minLen, maxLen int) ([]byte, bool) {
	if len(s) > base64.RawURLEncoding.EncodedLen(maxLen) {
		return nil, false
	}
	b, err := b64.DecodeString(s)
	if err != nil || len(b) < minLen || len(b) > maxLen {
		return nil, false
	}
	return b, true
}

// shareRequest is the body of POST /api/shares.
type shareRequest struct {
	Size         int64  `json:"size"`
	Parts        int    `json:"parts"`
	Meta         string `json:"meta"`
	ExpiresIn    string `json:"expires_in"`
	MaxDownloads *int64 `json:"max_downloads"`
}

type validShare struct {
	geo          blob.Geometry
	meta         []byte
	ttl          time.Duration
	maxDownloads *int64
}

func (b *shareRequest) validate(l limits) (*validShare, *httpx.APIError) {
	g, e := fileGeometry(b.Size, b.Parts, l)
	if e != nil {
		return nil, e
	}
	meta, ok := opaque(b.Meta, minMeta, maxMeta)
	if !ok {
		return nil, errBadRequest
	}
	ttl, e := expiry(b.ExpiresIn, l.defaultExpiry)
	if e != nil {
		return nil, e
	}
	if b.MaxDownloads != nil && (*b.MaxDownloads < 1 || *b.MaxDownloads > maxShareDownload) {
		return nil, errBadRequest
	}
	return &validShare{geo: g, meta: meta, ttl: ttl, maxDownloads: b.MaxDownloads}, nil
}

// requestRequest is the body of POST /api/requests. max_bytes is the total
// ciphertext the link accepts.
type requestRequest struct {
	ExpiresIn string `json:"expires_in"`
	MaxFiles  int64  `json:"max_files"`
	MaxBytes  int64  `json:"max_bytes"`
	SingleUse bool   `json:"single_use"`
}

type validRequest struct {
	ttl       time.Duration
	maxFiles  int64
	maxBytes  int64
	singleUse bool
}

// validate: 1 ≤ max_files ≤ 1000; 16 ≤ max_bytes ≤ max_files × (ciphertext
// of one maximal file).
func (b *requestRequest) validate(l limits) (*validRequest, *httpx.APIError) {
	ttl, e := expiry(b.ExpiresIn, l.defaultExpiry)
	if e != nil {
		return nil, e
	}
	if b.MaxFiles < 1 || b.MaxFiles > maxRequestFiles {
		return nil, errBadRequest
	}
	if b.MaxBytes < blob.TagSize || b.MaxBytes > b.MaxFiles*blob.CipherSize(l.maxFileSize) {
		return nil, errBadRequest
	}
	return &validRequest{ttl: ttl, maxFiles: b.MaxFiles, maxBytes: b.MaxBytes, singleUse: b.SingleUse}, nil
}

// requestFileRequest is the body of POST /api/r/{id}/files.
type requestFileRequest struct {
	Size       int64  `json:"size"`
	Parts      int    `json:"parts"`
	Meta       string `json:"meta"`
	WrappedKey string `json:"wrapped_key"`
}

type validRequestFile struct {
	geo        blob.Geometry
	meta       []byte
	wrappedKey []byte
}

func (b *requestFileRequest) validate(l limits) (*validRequestFile, *httpx.APIError) {
	g, e := fileGeometry(b.Size, b.Parts, l)
	if e != nil {
		return nil, e
	}
	meta, ok := opaque(b.Meta, minMeta, maxMeta)
	if !ok {
		return nil, errBadRequest
	}
	wk, ok := opaque(b.WrappedKey, wrappedKeyLen, wrappedKeyLen)
	if !ok {
		return nil, errBadRequest
	}
	return &validRequestFile{geo: g, meta: meta, wrappedKey: wk}, nil
}

// labelRequest is the body of PUT /api/requests/{id}/label.
type labelRequest struct {
	LabelMeta string `json:"label_meta"`
}

func (b *labelRequest) validate() ([]byte, *httpx.APIError) {
	l, ok := opaque(b.LabelMeta, minLabel, maxLabel)
	if !ok {
		return nil, errBadRequest
	}
	return l, nil
}

// finalizeRequest is the body of POST /upload/{id}/finalize.
type finalizeRequest struct {
	Parts int `json:"parts"`
}

// storeError maps link errors from the store to API errors.
func storeError(err error) *httpx.APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errLinkUnknown
	case errors.Is(err, store.ErrExpired):
		return errExpired
	case errors.Is(err, store.ErrExhausted):
		return errExhausted
	case errors.Is(err, store.ErrTokenSpent):
		return errTokenSpent
	case errors.Is(err, store.ErrClosed):
		return errClosed
	case errors.Is(err, store.ErrFull):
		return errFull
	case errors.Is(err, store.ErrQuota):
		return errQuota
	}
	return nil
}
