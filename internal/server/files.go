package server

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/store"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// quota returns the instance default per-owner quota (users.quota_bytes
// overrides it per account).
func (s *Server) quota() int64 { return s.cfg.Limits.UserQuotaBytes }

// removeBlobs deletes blob files after their rows are gone. Failures are
// logged; the orphan sweep of the cleanup job retries them.
func (s *Server) removeBlobs(r *http.Request, blobIDs ...string) {
	for _, id := range blobIDs {
		if err := s.blobs.Remove(id); err != nil {
			s.log.ErrorContext(r.Context(), "remove blob", "err", err)
		}
	}
}

// checkSpace answers 507 when the disk cannot take size more bytes on top
// of what the uploads in progress still have to write (their declared size
// minus what is already on disk), so concurrent uploads cannot together
// overrun the headroom (audit L-6). An upload's reservation ends when it
// is finalized or collected, since only incomplete blobs count.
func (s *Server) checkSpace(w http.ResponseWriter, r *http.Request, size int64) bool {
	pending, err := s.store.IncompleteBlobs(r.Context())
	if err != nil {
		s.apiError(w, r, "pending uploads", err)
		return false
	}
	reserved := int64(0)
	for _, p := range pending {
		reserved += max(0, p.Size-s.blobs.DiskBytes(p.ID))
	}
	if err := s.blobs.CheckSpace(size + reserved); err != nil {
		if errors.Is(err, blob.ErrNoSpace) {
			httpx.WriteError(w, errDiskFull)
		} else {
			s.apiError(w, r, "disk space", err)
		}
		return false
	}
	return true
}

// createdUpload is the answer to a file creation.
type createdUpload struct {
	ShareID     string `json:"share_id,omitempty"`
	UploadID    string `json:"upload_id"`
	UploadToken string `json:"upload_token"`
}

func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	var body shareRequest
	if !decode(w, r, &body) {
		return
	}
	v, e := body.validate(s.limits())
	if e != nil {
		httpx.WriteError(w, e)
		return
	}
	if !s.checkSpace(w, r, v.geo.Size) {
		return
	}
	now := s.now()
	token := ids.NewSecret()
	shareID, blobID, err := s.store.CreateShare(r.Context(), &store.NewShare{
		OwnerID: sess.UserID(), Size: v.geo.Size, Parts: v.geo.Parts, Meta: v.meta,
		ExpiresAt: now.Add(v.ttl), MaxDownloads: v.maxDownloads, TokenHash: ids.Hash(token), DefaultQuota: s.quota(),
	}, now)
	if e := storeError(err); e != nil {
		httpx.WriteError(w, e)
		return
	} else if err != nil {
		s.apiError(w, r, "create share", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, createdUpload{ShareID: shareID, UploadID: blobID, UploadToken: token})
}

type shareSummary struct {
	ID            string `json:"id"`
	Size          int64  `json:"size"`
	Parts         int    `json:"parts"`
	ExpiresAt     int64  `json:"expires_at"`
	MaxDownloads  *int64 `json:"max_downloads"`
	DownloadCount int64  `json:"download_count"`
	CreatedAt     int64  `json:"created_at"`
}

func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	shares, err := s.store.SharesByOwner(r.Context(), sess.UserID(), s.now())
	if err != nil {
		s.apiError(w, r, "list shares", err)
		return
	}
	out := make([]shareSummary, 0, len(shares))
	for _, sh := range shares {
		out = append(out, shareSummary{ID: sh.ID, Size: sh.Size, Parts: sh.Parts, ExpiresAt: sh.ExpiresAt.Unix(),
			MaxDownloads: sh.MaxDownloads, DownloadCount: sh.DownloadCount, CreatedAt: sh.CreatedAt.Unix()})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"shares": out})
}

// handleDeleteShare revokes a share (complete or still uploading) and
// deletes its blob.
func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	if !ids.Valid(id) {
		httpx.WriteError(w, errNotFound)
		return
	}
	blobID, err := s.store.DeleteShare(r.Context(), sess.UserID(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errNotFound)
		return
	} else if err != nil {
		s.apiError(w, r, "delete share", err)
		return
	}
	s.removeBlobs(r, blobID)
	w.WriteHeader(http.StatusNoContent)
}

type downloadGrant struct {
	Token string `json:"token"`
	Size  int64  `json:"size"`
	Parts int    `json:"parts"`
	Meta  string `json:"meta,omitempty"`
}

// handleShareDownload issues a download token for a share link. Issuing a
// token does not count as a download; its first use does.
func (s *Server) handleShareDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		httpx.WriteError(w, errLinkUnknown)
		return
	}
	if !decodeEmpty(w, r) {
		return
	}
	token := ids.NewSecret()
	sh, err := s.store.CreateShareToken(r.Context(), id, ids.Hash(token), s.now())
	if e := storeError(err); e != nil {
		httpx.WriteError(w, e)
		return
	} else if err != nil {
		s.apiError(w, r, "share token", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, downloadGrant{Token: token, Size: sh.Size, Parts: sh.Parts, Meta: b64.EncodeToString(sh.Meta)})
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	var body requestRequest
	if !decode(w, r, &body) {
		return
	}
	v, e := body.validate(s.limits())
	if e != nil {
		httpx.WriteError(w, e)
		return
	}
	now := s.now()
	rq := &store.Request{OwnerID: sess.UserID(), ExpiresAt: now.Add(v.ttl), MaxFiles: v.maxFiles, MaxBytes: v.maxBytes,
		SingleUse: v.singleUse, CreatedAt: now}
	if err := s.store.CreateRequest(r.Context(), rq); err != nil {
		s.apiError(w, r, "create request", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]string{"request_id": rq.ID})
}

type requestSummary struct {
	ID            string  `json:"id"`
	ExpiresAt     int64   `json:"expires_at"`
	MaxFiles      int64   `json:"max_files"`
	MaxBytes      int64   `json:"max_bytes"`
	SingleUse     bool    `json:"single_use"`
	FilesReceived int64   `json:"files_received"`
	BytesReceived int64   `json:"bytes_received"`
	Closed        bool    `json:"closed"`
	LabelMeta     *string `json:"label_meta"`
	CreatedAt     int64   `json:"created_at"`
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	reqs, err := s.store.RequestsByOwner(r.Context(), sess.UserID(), s.now())
	if err != nil {
		s.apiError(w, r, "list requests", err)
		return
	}
	out := make([]requestSummary, 0, len(reqs))
	for _, rq := range reqs {
		e := requestSummary{ID: rq.ID, ExpiresAt: rq.ExpiresAt.Unix(), MaxFiles: rq.MaxFiles, MaxBytes: rq.MaxBytes,
			SingleUse: rq.SingleUse, FilesReceived: rq.FilesReceived, BytesReceived: rq.BytesReceived,
			Closed: rq.ClosedAt != nil, CreatedAt: rq.CreatedAt.Unix()}
		if len(rq.LabelMeta) > 0 {
			l := b64.EncodeToString(rq.LabelMeta)
			e.LabelMeta = &l
		}
		out = append(out, e)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// handleDeleteRequest revokes a request link and deletes every file it
// received.
func (s *Server) handleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	if !ids.Valid(id) {
		httpx.WriteError(w, errNotFound)
		return
	}
	blobs, err := s.store.DeleteRequest(r.Context(), sess.UserID(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errNotFound)
		return
	} else if err != nil {
		s.apiError(w, r, "delete request", err)
		return
	}
	s.removeBlobs(r, blobs...)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetRequestLabel(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	var body labelRequest
	if !decode(w, r, &body) {
		return
	}
	label, e := body.validate()
	if e != nil {
		httpx.WriteError(w, e)
		return
	}
	if !ids.Valid(id) {
		httpx.WriteError(w, errNotFound)
		return
	}
	err := s.store.SetRequestLabel(r.Context(), sess.UserID(), id, label, s.now())
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errNotFound)
		return
	} else if err != nil {
		s.apiError(w, r, "set label", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCreateRequestFile starts an anonymous upload to a request link,
// reserving its place within the link's caps.
func (s *Server) handleCreateRequestFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		httpx.WriteError(w, errLinkUnknown)
		return
	}
	var body requestFileRequest
	if !decode(w, r, &body) {
		return
	}
	v, e := body.validate(s.limits())
	if e != nil {
		httpx.WriteError(w, e)
		return
	}
	if !s.checkSpace(w, r, v.geo.Size) {
		return
	}
	token := ids.NewSecret()
	blobID, err := s.store.CreateRequestFile(r.Context(), &store.NewRequestFile{
		RequestID: id, Size: v.geo.Size, Parts: v.geo.Parts, Meta: v.meta, WrappedKey: v.wrappedKey,
		TokenHash: ids.Hash(token), DefaultQuota: s.quota(),
	}, s.now())
	if e := storeError(err); e != nil {
		httpx.WriteError(w, e)
		return
	} else if err != nil {
		s.apiError(w, r, "create request file", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, createdUpload{UploadID: blobID, UploadToken: token})
}

type inboxEntry struct {
	ID         string `json:"id"`
	RequestID  string `json:"request_id"`
	Size       int64  `json:"size"`
	Parts      int    `json:"parts"`
	CreatedAt  int64  `json:"created_at"`
	Meta       string `json:"meta"`
	WrappedKey string `json:"wrapped_key"`
}

func (s *Server) handleListInbox(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	files, err := s.store.InboxByOwner(r.Context(), sess.UserID(), s.now())
	if err != nil {
		s.apiError(w, r, "list inbox", err)
		return
	}
	out := make([]inboxEntry, 0, len(files))
	for _, f := range files {
		out = append(out, inboxEntry{ID: f.ID, RequestID: f.RequestID, Size: f.Size, Parts: f.Parts,
			CreatedAt: f.CreatedAt.Unix(), Meta: b64.EncodeToString(f.Meta), WrappedKey: b64.EncodeToString(f.WrappedKey)})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"inbox": out})
}

func (s *Server) handleInboxDownload(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	if !ids.Valid(id) {
		httpx.WriteError(w, errNotFound)
		return
	}
	if !decodeEmpty(w, r) {
		return
	}
	ctx := r.Context()
	f, err := s.store.InboxFileByID(ctx, sess.UserID(), id, s.now())
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errNotFound)
		return
	} else if err != nil {
		s.apiError(w, r, "inbox file", err)
		return
	}
	token := ids.NewSecret()
	if err := s.store.CreateInboxToken(ctx, sess.UserID(), id, ids.Hash(token), s.now()); errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errNotFound)
		return
	} else if err != nil {
		s.apiError(w, r, "inbox token", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, downloadGrant{Token: token, Size: f.Size, Parts: f.Parts})
}

func (s *Server) handleDeleteInbox(w http.ResponseWriter, r *http.Request) {
	sess := apiSession(w, r)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	if !ids.Valid(id) {
		httpx.WriteError(w, errNotFound)
		return
	}
	blobID, err := s.store.DeleteInboxFile(r.Context(), sess.UserID(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errNotFound)
		return
	} else if err != nil {
		s.apiError(w, r, "delete inbox file", err)
		return
	}
	s.removeBlobs(r, blobID)
	w.WriteHeader(http.StatusNoContent)
}
