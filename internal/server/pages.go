package server

import (
	"errors"
	"net/http"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/i18n"
	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/web"
)

// Plain-language dead-link messages (DESIGN.md §9), also the English API
// messages; pages translate them.
var (
	msgLinkUnknown   = i18n.N("This link does not exist or has been revoked.")
	msgLinkExpired   = i18n.N("This link has expired.")
	msgLinkExhausted = i18n.N("This link has reached its download limit.")
	msgLinkClosed    = i18n.N("This link no longer accepts files.")
)

// ownerPage loads the session of an owner-only page. It redirects to /login
// without a session and then returns nil.
func ownerPage(w http.ResponseWriter, r *http.Request) *session.Session {
	sess := session.FromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return sess
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.ErrorContext(r.Context(), what, "err", err)
	s.pages.Error(w, r, http.StatusInternalServerError, i18n.N("Something went wrong"),
		i18n.N("The server had a problem. Please try again in a moment."), nil)
}

// handleHome serves the login page to visitors and the dashboard to users.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := session.FromContext(ctx)
	if sess == nil {
		s.pages.Render(w, r, http.StatusOK, web.PageLogin, web.PageData{})
		return
	}
	inbox, err := s.store.CountInbox(ctx, sess.UserID(), s.now())
	if err != nil {
		s.serverError(w, r, "count inbox", err)
		return
	}
	links, err := s.store.CountActiveLinks(ctx, sess.UserID(), s.now())
	if err != nil {
		s.serverError(w, r, "count links", err)
		return
	}
	s.pages.Render(w, r, http.StatusOK, web.PageDashboard, web.PageData{User: sess.User, View: &web.DashboardView{
		MaxFileSize:     s.cfg.Limits.MaxFileSizeBytes,
		DefaultExpiry:   s.cfg.Limits.DefaultExpiry,
		MaxRequestBytes: blob.CipherSize(s.cfg.Limits.MaxFileSizeBytes),
		InboxCount:      inbox,
		LinkCount:       links,
	}})
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	sess := ownerPage(w, r)
	if sess == nil {
		return
	}
	n, err := s.store.CountInbox(r.Context(), sess.UserID(), s.now())
	if err != nil {
		s.serverError(w, r, "count inbox", err)
		return
	}
	s.pages.Render(w, r, http.StatusOK, web.PageInbox, web.PageData{Title: "Received files", User: sess.User,
		View: &web.InboxView{Count: n}})
}

func (s *Server) handleLinks(w http.ResponseWriter, r *http.Request) {
	sess := ownerPage(w, r)
	if sess == nil {
		return
	}
	n, err := s.store.CountActiveLinks(r.Context(), sess.UserID(), s.now())
	if err != nil {
		s.serverError(w, r, "count links", err)
		return
	}
	s.pages.Render(w, r, http.StatusOK, web.PageLinks, web.PageData{Title: "Active links", User: sess.User,
		View: &web.LinksView{Count: n}})
}

func (s *Server) deadLink(w http.ResponseWriter, r *http.Request, status int, msg string) {
	title := i18n.N("Link not available")
	if status == http.StatusNotFound {
		title = i18n.N("Link not found")
	}
	s.pages.Error(w, r, status, title, msg, nil)
}

// handleSharePage renders the share recipient page, or a plain-language
// 404/410 page (without the script) when the link is dead.
func (s *Server) handleSharePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		s.deadLink(w, r, http.StatusNotFound, msgLinkUnknown)
		return
	}
	sh, err := s.store.ShareByID(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.deadLink(w, r, http.StatusNotFound, msgLinkUnknown)
		return
	case err != nil:
		s.serverError(w, r, "share page", err)
		return
	case !sh.ExpiresAt.After(s.now()), !sh.OwnerActive:
		// An owner who is disabled or lost access publishes nothing more
		// (audit 2026-11b L-2).
		s.deadLink(w, r, http.StatusGone, msgLinkExpired)
		return
	case sh.MaxDownloads != nil && sh.DownloadCount >= *sh.MaxDownloads:
		s.deadLink(w, r, http.StatusGone, msgLinkExhausted)
		return
	}
	plain, _ := blob.PlainSize(sh.Size)
	s.pages.Render(w, r, http.StatusOK, web.PageShare, web.PageData{Title: "Download a file", View: &web.ShareView{
		ID: sh.ID, Size: sh.Size, PlainSize: plain, Parts: sh.Parts, ExpiresAt: sh.ExpiresAt.Unix(),
	}})
}

// handleRequestPage renders the uploader page of a request link, or a dead
// link page.
func (s *Server) handleRequestPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		s.deadLink(w, r, http.StatusNotFound, msgLinkUnknown)
		return
	}
	ctx := r.Context()
	rq, err := s.store.RequestByID(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.deadLink(w, r, http.StatusNotFound, msgLinkUnknown)
		return
	case err != nil:
		s.serverError(w, r, "request page", err)
		return
	case !rq.ExpiresAt.After(s.now()):
		s.deadLink(w, r, http.StatusGone, msgLinkExpired)
		return
	}
	files := rq.MaxFiles - rq.FilesReceived
	remaining := rq.MaxBytes - rq.BytesReceived
	if rq.ClosedAt != nil || files <= 0 || remaining < blob.TagSize {
		s.deadLink(w, r, http.StatusGone, msgLinkClosed)
		return
	}
	// A single-use link closes on its first finalized file: offer only one.
	if rq.SingleUse {
		files = 1
	}
	owner, err := s.store.UserByID(ctx, rq.OwnerID)
	if err != nil {
		s.serverError(w, r, "request owner", err)
		return
	}
	// The owner lost access at the identity provider or was revoked: the
	// link is closed until they sign in again (audit I-3).
	if active, err := s.store.AccountActive(ctx, rq.OwnerID); err != nil {
		s.serverError(w, r, "request owner", err)
		return
	} else if !active {
		s.deadLink(w, r, http.StatusGone, msgLinkClosed)
		return
	}
	s.pages.Render(w, r, http.StatusOK, web.PageRequest, web.PageData{Title: "Send a file", View: &web.RequestView{
		ID:             rq.ID,
		OwnerName:      owner.DisplayName, // empty: the page names "the owner of this link"
		ExpiresAt:      rq.ExpiresAt.Unix(),
		MaxFiles:       files,
		MaxBytes:       min(blob.MaxPlainFor(remaining), s.cfg.Limits.MaxFileSizeBytes),
		RemainingBytes: remaining,
		MaxFileSize:    s.cfg.Limits.MaxFileSizeBytes,
	}})
}

func (s *Server) handleDLFallback(w http.ResponseWriter, r *http.Request) {
	s.pages.Error(w, r, http.StatusNotFound, i18n.N("Download did not start"), i18n.N("The download could not start. Go back and try again."), nil)
}
