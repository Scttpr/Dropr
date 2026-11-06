// Package web renders Dropr's server-side pages with html/template and serves
// the embedded static assets.
//
// Pages contain no inline scripts or styles (the CSP forbids them); every
// page works as a plain HTML document and browser modules only add the
// client-side crypto.
package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/scttpr/dropr/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// StaticFS returns the embedded static directory.
func StaticFS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}

// Page names.
const (
	PageLogin     = "login"
	PageDashboard = "dashboard"
	PageError     = "error"
	PageForbidden = "forbidden"
	PageLanding   = "landing"
	PageSetup     = "setup"
	PageInbox     = "inbox"
	PageLinks     = "links"
	PageShare     = "share"
	PageRequest   = "request"
)

var pageNames = []string{PageLogin, PageDashboard, PageError, PageForbidden, PageLanding,
	PageSetup, PageInbox, PageLinks, PageShare, PageRequest}

// pageScripts maps a page to its browser module (docs/PAGES.md §1.1). The
// script is only included when the page has a view model: dead-link and
// error pages render through PageError and never load one.
var pageScripts = map[string]string{
	PageDashboard: "dashboard.js",
	PageSetup:     "setup.js",
	PageInbox:     "inbox.js",
	PageLinks:     "links.js",
	PageShare:     "share.js",
	PageRequest:   "request.js",
}

// Script is a resolved module script tag.
type Script struct {
	Src       string
	Integrity string
}

// PageData is the view model shared by all pages.
type PageData struct {
	Title      string
	Message    string
	User       *store.User
	LoginLabel string
	// Scripts are the module scripts of the page, filled in by Render from
	// pageScripts. Assets missing from the build (no web build in dev or
	// tests) are left out with a warning.
	Scripts       []Script
	RefreshToRoot bool
	// Page is the page name, set by Render (navigation state).
	Page string
	// View is the page-specific view model (*DashboardView, *SetupView, …).
	View any
}

// Renderer renders pages.
type Renderer struct {
	pages      map[string]*template.Template
	assets     *Assets
	loginLabel string
	log        *slog.Logger

	missingOnce sync.Once
}

// NewRenderer parses every page against the layout.
func NewRenderer(assets *Assets, loginLabel string, log *slog.Logger) (*Renderer, error) {
	if log == nil {
		log = slog.Default()
	}
	funcs := template.FuncMap{
		"asset":     assets.URL,
		"integrity": assets.Integrity,
		"bytes":     FormatBytes,
		"expiresIn": func(at int64) string { return FormatExpiry(at, time.Now()) },
	}
	r := &Renderer{pages: map[string]*template.Template{}, assets: assets, loginLabel: loginLabel, log: log}
	for _, name := range pageNames {
		t, err := template.New("layout").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", name, err)
		}
		r.pages[name] = t
	}
	return r, nil
}

func (r *Renderer) script(logical string) (Script, error) {
	src, err := r.assets.URL(logical)
	if err != nil {
		return Script{}, err
	}
	sri, err := r.assets.Integrity(logical)
	return Script{Src: src, Integrity: sri}, err
}

// Assets returns the asset index.
func (r *Renderer) Assets() *Assets { return r.assets }

// Render writes page with status. Output is buffered so a template error
// never produces a half-written page.
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, status int, page string, data PageData) {
	t, ok := r.pages[page]
	if !ok {
		r.log.ErrorContext(req.Context(), "unknown page", "page", page)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data.Page = page
	if data.LoginLabel == "" {
		data.LoginLabel = r.loginLabel
	}
	if logical, ok := pageScripts[page]; ok && data.View != nil && data.Scripts == nil {
		if s, err := r.script(logical); err == nil {
			data.Scripts = []Script{s}
		} else {
			r.missingOnce.Do(func() {
				r.log.WarnContext(req.Context(), "browser modules missing from the build; pages load no script (run `make web`)", "asset", logical)
			})
		}
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		r.log.ErrorContext(req.Context(), "render page", "page", page, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if req.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}

// Error renders a plain-language error page.
func (r *Renderer) Error(w http.ResponseWriter, req *http.Request, status int, title, message string, user *store.User) {
	r.Render(w, req, status, PageError, PageData{Title: title, Message: message, User: user})
}

// NotFound renders the 404 page.
func (r *Renderer) NotFound(w http.ResponseWriter, req *http.Request) {
	r.Error(w, req, http.StatusNotFound, "Page not found", "This page doesn't exist, or the link has expired.", nil)
}

// SignInError implements oidc.Pages.
func (r *Renderer) SignInError(w http.ResponseWriter, req *http.Request, status int, message string) {
	r.Error(w, req, status, "Sign-in failed", message, nil)
}

// Forbidden implements oidc.Pages.
func (r *Renderer) Forbidden(w http.ResponseWriter, req *http.Request) {
	r.Render(w, req, http.StatusForbidden, PageForbidden, PageData{})
}

// CallbackLanding implements oidc.Pages: a same-origin page that navigates
// to "/" so the browser sends the SameSite=Strict session cookie (it is not
// sent within a redirect chain that started cross-site).
func (r *Renderer) CallbackLanding(w http.ResponseWriter, req *http.Request) {
	r.Render(w, req, http.StatusOK, PageLanding, PageData{RefreshToRoot: true})
}
