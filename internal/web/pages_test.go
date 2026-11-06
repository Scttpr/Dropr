package web

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/scttpr/dropr/internal/store"
)

// builtAssets mimics a web build: hashed page modules, the display settings
// module and manifest.json.
func builtAssets(t *testing.T) *Assets {
	t.Helper()
	fsys := fstest.MapFS{
		"app.css":     {Data: []byte("body{}")},
		"favicon.svg": {Data: []byte("<svg/>")},
		"sw.js":       {Data: []byte("self")},
	}
	manifest := `{"sw.js":"sw.js"`
	for _, logical := range append(slices.Collect(maps.Values(pageScripts)), PrefsScriptName) {
		file := strings.TrimSuffix(logical, ".js") + "-HASH.js"
		fsys[file] = &fstest.MapFile{Data: []byte("export{}")}
		manifest += `,"` + logical + `":"` + file + `"`
	}
	fsys["manifest.json"] = &fstest.MapFile{Data: []byte(manifest + "}")}
	a, err := LoadAssets(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var future = time.Now().Add(6*24*time.Hour + time.Hour).Unix()

// pageCases holds a realistic view model and the ids docs/PAGES.md marks as
// required for each page with a browser module.
var pageCases = map[string]struct {
	view  any
	attrs []string
	ids   []string
	text  []string
}{
	PageDashboard: {
		view:  &DashboardView{MaxFileSize: 5 << 30, DefaultExpiry: "1d", MaxRequestBytes: 5<<30 + 1234, InboxCount: 3, LinkCount: 2},
		attrs: []string{`data-max-file-size="5368709120"`, `data-default-expiry="1d"`, `data-max-request-bytes="5368710354"`},
		ids: []string{"share-form", "drop-zone", "file-input", "upload-panel", "upload-progress", "upload-status",
			"share-result", "share-link", "share-copy", "share-error", "request-form", "request-error",
			"request-result", "request-link", "request-copy", "expires-in", "max-downloads", "share-qr", "request-qr"},
		text: []string{"Drop a file here to share", "Ask someone to send me a file", `Received files (<span id="inbox-count">3</span>)`, `Active links (<span id="link-count">2</span>)`,
			`<option value="1d" selected>`, `action="/auth/logout"`},
	},
	PageSetup: {
		view:  &SetupView{PasskeyCount: 1, Next: "/"},
		attrs: []string{`data-passkey-count="1"`, `data-next="/"`},
		ids:   []string{"setup-register", "setup-status", "setup-error", "setup-step-1", "setup-step-2"},
		text:  []string{"Protect your received files", "Step 2 of 2: your spare passkey", "Create my spare passkey", `id="setup-where-auto" name="setup-where" value="auto" checked`},
	},
	PageInbox: {
		view: &InboxView{Count: 2},
		ids: []string{"inbox-unlock", "inbox-status", "inbox-error", "inbox-table", "inbox-list", "inbox-empty",
			"download-panel", "download-progress", "download-status"},
	},
	PageLinks: {
		view: &LinksView{Count: 1},
		ids: []string{"links-status", "links-error", "shares-table", "shares-list", "shares-empty",
			"requests-table", "requests-list", "requests-empty"},
	},
	PageShare: {
		view:  &ShareView{ID: "AAAAAAAAAAAAAAAAAAAAAA", PlainSize: 1536, ExpiresAt: future},
		attrs: []string{`data-share-id="AAAAAAAAAAAAAAAAAAAAAA"`, `data-expires-at="`},
		ids:   []string{"file-name", "download-button", "download-panel", "download-progress", "download-status", "download-error"},
		text:  []string{"Expires in 7 days", "1.50 KB"},
	},
	PageRequest: {
		view:  &RequestView{ID: "BBBBBBBBBBBBBBBBBBBBBB", OwnerName: "Alice", MaxFiles: 10, MaxBytes: 5 << 30, ExpiresAt: future},
		attrs: []string{`data-request-id="BBBBBBBBBBBBBBBBBBBBBB"`, `data-max-files="10"`, `data-max-bytes="5368709120"`},
		ids:   []string{"drop-zone", "file-input", "upload-panel", "upload-progress", "upload-status", "upload-done", "upload-error"},
		text:  []string{"Send a file to Alice", "✓ Sent. You can close this page.", " multiple>"},
	},
}

func TestPagesFollowDOMContract(t *testing.T) {
	t.Parallel()
	r, err := NewRenderer(builtAssets(t), "Sign in", nil)
	if err != nil {
		t.Fatal(err)
	}
	user := &store.User{DisplayName: "Alice"}
	for page, c := range pageCases {
		w := httptest.NewRecorder()
		r.Render(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, page, PageData{User: user, View: c.view})
		body := w.Body.String()
		if n := strings.Count(body, "<main "); n != 1 {
			t.Fatalf("%s: %d <main> elements", page, n)
		}
		if !strings.Contains(body, `<main id="main" class="site-main" data-page="`+page+`"`) {
			t.Errorf("%s: wrong <main>", page)
		}
		script := regexp.MustCompile(`<script type="module" src="/assets/` + page + `-HASH\.js" integrity="sha384-[A-Za-z0-9+/=]+"></script>`)
		prefsScript := regexp.MustCompile(`<script type="module" src="/assets/prefs-HASH\.js" integrity="sha384-[A-Za-z0-9+/=]+"></script>`)
		if n := strings.Count(body, "<script"); n != 2 || !script.MatchString(body) || !prefsScript.MatchString(body) {
			t.Errorf("%s: want the page module and prefs.js, both with SRI, got %d scripts", page, n)
		}
		for _, a := range c.attrs {
			if !strings.Contains(body, a) {
				t.Errorf("%s: missing %s", page, a)
			}
		}
		for _, id := range c.ids {
			if strings.Count(body, ` id="`+id+`"`) != 1 {
				t.Errorf("%s: id %q missing or duplicated", page, id)
			}
		}
		for _, s := range c.text {
			if !strings.Contains(body, s) {
				t.Errorf("%s: missing %q", page, s)
			}
		}
		if !strings.Contains(body, "<noscript>") {
			t.Errorf("%s: no noscript", page)
		}
		// Every data-js-only element starts hidden; status regions are polite live regions.
		for _, m := range regexp.MustCompile(`<[^>]+data-js-only[^>]*>`).FindAllString(body, -1) {
			if !strings.Contains(m, " hidden") {
				t.Errorf("%s: data-js-only element not hidden: %s", page, m)
			}
		}
		for _, m := range regexp.MustCompile(`<[^>]+id="[a-z-]+-status"[^>]*>`).FindAllString(body, -1) {
			if !strings.Contains(m, `role="status"`) || !strings.Contains(m, `aria-live="polite"`) {
				t.Errorf("%s: status region: %s", page, m)
			}
		}
		for _, m := range regexp.MustCompile(`<[^>]+id="[a-z-]+-error"[^>]*>`).FindAllString(body, -1) {
			if !strings.Contains(m, `role="alert"`) || !strings.Contains(m, `tabindex="-1"`) || !strings.Contains(m, " hidden") {
				t.Errorf("%s: error region: %s", page, m)
			}
		}
		if inline.MatchString(body) {
			t.Errorf("%s: inline code: %s", page, inline.FindString(body))
		}
	}
}

func TestPagesWithoutWebBuildLoadNoScript(t *testing.T) {
	t.Parallel()
	a, err := LoadAssets(fstest.MapFS{"app.css": {Data: []byte("x")}, "favicon.svg": {Data: []byte("<svg/>")}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRenderer(a, "Sign in", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.Render(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, PageShare, PageData{View: pageCases[PageShare].view})
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<script") || !strings.Contains(w.Body.String(), `data-page="share"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestErrorPagesLoadNoScript(t *testing.T) {
	t.Parallel()
	r, err := NewRenderer(builtAssets(t), "Sign in", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.Error(w, httptest.NewRequest(http.MethodGet, "/s/x", nil), http.StatusGone, "Link not available", "This link has expired.", nil)
	// Only the display settings module: no page module, no view model.
	if strings.Count(w.Body.String(), "<script") != 1 || !strings.Contains(w.Body.String(), "/assets/prefs-HASH.js") ||
		strings.Contains(w.Body.String(), "data-share-id") ||
		!strings.Contains(w.Body.String(), "This link has expired.") {
		t.Fatal(w.Body.String())
	}
}
