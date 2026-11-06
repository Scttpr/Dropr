package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/i18n"
	"github.com/scttpr/dropr/internal/store"
)

func render(t *testing.T, req *http.Request, page string, data PageData) *httptest.ResponseRecorder {
	t.Helper()
	r, err := NewRenderer(builtAssets(t), "Sign in", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.Render(w, req, http.StatusOK, page, data)
	return w
}

func TestPagesRenderInFrench(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")
	w := render(t, req, PageDashboard, PageData{User: &store.User{DisplayName: "Alice"}, View: pageCases[PageDashboard].view})
	body := w.Body.String()
	for _, want := range []string{
		`<html lang="fr" data-theme="light">`,
		"Partager un fichier",
		"ou choisissez-en un (jusqu&#39;à 5,00\u00a0Go)",
		`<option value="1d" selected>1 jour</option>`,
		"Se déconnecter",
		`aria-pressed="true">Français</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "Share a file") {
		t.Error("English left on a French page")
	}
	if got := w.Header().Get("Content-Language"); got != "fr" {
		t.Errorf("Content-Language = %q", got)
	}
}

func TestErrorPagesTranslateMsgids(t *testing.T) {
	t.Parallel()
	r, err := NewRenderer(builtAssets(t), "Sign in", nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/s/x", nil)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "fr"})
	w := httptest.NewRecorder()
	r.Error(w, req, http.StatusGone, "Link not available", "This link has expired.", nil)
	if body := w.Body.String(); !strings.Contains(body, "Lien indisponible") || !strings.Contains(body, "Ce lien a expiré.") {
		t.Fatal(body)
	}
}

func TestLoginLabelIsTranslatedUnlessCustom(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("Accept-Language", "fr")
	if body := render(t, req, PageLogin, PageData{}).Body.String(); !strings.Contains(body, ">Se connecter</a>") {
		t.Error("default label not translated")
	}
	if body := render(t, req, PageLogin, PageData{LoginLabel: "Sign in with Contoso"}).Body.String(); !strings.Contains(body, ">Sign in with Contoso</a>") {
		t.Error("custom label changed")
	}
}

func TestThemeDefaultsToLight(t *testing.T) {
	t.Parallel()
	for cookie, want := range map[string]string{
		"":       `data-theme="light"`,
		"dark":   `data-theme="dark"`,
		"system": `data-theme="system"`,
		"pink":   `data-theme="light"`,
	} {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: ThemeCookie, Value: cookie})
		}
		body := render(t, req, PageLogin, PageData{}).Body.String()
		if !strings.Contains(body, want) {
			t.Errorf("cookie %q: want %s", cookie, want)
		}
		scheme := map[string]string{`data-theme="dark"`: "dark", `data-theme="system"`: "light dark"}[want]
		if scheme == "" {
			scheme = "light"
		}
		if !strings.Contains(body, `<meta name="color-scheme" content="`+scheme+`">`) {
			t.Errorf("cookie %q: want color-scheme %q", cookie, scheme)
		}
	}
}

func TestPrefsFormReturnsToThePage(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/links?next=%2Finbox", nil)
	body := render(t, req, PageLogin, PageData{}).Body.String()
	if !strings.Contains(body, `<input type="hidden" name="next" value="/links?next=%2Finbox">`) {
		t.Fatal("next field missing")
	}
}

func TestHandlePrefs(t *testing.T) {
	t.Parallel()
	post := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/prefs", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandlePrefs(w, req)
		return w
	}

	w := post(url.Values{"lang": {"fr"}, "next": {"/links"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/links" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != i18n.CookieName || c[0].Value != "fr" || !c[0].Secure || c[0].Path != "/" || c[0].MaxAge <= 0 {
		t.Fatalf("lang cookie: %+v", c)
	}

	w = post(url.Values{"theme": {"dark"}, "next": {"/"}})
	if c := w.Result().Cookies(); len(c) != 1 || c[0].Name != ThemeCookie || c[0].Value != "dark" {
		t.Fatalf("theme cookie: %+v", c)
	}

	if c := post(url.Values{"lang": {"xx"}, "theme": {"pink"}}).Result().Cookies(); len(c) != 0 {
		t.Errorf("invalid values set cookies: %+v", c)
	}

	// Never an open redirect.
	for _, next := range []string{"", "https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)", "/ok\r\nX: y", "relative"} {
		if loc := post(url.Values{"theme": {"light"}, "next": {next}}).Header().Get("Location"); loc != "/" {
			t.Errorf("next %q redirected to %q", next, loc)
		}
	}
}

func TestFormatFrench(t *testing.T) {
	t.Parallel()
	for n, want := range map[int64]string{0: "0\u00a0o", 1536: "1,50\u00a0Ko", 5 << 30: "5,00\u00a0Go", 73400320: "70,0\u00a0Mo"} {
		if got := FormatBytesIn(i18n.FR, n); got != want {
			t.Errorf("FormatBytesIn(fr, %d) = %q, want %q", n, got, want)
		}
	}
	now := time.Unix(1_000_000, 0)
	for d, want := range map[int64]string{
		// Same table as web/test/i18n.test.ts.
		-5: "Expiré", 30: "Expire dans 1 minute", 600: "Expire dans 10 minutes", 3600: "Expire dans 1 heure",
		3601: "Expire dans 2 heures", 86_400: "Expire dans 1 jour", 7 * 86_400: "Expire dans 7 jours",
	} {
		if got := FormatExpiryIn(i18n.FR, now.Unix()+d, now); got != want {
			t.Errorf("FormatExpiryIn(fr, +%d) = %q, want %q", d, got, want)
		}
	}
}
