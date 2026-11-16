package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/scttpr/dropr/internal/store"
)

var brandAssetName = regexp.MustCompile(`^/assets/brand/logo-[0-9a-f]{8}\.svg$`)

func TestAddBrandServesSandboxedSVG(t *testing.T) {
	t.Parallel()
	a := builtAssets(t)
	svg, err := a.AddBrand("logo", []byte("<svg/>"), "image/svg+xml", "svg")
	if err != nil {
		t.Fatal(err)
	}
	png, err := a.AddBrand("favicon", []byte("\x89PNG\r\n\x1a\n"), "image/png", "png")
	if err != nil {
		t.Fatal(err)
	}
	if !brandAssetName.MatchString("/assets/" + svg.Public) {
		t.Errorf("public name %q", svg.Public)
	}
	if u, err := a.URL("brand/logo"); err != nil || u != "/assets/"+svg.Public {
		t.Errorf("URL: %q %v", u, err)
	}
	// Another logo gets another name, so caches never keep the old one.
	b := builtAssets(t)
	other, _ := b.AddBrand("logo", []byte("<svg></svg>"), "image/svg+xml", "svg")
	if other.Public == svg.Public {
		t.Error("name does not follow the content")
	}
	if _, err := a.AddBrand("logo", []byte("<svg/>"), "image/svg+xml", "svg"); err == nil {
		t.Error("duplicate brand accepted")
	}
	if _, err := a.AddBrand("x", []byte("<html>"), "text/html", "html"); err == nil {
		t.Error("HTML brand accepted")
	}

	h := a.Handler(http.NotFoundHandler())
	serve := func(public string) *httptest.ResponseRecorder {
		mux := http.NewServeMux()
		mux.Handle("GET /assets/{path...}", h)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, public, nil))
		return w
	}
	fav, _ := a.URL("favicon.svg")
	for _, u := range []string{"/assets/" + svg.Public, fav} {
		w := serve(u)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/svg+xml" ||
			w.Header().Get("Content-Security-Policy") != svgCSP ||
			w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Errorf("%s: %d %v", u, w.Code, w.Header())
		}
	}
	w := serve("/assets/" + png.Public)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" || w.Header().Get("Content-Security-Policy") != "" {
		t.Errorf("png: %d %v", w.Code, w.Header())
	}
}

func TestBrandedPages(t *testing.T) {
	t.Parallel()
	a := builtAssets(t)
	logo, _ := a.AddBrand("logo", []byte("<svg/>"), "image/svg+xml", "svg")
	dark, _ := a.AddBrand("logo-dark", []byte("<svg></svg>"), "image/svg+xml", "svg")
	fav, _ := a.AddBrand("favicon", []byte("\x89PNG\r\n\x1a\n"), "image/png", "png")
	render := func(b Brand, page string, data PageData) string {
		r, err := NewRenderer(a, Options{LoginLabel: "Sign in", Brand: b}, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		r.Render(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, page, data)
		return w.Body.String()
	}
	u := &store.User{ID: "u", DisplayName: "Alice"}
	data := map[string]PageData{
		PageLogin: {}, PageForbidden: {}, PageError: {Title: "Page not found", Message: "Gone", User: u},
		PageLanding: {RefreshTo: "/"}, PageDashboard: {User: u, View: &DashboardView{DefaultExpiry: "7d"}},
		PageInbox: {User: u, View: &InboxView{}}, PageLinks: {User: u, View: &LinksView{}},
		PageShare: {View: &ShareView{ID: "x"}}, PageRequest: {View: &RequestView{ID: "x"}},
	}

	custom := Brand{Name: "Drop & Care", LogoURL: "/assets/" + logo.Public, LogoDarkURL: "/assets/" + dark.Public,
		FaviconURL: "/assets/" + fav.Public, FaviconType: "image/png", Custom: true}
	for _, page := range pageNames {
		body := render(custom, page, data[page])
		title := regexp.MustCompile(`<title>([^<]*)</title>`).FindStringSubmatch(body)
		if len(title) != 2 || !strings.HasSuffix(title[1], "Drop &amp; Care") {
			t.Errorf("%s: title %v", page, title)
		}
		for _, want := range []string{
			`data-brand="Drop &amp; Care"`,
			`<span class="brand-name">Drop &amp; Care</span>`,
			`<img class="brand-logo brand-logo-light" src="/assets/` + logo.Public + `" alt="">`,
			`<img class="brand-logo brand-logo-dark" src="/assets/` + dark.Public + `" alt="">`,
			`<link rel="icon" href="/assets/` + fav.Public + `" type="image/png">`,
			`Powered by <a href="https://github.com/Scttpr/Dropr">Dropr</a>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s", page, want)
			}
		}
		if strings.Contains(body, "brand-mark") || strings.Contains(body, "favicon.") {
			t.Errorf("%s keeps the built-in logo or favicon", page)
		}
		credit := `Powered by <a href="https://github.com/Scttpr/Dropr">Dropr</a>`
		if strings.Contains(strings.ReplaceAll(body, credit, ""), "Dropr") {
			t.Errorf("%s still names Dropr outside the credit", page)
		}
	}
	if body := render(custom, PageForbidden, PageData{}); !strings.Contains(body, "You don&#39;t have access to Drop &amp; Care") {
		t.Errorf("forbidden heading: %s", body)
	}

	// A name alone: the built-in mark and favicon stay, without <img>.
	nameOnly := render(Brand{Name: "Drop and Care", Custom: true}, PageLogin, PageData{})
	if strings.Contains(nameOnly, "<img") || !strings.Contains(nameOnly, "brand-mark") ||
		!strings.Contains(nameOnly, "<h1>Drop and Care</h1>") || !strings.Contains(nameOnly, "Powered by") {
		t.Errorf("name only: %s", nameOnly)
	}
	// A light logo alone shows in every theme: no dark image.
	lightOnly := render(Brand{Name: "X", LogoURL: "/assets/" + logo.Public, Custom: true}, PageLogin, PageData{})
	if !strings.Contains(lightOnly, "brand-logo-light") || strings.Contains(lightOnly, "brand-logo-dark") {
		t.Errorf("light only: %s", lightOnly)
	}

	// Without configuration: Dropr, the built-in logo, no credit.
	for _, b := range []Brand{{}, DefaultBrand} {
		body := render(b, PageLogin, PageData{})
		if !strings.Contains(body, "<title>Sign in · Dropr</title>") || !strings.Contains(body, "<h1>Dropr</h1>") ||
			!strings.Contains(body, `<span class="brand-name">Dropr</span>`) || strings.Contains(body, "<img") ||
			strings.Contains(body, "Powered by") || !strings.Contains(body, `type="image/svg+xml"`) {
			t.Errorf("default brand: %s", body)
		}
	}
}
