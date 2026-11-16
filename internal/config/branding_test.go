package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSVG = `<?xml version="1.0" encoding="UTF-8"?>
<!-- logo -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10"><path d="M0 0h10v10z"/></svg>
`

func TestBrandingDefaults(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, err := Parse([]byte(f.prod("")))
	if err != nil {
		t.Fatal(err)
	}
	b := c.Branding
	if b.Name != DefaultBrandName || b.Logo != nil || b.LogoDark != nil || b.Favicon != nil || b.Custom() {
		t.Fatalf("defaults: %+v", b)
	}
}

func TestBranding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	file := func(name string, data []byte) string {
		p := filepath.Join(f.dir, name)
		write(t, p, data)
		return p
	}
	png := file("logo.png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...))
	webp := file("logo.webp", []byte("RIFF\x10\x00\x00\x00WEBPVP8 "))
	svg := file("logo.svg", []byte(testSVG))
	upper := file("LOGO.SVG", []byte("\ufeff"+testSVG))
	dir := filepath.Join(f.dir, "dir.svg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	brand := func(lines ...string) string { return f.prod("") + "\n[branding]\n" + strings.Join(lines, "\n") }
	q := func(k, p string) string { return k + ` = "` + p + `"` }

	ok := map[string]struct {
		cfg, name, warn string
	}{
		"name only":      {brand(`name = "Drop and Care"`), "Drop and Care", ""},
		"name cleaned":   {brand(`name = "  Drop\u202e and\u00a0\u00a0Care "`), "Drop and Care", ""},
		"png logo":       {brand(q("logo_file", png)), DefaultBrandName, ""},
		"webp logo":      {brand(q("logo_file", webp)), DefaultBrandName, ""},
		"svg everywhere": {brand(q("logo_file", svg), q("logo_dark_file", upper), q("favicon_file", svg)), DefaultBrandName, ""},
		"remote href": {brand(q("logo_file", file("remote.svg", []byte(`<svg><image href="https://cdn.example/x.png"/></svg>`)))),
			DefaultBrandName, "remote resources"},
		"remote css": {brand(q("logo_file", file("css.svg", []byte(`<svg><style>@import url( "//cdn.example/x.css");</style></svg>`)))),
			DefaultBrandName, "remote resources"},
		"40 runes": {brand(`name = "` + strings.Repeat("é", 40) + `"`), strings.Repeat("é", 40), ""},
	}
	for name, tc := range ok {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := Parse([]byte(tc.cfg))
			if err != nil {
				t.Fatal(err)
			}
			if c.Branding.Name != tc.name || !c.Branding.Custom() {
				t.Errorf("name %q, custom %v", c.Branding.Name, c.Branding.Custom())
			}
			warned := strings.Join(c.Warnings, "|")
			if (tc.warn == "") != (warned == "") || !strings.Contains(warned, tc.warn) {
				t.Errorf("warnings %q, want %q", warned, tc.warn)
			}
		})
	}

	c, err := Parse([]byte(brand(q("logo_file", svg), q("logo_dark_file", png), q("favicon_file", webp))))
	if err != nil {
		t.Fatal(err)
	}
	b := c.Branding
	if b.Logo.ContentType != "image/svg+xml" || b.Logo.Ext != "svg" || b.Logo.Data == nil ||
		b.LogoDark.ContentType != "image/png" || b.LogoDark.Ext != "png" ||
		b.Favicon.ContentType != "image/webp" || b.Favicon.Ext != "webp" {
		t.Errorf("files: %+v %+v %+v", b.Logo, b.LogoDark, b.Favicon)
	}

	bad := map[string]struct{ cfg, want string }{
		"empty name":       {brand(`name = ""`), "branding.name"},
		"blank name":       {brand(`name = "   "`), "branding.name"},
		"controls only":    {brand(`name = "\u200b\u202e\t"`), "branding.name"},
		"41 runes":         {brand(`name = "` + strings.Repeat("é", 41) + `"`), "branding.name"},
		"missing file":     {brand(q("logo_file", filepath.Join(f.dir, "nope.svg"))), "branding.logo_file"},
		"directory":        {brand(q("favicon_file", dir)), "not a regular file"},
		"too large":        {brand(q("logo_file", file("big.png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 256<<10-7)...)))), "larger than 256 KiB"},
		"png with svg":     {brand(q("logo_file", file("fake.png", []byte(testSVG)))), "not PNG"},
		"webp with png":    {brand(q("logo_file", file("fake.webp", []byte("\x89PNG\r\n\x1a\n0000")))), "not WebP"},
		"svg with png":     {brand(q("logo_file", file("fake.svg", []byte("\x89PNG\r\n\x1a\n")))), "UTF-8"},
		"svg with html":    {brand(q("logo_file", file("page.svg", []byte("<html><svg/></html>")))), "not SVG"},
		"bad extension":    {brand(q("logo_file", file("logo.gif", []byte("GIF89a")))), ".svg, .png or .webp"},
		"dark without":     {brand(q("logo_dark_file", svg)), "needs branding.logo_file"},
		"script":           {brand(q("logo_file", file("s.svg", []byte(`<svg><script>alert(1)</script></svg>`)))), "<script"},
		"script uppercase": {brand(q("logo_file", file("su.svg", []byte(`<svg><SCRIPT>alert(1)</SCRIPT></svg>`)))), "<script"},
		"onload":           {brand(q("logo_file", file("o.svg", []byte(`<svg onload="alert(1)"/>`)))), "event handler"},
		"onclick spaced":   {brand(q("logo_file", file("oc.svg", []byte("<svg><a\n\tonClick = 'x'/></svg>")))), "event handler"},
		"foreignObject":    {brand(q("logo_file", file("fo.svg", []byte(`<svg><foreignObject><div/></foreignObject></svg>`)))), "<foreignobject"},
		"javascript href":  {brand(q("logo_file", file("js.svg", []byte(`<svg><a href="javascript:alert(1)"/></svg>`)))), "javascript:"},
		"split scheme":     {brand(q("logo_file", file("js2.svg", []byte("<svg><a href=\"java\tscript:x\"/></svg>")))), "javascript:"},
		"char refs":        {brand(q("logo_file", file("js3.svg", []byte(`<svg><a href="&#106;ava&#x73;cript:x"/></svg>`)))), "javascript:"},
		"entity":           {brand(q("logo_file", file("e.svg", []byte(`<!DOCTYPE svg [<!ENTITY x "y">]><svg/>`)))), "not SVG"},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func FuzzCheckSVG(f *testing.F) {
	f.Add([]byte(testSVG))
	f.Add([]byte(`<svg onload="x"/>`))
	f.Add([]byte(`<svg><a href="&#x6a;avascript:x"/></svg>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := checkSVG(data); err == nil {
			low := bytes.ToLower(data)
			for _, bad := range []string{"<script", "<foreignobject", "javascript:"} {
				if bytes.Contains(low, []byte(bad)) {
					t.Fatalf("accepted SVG containing %s: %q", bad, data)
				}
			}
		}
	})
}
