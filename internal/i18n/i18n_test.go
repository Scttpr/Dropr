package i18n

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestFromAcceptLanguage(t *testing.T) {
	t.Parallel()
	for header, want := range map[string]Lang{
		"":                                 EN,
		"fr":                               FR,
		"fr-FR,fr;q=0.9,en-US;q=0.8":       FR,
		"en-US,en;q=0.9,fr;q=0.8":          EN,
		"de-DE,de;q=0.9,fr;q=0.7,en;q=0.5": FR,
		"de, it":                           EN,
		"en;q=0.2, fr;q=0.3":               FR,
		"fr;q=0, en;q=0.1":                 EN,
		"FR-ca":                            FR,
		"fr;q=abc, en":                     EN,
		"*":                                EN,
	} {
		if got := FromAcceptLanguage(header); got != want {
			t.Errorf("FromAcceptLanguage(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestNegotiateCookieWins(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "fr")
	if got := Negotiate(r); got != FR {
		t.Fatalf("header only: got %q", got)
	}
	r.Header.Set("Cookie", CookieName+"=en")
	if got := Negotiate(r); got != EN {
		t.Fatalf("cookie: got %q", got)
	}
	r.Header.Set("Cookie", CookieName+"=xx")
	if got := Negotiate(r); got != FR {
		t.Fatalf("invalid cookie must be ignored: got %q", got)
	}
}

func TestT(t *testing.T) {
	t.Parallel()
	if got := FR.T("Share a file"); got != "Partager un fichier" {
		t.Errorf("FR.T = %q", got)
	}
	if got := EN.T("%d active links.", 3); got != "3 active links." {
		t.Errorf("EN.T args = %q", got)
	}
	if got := FR.T("not a msgid"); got != "not a msgid" {
		t.Errorf("fallback = %q", got)
	}
}

var verbRE = regexp.MustCompile(`%[-+# 0]*\d*(?:\.\d+)?[a-zA-Z%]`)

// TestCatalogsComplete finds every msgid of the server-rendered interface
// (template {{t "…"}} calls, i18n.N("…") and .T("…") in Go) and checks
// that each translation exists and uses the same format verbs.
func TestCatalogsComplete(t *testing.T) {
	t.Parallel()
	ids := collectMsgids(t)
	if len(ids) < 100 {
		t.Fatalf("found only %d msgids: is the scanner broken?", len(ids))
	}
	for lang, cat := range catalogs {
		var missing []string
		for id := range ids {
			tr, ok := cat[id]
			if !ok {
				missing = append(missing, id)
				continue
			}
			if a, b := verbRE.FindAllString(id, -1), verbRE.FindAllString(tr, -1); !slices.Equal(a, b) {
				t.Errorf("%s: %q: verbs %v, translation has %v", lang, id, a, b)
			}
		}
		slices.Sort(missing)
		for _, id := range missing {
			t.Errorf("%s: missing translation for %s (%s)", lang, strconv.Quote(id), ids[id])
		}
		for id := range cat {
			if _, used := ids[id]; !used {
				t.Errorf("%s: unused translation %q", lang, id)
			}
		}
	}
}

var (
	tmplRE = regexp.MustCompile(`\{\{-?\s*t\s+("(?:[^"\\]|\\.)*")`)
	goRE   = regexp.MustCompile(`(?:i18n\.N|\.T)\(("(?:[^"\\]|\\.)*")`)
)

func collectMsgids(t *testing.T) map[string]string {
	t.Helper()
	root := ".."
	ids := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var re *regexp.Regexp
		switch {
		case d.IsDir():
			return nil
		case strings.HasSuffix(p, ".html") && strings.Contains(p, "templates"):
			re = tmplRE
		case strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"):
			re = goRE
		default:
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			id, err := strconv.Unquote(m[1])
			if err != nil {
				t.Errorf("%s: bad msgid %s", p, m[1])
				continue
			}
			ids[id] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}
