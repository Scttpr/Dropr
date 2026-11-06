// Package i18n picks the interface language of a request and translates the
// server-rendered text.
//
// Messages are identified by their English source text (gettext style), so
// templates and handlers stay readable and English needs no catalog. Other
// languages map each English msgid to its translation; a missing entry falls
// back to English. TestCatalogsComplete scans the templates and the Go
// sources for msgids and fails on any untranslated one.
//
// The browser modules carry their own typed catalogs (web/src/lib/locales/)
// and read the language from <html lang>, which the server sets from the
// same negotiation, so both sides always agree.
package i18n

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Lang is a supported interface language (a BCP 47 primary language tag).
type Lang string

// Supported languages.
const (
	EN Lang = "en"
	FR Lang = "fr"
)

// Default is used when nothing in the request matches a supported language.
const Default = EN

// Supported lists the languages in the order the language picker shows them.
var Supported = []Lang{EN, FR}

// CookieName holds an explicit language choice. It is not HttpOnly: the
// browser modules set it so a change keeps the URL fragment (link keys).
const CookieName = "__Host-dropr_lang"

// Parse returns the supported language of a tag ("fr-CA" → FR).
func Parse(tag string) (Lang, bool) {
	primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
	l := Lang(primary)
	return l, slices.Contains(Supported, l)
}

// Name is the language's name in itself, for the picker.
func (l Lang) Name() string {
	switch l {
	case FR:
		return "Français"
	default:
		return "English"
	}
}

// Negotiate picks the language of r: an explicit choice (cookie) first, then
// the best Accept-Language match, then Default.
func Negotiate(r *http.Request) Lang {
	if c, err := r.Cookie(CookieName); err == nil {
		if l, ok := Parse(c.Value); ok {
			return l
		}
	}
	return FromAcceptLanguage(r.Header.Get("Accept-Language"))
}

// FromAcceptLanguage returns the supported language with the highest q-value
// in an Accept-Language header (RFC 9110 §12.5.4). Ties keep header order.
func FromAcceptLanguage(header string) Lang {
	best, bestQ := Default, 0.0
	for part := range strings.SplitSeq(header, ",") {
		tag, params, _ := strings.Cut(part, ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil || f < 0 || f > 1 {
				continue
			}
			q = f
		}
		if l, ok := Parse(tag); ok && q > bestQ {
			best, bestQ = l, q
		}
	}
	return best
}

// T translates msgid into l. With args, the translation is a fmt format.
func (l Lang) T(msgid string, args ...any) string {
	s := msgid
	if tr, ok := catalogs[l][msgid]; ok {
		s = tr
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// N marks a Go string constant as a msgid for TestCatalogsComplete and
// returns it unchanged; translation happens later, with T.
func N(msgid string) string { return msgid }

var catalogs = map[Lang]map[string]string{FR: fr}
