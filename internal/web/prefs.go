package web

import (
	"net/http"
	"regexp"
	"time"

	"github.com/scttpr/dropr/internal/i18n"
)

// Theme is the color theme of the pages.
type Theme string

// Themes. Light is the default; System follows the operating system.
const (
	ThemeLight  Theme = "light"
	ThemeDark   Theme = "dark"
	ThemeSystem Theme = "system"
)

// DefaultTheme applies until the visitor picks another one.
const DefaultTheme = ThemeLight

// ThemeCookie holds an explicit theme choice. Not HttpOnly: prefs.js sets it
// so a change applies without a reload.
const ThemeCookie = "__Host-dropr_theme"

// prefsMaxAge keeps display preferences for a year.
const prefsMaxAge = 365 * 24 * time.Hour

// ParseTheme returns the theme named s.
func ParseTheme(s string) (Theme, bool) {
	switch t := Theme(s); t {
	case ThemeLight, ThemeDark, ThemeSystem:
		return t, true
	}
	return "", false
}

// ColorScheme is the <meta name="color-scheme"> value of the theme.
func (t Theme) ColorScheme() string {
	switch t {
	case ThemeDark:
		return "dark"
	case ThemeSystem:
		return "light dark"
	default:
		return "light"
	}
}

// ThemeOf returns the theme chosen by the visitor of r, or DefaultTheme.
func ThemeOf(r *http.Request) Theme {
	if c, err := r.Cookie(ThemeCookie); err == nil {
		if t, ok := ParseTheme(c.Value); ok {
			return t
		}
	}
	return DefaultTheme
}

func prefCookie(name, value string) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: not HttpOnly on purpose (prefs.js sets it); holds no secret
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(prefsMaxAge.Seconds()),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// safeNext matches a same-origin path: no scheme, no "//host", no backslash.
var safeNext = regexp.MustCompile(`^/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*)?(?:\?[A-Za-z0-9\-._~!$&'()*+,;=:@%/?]*)?$`)

// HandlePrefs serves POST /prefs, the no-JavaScript path of the display
// settings: it stores the chosen language and/or theme and sends the
// browser back to the page it came from (a same-origin path only).
func HandlePrefs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if v := r.PostForm.Get("lang"); v != "" {
		if l, ok := i18n.Parse(v); ok {
			http.SetCookie(w, prefCookie(i18n.CookieName, string(l)))
		}
	}
	if v := r.PostForm.Get("theme"); v != "" {
		if t, ok := ParseTheme(v); ok {
			http.SetCookie(w, prefCookie(ThemeCookie, string(t)))
		}
	}
	next := r.PostForm.Get("next")
	if !safeNext.MatchString(next) || len(next) > 2048 || (len(next) > 1 && next[1] == '/') {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // G710: next is checked against safeNext (same-origin path)
}
