// Package httpx holds Dropr's HTTP middleware: security headers and CSP,
// CSRF protection, body limits, client IP resolution behind trusted proxies,
// per-IP rate limiting, privacy-preserving request logging and panic
// recovery.
package httpx

import (
	"net/http"
	"strings"
)

// HeaderOptions configures SecurityHeaders.
type HeaderOptions struct {
	// FormActionOrigins are extra origins allowed in CSP form-action (the
	// OIDC provider: redirects that follow a form post are subject to it).
	FormActionOrigins []string
}

// CSP builds the Content-Security-Policy of PLAN.md §7.
func CSP(formActionOrigins []string) string {
	sources := []string{"'self'"}
	for _, o := range formActionOrigins {
		if o = sanitizeSource(o); o != "" {
			sources = append(sources, o)
		}
	}
	formAction := strings.Join(sources, " ")
	return strings.Join([]string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self'",
		"connect-src 'self'",
		"worker-src 'self'",
		"manifest-src 'self'",
		"form-action " + formAction,
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"require-trusted-types-for 'script'",
		// The only policy the browser modules create: it turns exactly
		// "/sw.js" into a TrustedScriptURL for serviceWorker.register().
		"trusted-types dropr-sw",
	}, "; ")
}

// sanitizeSource keeps a CSP source expression from injecting directives.
func sanitizeSource(s string) string {
	if strings.ContainsAny(s, ";, \t\r\n'\"") {
		return ""
	}
	return s
}

// PermissionsPolicy disables every powerful feature except clipboard writes
// (the "Copy link" button), limited to this origin.
const PermissionsPolicy = "accelerometer=(), ambient-light-sensor=(), autoplay=(), bluetooth=(), " +
	"browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(), " +
	"encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), " +
	"identity-credentials-get=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), " +
	"midi=(), otp-credentials=(), payment=(), picture-in-picture=(), " +
	"publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), " +
	"serial=(), storage-access=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()"

// HSTS is sent in both TLS modes (PLAN.md §7). Browsers ignore it over
// plain HTTP, so dev on http://localhost is unaffected.
const HSTS = "max-age=63072000; includeSubDomains; preload"

// SecurityHeaders sets the security headers on every response. Cache-Control
// defaults to no-store; handlers serving immutable assets override it.
func SecurityHeaders(o HeaderOptions) func(http.Handler) http.Handler {
	csp := CSP(o.FormActionOrigins)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("Strict-Transport-Security", HSTS)
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Origin-Agent-Cluster", "?1")
			h.Set("Permissions-Policy", PermissionsPolicy)
			h.Set("X-Permitted-Cross-Domain-Policies", "none")
			h.Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
		})
	}
}
