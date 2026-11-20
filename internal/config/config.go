// Package config loads and validates dropr.toml.
//
// Loading is strict: unknown keys are rejected, every value is validated, and
// the production-mode refusal rules of DESIGN.md (§5.1.2, §7, §10) are enforced
// here so that a misconfigured instance never starts. Secrets are read from
// files only, never from the TOML file itself or the environment.
package config

import (
	"cmp"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scttpr/dropr/internal/i18n"
)

// Mode values.
const (
	ModeProduction = "production"
	ModeDev        = "dev"
)

// TLS modes.
const (
	TLSACME  = "acme"
	TLSProxy = "proxy"
)

// Session cookie lifetimes (session_cookie).
const (
	SessionCookiePersistent = "persistent"
	SessionCookieBrowser    = "browser"
)

// Client authentication methods at the token endpoint.
const (
	ClientAuthPrivateKeyJWT = "private_key_jwt"
	ClientAuthSecret        = "client_secret"
)

// Themes of ui.default_theme.
const (
	ThemeLight  = "light"
	ThemeDark   = "dark"
	ThemeSystem = "system"
)

// Link expiry choices (limits.expiry_choices, DESIGN.md §6).
var (
	defaultExpiryChoices = []string{"1h", "1d", "7d", "30d"}
	expiryChoiceRE       = regexp.MustCompile(`^[1-9][0-9]{0,3}[hd]$`)
)

// Expiry choice bounds and count.
const (
	minExpiry        = time.Hour
	maxExpiry        = 365 * 24 * time.Hour
	maxExpiryChoices = 8
)

// Session lifetime bounds (session_idle_timeout, session_max_age).
const (
	defaultSessionIdle   = 30 * time.Minute
	defaultSessionMaxAge = 8 * time.Hour
	minSessionIdle       = 5 * time.Minute
	maxSessionIdle       = 24 * time.Hour
	minSessionMaxAge     = 15 * time.Minute
	maxSessionMaxAge     = 30 * 24 * time.Hour
)

// Download and request link caps.
const (
	// MaxDownloadsCap is the largest max_downloads a share accepts.
	MaxDownloadsCap = 999_999
	// MaxRequestFilesCap is the largest max_files a request link accepts.
	MaxRequestFilesCap = 1000
)

// Config is the validated instance configuration. Fields tagged `toml:"-"`
// are derived during Load and are what the rest of the program should use.
type Config struct {
	PublicURL      string   `toml:"public_url"`
	Mode           string   `toml:"mode"`
	DataDir        string   `toml:"data_dir"`
	Listen         string   `toml:"listen"`
	TLS            string   `toml:"tls"`
	ACMEEmail      string   `toml:"acme_email"`
	RedirectHTTP   bool     `toml:"redirect_http"`
	RedirectListen string   `toml:"redirect_listen"`
	TrustedProxies []string `toml:"trusted_proxies"`
	// TrustUnixSocketProxy trusts X-Forwarded-For from the peer of a unix:
	// listen socket without trusted_proxies (the peer can only be a local
	// process with access to the socket file, i.e. the reverse proxy).
	TrustUnixSocketProxy bool   `toml:"trust_unix_socket_proxy"`
	RefreshKeyFile       string `toml:"refresh_key_file"`
	LoginLabel           string `toml:"login_label"`
	// AutoLogin sends visitors of owner pages straight to the identity
	// provider instead of showing the sign-in page (/login still shows it).
	AutoLogin bool `toml:"auto_login"`
	// SessionCookie is "persistent" (the cookie lasts until the session's
	// absolute timeout) or "browser" (dropped when the browser closes).
	SessionCookie string `toml:"session_cookie"`
	// SessionIdleTimeout ends a session after this long without a request;
	// SessionMaxAge ends it this long after sign-in, whatever its activity.
	SessionIdleTimeout string `toml:"session_idle_timeout"`
	SessionMaxAge      string `toml:"session_max_age"`
	LogLevel           string `toml:"log_level"`

	Limits   Limits   `toml:"limits"`
	OIDC     OIDC     `toml:"oidc"`
	Branding Branding `toml:"branding"`
	UI       UI       `toml:"ui"`

	// Derived.
	Public         *url.URL       `toml:"-"` // parsed public_url, no trailing slash
	Origin         string         `toml:"-"` // scheme://host[:port]
	TrustedProxyNs []netip.Prefix `toml:"-"`
	RefreshKey     []byte         `toml:"-"` // 32-byte master key
	Level          slog.Level     `toml:"-"`
	SessionIdle    time.Duration  `toml:"-"`
	SessionLife    time.Duration  `toml:"-"`
	Warnings       []string       `toml:"-"` // non-fatal findings for the operator
}

// UI holds the display defaults a visitor sees until they pick their own.
type UI struct {
	// DefaultTheme is "light", "dark" or "system" (follow the device).
	DefaultTheme string `toml:"default_theme"`
	// DefaultLanguage applies when the browser asks for no supported
	// language ("en" or "fr").
	DefaultLanguage string `toml:"default_language"`
}

// Limits holds size and expiry limits.
type Limits struct {
	MaxFileSize   string   `toml:"max_file_size"`
	UserQuota     string   `toml:"user_quota"`
	ExpiryChoices []string `toml:"expiry_choices"`
	DefaultExpiry string   `toml:"default_expiry"`
	DiskHeadroom  string   `toml:"disk_headroom"`
	// MaxDownloads caps max_downloads of a share (0: no cap). With a cap,
	// every share has a download limit: DefaultMaxDownloads when set,
	// else the cap. DefaultMaxDownloads (0: none) prefills the form.
	MaxDownloads        int64 `toml:"max_downloads"`
	DefaultMaxDownloads int64 `toml:"default_max_downloads"`
	// MaxRequestFiles caps max_files of a request link (1 to 1000).
	MaxRequestFiles int `toml:"max_request_files"`
	// Transfer limits (audit L-4): concurrent part uploads and downloads in
	// total and per client address, and the minimum rate (bytes per second,
	// averaged over 60 s) below which a transfer is cut ("0" disables).
	MaxTransfers      int    `toml:"max_transfers"`
	MaxTransfersPerIP int    `toml:"max_transfers_per_ip"`
	MinTransferRate   string `toml:"min_transfer_rate"`
	// Per-client-address limit of /auth/login, /auth/callback and
	// /auth/frontchannel-logout: requests per minute on average, and burst.
	AuthRatePerMinute int `toml:"auth_rate_per_minute"`
	AuthBurst         int `toml:"auth_burst"`

	MinTransferRateBytes int64         `toml:"-"`
	MaxFileSizeBytes     int64         `toml:"-"`
	UserQuotaBytes       int64         `toml:"-"`
	DefaultExpiryDur     time.Duration `toml:"-"`
	DiskHeadroomBytes    int64         `toml:"-"` // 0 = automatic: max(1 GiB, 5% of the file system)
	// Expiries maps each choice of ExpiryChoices (sorted shortest first)
	// to its duration.
	Expiries map[string]time.Duration `toml:"-"`
}

// Expiry returns the duration of a link expiry choice of this instance.
func (l *Limits) Expiry(choice string) (time.Duration, bool) {
	d, ok := l.Expiries[choice]
	return d, ok
}

// OIDC holds the relying-party configuration (DESIGN.md §5.1).
type OIDC struct {
	Issuer                string            `toml:"issuer"`
	ClientID              string            `toml:"client_id"`
	ClientAuth            string            `toml:"client_auth"`
	ClientKeyFile         string            `toml:"client_key_file"`
	ClientKeyID           string            `toml:"client_key_id"`
	ClientAssertionAlg    string            `toml:"client_assertion_alg"`
	ClientAssertionX5TSHA bool              `toml:"client_assertion_x5t_sha1"`
	ClientSecretFile      string            `toml:"client_secret_file"`
	Scopes                []string          `toml:"scopes"`
	RoleClaim             string            `toml:"role_claim"`
	RequiredRole          string            `toml:"required_role"`
	DisplayClaim          string            `toml:"display_claim"`
	RequiredClaims        map[string]string `toml:"required_claims"`
	RevalidateEvery       string            `toml:"revalidate_every"`
	AllowUnadvertisedPKCE bool              `toml:"allow_unadvertised_pkce"`

	// Derived.
	ClientKey     crypto.Signer       `toml:"-"`
	ClientCert    *x509.Certificate   `toml:"-"`
	ClientChain   []*x509.Certificate `toml:"-"`
	ClientSecret  string              `toml:"-"`
	RevalidateDur time.Duration       `toml:"-"`
	RoleClaimPath []string            `toml:"-"`
	IssuerURL     *url.URL            `toml:"-"`
	RedirectURL   string              `toml:"-"`
	PostLogoutURL string              `toml:"-"`
}

// Production reports whether the instance runs in production mode.
func (c *Config) Production() bool { return c.Mode == ModeProduction }

// Load reads, decodes, defaults and validates the configuration file at path,
// then loads the secrets it references.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(data)
}

// Parse is Load for in-memory TOML.
func Parse(data []byte) (*Config, error) {
	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if md.IsDefined("branding", "name") && c.Branding.Name == "" {
		// Not defaulted: an explicit empty name is a mistake.
		c.Branding.Name = " "
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := c.loadSecrets(); err != nil {
		return nil, err
	}
	if err := c.loadBranding(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&c.Mode, ModeProduction)
	def(&c.TLS, TLSACME)
	if c.Listen == "" {
		if c.TLS == TLSProxy {
			c.Listen = "127.0.0.1:8080"
		} else {
			c.Listen = ":8443"
		}
	}
	def(&c.RedirectListen, ":8080")
	def(&c.LoginLabel, "Sign in")
	def(&c.Branding.Name, DefaultBrandName)
	def(&c.SessionCookie, SessionCookiePersistent)
	def(&c.SessionIdleTimeout, "30m")
	def(&c.SessionMaxAge, "8h")
	def(&c.UI.DefaultTheme, ThemeLight)
	def(&c.UI.DefaultLanguage, "en")
	def(&c.LogLevel, "info")
	def(&c.Limits.MaxFileSize, "5GB")
	def(&c.Limits.UserQuota, "50GB")
	def(&c.Limits.DefaultExpiry, "7d")
	def(&c.Limits.MinTransferRate, "4KB")
	if c.Limits.ExpiryChoices == nil {
		c.Limits.ExpiryChoices = slices.Clone(defaultExpiryChoices)
	}
	if c.Limits.MaxRequestFiles == 0 {
		c.Limits.MaxRequestFiles = MaxRequestFilesCap
	}
	if c.Limits.MaxTransfers == 0 {
		c.Limits.MaxTransfers = 512
	}
	if c.Limits.MaxTransfersPerIP == 0 {
		c.Limits.MaxTransfersPerIP = 32
	}
	if c.Limits.AuthRatePerMinute == 0 {
		c.Limits.AuthRatePerMinute = 30
	}
	if c.Limits.AuthBurst == 0 {
		c.Limits.AuthBurst = 10
	}
	def(&c.OIDC.ClientAuth, ClientAuthPrivateKeyJWT)
	def(&c.OIDC.RoleClaim, "roles")
	def(&c.OIDC.DisplayClaim, "name")
	def(&c.OIDC.RevalidateEvery, "15m")
	if c.OIDC.Scopes == nil {
		c.OIDC.Scopes = []string{"openid", "profile", "offline_access"}
	}
}

func (c *Config) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	switch c.Mode {
	case ModeProduction, ModeDev:
	default:
		fail("mode must be %q or %q", ModeProduction, ModeDev)
	}
	if err := c.Level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		fail("log_level: %v", err)
	}

	// public_url
	pub, err := parseBaseURL(c.PublicURL)
	if err != nil {
		fail("public_url: %v", err)
	} else {
		c.Public = pub
		c.Origin = pub.Scheme + "://" + pub.Host
		if pub.Scheme != "https" {
			if c.Production() {
				fail("public_url must be https:// in production mode")
			} else if !isLoopbackHost(pub.Hostname()) {
				fail("public_url may use http:// only for localhost in dev mode")
			}
		}
	}

	switch c.TLS {
	case TLSACME:
		if pub != nil {
			if pub.Scheme != "https" {
				fail(`tls = "acme" requires an https:// public_url`)
			}
			h := pub.Hostname()
			if net.ParseIP(h) != nil || isLoopbackHost(h) || !strings.Contains(h, ".") {
				fail(`tls = "acme" requires public_url to be a public DNS name, got %q`, h)
			}
		}
		if len(c.TrustedProxies) > 0 {
			fail(`trusted_proxies is only valid with tls = "proxy"`)
		}
		if strings.HasPrefix(c.Listen, "unix:") {
			fail(`a unix: listen socket is only valid with tls = "proxy"`)
		}
		if c.TrustUnixSocketProxy {
			fail(`trust_unix_socket_proxy is only valid with tls = "proxy"`)
		}
	case TLSProxy:
		// DESIGN.md §7: refuse to start behind a proxy unless the public URL is
		// https. Dev mode may use http://localhost (validated above).
		if pub != nil && pub.Scheme != "https" && c.Production() {
			fail(`tls = "proxy" requires an https:// public_url`)
		}
		if c.RedirectHTTP {
			fail(`redirect_http is only valid with tls = "acme"`)
		}
		c.validateProxyTrust(fail)
	default:
		fail("tls must be %q or %q", TLSACME, TLSProxy)
	}
	if err := validateListen(c.Listen); err != nil {
		fail("listen: %v", err)
	}
	if c.RedirectHTTP {
		if err := validateListen(c.RedirectListen); err != nil || strings.HasPrefix(c.RedirectListen, "unix:") {
			fail("redirect_listen: must be host:port")
		}
	}
	for _, p := range c.TrustedProxies {
		pfx, err := parsePrefix(p)
		if err != nil {
			fail("trusted_proxies: %v", err)
			continue
		}
		c.TrustedProxyNs = append(c.TrustedProxyNs, pfx)
	}

	if c.DataDir == "" {
		fail("data_dir is required")
	}
	if c.RefreshKeyFile == "" {
		fail("refresh_key_file is required")
	}
	if c.ACMEEmail != "" && !strings.Contains(c.ACMEEmail, "@") {
		fail("acme_email is not an email address")
	}
	if strings.TrimSpace(c.LoginLabel) == "" || len(c.LoginLabel) > 64 {
		fail("login_label must be 1-64 characters")
	}
	switch c.SessionCookie {
	case SessionCookiePersistent, SessionCookieBrowser:
	default:
		fail("session_cookie must be %q or %q", SessionCookiePersistent, SessionCookieBrowser)
	}
	c.validateSession(fail)
	c.validateUI(fail)

	c.validateLimits(fail)
	c.validateOIDC(fail)
	c.validateBranding(fail)
	return joinErrs(errs)
}

// minProductionHeadroom is the smallest explicit disk_headroom accepted
// without a warning in production (audit 2026-11 I5).
const minProductionHeadroom = 256 * MiB

func (c *Config) validateLimits(fail func(string, ...any)) {
	l := &c.Limits
	var err error
	if l.MaxFileSizeBytes, err = ParseSize(l.MaxFileSize); err != nil {
		fail("limits.max_file_size: %v", err)
	} else if l.MaxFileSizeBytes <= 0 || l.MaxFileSizeBytes > MaxFileSizeCap {
		fail("limits.max_file_size must be between 1 byte and 100GB")
	}
	if l.UserQuotaBytes, err = ParseSize(l.UserQuota); err != nil {
		fail("limits.user_quota: %v", err)
	} else if l.UserQuotaBytes <= 0 {
		fail("limits.user_quota must be positive")
	}
	c.validateExpiries(fail)
	switch {
	case l.MaxDownloads < 0 || l.MaxDownloads > MaxDownloadsCap:
		fail("limits.max_downloads must be between 0 (no cap) and %d", MaxDownloadsCap)
	case l.DefaultMaxDownloads < 0 || l.DefaultMaxDownloads > MaxDownloadsCap:
		fail("limits.default_max_downloads must be between 0 (no limit) and %d", MaxDownloadsCap)
	case l.MaxDownloads > 0 && l.DefaultMaxDownloads > l.MaxDownloads:
		fail("limits.default_max_downloads must be at most limits.max_downloads")
	}
	if l.MaxRequestFiles < 1 || l.MaxRequestFiles > MaxRequestFilesCap {
		fail("limits.max_request_files must be between 1 and %d", MaxRequestFilesCap)
	}
	if l.DiskHeadroom != "" {
		if l.DiskHeadroomBytes, err = ParseSize(l.DiskHeadroom); err != nil {
			fail("limits.disk_headroom: %v", err)
		} else if c.Production() && l.DiskHeadroomBytes > 0 && l.DiskHeadroomBytes < minProductionHeadroom {
			c.Warnings = append(c.Warnings, "limits.disk_headroom is below 256MB: uploads can fill the disk the database and logs need")
		}
	}
	if l.MinTransferRateBytes, err = ParseSize(l.MinTransferRate); err != nil {
		fail("limits.min_transfer_rate: %v", err)
	} else if l.MinTransferRateBytes > 10*MiB {
		fail("limits.min_transfer_rate must be at most 10MB (per second)")
	} else if l.MinTransferRateBytes == 0 && c.Production() {
		c.Warnings = append(c.Warnings, "limits.min_transfer_rate = 0 disables the slow-transfer cutoff: stalled clients can hold transfer slots indefinitely")
	}
	if l.MaxTransfers < 1 || l.MaxTransfersPerIP < 1 || l.MaxTransfersPerIP > l.MaxTransfers {
		fail("limits.max_transfers and limits.max_transfers_per_ip must be positive, the latter at most the former")
	}
	if l.AuthRatePerMinute < 1 || l.AuthRatePerMinute > maxAuthRate {
		fail("limits.auth_rate_per_minute must be between 1 and %d", maxAuthRate)
	}
	if l.AuthBurst < 1 || l.AuthBurst > maxAuthRate {
		fail("limits.auth_burst must be between 1 and %d", maxAuthRate)
	}
}

// maxAuthRate bounds limits.auth_rate_per_minute and limits.auth_burst.
const maxAuthRate = 10000

// validateExpiries checks limits.expiry_choices ("12h", "3d": hours or days,
// 1h to 365d, at most 8, no two of the same length), sorts them shortest
// first and checks that limits.default_expiry is one of them.
func (c *Config) validateExpiries(fail func(string, ...any)) {
	l := &c.Limits
	if len(l.ExpiryChoices) == 0 || len(l.ExpiryChoices) > maxExpiryChoices {
		fail("limits.expiry_choices must list 1 to %d choices", maxExpiryChoices)
		return
	}
	l.Expiries = make(map[string]time.Duration, len(l.ExpiryChoices))
	seen := map[time.Duration]string{}
	ok := true
	for _, ch := range l.ExpiryChoices {
		var d time.Duration
		var err error
		if expiryChoiceRE.MatchString(ch) {
			d, err = ParseDuration(ch)
		}
		switch {
		case !expiryChoiceRE.MatchString(ch) || err != nil:
			fail(`limits.expiry_choices: %q must be a number of hours or days ("12h", "3d")`, ch)
		case d < minExpiry || d > maxExpiry:
			fail("limits.expiry_choices: %q must be between 1h and 365d", ch)
		case seen[d] != "":
			fail("limits.expiry_choices: %q and %q are the same duration", seen[d], ch)
		default:
			seen[d] = ch
			l.Expiries[ch] = d
			continue
		}
		ok = false
	}
	if !ok {
		return
	}
	slices.SortFunc(l.ExpiryChoices, func(a, b string) int { return cmp.Compare(l.Expiries[a], l.Expiries[b]) })
	d, found := l.Expiries[l.DefaultExpiry]
	if !found {
		fail("limits.default_expiry must be one of limits.expiry_choices (%s)", strings.Join(l.ExpiryChoices, ", "))
	}
	l.DefaultExpiryDur = d
}

func (c *Config) validateSession(fail func(string, ...any)) {
	var err error
	if c.SessionIdle, err = ParseDuration(c.SessionIdleTimeout); err != nil {
		fail("session_idle_timeout: %v", err)
	} else if c.SessionIdle < minSessionIdle || c.SessionIdle > maxSessionIdle {
		fail("session_idle_timeout must be between 5m and 24h")
	}
	if c.SessionLife, err = ParseDuration(c.SessionMaxAge); err != nil {
		fail("session_max_age: %v", err)
	} else if c.SessionLife < minSessionMaxAge || c.SessionLife > maxSessionMaxAge {
		fail("session_max_age must be between 15m and 30d")
	} else if c.SessionIdle > c.SessionLife {
		fail("session_idle_timeout must be at most session_max_age")
	}
}

func (c *Config) validateUI(fail func(string, ...any)) {
	switch c.UI.DefaultTheme {
	case ThemeLight, ThemeDark, ThemeSystem:
	default:
		fail("ui.default_theme must be %q, %q or %q", ThemeLight, ThemeDark, ThemeSystem)
	}
	if l, ok := i18n.Parse(c.UI.DefaultLanguage); !ok || string(l) != c.UI.DefaultLanguage {
		names := make([]string, len(i18n.Supported))
		for i, l := range i18n.Supported {
			names[i] = strconv.Quote(string(l))
		}
		fail("ui.default_language must be one of %s", strings.Join(names, ", "))
	}
}

func (c *Config) validateOIDC(fail func(string, ...any)) {
	o := &c.OIDC
	iss, err := url.Parse(o.Issuer)
	switch {
	case o.Issuer == "":
		fail("oidc.issuer is required")
	case err != nil || !iss.IsAbs() || iss.Host == "" || iss.RawQuery != "" || iss.Fragment != "" || iss.User != nil:
		fail("oidc.issuer must be an absolute URL without query, fragment or credentials")
	default:
		o.IssuerURL = iss
		if iss.Scheme != "https" {
			if c.Production() || iss.Scheme != "http" || !isLoopbackHost(iss.Hostname()) {
				fail("oidc.issuer must be https:// (http://localhost is allowed in dev mode only)")
			}
		}
		if err := checkSingleTenantIssuer(iss); err != nil {
			fail("oidc.issuer: %v", err)
		}
		if tenant, ok := entraTenant(iss); ok {
			if tid, set := o.RequiredClaims["tid"]; set && !strings.EqualFold(tid, tenant) {
				fail("oidc.required_claims.tid %q does not match the issuer tenant %q", tid, tenant)
			} else if !set {
				c.Warnings = append(c.Warnings, "Entra ID issuer without required_claims.tid; adding it is recommended")
			}
		}
	}
	if o.ClientID == "" {
		fail("oidc.client_id is required")
	}
	if o.RequiredRole == "" {
		fail("oidc.required_role is required")
	}
	if !slices.Contains(o.Scopes, "openid") {
		fail(`oidc.scopes must include "openid"`)
	}
	for _, s := range o.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n\"\\") {
			fail("oidc.scopes: invalid scope %q", s)
		}
	}
	path, err := ParseClaimPath(o.RoleClaim)
	if err != nil {
		fail("oidc.role_claim: %v", err)
	}
	o.RoleClaimPath = path
	if o.DisplayClaim == "" || strings.ContainsAny(o.DisplayClaim, " .") {
		fail("oidc.display_claim must be a top-level claim name")
	}
	for k := range o.RequiredClaims {
		if k == "" {
			fail("oidc.required_claims: empty claim name")
		}
		switch k {
		case "iss", "aud", "sub", "exp", "iat", "nbf", "nonce", "azp":
			fail("oidc.required_claims must not override registered claim %q", k)
		}
	}
	if o.RevalidateDur, err = ParseDuration(o.RevalidateEvery); err != nil {
		fail("oidc.revalidate_every: %v", err)
	} else if o.RevalidateDur < time.Minute || o.RevalidateDur > time.Hour {
		fail("oidc.revalidate_every must be between 1m and 1h")
	}

	switch o.ClientAuth {
	case ClientAuthPrivateKeyJWT:
		if o.ClientKeyFile == "" {
			fail("oidc.client_key_file is required for private_key_jwt")
		}
		if o.ClientSecretFile != "" {
			fail("oidc.client_secret_file must not be set with private_key_jwt")
		}
		switch o.ClientAssertionAlg {
		case "", "RS256", "PS256", "ES256":
		default:
			fail("oidc.client_assertion_alg must be RS256, PS256 or ES256")
		}
	case ClientAuthSecret:
		if c.Production() {
			fail(`oidc.client_auth = "client_secret" is only allowed in dev mode; production requires private_key_jwt`)
		}
		if o.ClientSecretFile == "" {
			fail("oidc.client_secret_file is required for client_secret")
		}
		if o.ClientKeyFile != "" || o.ClientAssertionAlg != "" || o.ClientKeyID != "" {
			fail("oidc.client_key_* settings are only valid with private_key_jwt")
		}
	default:
		fail("oidc.client_auth must be %q or %q", ClientAuthPrivateKeyJWT, ClientAuthSecret)
	}
	if c.Public != nil {
		o.RedirectURL = c.Origin + "/auth/callback"
		o.PostLogoutURL = c.Origin + "/login"
	}
}

func (c *Config) loadSecrets() error {
	if err := c.checkSecretFiles(c.RefreshKeyFile, c.OIDC.ClientKeyFile, c.OIDC.ClientSecretFile); err != nil {
		return err
	}
	key, err := LoadRefreshKey(c.RefreshKeyFile)
	if err != nil {
		return fmt.Errorf("config: refresh_key_file: %w", err)
	}
	c.RefreshKey = key
	if looksLikePassphrase(key) {
		c.Warnings = append(c.Warnings, "refresh_key_file holds 32 printable characters, used as the raw key: it looks like a passphrase or hex string, not random bytes; "+
			"generate a key with: openssl rand -base64 32 (replacing it ends all sessions)")
	}

	o := &c.OIDC
	switch o.ClientAuth {
	case ClientAuthPrivateKeyJWT:
		ck, err := LoadClientKey(o.ClientKeyFile)
		if err != nil {
			return fmt.Errorf("config: oidc.client_key_file: %w", err)
		}
		o.ClientKey, o.ClientCert, o.ClientChain = ck.Key, ck.Cert, ck.Chain
		if c.Production() && isTestOnlyKey(ck.Key) {
			c.Warnings = append(c.Warnings, "oidc.client_key_file is the public TEST-ONLY key committed in dev/keycloak/test-keys: anyone can sign client assertions with it; generate your own key pair")
		}
		if err := checkAlgForKey(o.ClientAssertionAlg, o.ClientKey); err != nil {
			return fmt.Errorf("config: oidc.client_assertion_alg: %w", err)
		}
		if o.ClientCert != nil {
			now := time.Now()
			if now.After(o.ClientCert.NotAfter) || now.Before(o.ClientCert.NotBefore) {
				msg := fmt.Sprintf("oidc client certificate is not valid now (valid %s to %s)",
					o.ClientCert.NotBefore.Format(time.DateOnly), o.ClientCert.NotAfter.Format(time.DateOnly))
				if c.Production() {
					return errors.New("config: " + msg)
				}
				c.Warnings = append(c.Warnings, msg)
			} else if o.ClientCert.NotAfter.Sub(now) < 30*24*time.Hour {
				c.Warnings = append(c.Warnings, "oidc client certificate expires within 30 days")
			}
		} else if o.ClientAssertionX5TSHA {
			return errors.New("config: oidc.client_assertion_x5t_sha1 requires a certificate in client_key_file")
		}
	case ClientAuthSecret:
		s, err := LoadSecretFile(o.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("config: oidc.client_secret_file: %w", err)
		}
		o.ClientSecret = s
	}
	return nil
}

// RequiredClaimKeys returns the required claim names in sorted order.
func (o *OIDC) RequiredClaimKeys() []string {
	return slices.Sorted(maps.Keys(o.RequiredClaims))
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("must be an http(s) URL")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("must be scheme://host[:port] without credentials, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("must not contain a path (Dropr is served from the root of its own origin)")
	}
	if u.Host != strings.ToLower(u.Host) {
		return nil, errors.New("host must be lowercase")
	}
	u.Path = ""
	u.RawPath = ""
	return u, nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

func validateListen(l string) error {
	if path, ok := strings.CutPrefix(l, "unix:"); ok {
		if path == "" || !strings.HasPrefix(path, "/") {
			return errors.New("unix socket path must be absolute")
		}
		return nil
	}
	_, port, err := net.SplitHostPort(l)
	if err != nil || port == "" {
		return fmt.Errorf("%q is not host:port or unix:/path", l)
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Entra ID hosts across public and sovereign clouds.
var entraHosts = map[string]bool{
	"login.microsoftonline.com":        true,
	"login.microsoft.com":              true,
	"login.windows.net":                true,
	"sts.windows.net":                  true,
	"login.microsoftonline.us":         true,
	"login.chinacloudapi.cn":           true,
	"login.partner.microsoftonline.cn": true,
}

// checkSingleTenantIssuer refuses multi-tenant and templated issuers. A
// multi-tenant issuer would accept tokens from any tenant, which breaks the
// (iss, sub) identity model.
func checkSingleTenantIssuer(u *url.URL) error {
	if strings.ContainsAny(u.String(), "{}") || strings.Contains(u.EscapedPath(), "%7B") {
		return errors.New("templated issuers (containing {tenantid}) are refused; use a single-tenant issuer")
	}
	if entraHosts[strings.ToLower(u.Hostname())] {
		seg, _, _ := strings.Cut(strings.Trim(u.Path, "/"), "/")
		switch strings.ToLower(seg) {
		case "common", "organizations", "consumers", "":
			return fmt.Errorf("multi-tenant Entra issuer %q is refused; use https://login.microsoftonline.com/<tenant-id>/v2.0", u.String())
		}
	}
	return nil
}

func entraTenant(u *url.URL) (string, bool) {
	if !entraHosts[strings.ToLower(u.Hostname())] {
		return "", false
	}
	seg, _, _ := strings.Cut(strings.Trim(u.Path, "/"), "/")
	return seg, seg != ""
}

// ParseClaimPath splits a dotted claim path ("realm_access.roles").
func ParseClaimPath(p string) ([]string, error) {
	if p == "" {
		return nil, errors.New("empty claim path")
	}
	parts := strings.Split(p, ".")
	if len(parts) > 8 {
		return nil, errors.New("claim path too deep")
	}
	for _, s := range parts {
		if s == "" {
			return nil, fmt.Errorf("invalid claim path %q", p)
		}
	}
	return parts, nil
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = "  - " + e.Error()
	}
	return fmt.Errorf("config: invalid configuration:\n%s", strings.Join(msgs, "\n"))
}

// validateProxyTrust enforces how client addresses are learned behind a
// reverse proxy (audit L-1). Without it every client appears with the
// proxy's address (or none), so all share one rate-limit bucket and a
// single client can lock everyone out of signing in.
//
//   - TCP listener: trusted_proxies must list the proxy's address.
//   - unix: listener: the peer is necessarily the proxy, but trusting its
//     X-Forwarded-For must still be explicit: trusted_proxies (also used to
//     skip inner proxies in the header) or trust_unix_socket_proxy = true.
//
// Production refuses to start otherwise; dev mode only warns.
func (c *Config) validateProxyTrust(fail func(string, ...any)) {
	unix := strings.HasPrefix(c.Listen, "unix:")
	if c.TrustUnixSocketProxy && !unix {
		fail("trust_unix_socket_proxy is only valid with a unix: listen socket")
		return
	}
	if len(c.TrustedProxies) > 0 || c.TrustUnixSocketProxy {
		return
	}
	var msg string
	if unix {
		msg = `tls = "proxy" on a unix: socket needs trust_unix_socket_proxy = true (and a proxy that sets X-Forwarded-For) or trusted_proxies; ` +
			`otherwise every client shares one address and one rate-limit bucket`
	} else {
		msg = `tls = "proxy" needs trusted_proxies (the address of your reverse proxy, e.g. ["127.0.0.1"]); ` +
			`otherwise every client appears with the proxy's address and one client can rate-limit everyone`
	}
	if c.Production() {
		fail("%s", msg)
	} else {
		c.Warnings = append(c.Warnings, msg)
	}
}
