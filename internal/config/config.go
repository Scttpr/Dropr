// Package config loads and validates dropr.toml.
//
// Loading is strict: unknown keys are rejected, every value is validated, and
// the production-mode refusal rules of DESIGN.md (§5.1.2, §7, §10) are enforced
// here so that a misconfigured instance never starts. Secrets are read from
// files only, never from the TOML file itself or the environment.
package config

import (
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
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
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

// Client authentication methods at the token endpoint.
const (
	ClientAuthPrivateKeyJWT = "private_key_jwt"
	ClientAuthSecret        = "client_secret"
)

// Allowed link expiries (DESIGN.md §6).
var allowedExpiries = map[string]time.Duration{
	"1h":  time.Hour,
	"1d":  24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

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
	LogLevel             string `toml:"log_level"`

	Limits Limits `toml:"limits"`
	OIDC   OIDC   `toml:"oidc"`

	// Derived.
	Public         *url.URL       `toml:"-"` // parsed public_url, no trailing slash
	Origin         string         `toml:"-"` // scheme://host[:port]
	TrustedProxyNs []netip.Prefix `toml:"-"`
	RefreshKey     []byte         `toml:"-"` // 32-byte master key
	Level          slog.Level     `toml:"-"`
	Warnings       []string       `toml:"-"` // non-fatal findings for the operator
}

// Limits holds size and expiry limits.
type Limits struct {
	MaxFileSize   string `toml:"max_file_size"`
	UserQuota     string `toml:"user_quota"`
	DefaultExpiry string `toml:"default_expiry"`
	DiskHeadroom  string `toml:"disk_headroom"`
	// Transfer limits (audit L-4): concurrent part uploads and downloads in
	// total and per client address, and the minimum rate (bytes per second,
	// averaged over 60 s) below which a transfer is cut ("0" disables).
	MaxTransfers      int    `toml:"max_transfers"`
	MaxTransfersPerIP int    `toml:"max_transfers_per_ip"`
	MinTransferRate   string `toml:"min_transfer_rate"`

	MinTransferRateBytes int64         `toml:"-"`
	MaxFileSizeBytes     int64         `toml:"-"`
	UserQuotaBytes       int64         `toml:"-"`
	DefaultExpiryDur     time.Duration `toml:"-"`
	DiskHeadroomBytes    int64         `toml:"-"` // 0 = automatic: max(1 GiB, 5% of the file system)
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

// ExpiryDuration maps a link expiry choice ("1h", "1d", "7d", "30d") to its
// duration.
func ExpiryDuration(s string) (time.Duration, bool) {
	d, ok := allowedExpiries[s]
	return d, ok
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
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := c.loadSecrets(); err != nil {
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
	def(&c.LogLevel, "info")
	def(&c.Limits.MaxFileSize, "5GB")
	def(&c.Limits.UserQuota, "50GB")
	def(&c.Limits.DefaultExpiry, "7d")
	def(&c.Limits.MinTransferRate, "4KB")
	if c.Limits.MaxTransfers == 0 {
		c.Limits.MaxTransfers = 512
	}
	if c.Limits.MaxTransfersPerIP == 0 {
		c.Limits.MaxTransfersPerIP = 32
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

	c.validateLimits(fail)
	c.validateOIDC(fail)
	return joinErrs(errs)
}

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
	d, ok := allowedExpiries[l.DefaultExpiry]
	if !ok {
		fail("limits.default_expiry must be one of 1h, 1d, 7d, 30d")
	}
	l.DefaultExpiryDur = d
	if l.DiskHeadroom != "" {
		if l.DiskHeadroomBytes, err = ParseSize(l.DiskHeadroom); err != nil {
			fail("limits.disk_headroom: %v", err)
		}
	}
	if l.MinTransferRateBytes, err = ParseSize(l.MinTransferRate); err != nil {
		fail("limits.min_transfer_rate: %v", err)
	} else if l.MinTransferRateBytes > 10*MiB {
		fail("limits.min_transfer_rate must be at most 10MB (per second)")
	}
	if l.MaxTransfers < 1 || l.MaxTransfersPerIP < 1 || l.MaxTransfersPerIP > l.MaxTransfers {
		fail("limits.max_transfers and limits.max_transfers_per_ip must be positive, the latter at most the former")
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

	o := &c.OIDC
	switch o.ClientAuth {
	case ClientAuthPrivateKeyJWT:
		ck, err := LoadClientKey(o.ClientKeyFile)
		if err != nil {
			return fmt.Errorf("config: oidc.client_key_file: %w", err)
		}
		o.ClientKey, o.ClientCert, o.ClientChain = ck.Key, ck.Cert, ck.Chain
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
