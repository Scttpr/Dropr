// Package oidc implements Dropr's generic OpenID Connect relying party
// (DESIGN.md §5.1): discovery with issuer pinning and capability checks,
// Authorization Code + PKCE (S256) with state and nonce, private_key_jwt
// client authentication, strict ID token verification, just-in-time
// provisioning, periodic revalidation through the refresh token, and
// RP-initiated plus front-channel logout.
//
// Nothing provider-specific is hard-coded; differences live in configuration.
package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/seal"
	"github.com/scttpr/dropr/internal/store"
)

// asymmetricAlgs are the only ID token signature algorithms accepted. "none"
// and every HMAC algorithm are excluded, so a token "signed" with the
// provider's public key as an HMAC secret is rejected before any key lookup.
var asymmetricAlgs = []string{
	gooidc.RS256, gooidc.RS384, gooidc.RS512,
	gooidc.PS256, gooidc.PS384, gooidc.PS512,
	gooidc.ES256, gooidc.ES384, gooidc.ES512,
	gooidc.EdDSA,
}

// Metadata is the subset of the discovery document Dropr uses.
type Metadata struct {
	Issuer                             string   `json:"issuer"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	JWKSURI                            string   `json:"jwks_uri"`
	UserinfoEndpoint                   string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                 string   `json:"end_session_endpoint"`
	CodeChallengeMethods               []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgs       []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	GrantTypes                         []string `json:"grant_types_supported"`
	ScopesSupported                    []string `json:"scopes_supported"`
	IDTokenSigningAlgs                 []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypes                      []string `json:"response_types_supported"`
	FrontchannelLogoutSupported        bool     `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported bool     `json:"frontchannel_logout_session_supported"`
	AuthorizationResponseISSSupported  bool     `json:"authorization_response_iss_parameter_supported"`
}

// Pages renders the user-facing outcomes of the auth flow.
type Pages interface {
	// SignInError renders a plain-language sign-in failure.
	SignInError(w http.ResponseWriter, r *http.Request, status int, message string)
	// Forbidden renders the "no access" page (role missing or account disabled).
	Forbidden(w http.ResponseWriter, r *http.Request)
	// CallbackLanding renders the same-origin page that navigates to "/".
	CallbackLanding(w http.ResponseWriter, r *http.Request)
}

// Options configures the relying party.
type Options struct {
	OIDC         *config.OIDC
	Production   bool
	PublicOrigin string // scheme://host[:port], no trailing slash
	RefreshKey   []byte // instance master key (state cookie key is derived)
	Store        *store.Store
	Sessions     *session.Manager
	Pages        Pages
	HTTPClient   *http.Client // nil: a hardened default
	Logger       *slog.Logger
	Now          func() time.Time
}

// Provider is the configured relying party.
type Provider struct {
	cfg        *config.OIDC
	production bool
	origin     string
	meta       Metadata
	verifier   *gooidc.IDTokenVerifier
	signer     *assertionSigner // nil with client_secret
	secretAuth string           // "basic" or "post" with client_secret
	cookie     *seal.AEAD
	st         *store.Store
	sessions   *session.Manager
	pages      Pages
	client     *http.Client
	log        *slog.Logger
	now        func() time.Time
	// formOrigins are the provider origins the browser is sent to.
	formOrigins []string
}

// clockSkew is the tolerance applied to exp, nbf and iat.
const clockSkew = time.Minute

// DefaultHTTPClient returns the client used to talk to the provider: TLS 1.2+,
// bounded time, and no redirect following (discovery, JWKS, token and
// userinfo endpoints must answer directly).
func DefaultHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = 15 * time.Second
	return &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// New performs discovery against the configured issuer, verifies its
// capabilities and returns the relying party. Warnings describe capability
// gaps tolerated in dev mode. In production any gap is an error.
func New(ctx context.Context, o Options) (*Provider, []string, error) {
	if o.OIDC == nil || o.Store == nil || o.Sessions == nil || o.Pages == nil {
		return nil, nil, errors.New("oidc: incomplete options")
	}
	if o.HTTPClient == nil {
		o.HTTPClient = DefaultHTTPClient()
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	cookie, err := seal.NewDerived(o.RefreshKey, seal.InfoOIDCCookie)
	if err != nil {
		return nil, nil, err
	}
	// The verifier's key set refreshes in the background of later requests,
	// so it gets a context that outlives startup but keeps the HTTP client.
	baseCtx := gooidc.ClientContext(context.WithoutCancel(ctx), o.HTTPClient)
	discCtx, cancel := context.WithTimeout(gooidc.ClientContext(ctx, o.HTTPClient), 30*time.Second)
	defer cancel()

	// go-oidc requires the discovered "issuer" to equal the configured one
	// exactly (no normalization), which is the pinning DESIGN.md asks for.
	op, err := gooidc.NewProvider(discCtx, o.OIDC.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: discovery for %s failed: %w", o.OIDC.Issuer, err)
	}
	var meta Metadata
	if err := op.Claims(&meta); err != nil {
		return nil, nil, fmt.Errorf("oidc: discovery document: %w", err)
	}
	if meta.Issuer != o.OIDC.Issuer {
		return nil, nil, fmt.Errorf("oidc: discovered issuer %q does not match configured %q", meta.Issuer, o.OIDC.Issuer)
	}

	p := &Provider{
		cfg:        o.OIDC,
		production: o.Production,
		origin:     strings.TrimSuffix(o.PublicOrigin, "/"),
		meta:       meta,
		cookie:     cookie,
		st:         o.Store,
		sessions:   o.Sessions,
		pages:      o.Pages,
		client:     o.HTTPClient,
		log:        o.Logger.With("component", "oidc"),
		now:        o.Now,
	}
	warnings, err := p.checkCapabilities()
	if err != nil {
		return nil, warnings, err
	}

	algs := intersect(asymmetricAlgs, meta.IDTokenSigningAlgs)
	p.verifier = op.VerifierContext(baseCtx, &gooidc.Config{
		ClientID:             o.OIDC.ClientID,
		SupportedSigningAlgs: algs,
		// exp, nbf and iat are checked in verifyIDToken with a uniform skew.
		SkipExpiryCheck: true,
		Now:             o.Now,
	})

	switch o.OIDC.ClientAuth {
	case config.ClientAuthPrivateKeyJWT:
		alg, err := chooseAssertionAlg(o.OIDC.ClientAssertionAlg, o.OIDC.ClientKey, meta.TokenEndpointAuthSigningAlgs)
		if err != nil {
			return nil, warnings, err
		}
		p.signer, err = newAssertionSigner(o.OIDC.ClientKey, o.OIDC.ClientCert, alg, o.OIDC.ClientKeyID,
			o.OIDC.ClientID, o.OIDC.ClientAssertionX5TSHA)
		if err != nil {
			return nil, warnings, err
		}
	case config.ClientAuthSecret:
		p.secretAuth = "basic"
		if len(meta.TokenEndpointAuthMethods) > 0 && !slices.Contains(meta.TokenEndpointAuthMethods, "client_secret_basic") {
			p.secretAuth = "post"
		}
	}

	for _, ep := range []string{o.OIDC.Issuer, meta.AuthorizationEndpoint, meta.EndSessionEndpoint} {
		if ep == "" {
			continue
		}
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			if org := u.Scheme + "://" + u.Host; !slices.Contains(p.formOrigins, org) {
				p.formOrigins = append(p.formOrigins, org)
			}
		}
	}
	return p, warnings, nil
}

// checkCapabilities verifies the discovery document against what Dropr
// requires (DESIGN.md §5.1.2, §10). Hard requirements fail in every mode;
// "production" requirements fail in production and warn in dev.
func (p *Provider) checkCapabilities() ([]string, error) {
	m := p.meta
	var warnings, prodErrs []string
	need := func(msg string) { prodErrs = append(prodErrs, msg) }

	for name, ep := range map[string]string{
		"authorization_endpoint": m.AuthorizationEndpoint,
		"token_endpoint":         m.TokenEndpoint,
		"jwks_uri":               m.JWKSURI,
	} {
		if ep == "" {
			return nil, fmt.Errorf("oidc: discovery document lacks %s", name)
		}
	}
	for name, ep := range map[string]string{
		"authorization_endpoint": m.AuthorizationEndpoint,
		"token_endpoint":         m.TokenEndpoint,
		"jwks_uri":               m.JWKSURI,
		"userinfo_endpoint":      m.UserinfoEndpoint,
		"end_session_endpoint":   m.EndSessionEndpoint,
	} {
		if ep == "" {
			continue
		}
		u, err := url.Parse(ep)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return nil, fmt.Errorf("oidc: invalid %s %q", name, ep)
		}
		if u.Scheme != "https" && (p.production || u.Scheme != "http") {
			return nil, fmt.Errorf("oidc: %s must be https", name)
		}
	}
	if len(intersect(asymmetricAlgs, m.IDTokenSigningAlgs)) == 0 {
		return nil, fmt.Errorf("oidc: provider advertises no asymmetric ID token algorithm (got %v)", m.IDTokenSigningAlgs)
	}
	if len(m.ResponseTypes) > 0 && !slices.Contains(m.ResponseTypes, "code") {
		return nil, errors.New(`oidc: provider does not support response_type "code"`)
	}

	// PKCE S256.
	switch {
	case slices.Contains(m.CodeChallengeMethods, "S256"):
	case len(m.CodeChallengeMethods) > 0:
		need(fmt.Sprintf("provider does not support PKCE S256 (supports %v)", m.CodeChallengeMethods))
	case p.cfg.AllowUnadvertisedPKCE:
		warnings = append(warnings, "provider does not advertise code_challenge_methods_supported; assuming PKCE S256 (allow_unadvertised_pkce)")
	default:
		need("provider does not advertise PKCE S256 support (code_challenge_methods_supported); " +
			"if it supports PKCE without advertising it (e.g. Microsoft Entra ID), set oidc.allow_unadvertised_pkce = true")
	}

	// Client authentication. Absent list means client_secret_basic only.
	methods := m.TokenEndpointAuthMethods
	if len(methods) == 0 {
		methods = []string{"client_secret_basic"}
	}
	switch p.cfg.ClientAuth {
	case config.ClientAuthPrivateKeyJWT:
		if !slices.Contains(methods, "private_key_jwt") {
			return warnings, fmt.Errorf("oidc: provider does not support private_key_jwt (supports %v)", methods)
		}
	case config.ClientAuthSecret:
		if !slices.Contains(methods, "client_secret_basic") && !slices.Contains(methods, "client_secret_post") {
			return warnings, fmt.Errorf("oidc: provider supports neither client_secret_basic nor client_secret_post (supports %v)", methods)
		}
		if !slices.Contains(methods, "private_key_jwt") {
			need("provider does not support private_key_jwt, required in production")
		}
	}

	// Refresh tokens (needed for revalidation).
	switch {
	case len(m.GrantTypes) > 0:
		if !slices.Contains(m.GrantTypes, "refresh_token") {
			need("provider does not support the refresh_token grant, required for revalidation")
		}
	case slices.Contains(m.ScopesSupported, "offline_access"):
	default:
		need("provider advertises neither the refresh_token grant nor the offline_access scope; revalidation needs refresh tokens")
	}

	if m.EndSessionEndpoint == "" {
		warnings = append(warnings, "provider has no end_session_endpoint; logout ends only the local session")
	}
	if len(prodErrs) > 0 {
		if p.production {
			return warnings, fmt.Errorf("oidc: refusing to start in production mode: %s", strings.Join(prodErrs, "; "))
		}
		warnings = append(warnings, prodErrs...)
	}
	return warnings, nil
}

// Metadata returns the discovery metadata.
func (p *Provider) Metadata() Metadata { return p.meta }

// FormActionOrigins returns the provider origins that must be allowed in the
// CSP form-action directive (redirects after form posts are subject to it).
func (p *Provider) FormActionOrigins() []string { return slices.Clone(p.formOrigins) }

// IssuerOrigin returns scheme://host of the issuer.
func (p *Provider) IssuerOrigin() string {
	u := p.cfg.IssuerURL
	if u == nil {
		if parsed, err := url.Parse(p.cfg.Issuer); err == nil {
			u = parsed
		}
	}
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func intersect(allowed, offered []string) []string {
	var out []string
	for _, a := range allowed {
		if slices.Contains(offered, a) {
			out = append(out, a)
		}
	}
	return out
}
