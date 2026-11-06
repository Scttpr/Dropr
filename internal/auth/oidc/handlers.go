package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/ids"
)

// StateCookieName holds the sealed state, nonce and PKCE verifier between
// /auth/login and /auth/callback. SameSite=Lax is required: the callback is a
// top-level cross-site navigation from the provider.
const StateCookieName = "__Host-dropr_oidc"

const stateTTL = 10 * time.Minute

var stateAAD = []byte("dropr/v1 oidc-state")

type statePayload struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	IssuedAt int64  `json:"t"`
}

// HandleLogin starts the Authorization Code + PKCE flow.
func (p *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	st := statePayload{
		State:    ids.NewSecret(),
		Nonce:    ids.NewSecret(),
		Verifier: oauth2.GenerateVerifier(),
		IssuedAt: p.now().Unix(),
	}
	raw, err := json.Marshal(st)
	if err != nil {
		p.fail(w, r, http.StatusInternalServerError, "Sign-in could not be started.", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    b64.EncodeToString(p.cookie.Seal(raw, stateAAD)),
		Path:     "/",
		MaxAge:   int(stateTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, p.authCodeURL(st), http.StatusFound)
}

func (p *Provider) authCodeURL(st statePayload) string {
	u, _ := url.Parse(p.meta.AuthorizationEndpoint) // validated at startup
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", st.State)
	q.Set("nonce", st.Nonce)
	q.Set("code_challenge", oauth2.S256ChallengeFromVerifier(st.Verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

func clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: StateCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (p *Provider) readState(r *http.Request) (*statePayload, error) {
	cs := r.CookiesNamed(StateCookieName)
	if len(cs) != 1 {
		return nil, errors.New("missing or duplicate state cookie")
	}
	ct, err := b64.DecodeString(cs[0].Value)
	if err != nil {
		return nil, errors.New("malformed state cookie")
	}
	raw, err := p.cookie.Open(ct, stateAAD)
	if err != nil {
		return nil, errors.New("state cookie failed authentication")
	}
	var st statePayload
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, errors.New("malformed state payload")
	}
	age := p.now().Sub(time.Unix(st.IssuedAt, 0))
	if age < -clockSkew || age > stateTTL {
		return nil, errors.New("state cookie expired")
	}
	if st.State == "" || st.Nonce == "" || st.Verifier == "" {
		return nil, errors.New("incomplete state payload")
	}
	return &st, nil
}

// HandleCallback completes the flow: it checks state, redeems the code with
// the PKCE verifier, verifies the ID token, provisions the user, creates a
// fresh session and renders the landing page.
func (p *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// The state cookie is single-use whatever the outcome.
	clearStateCookie(w)

	st, err := p.readState(r)
	if err != nil {
		p.fail(w, r, http.StatusBadRequest, "Your sign-in attempt expired or was started in another window. Please sign in again.", err)
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		p.fail(w, r, http.StatusBadRequest, "Your sign-in attempt expired or was started in another window. Please sign in again.",
			errors.New("state mismatch"))
		return
	}
	// RFC 9207 mix-up defense: if the provider names itself, it must be ours.
	if iss, present := q["iss"]; present || p.meta.AuthorizationResponseISSSupported {
		if len(iss) != 1 || iss[0] != p.cfg.Issuer {
			p.fail(w, r, http.StatusBadRequest, "The sign-in response came from an unexpected provider.", errors.New("iss parameter mismatch"))
			return
		}
	}
	if e := q.Get("error"); e != "" {
		code := "unknown"
		if len(e) < 64 && isPrintableASCII(e) {
			code = e
		}
		p.log.InfoContext(ctx, "provider returned an authorization error", "error_code", code)
		p.pages.SignInError(w, r, http.StatusUnauthorized, "Sign-in was canceled or refused by your identity provider.")
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		p.fail(w, r, http.StatusBadRequest, "The sign-in response was incomplete. Please sign in again.", errors.New("missing code"))
		return
	}

	tr, err := p.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {st.Verifier},
	})
	if err != nil {
		p.fail(w, r, http.StatusBadGateway, "Sign-in failed while contacting your identity provider. Please try again.", err)
		return
	}
	id, err := p.verifyIDToken(ctx, tr.IDToken, st.Nonce, verifyLogin)
	switch {
	case errors.Is(err, ErrRoleMissing), errors.Is(err, ErrClaimMismatch):
		p.log.InfoContext(ctx, "login refused: not authorized", "reason", err.Error())
		if id != nil {
			// An existing account that lost the role: its request links stop
			// accepting uploads (audit I-3).
			if lerr := p.st.MarkAccessLost(ctx, id.Issuer, id.Subject, p.now()); lerr != nil {
				p.log.ErrorContext(ctx, "record lost access", "err", lerr)
			}
		}
		p.pages.Forbidden(w, r)
		return
	case err != nil:
		p.fail(w, r, http.StatusUnauthorized, "Your identity provider's response could not be verified.", err)
		return
	}
	if tr.RefreshToken == "" {
		p.fail(w, r, http.StatusBadGateway,
			"Your identity provider did not issue a refresh token, so your access cannot be kept up to date. Ask your administrator to check the provider setup.",
			errors.New("no refresh token in token response"))
		return
	}

	u, created, err := p.st.ProvisionUser(ctx, id.Issuer, id.Subject, id.DisplayName, p.now())
	if err != nil {
		p.fail(w, r, http.StatusInternalServerError, "Sign-in failed. Please try again.", err)
		return
	}
	if u.DisabledAt != nil {
		p.log.InfoContext(ctx, "login refused: account disabled", "user", u.ID)
		p.pages.Forbidden(w, r)
		return
	}
	if _, err := p.sessions.Create(ctx, w, r, session.NewParams{
		User: u, RefreshToken: tr.RefreshToken, OIDCSID: id.SID,
	}); err != nil {
		p.fail(w, r, http.StatusInternalServerError, "Sign-in failed. Please try again.", err)
		return
	}
	p.log.InfoContext(ctx, "login", "user", u.ID, "new_account", created)
	p.pages.CallbackLanding(w, r)
}

// HandleLogout ends the local session, then sends the browser to the
// provider's end_session_endpoint (RP-initiated logout) when there is one.
//
// The request carries client_id and post_logout_redirect_uri rather than
// id_token_hint, so Dropr never stores ID tokens; providers may then ask the
// user to confirm the logout, which is the safer behavior anyway.
func (p *Provider) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := session.FromContext(ctx)
	if err := p.sessions.Destroy(ctx, w, s); err != nil {
		p.log.ErrorContext(ctx, "logout: destroy session", "err", err)
	}
	if s != nil {
		p.log.InfoContext(ctx, "logout", "user", s.UserID())
	}
	target := "/login"
	if p.meta.EndSessionEndpoint != "" {
		u, err := url.Parse(p.meta.EndSessionEndpoint)
		if err == nil {
			q := u.Query()
			q.Set("client_id", p.cfg.ClientID)
			q.Set("post_logout_redirect_uri", p.cfg.PostLogoutURL)
			u.RawQuery = q.Encode()
			target = u.String()
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// HandleFrontchannelLogout implements OIDC Front-Channel Logout: the provider
// loads this URL (usually in an iframe) with iss and sid; every session bound
// to that provider session is ended. The browser's own cookies are not used
// (SameSite=Strict cookies are not sent in cross-site frames).
func (p *Provider) HandleFrontchannelLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	iss, sid := q.Get("iss"), q.Get("sid")
	h := w.Header()
	// Allow only the provider to frame this response.
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors "+p.IssuerOrigin())
	h.Del("X-Frame-Options")
	h.Set("Cache-Control", "no-store")
	if iss != p.cfg.Issuer || sid == "" || len(sid) > 512 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	n, err := p.st.DeleteSessionsByOIDCSID(ctx, sid)
	if err != nil {
		p.log.ErrorContext(ctx, "front-channel logout", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	p.log.InfoContext(ctx, "front-channel logout", "sessions", n)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

func (p *Provider) fail(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	p.log.WarnContext(r.Context(), "sign-in failed", "status", status, "reason", err.Error())
	p.pages.SignInError(w, r, status, msg)
}
