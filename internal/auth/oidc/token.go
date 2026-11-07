package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// tokenResponse is a successful token endpoint response (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// tokenError is an error response (RFC 6749 §5.2). Only the code is logged;
// descriptions may echo user data.
type tokenError struct {
	Status int
	Code   string
}

func (e *tokenError) Error() string {
	return fmt.Sprintf("oidc: token endpoint returned %d (%s)", e.Status, e.Code)
}

const maxTokenResponse = 1 << 20

// tokenRequest POSTs form to the token endpoint with client authentication.
func (p *Provider) tokenRequest(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, err := p.clientAuthRequest(ctx, p.meta.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil {
		return nil, fmt.Errorf("oidc: token endpoint: %w", err)
	}
	if len(body) > maxTokenResponse {
		return nil, errors.New("oidc: token response too large")
	}
	if resp.StatusCode != http.StatusOK {
		te := &tokenError{Status: resp.StatusCode, Code: "unknown"}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" && len(e.Error) < 64 && isPrintableASCII(e.Error) {
			te.Code = e.Error
		}
		return nil, te
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, errors.New("oidc: token response is not JSON")
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, errors.New("oidc: token response lacks a bearer access token")
	}
	return &tr, nil
}

// revokeTimeout bounds a background revocation request.
const revokeTimeout = 10 * time.Second

// revokeRefreshToken asks the provider to revoke a refresh token (RFC 7009)
// in the background. It never blocks or fails the caller: the outcome is only
// logged (audit 2026-11 A07-4).
func (p *Provider) revokeRefreshToken(ctx context.Context, refreshToken string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	go func() {
		defer cancel()
		req, err := p.clientAuthRequest(ctx, p.meta.RevocationEndpoint, url.Values{
			"token":           {refreshToken},
			"token_type_hint": {"refresh_token"},
		})
		if err == nil {
			var resp *http.Response
			if resp, err = p.client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					err = fmt.Errorf("revocation endpoint returned %d", resp.StatusCode)
				}
			}
		}
		if err != nil {
			p.log.WarnContext(ctx, "refresh token revocation failed", "err", err)
		}
	}()
}

// clientAuthRequest builds a form POST to endpoint carrying the configured
// client authentication (private_key_jwt or client_secret). The assertion's
// audience is the token endpoint, which providers accept for their other
// client-authenticated endpoints too.
func (p *Provider) clientAuthRequest(ctx context.Context, endpoint string, form url.Values) (*http.Request, error) {
	form.Set("client_id", p.cfg.ClientID)
	if p.signer != nil {
		a, err := p.signer.sign(p.meta.TokenEndpoint, p.now())
		if err != nil {
			return nil, fmt.Errorf("oidc: sign client assertion: %w", err)
		}
		form.Set("client_assertion_type", ClientAssertionType)
		form.Set("client_assertion", a)
	} else if p.secretAuth == "post" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.signer == nil && p.secretAuth == "basic" {
		// RFC 6749 §2.3.1: form-urlencode both parts before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	return req, nil
}

// fetchUserinfo calls the userinfo endpoint with an access token and returns
// its claims. Only plain JSON responses are accepted.
func (p *Provider) fetchUserinfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if p.meta.UserinfoEndpoint == "" {
		return nil, errors.New("oidc: provider has no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.meta.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: userinfo returned %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, errors.New("oidc: userinfo response is not plain JSON")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTokenResponse {
		return nil, errors.New("oidc: userinfo response too large")
	}
	return decodeClaims(body)
}

func isPrintableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
