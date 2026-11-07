package oidc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"
)

// Identity is the verified result of an ID token (or userinfo) check.
type Identity struct {
	Issuer      string
	Subject     string
	SID         string
	DisplayName string
}

// Verification failures that map to distinct user-facing outcomes.
var (
	// ErrRoleMissing means the token is valid but lacks the required role.
	ErrRoleMissing = errors.New("oidc: required role missing")
	// ErrClaimMismatch means a required_claims entry did not match.
	ErrClaimMismatch = errors.New("oidc: required claim mismatch")
)

const maxSubjectLen = 255

// verifyMode distinguishes the initial login from a refresh.
type verifyMode int

const (
	verifyLogin verifyMode = iota
	verifyRefresh
)

// verifyIDToken applies every ID token check of DESIGN.md §5.1:
//
//   - signature against the discovered JWKS, asymmetric algorithms only
//     (go-oidc, restricted to asymmetricAlgs);
//   - iss exact match and aud contains client_id (go-oidc);
//   - azp: required and equal to client_id when aud has several values, and
//     equal to client_id whenever present (OIDC Core §3.1.3.7);
//   - exp, nbf, iat with ±clockSkew;
//   - nonce equal to the one stored in the state cookie (login only; OIDC Core
//     §12.2 does not require a nonce on refreshed tokens and Dropr does not
//     persist it);
//   - every required_claims entry, exact string match;
//   - the role claim contains required_role.
//
// It returns ErrRoleMissing / ErrClaimMismatch for authorization failures and
// other errors for invalid tokens.
func (p *Provider) verifyIDToken(ctx context.Context, raw, nonce string, mode verifyMode) (*Identity, error) {
	if raw == "" {
		return nil, errors.New("oidc: no id_token in token response")
	}
	tok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token: %w", err)
	}
	var rawClaims json.RawMessage
	if err := tok.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("oidc: id_token claims: %w", err)
	}
	claims, err := decodeClaims(rawClaims)
	if err != nil {
		return nil, err
	}
	if err := p.checkTimes(claims); err != nil {
		return nil, err
	}

	aud := tok.Audience
	azp, hasAZP := claims["azp"]
	if hasAZP {
		if s, ok := azp.(string); !ok || s != p.cfg.ClientID {
			return nil, errors.New("oidc: id_token azp is not this client")
		}
	} else if len(aud) > 1 {
		return nil, errors.New("oidc: id_token has several audiences but no azp")
	}

	if mode == verifyLogin {
		n, _ := claims["nonce"].(string)
		if nonce == "" || subtle.ConstantTimeCompare([]byte(n), []byte(nonce)) != 1 {
			return nil, errors.New("oidc: id_token nonce mismatch")
		}
	}
	return p.authorize(tok.Issuer, claims)
}

// authorize checks subject, required claims and role on a verified claim set.
func (p *Provider) authorize(issuer string, claims map[string]any) (*Identity, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" || len(sub) > maxSubjectLen {
		return nil, errors.New("oidc: invalid sub claim")
	}
	// On authorization failures the (verified) identity is returned with the
	// error, so the caller can record that the account lost access.
	id := &Identity{Issuer: issuer, Subject: sub}
	for _, k := range p.cfg.RequiredClaimKeys() {
		v, ok := claims[k].(string)
		if !ok || v != p.cfg.RequiredClaims[k] {
			return id, fmt.Errorf("%w: %s", ErrClaimMismatch, k)
		}
	}
	if !HasRole(claims, p.cfg.RoleClaimPath, p.cfg.RequiredRole) {
		return id, ErrRoleMissing
	}
	id.SID, _ = claims["sid"].(string)
	id.DisplayName, _ = claims[p.cfg.DisplayClaim].(string)
	return id, nil
}

func (p *Provider) checkTimes(claims map[string]any) error {
	now := p.now()
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return errors.New("oidc: id_token lacks exp")
	}
	if !now.Before(exp.Add(clockSkew)) {
		return errors.New("oidc: id_token expired")
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return errors.New("oidc: id_token lacks iat")
	}
	if iat.After(now.Add(clockSkew)) {
		return errors.New("oidc: id_token issued in the future")
	}
	if v, present := claims["nbf"]; present {
		nbf, ok := numericDate(v)
		if !ok {
			return errors.New("oidc: id_token has malformed nbf")
		}
		if nbf.After(now.Add(clockSkew)) {
			return errors.New("oidc: id_token not yet valid")
		}
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1<<40 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// decodeClaims parses a JSON object, keeping numbers exact.
func decodeClaims(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("oidc: decode claims: %w", err)
	}
	// d.More() would accept a stray "}" or "]" (audit 2026-11 A03-2).
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("oidc: trailing data after claims")
	}
	if m == nil {
		return nil, errors.New("oidc: claims are not an object")
	}
	return m, nil
}

// LookupClaim follows a dotted claim path through nested JSON objects.
func LookupClaim(claims map[string]any, path []string) (any, bool) {
	var cur any = claims
	for _, seg := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// HasRole reports whether the claim at path equals role (string claim) or
// contains it (array claim). Non-string array elements are ignored and the
// comparison is exact and case-sensitive.
func HasRole(claims map[string]any, path []string, role string) bool {
	if role == "" || len(path) == 0 {
		return false
	}
	v, ok := LookupClaim(claims, path)
	if !ok {
		return false
	}
	switch t := v.(type) {
	case string:
		return t == role
	case []any:
		return slices.ContainsFunc(t, func(e any) bool {
			s, ok := e.(string)
			return ok && s == role
		})
	default:
		return false
	}
}
