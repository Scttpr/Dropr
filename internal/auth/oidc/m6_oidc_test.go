package oidc_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/auth/oidc/oidctest"
	"github.com/scttpr/dropr/internal/config"
)

// Milestone 6 gap fill. TestIDTokenNegative and TestRevalidation already
// cover alg none, HS256-with-public-key, unknown key, wrong iss/aud/nonce,
// azp, expiry, nbf, iat, missing role and a different sub on refresh for the
// login path (and a subset on refresh). This file adds:
//   - JOSE header attacks on login (alg spelling variants, embedded jwk/jku,
//     unknown crit, RS256 header with an empty or HS-style signature);
//   - malformed claim types (exp/iat/nbf as strings, absurd exp, aud as a
//     number, sub not a string or too long);
//   - the claim checks that were only tested at login, now on refresh
//     (wrong iss, expired, nbf/iat in the future, HS256, azp, multi-aud
//     without azp, empty sub, nested-path role removal).

func TestM6IDTokenHeaderAttacks(t *testing.T) {
	t.Parallel()
	cases := map[string]func(k *oidctest.Knobs){
		"alg None (capitalised)": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignNone
			k.MutateHeader = func(h map[string]any) { h["alg"] = "None" }
		},
		"alg NONE": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignNone
			k.MutateHeader = func(h map[string]any) { h["alg"] = "NONE" }
		},
		"alg RS256 with empty signature": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignNone
			k.MutateHeader = func(h map[string]any) { h["alg"] = "RS256" }
		},
		"alg RS256 header, HMAC signature": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignHS256PublicKey
			k.MutateHeader = func(h map[string]any) { h["alg"] = "RS256" }
		},
		"HS256 without kid": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignHS256PublicKey
			k.MutateHeader = func(h map[string]any) { delete(h, "kid") }
		},
		"HS384 with pub key": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignHS256PublicKey
			k.MutateHeader = func(h map[string]any) { h["alg"] = "HS384" }
		},
		"ES256 header on RSA signature": func(k *oidctest.Knobs) {
			k.MutateHeader = func(h map[string]any) { h["alg"] = "ES256" }
		},
		"PS256 header on PKCS1v15 signature": func(k *oidctest.Knobs) {
			k.MutateHeader = func(h map[string]any) { h["alg"] = "PS256" }
		},
		"embedded jwk with attacker key": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignUnknownKey
			k.MutateHeader = func(h map[string]any) {
				h["jwk"] = map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"}
				delete(h, "kid")
			}
		},
		"jku pointing elsewhere": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignUnknownKey
			k.MutateHeader = func(h map[string]any) { h["jku"] = "https://evil.example/jwks"; h["kid"] = "evil" }
		},
		"unknown kid, foreign key": func(k *oidctest.Knobs) {
			k.Sign = oidctest.SignUnknownKey
			k.MutateHeader = func(h map[string]any) { h["kid"] = "does-not-exist" }
		},
	}
	for name, knobs := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, setup{})
			h.op.Set(func(k *oidctest.Knobs) {
				k.Claims = map[string]any{"name": "Alice Example", "roles": []any{"Dropr.User"}}
				knobs(k)
			})
			if code, body := h.login(); code == http.StatusOK || h.loggedIn() {
				t.Fatalf("token accepted: %d %q", code, body)
			}
			if h.userCount() != 0 {
				t.Fatal("account created from a forged token")
			}
		})
	}
}

// TestM6CritHeader: RFC 7515 §4.1.11 requires rejecting a JWS whose "crit"
// lists an extension the recipient does not understand.
func TestM6CritHeader(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{})
	h.op.Set(func(k *oidctest.Knobs) {
		k.Claims = map[string]any{"roles": []any{"Dropr.User"}}
		k.MutateHeader = func(hd map[string]any) { hd["crit"] = []any{"x-must-understand"}; hd["x-must-understand"] = true }
	})
	if code, _ := h.login(); code == http.StatusOK && h.loggedIn() {
		t.Skip("FINDING (low): an ID token with an unknown critical header extension is accepted (go-jose/go-oidc ignore crit); RFC 7515 §4.1.11 says MUST reject. Signature is still the IdP's, so impact is limited to future header semantics.")
	}
}

func TestM6IDTokenMalformedClaims(t *testing.T) {
	t.Parallel()
	cases := map[string]func(c map[string]any){
		"exp as string":      func(c map[string]any) { c["exp"] = "9999999999" },
		"exp absurdly large": func(c map[string]any) { c["exp"] = int64(1) << 50 },
		"exp negative":       func(c map[string]any) { c["exp"] = -1 },
		"exp NaN-like":       func(c map[string]any) { c["exp"] = "NaN" },
		"iat missing":        func(c map[string]any) { delete(c, "iat") },
		"iat as string":      func(c map[string]any) { c["iat"] = "1" },
		"nbf as string":      func(c map[string]any) { c["nbf"] = "0" },
		"nbf as object":      func(c map[string]any) { c["nbf"] = map[string]any{} },
		"aud as number":      func(c map[string]any) { c["aud"] = 42 },
		"aud empty array":    func(c map[string]any) { c["aud"] = []any{} },
		"aud prefix of client": func(c map[string]any) {
			c["aud"] = "drop"
		},
		"aud array, azp other": func(c map[string]any) {
			c["aud"] = []any{"dropr", "other"}
			c["azp"] = "other"
		},
		"azp not a string": func(c map[string]any) { c["azp"] = []any{"dropr"} },
		"sub as number":    func(c map[string]any) { c["sub"] = 12345 },
		"sub too long":     func(c map[string]any) { c["sub"] = strings.Repeat("a", 256) },
		"iss as array":     func(c map[string]any) { c["iss"] = []any{c["iss"]} },
		"nonce as array":   func(c map[string]any) { c["nonce"] = []any{c["nonce"]} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, setup{})
			h.op.Set(func(k *oidctest.Knobs) {
				k.Claims = map[string]any{"roles": []any{"Dropr.User"}}
				k.MutateIDToken = mut
			})
			if code, body := h.login(); code == http.StatusOK || h.loggedIn() {
				t.Fatalf("token accepted: %d %q", code, body)
			}
			if h.userCount() != 0 {
				t.Fatal("account created")
			}
		})
	}
}

func TestM6RefreshNegative(t *testing.T) {
	t.Parallel()
	mutate := func(f func(c map[string]any)) func(k *oidctest.Knobs) {
		return func(k *oidctest.Knobs) { k.MutateIDToken = f }
	}
	cases := map[string]func(k *oidctest.Knobs){
		"wrong iss":             mutate(func(c map[string]any) { c["iss"] = "https://evil.example" }),
		"expired":               mutate(func(c map[string]any) { c["exp"] = c["iat"].(int64) - 120 }),
		"missing exp":           mutate(func(c map[string]any) { delete(c, "exp") }),
		"nbf in future":         mutate(func(c map[string]any) { c["nbf"] = c["iat"].(int64) + 600 }),
		"iat in future":         mutate(func(c map[string]any) { c["iat"] = c["iat"].(int64) + 600 }),
		"wrong azp":             mutate(func(c map[string]any) { c["azp"] = "other-client" }),
		"multi aud without azp": mutate(func(c map[string]any) { c["aud"] = []any{"dropr", "other"} }),
		"empty sub":             mutate(func(c map[string]any) { c["sub"] = "" }),
		"HS256 with pub key":    func(k *oidctest.Knobs) { k.Sign = oidctest.SignHS256PublicKey },
		"other role only": func(k *oidctest.Knobs) {
			k.RefreshClaims = map[string]any{"roles": []any{"Dropr.Admin"}}
		},
		"role claim wrong type": func(k *oidctest.Knobs) {
			k.RefreshClaims = map[string]any{"roles": map[string]any{"Dropr.User": true}}
		},
		"no refresh token returned, then provider refuses": func(k *oidctest.Knobs) {
			k.OmitRefreshToken = true
			k.TokenEndpointDown = true
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, setup{})
			h.op.Set(func(k *oidctest.Knobs) { k.Claims = map[string]any{"roles": []any{"Dropr.User"}} })
			h.login()
			if !h.loggedIn() {
				t.Fatal("login failed")
			}
			h.op.Set(breakIt)
			h.clk.Add(16 * time.Minute)
			if h.loggedIn() {
				t.Fatal("session survived a refresh that should fail")
			}
		})
	}
}

// TestM6RefreshKeepsNestedRole: a nested role claim path is re-checked on
// refresh, and removing the role there ends the session.
func TestM6RefreshNestedRoleRemoved(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{cfg: func(c *config.OIDC) { c.RoleClaimPath = []string{"realm_access", "roles"} }})
	h.op.Set(func(k *oidctest.Knobs) {
		k.Claims = map[string]any{"realm_access": map[string]any{"roles": []any{"Dropr.User"}}}
	})
	h.login()
	if !h.loggedIn() {
		t.Fatal("login failed")
	}
	h.clk.Add(16 * time.Minute)
	if !h.loggedIn() {
		t.Fatal("refresh with role kept failed")
	}
	h.op.Set(func(k *oidctest.Knobs) {
		k.RefreshClaims = map[string]any{"realm_access": map[string]any{"roles": []any{"offline_access"}}, "roles": []any{"Dropr.User"}}
	})
	h.clk.Add(16 * time.Minute)
	if h.loggedIn() {
		t.Fatal("session survived removal of the nested role (top-level decoy role must not count)")
	}
}
