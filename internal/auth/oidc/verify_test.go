package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/config"
)

func TestLookupAndHasRole(t *testing.T) {
	t.Parallel()
	claims, err := decodeClaims([]byte(`{"roles":["a","Dropr.User"],"realm_access":{"roles":["Dropr.User"]},
		"single":"Dropr.User","num":[1,2],"deep":{"x":{"y":"Dropr.User"}},"nullv":null}`))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"roles": true, "realm_access.roles": true, "single": true, "deep.x.y": true,
		"num": false, "missing": false, "roles.x": false, "realm_access": false, "nullv": false, "single.x": false,
	} {
		p, _ := config.ParseClaimPath(path)
		if got := HasRole(claims, p, "Dropr.User"); got != want {
			t.Errorf("%s: %v", path, got)
		}
	}
	if HasRole(claims, []string{"roles"}, "") {
		t.Error("empty role matched")
	}
}

func TestDecodeClaimsRejects(t *testing.T) {
	t.Parallel()
	for _, in := range []string{``, `null`, `[]`, `"x"`, `{"a":1} {"b":2}`, `{`} {
		if _, err := decodeClaims([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestCheckTimes(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	p := &Provider{now: func() time.Time { return now }}
	n := func(v int64) json.Number { return json.Number(strconv.FormatInt(v, 10)) }
	base := func() map[string]any {
		return map[string]any{"exp": n(now.Unix() + 300), "iat": n(now.Unix())}
	}
	if err := p.checkTimes(base()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"expired":       func(c map[string]any) { c["exp"] = n(now.Unix() - 61) },
		"iat future":    func(c map[string]any) { c["iat"] = n(now.Unix() + 61) },
		"nbf future":    func(c map[string]any) { c["nbf"] = n(now.Unix() + 61) },
		"exp string":    func(c map[string]any) { c["exp"] = "9999999999" },
		"nbf malformed": func(c map[string]any) { c["nbf"] = "soon" },
		"no iat":        func(c map[string]any) { delete(c, "iat") },
		"negative exp":  func(c map[string]any) { c["exp"] = n(-1) },
		"huge exp":      func(c map[string]any) { c["exp"] = json.Number("1e300") },
	}
	for name, mut := range cases {
		c := base()
		mut(c)
		if err := p.checkTimes(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Within skew is fine.
	c := base()
	c["exp"] = n(now.Unix() - 30)
	c["nbf"] = n(now.Unix() + 30)
	if err := p.checkTimes(c); err != nil {
		t.Errorf("skew: %v", err)
	}
}

func TestES256AssertionSignatureFormat(t *testing.T) {
	t.Parallel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := newAssertionSigner(k, nil, "ES256", "", "client", false)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := s.sign("https://op/token", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	sig, _ := b64.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("ES256 signature must be raw r||s (64 bytes), got %d", len(sig))
	}
	if _, err := newAssertionSigner(k, nil, "RS256", "", "client", false); err == nil {
		t.Error("RS256 with EC key accepted")
	}
	if _, err := chooseAssertionAlg("", k, []string{"RS256"}); err == nil {
		t.Error("EC key with RSA-only provider accepted")
	}
}

func FuzzHasRole(f *testing.F) {
	f.Add(`{"roles":["Dropr.User"]}`, "roles")
	f.Add(`{"a":{"b":"Dropr.User"}}`, "a.b")
	f.Add(`{"a":[{"b":"Dropr.User"}]}`, "a.b")
	f.Fuzz(func(t *testing.T, doc, path string) {
		claims, err := decodeClaims([]byte(doc))
		if err != nil {
			return
		}
		p, err := config.ParseClaimPath(path)
		if err != nil {
			return
		}
		if HasRole(claims, p, "Dropr.User") {
			v, ok := LookupClaim(claims, p)
			if !ok {
				t.Fatal("role found at a missing path")
			}
			switch x := v.(type) {
			case string:
				if x != "Dropr.User" {
					t.Fatal("wrong string matched")
				}
			case []any:
			default:
				t.Fatalf("matched non-string, non-array %T", v)
			}
		}
	})
}

func FuzzDecodeClaims(f *testing.F) {
	f.Add([]byte(`{"exp":1e400,"iat":-1}`))
	f.Add([]byte(`{"nbf":"x"}`))
	now := time.Unix(1_700_000_000, 0)
	p := &Provider{now: func() time.Time { return now }}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := decodeClaims(b)
		if err != nil {
			return
		}
		if p.checkTimes(c) == nil {
			exp, ok := numericDate(c["exp"])
			if !ok || !now.Before(exp.Add(clockSkew)) {
				t.Fatal("accepted expired or missing exp")
			}
		}
	})
}
