//go:build keycloak

// Integration test against the dev Keycloak (dev/compose.yaml):
//
//	make keycloak-up && make test-keycloak
//
// It runs Dropr in-process on 127.0.0.1:8080 (the redirect URI registered in
// the dev realm) and drives real logins through Keycloak's HTML login form.
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/store/storetest"
)

const (
	kcBase   = "http://localhost:8180"
	kcIssuer = kcBase + "/realms/dropr"
	dropOrig = "http://localhost:8080"
)

func keycloakConfig(t *testing.T, pkjwt bool) *config.Config {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	refresh := filepath.Join(dir, "refresh")
	if err := os.WriteFile(refresh, key, 0o600); err != nil {
		t.Fatal(err)
	}
	clientAuth := `client_id = "dropr"
client_auth = "client_secret"
client_secret_file = "../../dev/client_secret"`
	if pkjwt {
		clientAuth = `client_id = "dropr-pkjwt"
client_auth = "private_key_jwt"
client_key_file = "../../dev/keycloak/test-keys/dropr-pkjwt.TEST-ONLY.pem"
client_key_id = "dropr-dev-test"`
	}
	cfg, err := config.Parse([]byte(`
mode = "dev"
tls = "proxy"
public_url = "` + dropOrig + `"
data_dir = "` + dir + `"
refresh_key_file = "` + refresh + `"
[oidc]
issuer = "` + kcIssuer + `"
` + clientAuth + `
scopes = ["openid", "profile"]
role_claim = "realm_access.roles"
required_role = "Dropr.User"
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type kcEnv struct {
	t      *testing.T
	st     *store.Store
	client *http.Client
}

func startDropr(t *testing.T, pkjwt bool) *kcEnv {
	t.Helper()
	if _, err := http.Get(kcIssuer + "/.well-known/openid-configuration"); err != nil { //nolint:noctx // test probe
		t.Skipf("Keycloak not reachable at %s (run `make keycloak-up`): %v", kcBase, err)
	}
	cfg := keycloakConfig(t, pkjwt)
	st := storetest.New(t)
	s, err := New(t.Context(), Deps{Config: cfg, Store: st, Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("port 8080 busy (stop `make dev`?): %v", err)
	}
	hs := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Shutdown(context.Background()) })
	jar, _ := cookiejar.New(nil)
	return &kcEnv{t: t, st: st, client: &http.Client{Jar: jar, Timeout: 20 * time.Second}}
}

var formAction = regexp.MustCompile(`<form[^>]+id="kc-form-login"[^>]*action="([^"]+)"`)

// login drives the browser flow through Keycloak's login form.
func (e *kcEnv) login(user, password string) (int, string) {
	e.t.Helper()
	resp, err := e.client.Get(dropOrig + "/auth/login") //nolint:noctx // test
	if err != nil {
		e.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := formAction.FindSubmatch(page)
	if m == nil {
		e.t.Fatalf("no Keycloak login form (status %d, url %s)", resp.StatusCode, resp.Request.URL)
	}
	action := html.UnescapeString(string(m[1]))
	resp, err = e.client.PostForm(action, url.Values{"username": {user}, "password": {password}, "credentialId": {""}}) //nolint:noctx // test
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (e *kcEnv) home() string {
	e.t.Helper()
	resp, err := e.client.Get(dropOrig + "/") //nolint:noctx // test
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// expireRevalidation makes every session due for revalidation.
func (e *kcEnv) expireRevalidation() {
	e.t.Helper()
	if _, err := e.st.DB().W.ExecContext(e.t.Context(), `UPDATE sessions SET revalidated_at = revalidated_at - 3600`); err != nil {
		e.t.Fatal(err)
	}
}

func adminToken(t *testing.T) string {
	t.Helper()
	resp, err := http.PostForm(kcBase+"/realms/master/protocol/openid-connect/token", url.Values{ //nolint:noctx // test
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil || tr.AccessToken == "" {
		t.Fatalf("admin token: %v", err)
	}
	return tr.AccessToken
}

func adminCall(t *testing.T, method, path string, out any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, kcBase+"/admin/realms/dropr"+path, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		t.Fatalf("admin %s %s: %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
}

func TestKeycloakLoginRevalidateLogout(t *testing.T) {
	for _, pkjwt := range []bool{false, true} {
		name := "client_secret"
		if pkjwt {
			name = "private_key_jwt"
		}
		t.Run(name, func(t *testing.T) {
			e := startDropr(t, pkjwt)
			code, body := e.login("alice", "alice-dev-password")
			if code != http.StatusOK || !strings.Contains(body, "signed in") {
				t.Fatalf("login: %d %s", code, body)
			}
			if h := e.home(); !strings.Contains(h, signedInMarker) || !strings.Contains(h, "Alice Example") {
				t.Fatalf("dashboard missing: %s", h)
			}

			// Revalidation through the real refresh grant (twice: Keycloak
			// rotates refresh tokens and refuses reuse).
			for range 2 {
				e.expireRevalidation()
				if !strings.Contains(e.home(), signedInMarker) {
					t.Fatal("revalidation against Keycloak failed")
				}
			}

			// RP-initiated logout.
			noFollow := *e.client
			noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, dropOrig+"/auth/logout", nil)
			req.Header.Set("Origin", dropOrig)
			resp, err := noFollow.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			loc := resp.Header.Get("Location")
			if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, kcIssuer+"/protocol/openid-connect/logout?") {
				t.Fatalf("logout redirect: %d %s", resp.StatusCode, loc)
			}
			lresp, err := e.client.Get(loc) //nolint:noctx // test
			if err != nil {
				t.Fatal(err)
			}
			_ = lresp.Body.Close()
			if lresp.StatusCode != http.StatusOK {
				t.Fatalf("Keycloak end_session: %d", lresp.StatusCode)
			}
			if strings.Contains(e.home(), signedInMarker) {
				t.Fatal("still signed in after logout")
			}
		})
	}
}

func TestKeycloakRoleMissingAndBadPassword(t *testing.T) {
	e := startDropr(t, false)
	code, body := e.login("mallory", "mallory-dev-password")
	if code != http.StatusForbidden || !strings.Contains(body, "have access") {
		t.Fatalf("mallory: %d", code)
	}
	if users, _ := e.st.ListUsers(t.Context()); len(users) != 0 {
		t.Fatal("account created for user without role")
	}
	// Fresh browser: Keycloak keeps mallory's SSO session in the old jar.
	jar, _ := cookiejar.New(nil)
	e.client.Jar = jar
	code, body = e.login("bob", "wrong-password")
	if code == http.StatusOK && strings.Contains(body, "signed in") {
		t.Fatal("wrong password accepted")
	}
}

func TestKeycloakAdminRevocationKillsSession(t *testing.T) {
	e := startDropr(t, true)
	if code, _ := e.login("bob", "bob-dev-password"); code != http.StatusOK {
		t.Fatal("login failed")
	}
	var users []struct {
		ID string `json:"id"`
	}
	adminCall(t, http.MethodGet, "/users?username=bob&exact=true", &users)
	if len(users) != 1 {
		t.Fatal("bob not found in Keycloak")
	}
	// "Sign out all sessions" for bob at the provider.
	adminCall(t, http.MethodPost, "/users/"+users[0].ID+"/logout", nil)
	e.expireRevalidation()
	if strings.Contains(e.home(), signedInMarker) {
		t.Fatal("session survived provider-side revocation")
	}
	if n, _ := e.st.ListUsers(t.Context()); len(n) != 1 || n[0].Sessions != 0 {
		t.Fatal("session row not deleted")
	}
}

// signedInMarker appears on every page served to a signed-in user (the
// sign-out form of the layout).
const signedInMarker = `action="/auth/logout"`
