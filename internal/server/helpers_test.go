package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/auth/passkey/passkeytest"
	"github.com/scttpr/dropr/internal/auth/session"
)

var b64t = base64.RawURLEncoding

// api sends a same-origin JSON request (body marshaled unless it is nil,
// []byte or json.RawMessage) and returns the response and its body.
func (e *testEnv) api(method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	return e.apiWith(e.client, method, path, body, hdr)
}

func (e *testEnv) apiWith(c *http.Client, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case json.RawMessage:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequestWithContext(e.t.Context(), method, e.origin+path, rd)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// errCode returns the "error" field of a JSON error body.
func errCode(b []byte) string {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &v)
	return v.Error
}

func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

// login signs the env's client in through the fake provider.
func (e *testEnv) login() {
	e.t.Helper()
	resp, _ := e.do(http.MethodGet, "/auth/login", nil)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("login: %d", resp.StatusCode)
	}
}

// newClient returns another signed-in client (a second session of the same
// user).
func (e *testEnv) newClient() *http.Client {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: e.client.Transport}
	req, _ := http.NewRequestWithContext(e.t.Context(), http.MethodGet, e.origin+"/auth/login", nil)
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return c
}

func sessionCookie(c *http.Client, origin string) string {
	u, _ := url.Parse(origin)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			return ck.Value
		}
	}
	return ""
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// owner is a signed-in user with a software authenticator.
type owner struct {
	e       *testEnv
	c       *http.Client
	auth    *passkeytest.Authenticator
	pub     []byte
	creds   []*passkeytest.Credential
	wrapped [][]byte
	// noConfirm omits the (optional) confirmation assertion at registration.
	noConfirm bool
}

func (e *testEnv) newOwner() *owner {
	e.login()
	return &owner{e: e, c: e.client, auth: &passkeytest.Authenticator{Origin: e.origin}, pub: randBytes(32)}
}

// register runs register/begin + finish and returns the finish response.
func (o *owner) register(pub []byte, synced bool, opts passkeytest.Options) (*http.Response, []byte, *passkeytest.Credential) {
	o.e.t.Helper()
	resp, body := o.e.apiWith(o.c, http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK {
		return resp, body, nil
	}
	cred, c, err := o.auth.Register(body, synced, opts)
	if err != nil {
		o.e.t.Fatal(err)
	}
	wrapped := randBytes(12 + 120 + 16)
	finish := map[string]any{
		"credential": cred, "wrapped_privkey": b64t.EncodeToString(wrapped), "pubkey": b64t.EncodeToString(pub),
	}
	if !o.noConfirm {
		// The browser asserts once with the new credential (for the PRF
		// output) over the confirmation challenge.
		confirm, err := o.auth.Confirm(c, body, passkeytest.Options{})
		if err != nil {
			o.e.t.Fatal(err)
		}
		finish["confirm"] = confirm
	}
	resp, body = o.e.apiWith(o.c, http.MethodPost, "/api/passkeys/register/finish", finish, nil)
	if resp.StatusCode == http.StatusOK {
		o.creds = append(o.creds, c)
		o.wrapped = append(o.wrapped, wrapped)
	}
	return resp, body, c
}

// unlockFor runs unlock/begin with a purpose ("add", or "delete" with the
// passkey ID) and finish with credential i, leaving a management grant.
func (o *owner) unlockFor(i int, purpose string, passkeyID []byte) (*http.Response, []byte) {
	o.e.t.Helper()
	req := map[string]any{"purpose": purpose}
	if passkeyID != nil {
		req["passkey_id"] = b64t.EncodeToString(passkeyID)
	}
	resp, body := o.e.apiWith(o.c, http.MethodPost, "/api/passkeys/unlock/begin", req, nil)
	if resp.StatusCode != http.StatusOK {
		return resp, body
	}
	cred, err := o.auth.Assert(o.creds[i], body, passkeytest.Options{})
	if err != nil {
		o.e.t.Fatal(err)
	}
	return o.e.apiWith(o.c, http.MethodPost, "/api/passkeys/unlock/finish", map[string]any{"credential": cred}, nil)
}

func (o *owner) mustGrant(purpose string, passkeyID []byte) {
	o.e.t.Helper()
	if resp, body := o.unlockFor(0, purpose, passkeyID); resp.StatusCode != http.StatusOK {
		o.e.t.Fatalf("unlock for %s: %d %s", purpose, resp.StatusCode, body)
	}
}

// setup registers the two required passkeys (the second one synced).
func (o *owner) setup() *owner {
	o.e.t.Helper()
	for i := range 2 {
		if resp, body, _ := o.register(o.pub, i == 1, passkeytest.Options{}); resp.StatusCode != http.StatusOK {
			o.e.t.Fatalf("register %d: %d %s", i, resp.StatusCode, body)
		}
	}
	return o
}

// unlock runs unlock/begin + finish with credential i.
func (o *owner) unlock(i int, opts passkeytest.Options) (*http.Response, []byte) {
	o.e.t.Helper()
	resp, body := o.e.apiWith(o.c, http.MethodPost, "/api/passkeys/unlock/begin", nil, nil)
	if resp.StatusCode != http.StatusOK {
		return resp, body
	}
	cred, err := o.auth.Assert(o.creds[i], body, opts)
	if err != nil {
		o.e.t.Fatal(err)
	}
	return o.e.apiWith(o.c, http.MethodPost, "/api/passkeys/unlock/finish", map[string]any{"credential": cred}, nil)
}

func (o *owner) mustUnlock() {
	o.e.t.Helper()
	if resp, body := o.unlock(0, passkeytest.Options{}); resp.StatusCode != http.StatusOK {
		o.e.t.Fatalf("unlock: %d %s", resp.StatusCode, body)
	}
}
