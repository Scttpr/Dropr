package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"
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

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// owner is a signed-in user and the client holding their session.
type owner struct {
	e *testEnv
	c *http.Client
}

func (e *testEnv) newOwner() *owner {
	e.login()
	return &owner{e: e, c: e.client}
}
