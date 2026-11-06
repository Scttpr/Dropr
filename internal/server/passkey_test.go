package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/auth/passkey"
	"github.com/scttpr/dropr/internal/auth/passkey/passkeytest"
)

func TestPasskeyRegistrationAndUnlock(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()

	// Creation options follow the contract.
	resp, body := e.api(http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("begin: %d %s", resp.StatusCode, body)
	}
	var opts struct {
		PublicKey struct {
			RP                     struct{ ID string }
			User                   struct{ ID string }
			Attestation            string
			AuthenticatorSelection struct {
				ResidentKey      string
				UserVerification string
			}
			Extensions         map[string]json.RawMessage
			ExcludeCredentials []struct{ ID string }
		}
	}
	mustJSON(t, body, &opts)
	pk := opts.PublicKey
	if pk.RP.ID != "localhost" || pk.AuthenticatorSelection.ResidentKey != "required" ||
		pk.AuthenticatorSelection.UserVerification != "required" || (pk.Attestation != "none" && pk.Attestation != "") {
		t.Errorf("creation options: %s", body)
	}
	if _, ok := pk.Extensions["prf"]; !ok {
		t.Errorf("prf not requested: %s", body)
	}
	handle := pk.User.ID
	if raw, _ := b64t.DecodeString(handle); len(raw) != 32 {
		t.Errorf("user handle %q", handle)
	}

	// First registration stores the key and unlocks the session (rotating it).
	before := sessionCookie(e.client, e.origin)
	resp, body, _ = o.register(o.pub, false, passkeytest.Options{})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"passkey_count":1`) {
		t.Fatalf("register 1: %d %s", resp.StatusCode, body)
	}
	o.noConfirm = false
	if after := sessionCookie(e.client, e.origin); after == before || after == "" {
		t.Error("first registration did not rotate the session")
	}
	resp, page := e.do(http.MethodGet, "/", nil)
	if resp.Request.URL.Path != "/setup" || !strings.Contains(page, `data-passkey-count="1"`) {
		t.Errorf("after one passkey: %s", resp.Request.URL)
	}

	// The second begin excludes the first credential and keeps the handle.
	resp, body = e.api(http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	mustJSON(t, body, &opts)
	if resp.StatusCode != http.StatusOK || opts.PublicKey.User.ID != handle || len(opts.PublicKey.ExcludeCredentials) != 1 ||
		opts.PublicKey.ExcludeCredentials[0].ID != b64t.EncodeToString(o.creds[0].ID) {
		t.Errorf("second begin: %s", body)
	}

	// A different public key is refused; the identical one is accepted.
	// (The first registration's confirmation granted one addition, which the
	// begin above consumed; each attempt needs a fresh assertion.)
	o.mustGrant("add", nil)
	if resp, body, _ := o.register(randBytes(32), true, passkeytest.Options{}); resp.StatusCode != http.StatusConflict || errCode(body) != "pubkey_mismatch" {
		t.Fatalf("mismatch: %d %s", resp.StatusCode, body)
	}
	if resp, body, _ := o.register(o.pub, true, passkeytest.Options{}); resp.StatusCode != http.StatusForbidden || errCode(body) != "reauth_required" {
		t.Fatalf("second addition without a fresh assertion: %d %s", resp.StatusCode, body)
	}
	o.mustGrant("add", nil)
	if resp, body, _ := o.register(o.pub, true, passkeytest.Options{}); resp.StatusCode != http.StatusOK ||
		!strings.Contains(string(body), `"setup_complete":true`) {
		t.Fatalf("register 2: %d %s", resp.StatusCode, body)
	}
	resp, page = e.do(http.MethodGet, "/", nil)
	if resp.Request.URL.Path != "/" || !strings.Contains(page, "Drop a file here to share") {
		t.Errorf("dashboard after setup: %s", resp.Request.URL)
	}
	if resp, _ := e.do(http.MethodGet, "/setup", nil); resp.Request.URL.Path != "/" {
		t.Error("/setup does not redirect once complete")
	}

	// Unlock with the second passkey returns its wrapped key and rotates the
	// session; the old session ID stops working.
	old := sessionCookie(e.client, e.origin)
	resp, body = o.unlock(1, passkeytest.Options{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock: %d %s", resp.StatusCode, body)
	}
	var un struct {
		WrappedPrivkey string `json:"wrapped_privkey"`
		CredentialID   string `json:"credential_id"`
		UserHandle     string `json:"user_handle"`
	}
	mustJSON(t, body, &un)
	if un.CredentialID != b64t.EncodeToString(o.creds[1].ID) || un.WrappedPrivkey != b64t.EncodeToString(o.wrapped[1]) || un.UserHandle != handle {
		t.Errorf("unlock result: %s", body)
	}
	if now := sessionCookie(e.client, e.origin); now == old {
		t.Error("unlock did not rotate the session")
	}
	stale := &http.Client{Transport: e.client.Transport}
	resp, _ = e.apiWith(stale, http.MethodGet, "/api/passkeys", nil, map[string]string{"Cookie": "__Host-dropr_session=" + old})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old session still valid: %d", resp.StatusCode)
	}

	// Listing shows use (the first passkey's confirmation at registration
	// and the second's unlock); deleting below two is refused.
	resp, body = e.api(http.MethodGet, "/api/passkeys", nil, nil)
	var list struct {
		Passkeys []struct {
			ID         string
			LastUsedAt *int64 `json:"last_used_at"`
		}
	}
	mustJSON(t, body, &list)
	if resp.StatusCode != http.StatusOK || len(list.Passkeys) != 2 || list.Passkeys[1].LastUsedAt == nil || list.Passkeys[0].LastUsedAt == nil {
		t.Errorf("list: %s", body)
	}
	o.mustGrant("delete", o.creds[0].ID)
	resp, body = e.api(http.MethodDelete, "/api/passkeys/"+list.Passkeys[0].ID, nil, nil)
	if resp.StatusCode != http.StatusConflict || errCode(body) != "too_few_passkeys" {
		t.Errorf("delete below two: %d %s", resp.StatusCode, body)
	}

	// A third passkey can be added and then one deleted, each after a
	// fresh assertion for that action; another session can do neither.
	o.mustGrant("add", nil)
	if resp, body, _ := o.register(o.pub, false, passkeytest.Options{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("register 3: %d %s", resp.StatusCode, body)
	}
	other := e.newClient()
	resp, body = e.apiWith(other, http.MethodDelete, "/api/passkeys/"+list.Passkeys[0].ID, nil, nil)
	if resp.StatusCode != http.StatusForbidden || errCode(body) != "reauth_required" {
		t.Errorf("delete from another session: %d %s", resp.StatusCode, body)
	}
	resp, body = e.apiWith(other, http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	if resp.StatusCode != http.StatusForbidden || errCode(body) != "reauth_required" {
		t.Errorf("register from another session: %d %s", resp.StatusCode, body)
	}
	o.mustGrant("delete", o.creds[0].ID)
	if resp, body := e.api(http.MethodDelete, "/api/passkeys/"+list.Passkeys[0].ID, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.api(http.MethodDelete, "/api/passkeys/"+list.Passkeys[0].ID, nil, nil); resp.StatusCode != http.StatusForbidden || errCode(body) != "reauth_required" {
		t.Errorf("delete twice (grant is single-use): %d %s", resp.StatusCode, body)
	}
	if resp, body := o.unlockFor(1, "delete", o.creds[0].ID); resp.StatusCode != http.StatusNotFound {
		t.Errorf("grant for a deleted passkey: %d %s", resp.StatusCode, body)
	}
}

// Audit M-1: adding or deleting a passkey needs a fresh, user-verified
// assertion by an existing passkey, made in the same session, for that
// exact action, at most GrantTTL ago, and usable once. The session-wide
// unlock flag is not enough.
func TestPasskeyManagementNeedsFreshAssertion(t *testing.T) {
	t.Parallel()
	clk := newClock()
	e := newTestEnvWith(t, testOpts{now: clk.Now})
	o := e.newOwner().setup()
	o.mustUnlock() // a plain unlock: the session is unlocked for hours

	reg := func() (int, string) {
		resp, body, _ := o.register(o.pub, false, passkeytest.Options{})
		return resp.StatusCode, errCode(body)
	}
	del := func(id []byte) (int, string) {
		resp, body := e.api(http.MethodDelete, "/api/passkeys/"+b64t.EncodeToString(id), nil, nil)
		return resp.StatusCode, errCode(body)
	}
	want := func(name string, gotStatus int, gotCode string, status int, code string) {
		t.Helper()
		if gotStatus != status || gotCode != code {
			t.Errorf("%s: %d %s, want %d %s", name, gotStatus, gotCode, status, code)
		}
	}

	// The audit's attack: an unlocked session cannot add or delete.
	s, c := reg()
	want("add with only the unlock flag", s, c, http.StatusForbidden, "reauth_required")
	s, c = del(o.creds[0].ID)
	want("delete with only the unlock flag", s, c, http.StatusForbidden, "reauth_required")

	// Bound to the action: an "add" grant does not delete, and is gone.
	o.mustGrant("add", nil)
	s, c = del(o.creds[0].ID)
	want("delete with an add grant", s, c, http.StatusForbidden, "reauth_required")
	s, c = reg()
	want("add after the grant was spent", s, c, http.StatusForbidden, "reauth_required")

	// Bound to the target: a grant to delete passkey 1 does not delete 0.
	o.mustGrant("add", nil)
	s, c = reg()
	want("add with a grant", s, c, http.StatusOK, "")
	o.mustGrant("delete", o.creds[1].ID)
	s, c = del(o.creds[0].ID)
	want("delete another passkey", s, c, http.StatusForbidden, "reauth_required")
	s, c = del(o.creds[1].ID)
	want("delete after the grant was spent", s, c, http.StatusForbidden, "reauth_required")

	// Bound to the session: a grant made here is useless in another session.
	o.mustGrant("delete", o.creds[2].ID)
	resp, body := e.apiWith(e.newClient(), http.MethodDelete, "/api/passkeys/"+b64t.EncodeToString(o.creds[2].ID), nil, nil)
	want("delete from another session", resp.StatusCode, errCode(body), http.StatusForbidden, "reauth_required")

	// At most GrantTTL old.
	o.mustGrant("delete", o.creds[2].ID)
	clk.Advance(passkey.GrantTTL + time.Second)
	s, c = del(o.creds[2].ID)
	want("delete with an expired grant", s, c, http.StatusForbidden, "reauth_required")
	o.mustGrant("add", nil)
	clk.Advance(passkey.GrantTTL + time.Second)
	s, c = reg()
	want("add with an expired grant", s, c, http.StatusForbidden, "reauth_required")

	// A fresh grant for the right passkey works.
	o.mustGrant("delete", o.creds[2].ID)
	s, c = del(o.creds[2].ID)
	want("delete with a fresh grant", s, c, http.StatusNoContent, "")

	// Unknown purposes and malformed targets are refused.
	for _, b := range []map[string]any{
		{"purpose": "everything"},
		{"purpose": "add", "passkey_id": b64t.EncodeToString(o.creds[0].ID)},
		{"purpose": "unlock", "passkey_id": b64t.EncodeToString(o.creds[0].ID)},
	} {
		if resp, body := e.api(http.MethodPost, "/api/passkeys/unlock/begin", b, nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unlock/begin %v: %d %s", b, resp.StatusCode, body)
		}
	}
	if resp, body := e.api(http.MethodPost, "/api/passkeys/unlock/begin", map[string]any{"purpose": "delete", "passkey_id": "AAAA"}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete grant for an unknown passkey: %d %s", resp.StatusCode, body)
	}
}

// Audit M-1 / I-5: the initial setup (no passkey yet) needs no grant, but
// it belongs to the session that started it, and the first passkey (with or
// without a confirmation assertion) grants the second passkey.
func TestPasskeyInitialSetupWindow(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()

	// Another session of the same account cannot start a parallel setup.
	resp, body := e.api(http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("begin: %d %s", resp.StatusCode, body)
	}
	other := e.newClient()
	if resp, body := e.apiWith(other, http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil); resp.StatusCode != http.StatusConflict ||
		errCode(body) != "setup_in_progress" {
		t.Errorf("parallel setup: %d %s", resp.StatusCode, body)
	}

	// A present confirmation that is not user-verified is refused.
	_, body = e.api(http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	cred, c, _ := o.auth.Register(body, false, passkeytest.Options{})
	confirm, _ := o.auth.Confirm(c, body, passkeytest.Options{NoUV: true})
	resp, body = e.api(http.MethodPost, "/api/passkeys/register/finish", map[string]any{"credential": cred, "confirm": confirm,
		"wrapped_privkey": b64t.EncodeToString(randBytes(150)), "pubkey": b64t.EncodeToString(o.pub)}, nil)
	if resp.StatusCode != http.StatusBadRequest || errCode(body) != "passkey_failed" {
		t.Fatalf("unverified confirmation: %d %s", resp.StatusCode, body)
	}
	// A confirmation by another credential is refused.
	_, body = e.api(http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	cred, _, _ = o.auth.Register(body, false, passkeytest.Options{})
	_, stranger, _ := o.auth.Register(body, false, passkeytest.Options{})
	confirm, _ = o.auth.Confirm(stranger, body, passkeytest.Options{})
	resp, body = e.api(http.MethodPost, "/api/passkeys/register/finish", map[string]any{"credential": cred, "confirm": confirm,
		"wrapped_privkey": b64t.EncodeToString(randBytes(150)), "pubkey": b64t.EncodeToString(o.pub)}, nil)
	if resp.StatusCode != http.StatusBadRequest || errCode(body) != "passkey_failed" {
		t.Fatalf("confirmation by another credential: %d %s", resp.StatusCode, body)
	}

	// The confirmation is optional: without it the first passkey is accepted
	// (UV and PRF were checked at creation), unlocks the session, and grants
	// exactly the second registration.
	o.noConfirm = true
	if resp, body, _ := o.register(o.pub, false, passkeytest.Options{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("register 1: %d %s", resp.StatusCode, body)
	}
	if resp, body := e.apiWith(other, http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil); resp.StatusCode != http.StatusForbidden ||
		errCode(body) != "reauth_required" {
		t.Errorf("second passkey from another session: %d %s", resp.StatusCode, body)
	}
	if resp, body, _ := o.register(o.pub, true, passkeytest.Options{}); resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"setup_complete":true`) {
		t.Fatalf("register 2: %d %s", resp.StatusCode, body)
	}
	if resp, body, _ := o.register(o.pub, true, passkeytest.Options{}); resp.StatusCode != http.StatusForbidden || errCode(body) != "reauth_required" {
		t.Errorf("third passkey without assertion: %d %s", resp.StatusCode, body)
	}
}

func TestPasskeyAssertionBinding(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner().setup()

	unlockFinish := func(c *http.Client, cred json.RawMessage) (*http.Response, []byte) {
		return e.apiWith(c, http.MethodPost, "/api/passkeys/unlock/finish", map[string]any{"credential": cred}, nil)
	}
	begin := func(c *http.Client) []byte {
		resp, body := e.apiWith(c, http.MethodPost, "/api/passkeys/unlock/begin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("begin: %d %s", resp.StatusCode, body)
		}
		return body
	}

	// An assertion for session A's challenge is useless in session B.
	other := e.newClient()
	begin(other) // B has its own ceremony with another challenge
	cred, _ := o.auth.Assert(o.creds[0], begin(e.client), passkeytest.Options{})
	if resp, body := unlockFinish(other, cred); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("cross-session assertion: %d %s", resp.StatusCode, body)
	}
	// A's ceremony still works once; replaying the same assertion fails.
	if resp, body := unlockFinish(e.client, cred); resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock: %d %s", resp.StatusCode, body)
	}
	if resp, body := unlockFinish(e.client, cred); resp.StatusCode != http.StatusBadRequest || errCode(body) != "ceremony_expired" {
		t.Errorf("replay: %d %s", resp.StatusCode, body)
	}
	// Reusing an old challenge in a new ceremony fails, and burns it.
	opts := begin(e.client)
	stale, _ := o.auth.Assert(o.creds[0], opts, passkeytest.Options{Challenge: []byte("0123456789abcdef0123456789abcdef")})
	if resp, body := unlockFinish(e.client, stale); resp.StatusCode != http.StatusBadRequest || errCode(body) != "passkey_failed" {
		t.Errorf("wrong challenge: %d %s", resp.StatusCode, body)
	}
	good, _ := o.auth.Assert(o.creds[0], opts, passkeytest.Options{})
	if resp, _ := unlockFinish(e.client, good); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("ceremony reusable after a failure: %d", resp.StatusCode)
	}

	for name, opt := range map[string]passkeytest.Options{
		"wrong origin": {Origin: "http://evil.example"},
		"no UV":        {NoUV: true},
		"wrong type":   {Type: "webauthn.create"},
	} {
		if resp, body := o.unlock(0, opt); resp.StatusCode != http.StatusBadRequest || errCode(body) != "passkey_failed" {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}

	// Counter policy: synced passkeys (always 0) never trip clone
	// detection; a regressing non-zero counter does.
	for range 2 {
		if resp, body := o.unlock(1, passkeytest.Options{}); resp.StatusCode != http.StatusOK {
			t.Fatalf("synced unlock: %d %s", resp.StatusCode, body)
		}
	}
	o.mustUnlock()
	one := uint32(1)
	if resp, body := o.unlock(0, passkeytest.Options{Counter: &one}); resp.StatusCode != http.StatusForbidden || errCode(body) != "passkey_cloned" {
		t.Errorf("counter regression: %d %s", resp.StatusCode, body)
	}
	o.mustUnlock() // the stored counter was not lowered
}

func TestPasskeyRegistrationRejections(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	o := e.newOwner()
	cases := []struct {
		name string
		opts passkeytest.Options
		code string
	}{
		{"no UV", passkeytest.Options{NoUV: true}, "passkey_failed"},
		{"no PRF", passkeytest.Options{NoPRF: true}, "prf_unsupported"},
		{"wrong origin", passkeytest.Options{Origin: "https://localhost.evil"}, "passkey_failed"},
		{"wrong challenge", passkeytest.Options{Challenge: bytes.Repeat([]byte{1}, 32)}, "passkey_failed"},
	}
	for _, c := range cases {
		if resp, body, _ := o.register(o.pub, false, c.opts); resp.StatusCode != http.StatusBadRequest || errCode(body) != c.code {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, body)
		}
	}
	// Malformed key material.
	_, body := e.api(http.MethodPost, "/api/passkeys/register/begin", map[string]any{}, nil)
	cred, _, _ := o.auth.Register(body, false, passkeytest.Options{})
	resp, body := e.api(http.MethodPost, "/api/passkeys/register/finish", map[string]any{
		"credential": cred, "wrapped_privkey": b64t.EncodeToString(make([]byte, 20)), "pubkey": b64t.EncodeToString(o.pub),
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short wrapped key: %d %s", resp.StatusCode, body)
	}
	// Finish without begin, and anonymous calls.
	if resp, body := e.api(http.MethodPost, "/api/passkeys/register/finish", map[string]any{"credential": cred,
		"wrapped_privkey": b64t.EncodeToString(make([]byte, 200)), "pubkey": b64t.EncodeToString(o.pub)}, nil); resp.StatusCode != http.StatusBadRequest ||
		errCode(body) != "ceremony_expired" {
		t.Errorf("finish without begin: %d %s", resp.StatusCode, body)
	}
	anon := &http.Client{Transport: e.client.Transport}
	for _, p := range []string{"/api/passkeys/register/begin", "/api/passkeys/unlock/begin"} {
		if resp, body := e.apiWith(anon, http.MethodPost, p, map[string]any{}, nil); resp.StatusCode != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
			t.Errorf("anonymous %s: %d", p, resp.StatusCode)
		}
	}
	if resp, body := e.api(http.MethodPost, "/api/passkeys/unlock/begin", nil, nil); resp.StatusCode != http.StatusConflict || errCode(body) != "no_passkeys" {
		t.Errorf("unlock without passkeys: %d %s", resp.StatusCode, body)
	}
}
