// Package passkey implements the WebAuthn ceremonies that protect the inbox
// key (PLAN.md §5.2, ARCHITECTURE.md §3 "Passkeys").
//
// OIDC proves who the user is; a passkey with the PRF extension protects the
// data. Each passkey wraps its own copy of the owner's X25519 private key
// under a KEK derived in the browser from the passkey's PRF output, salted
// with the account's WebAuthn user handle. The server stores only wrapped
// keys and the public key, and releases a wrapped key only after a
// user-verified assertion bound to the current OIDC session.
//
// Ceremony state (the go-webauthn SessionData) is kept server-side in the
// webauthn_ceremonies table, keyed by the hash of the session ID with a
// foreign key to the session row. It is single-use (deleted when a finish
// call reads it, whatever the outcome), lives 5 minutes, and dies with the
// session. Ordering at unlock: finish first consumes the ceremony, then
// verifies, then rotates the session ID (session.MarkUnlocked). Rotation
// deletes the old session row, which would cascade to any ceremony still
// attached, so the ceremony must be (and is) consumed before rotating. A
// ceremony begun in one tab is lost if another tab rotates the session in
// between; the user simply retries.
//
// Account key setup: the first registration stores the public key in
// user_keys and marks the session unlocked (the browser just created and
// holds the key). Setup is complete with two passkeys (SetupComplete).
//
// Passkey management (audit M-1): adding or deleting a passkey once the
// account has one needs a grant, i.e. a fresh user-verified assertion by an
// existing passkey of the account, made in this session for that action:
// unlock/begin with purpose "add", or "delete" plus the passkey ID, then
// unlock/finish, leaves one single-use grant on the (rotated) session,
// valid GrantTTL. register/begin and DELETE consume it; the long-lived
// session unlock flag is not enough. The only exception is the initial
// setup of an account without passkeys: its registration ceremony belongs
// to the session that began it (another session of the account is refused
// while it is pending). Its registration ceremony already proves possession
// with user verification over a server challenge, so a confirmation
// assertion by the new credential (over a second server challenge, which
// the browser runs anyway when create() returns no PRF output) is optional;
// when present it is verified. A first registration leaves an "add" grant,
// so the second passkey of the setup needs no extra prompt within GrantTTL.
// Later registrations may carry a confirmation
// too; it is then verified.
//
// Signature counters: go-webauthn flags a possible clone when a non-zero
// counter fails to increase. Synced passkeys always report 0, which is never
// flagged. A flagged assertion is refused and the stored counter is left
// unchanged.
package passkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/store"
)

// Policy constants.
const (
	// Required is the number of passkeys that completes setup and the
	// minimum an account may keep.
	Required = 2
	// MaxPasskeys bounds registrations per account.
	MaxPasskeys = 20
	// CeremonyTTL is how long a begun ceremony can be finished.
	CeremonyTTL = 5 * time.Minute
	// GrantTTL is how long a passkey management grant (a fresh assertion
	// made to add or delete a passkey) can be used.
	GrantTTL = 5 * time.Minute
	// PubkeySize is the X25519 public key size.
	PubkeySize = 32
	// Wrapped private key bounds: iv(12) + GCM(JWK JSON {kty,crv,d,x}) with
	// a 16-byte tag. The smallest such JWK is well over 64 bytes; FORMAT.md
	// §8.6 caps the whole at 1024.
	MinWrappedPrivkey = 12 + 64 + 16
	MaxWrappedPrivkey = 1024
	// Credential ID bounds (schema CHECK).
	minCredentialID = 16
	maxCredentialID = 1023
)

// PRFSalt is the PRF eval input the browser uses (ARCHITECTURE.md §2):
// SHA-256("dropr/v1 prf"). The server also puts it in the assertion options.
var PRFSalt = sha256.Sum256([]byte("dropr/v1 prf"))

const (
	kindRegister = "register"
	kindUnlock   = "unlock"
)

var b64 = base64.RawURLEncoding

// Options configure the service.
type Options struct {
	// Public is the instance public URL; its host is the RP ID and its
	// origin the only accepted WebAuthn origin.
	Public   *url.URL
	Origin   string
	Store    *store.Store
	Sessions *session.Manager
	// Limiter rate-limits begin/finish calls per session.
	Limiter *httpx.RateLimiter
	Logger  *slog.Logger
	Now     func() time.Time
}

// Service runs the passkey ceremonies.
type Service struct {
	wa       *webauthn.WebAuthn
	st       *store.Store
	sessions *session.Manager
	rl       *httpx.RateLimiter
	log      *slog.Logger
	now      func() time.Time
}

// New returns the service. The public URL host must be a domain name
// (WebAuthn does not accept IP addresses as RP IDs).
func New(o Options) (*Service, error) {
	if o.Public == nil || o.Store == nil || o.Sessions == nil {
		return nil, errors.New("passkey: missing dependencies")
	}
	rpID := o.Public.Hostname()
	if err := protocol.ValidateRPID(rpID); err != nil {
		return nil, fmt.Errorf("passkey: public_url host %q cannot be a WebAuthn RP ID (use a domain name): %w", rpID, err)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Dropr",
		RPOrigins:     []string{o.Origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL},
		},
		// Browsers and password managers may add outputs we did not ask
		// for; they carry nothing we rely on.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{wa: wa, st: o.Store, sessions: o.Sessions, rl: o.Limiter, log: o.Logger, now: o.Now}, nil
}

// SetupComplete reports how many passkeys the user has and whether that
// completes setup.
func (s *Service) SetupComplete(ctx context.Context, userID string) (count int, complete bool, err error) {
	n, err := s.st.CountPasskeys(ctx, userID)
	if err != nil {
		return 0, false, err
	}
	return n, n >= Required, nil
}

// waUser adapts an account to webauthn.User.
type waUser struct {
	handle []byte
	name   string
	creds  []webauthn.Credential
	rows   []*store.Passkey
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) loadUser(ctx context.Context, sess *session.Session) (*waUser, error) {
	handle, err := s.st.WebAuthnHandle(ctx, sess.UserID())
	if err != nil {
		return nil, err
	}
	rows, err := s.st.Passkeys(ctx, sess.UserID())
	if err != nil {
		return nil, err
	}
	u := &waUser{handle: handle, name: "Dropr account", rows: rows}
	if sess.User != nil && sess.User.DisplayName != "" {
		u.name = sess.User.DisplayName
	}
	for _, p := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(p.Credential, &c); err != nil {
			return nil, fmt.Errorf("passkey: stored credential: %w", err)
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

// API errors.
var (
	errUnauthenticated = httpx.Errorf(http.StatusUnauthorized, "unauthenticated", "Your session has expired. Please sign in again.")
	errBadRequest      = httpx.Errorf(http.StatusBadRequest, "bad_request", "The request was not accepted. Please reload the page and try again.")
	errCeremony        = httpx.Errorf(http.StatusBadRequest, "ceremony_expired", "The passkey prompt expired. Please try again.")
	errVerify          = httpx.Errorf(http.StatusBadRequest, "passkey_failed", "Your passkey could not be verified. Please try again.")
	errPRF             = httpx.Errorf(http.StatusBadRequest, "prf_unsupported", "This passkey cannot protect your files: it does not support the PRF extension. Please use another passkey or browser.")
	errReauth          = httpx.Errorf(http.StatusForbidden, "reauth_required", "Confirm with one of your existing passkeys first.")
	errMismatch        = httpx.Errorf(http.StatusConflict, "pubkey_mismatch", "This passkey was set up for a different key. Reload the page and unlock with an existing passkey first.")
	errExists          = httpx.Errorf(http.StatusConflict, "passkey_exists", "This passkey is already registered.")
	errTooMany         = httpx.Errorf(http.StatusConflict, "too_many_passkeys", "You have registered the maximum number of passkeys.")
	errNoPasskeys      = httpx.Errorf(http.StatusConflict, "no_passkeys", "You have no passkeys yet. Set them up first.")
	errTooFew          = httpx.Errorf(http.StatusConflict, "too_few_passkeys", "You must keep at least two passkeys.")
	errSetupBusy       = httpx.Errorf(http.StatusConflict, "setup_in_progress", "Passkey setup is already in progress in another browser or tab. Finish it there, or try again in 5 minutes.")
	errChanged         = httpx.Errorf(http.StatusConflict, "passkeys_changed", "Your passkeys changed in the meantime. Reload the page and try again.")
	errClone           = httpx.Errorf(http.StatusForbidden, "passkey_cloned", "This passkey looks like a copy of another one and was refused. Use another passkey.")
	errNotFound        = httpx.Errorf(http.StatusNotFound, "not_found", "This passkey does not exist.")
	errRateLimited     = httpx.Errorf(http.StatusTooManyRequests, "rate_limited", "Too many attempts. Please wait a moment and try again.")
	errTooLarge        = httpx.Errorf(http.StatusRequestEntityTooLarge, "too_large", "The request is too large.")
)

func (s *Service) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.ErrorContext(r.Context(), "passkey: "+what, "err", err)
	httpx.WriteError(w, httpx.Errorf(http.StatusInternalServerError, "internal", "Something went wrong on the server. Please try again."))
}

// session returns the request's session, writing 401 and returning nil if
// there is none, and enforces the per-session rate limit when limited.
func (s *Service) session(w http.ResponseWriter, r *http.Request, limited bool) *session.Session {
	sess := session.FromContext(r.Context())
	if sess == nil {
		httpx.WriteError(w, errUnauthenticated)
		return nil
	}
	if limited && s.rl != nil {
		if ok, wait := s.rl.AllowKey([32]byte(sess.IDHash())); !ok {
			httpx.SetRetryAfter(w, wait)
			httpx.WriteError(w, errRateLimited)
			return nil
		}
	}
	return sess
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := httpx.DecodeJSON(r, v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			httpx.WriteError(w, errTooLarge)
		} else {
			httpx.WriteError(w, errBadRequest)
		}
		return false
	}
	return true
}

// decodeOptionalBody is decodeBody for endpoints whose body may be empty.
func decodeOptionalBody(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteError(w, errTooLarge)
		return false
	}
	if len(b) == 0 {
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return decodeBody(w, r, v)
}

// ceremony is the server-side state of a pending WebAuthn ceremony.
type ceremony struct {
	// SD is the go-webauthn state of the registration or assertion.
	SD webauthn.SessionData `json:"sd"`
	// Confirm (registration) is the state of the confirmation assertion
	// the new credential may make over a second challenge.
	Confirm *webauthn.SessionData `json:"confirm,omitempty"`
	// Setup (registration) marks the initial registration of an account
	// without passkeys, begun without a grant.
	Setup bool `json:"setup,omitempty"`
	// Purpose and Target (assertion): the grant a successful assertion
	// leaves ("" = plain unlock, "add", or "delete" of passkey Target).
	Purpose string `json:"purpose,omitempty"`
	Target  []byte `json:"target,omitempty"`
}

func (s *Service) putCeremony(ctx context.Context, sess *session.Session, kind string, c *ceremony, expires time.Time) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.st.PutCeremony(ctx, sess.IDHash(), kind, data, expires)
}

func (s *Service) takeCeremony(ctx context.Context, sess *session.Session, kind string) (*ceremony, error) {
	data, err := s.st.TakeCeremony(ctx, sess.IDHash(), kind, s.now())
	if err != nil {
		return nil, err
	}
	var c ceremony
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// RegisterBeginResponse is the body of register/begin: the WebAuthn
// creation options plus the challenge of the confirmation assertion.
type RegisterBeginResponse struct {
	*protocol.CredentialCreation
	Confirm ConfirmOptions `json:"confirm"`
}

// ConfirmOptions carries the challenge (base64url) the browser asserts over
// with the newly created credential (optional; verified when sent).
type ConfirmOptions struct {
	Challenge string `json:"challenge"`
}

// RegisterBegin answers POST /api/passkeys/register/begin with WebAuthn
// creation options. An account without passkeys may begin its initial
// setup (unless another of its sessions is already doing so); otherwise the
// session must hold an "add" grant, which this consumes.
func (s *Service) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, true)
	if sess == nil {
		return
	}
	ctx := r.Context()
	u, err := s.loadUser(ctx, sess)
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	if len(u.rows) >= MaxPasskeys {
		httpx.WriteError(w, errTooMany)
		return
	}
	now := s.now()
	expires := now.Add(CeremonyTTL)
	setup := len(u.rows) == 0
	if setup {
		busy, err := s.st.PendingSetupElsewhere(ctx, sess.UserID(), sess.IDHash(), now)
		if err != nil {
			s.internal(w, r, "pending setup", err)
			return
		}
		if busy {
			httpx.WriteError(w, errSetupBusy)
			return
		}
	} else {
		gexp, err := s.st.TakePasskeyGrant(ctx, sess.IDHash(), store.GrantAdd, nil, now)
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, errReauth)
			return
		} else if err != nil {
			s.internal(w, r, "take grant", err)
			return
		}
		// The registration must finish within the grant's lifetime.
		if gexp.Before(expires) {
			expires = gexp
		}
	}
	exclude := make([]protocol.CredentialDescriptor, len(u.creds))
	for i := range u.creds {
		exclude[i] = u.creds[i].Descriptor()
	}
	creation, sd, err := s.wa.BeginRegistration(u,
		webauthn.WithExclusions(exclude),
		webauthn.WithExtensions(webauthn.WithExtensionPRFSupport(), webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		s.internal(w, r, "begin registration", err)
		return
	}
	_, confirm, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.internal(w, r, "begin confirmation", err)
		return
	}
	confirm.UserID = u.handle
	if err := s.putCeremony(ctx, sess, kindRegister, &ceremony{SD: *sd, Confirm: confirm, Setup: setup}, expires); err != nil {
		s.internal(w, r, "store ceremony", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, RegisterBeginResponse{CredentialCreation: creation, Confirm: ConfirmOptions{Challenge: confirm.Challenge}})
}

type registerFinishBody struct {
	Credential     json.RawMessage `json:"credential"`
	WrappedPrivkey string          `json:"wrapped_privkey"`
	Pubkey         string          `json:"pubkey"`
	Confirm        json.RawMessage `json:"confirm,omitempty"`
}

// RegisterFinishResponse is the body of a successful registration.
type RegisterFinishResponse struct {
	ID            string `json:"id"`
	PasskeyCount  int    `json:"passkey_count"`
	SetupComplete bool   `json:"setup_complete"`
}

// ParseRegisterFinish validates the non-WebAuthn fields of a registration
// body and parses the credential. Exposed for fuzzing.
func ParseRegisterFinish(body []byte) (*protocol.ParsedCredentialCreationData, []byte, []byte, error) {
	var b registerFinishBody
	if err := httpx.DecodeJSONBytesFrom(bytesReader(body), &b); err != nil {
		return nil, nil, nil, err
	}
	return parseRegisterFinish(&b)
}

func parseRegisterFinish(b *registerFinishBody) (*protocol.ParsedCredentialCreationData, []byte, []byte, error) {
	wrapped, err := b64.Strict().DecodeString(b.WrappedPrivkey)
	if err != nil || len(wrapped) < MinWrappedPrivkey || len(wrapped) > MaxWrappedPrivkey {
		return nil, nil, nil, errors.New("passkey: invalid wrapped_privkey")
	}
	pub, err := b64.Strict().DecodeString(b.Pubkey)
	if err != nil || len(pub) != PubkeySize {
		return nil, nil, nil, errors.New("passkey: invalid pubkey")
	}
	if len(b.Credential) == 0 {
		return nil, nil, nil, errors.New("passkey: missing credential")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(b.Credential)
	if err != nil {
		return nil, nil, nil, err
	}
	return parsed, wrapped, pub, nil
}

// RegisterFinish answers POST /api/passkeys/register/finish.
func (s *Service) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, true)
	if sess == nil {
		return
	}
	var body registerFinishBody
	if !decodeBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	cer, err := s.takeCeremony(ctx, sess, kindRegister)
	if err != nil {
		httpx.WriteError(w, errCeremony)
		return
	}
	parsed, wrapped, pub, err := parseRegisterFinish(&body)
	if err != nil {
		httpx.WriteError(w, errVerify)
		return
	}
	u, err := s.loadUser(ctx, sess)
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	if cer.Setup != (len(u.rows) == 0) {
		httpx.WriteError(w, errChanged)
		return
	}
	cred, err := s.wa.CreateCredential(u, cer.SD, parsed)
	if err != nil {
		s.log.InfoContext(ctx, "passkey registration refused", "user", sess.UserID(), "reason", describe(err))
		httpx.WriteError(w, errVerify)
		return
	}
	if !cred.Flags.UserVerified || !cred.Flags.UserPresent {
		httpx.WriteError(w, errVerify)
		return
	}
	if prf := parsed.ClientExtensionResults.PRF; prf == nil || ((prf.Enabled == nil || !*prf.Enabled) && prf.Results == nil) {
		httpx.WriteError(w, errPRF)
		return
	}
	if len(cred.ID) < minCredentialID || len(cred.ID) > maxCredentialID {
		httpx.WriteError(w, errVerify)
		return
	}
	now := s.now()
	var lastUsed *time.Time
	if len(body.Confirm) > 0 {
		confirmed, e := s.verifyConfirmation(ctx, sess, u, cer, cred, body.Confirm)
		if e != nil {
			httpx.WriteError(w, e)
			return
		}
		cred, lastUsed = confirmed, &now
	}
	// The attestation (format "none") carries nothing worth keeping.
	cred.Attestation = webauthn.CredentialAttestation{}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		s.internal(w, r, "encode credential", err)
		return
	}
	err = s.st.AddPasskey(ctx, &store.Passkey{
		ID: cred.ID, UserID: sess.UserID(), Credential: credJSON, SignCount: cred.Authenticator.SignCount,
		WrappedPrivkey: wrapped, CreatedAt: now, LastUsedAt: lastUsed,
	}, pub, cer.Setup)
	switch {
	case errors.Is(err, store.ErrKeyMismatch):
		httpx.WriteError(w, errMismatch)
		return
	case errors.Is(err, store.ErrConflict):
		httpx.WriteError(w, errExists)
		return
	case errors.Is(err, store.ErrPasskeysChanged):
		httpx.WriteError(w, errChanged)
		return
	case err != nil:
		s.internal(w, r, "store passkey", err)
		return
	}
	via := "grant"
	if cer.Setup {
		via = "setup"
		// The browser created the account key pair and holds it: this
		// registration counts as an unlock. The first passkey
		// grants the next registration (the second passkey of the setup).
		ns, err := s.sessions.MarkUnlocked(ctx, w, sess)
		if err != nil {
			s.internal(w, r, "mark unlocked", err)
			return
		}
		if err := s.st.PutPasskeyGrant(ctx, ns.IDHash(), store.GrantAdd, nil, now.Add(GrantTTL)); err != nil {
			s.internal(w, r, "store grant", err)
			return
		}
	}
	n, complete, err := s.SetupComplete(ctx, sess.UserID())
	if err != nil {
		s.internal(w, r, "count passkeys", err)
		return
	}
	s.log.WarnContext(ctx, "passkey added", "user", sess.UserID(), "via", via, "passkeys", n)
	httpx.WriteJSON(w, http.StatusOK, RegisterFinishResponse{ID: b64.EncodeToString(cred.ID), PasskeyCount: n, SetupComplete: complete})
}

// verifyConfirmation checks the confirmation assertion a registration
// carries: made by the new credential, user-verified, over the
// ceremony's confirmation challenge. It returns the credential with the
// counter and flags of that assertion.
func (s *Service) verifyConfirmation(ctx context.Context, sess *session.Session, u *waUser, cer *ceremony, cred *webauthn.Credential, raw json.RawMessage) (*webauthn.Credential, *httpx.APIError) {
	if cer.Confirm == nil {
		return nil, errVerify
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return nil, errVerify
	}
	nu := &waUser{handle: u.handle, name: u.name, creds: []webauthn.Credential{*cred}}
	got, err := s.wa.ValidateLogin(nu, *cer.Confirm, parsed)
	if err != nil {
		s.log.InfoContext(ctx, "passkey confirmation refused", "user", sess.UserID(), "reason", describe(err))
		return nil, errVerify
	}
	if !parsed.Response.AuthenticatorData.Flags.UserVerified() || !bytes.Equal(got.ID, cred.ID) {
		return nil, errVerify
	}
	if got.Authenticator.CloneWarning {
		return nil, errClone
	}
	return got, nil
}

type unlockBeginBody struct {
	Purpose   string `json:"purpose"`
	PasskeyID string `json:"passkey_id"`
}

// UnlockBegin answers POST /api/passkeys/unlock/begin with WebAuthn
// assertion options limited to the user's passkeys. The optional body
// `{"purpose": "unlock"|"add"|"delete", "passkey_id"}` names the passkey
// management grant a successful assertion leaves (ARCHITECTURE.md §3).
func (s *Service) UnlockBegin(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, true)
	if sess == nil {
		return
	}
	var body unlockBeginBody
	if !decodeOptionalBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	u, err := s.loadUser(ctx, sess)
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	if len(u.creds) == 0 {
		httpx.WriteError(w, errNoPasskeys)
		return
	}
	cer := &ceremony{}
	switch body.Purpose {
	case "", "unlock":
		if body.PasskeyID != "" {
			httpx.WriteError(w, errBadRequest)
			return
		}
	case store.GrantAdd:
		if body.PasskeyID != "" {
			httpx.WriteError(w, errBadRequest)
			return
		}
		cer.Purpose = store.GrantAdd
	case store.GrantDelete:
		id, ok := decodeCredentialID(body.PasskeyID)
		if !ok || !u.owns(id) {
			httpx.WriteError(w, errNotFound)
			return
		}
		cer.Purpose, cer.Target = store.GrantDelete, id
	default:
		httpx.WriteError(w, errBadRequest)
		return
	}
	assertion, sd, err := s.wa.BeginLogin(u,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: PRFSalt[:]})),
	)
	if err != nil {
		s.internal(w, r, "begin login", err)
		return
	}
	cer.SD = *sd
	if err := s.putCeremony(ctx, sess, kindUnlock, cer, s.now().Add(CeremonyTTL)); err != nil {
		s.internal(w, r, "store ceremony", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, assertion)
}

func decodeCredentialID(s string) ([]byte, bool) {
	id, err := b64.Strict().DecodeString(s)
	return id, err == nil && len(id) >= minCredentialID && len(id) <= maxCredentialID
}

func (u *waUser) owns(id []byte) bool {
	for _, p := range u.rows {
		if bytes.Equal(p.ID, id) {
			return true
		}
	}
	return false
}

type unlockFinishBody struct {
	Credential json.RawMessage `json:"credential"`
}

// UnlockResponse is the body of a successful unlock.
type UnlockResponse struct {
	WrappedPrivkey string `json:"wrapped_privkey"`
	CredentialID   string `json:"credential_id"`
	UserHandle     string `json:"user_handle"`
}

// UnlockFinish answers POST /api/passkeys/unlock/finish: it verifies the
// assertion against the ceremony of this session, records the use, marks
// the session unlocked (rotating its ID), leaves the grant the ceremony was
// begun for on the new session, and returns the wrapped key of the passkey
// that was used.
func (s *Service) UnlockFinish(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, true)
	if sess == nil {
		return
	}
	var body unlockFinishBody
	if !decodeBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	cer, err := s.takeCeremony(ctx, sess, kindUnlock)
	if err != nil {
		httpx.WriteError(w, errCeremony)
		return
	}
	if len(body.Credential) == 0 {
		httpx.WriteError(w, errVerify)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		httpx.WriteError(w, errVerify)
		return
	}
	u, err := s.loadUser(ctx, sess)
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	cred, err := s.wa.ValidateLogin(u, cer.SD, parsed)
	if err != nil {
		s.log.InfoContext(ctx, "passkey assertion refused", "user", sess.UserID(), "reason", describe(err))
		httpx.WriteError(w, errVerify)
		return
	}
	if !parsed.Response.AuthenticatorData.Flags.UserVerified() {
		httpx.WriteError(w, errVerify)
		return
	}
	if cred.Authenticator.CloneWarning {
		s.log.WarnContext(ctx, "passkey sign counter did not increase; possible clone", "user", sess.UserID())
		httpx.WriteError(w, errClone)
		return
	}
	var row *store.Passkey
	for _, p := range u.rows {
		if bytes.Equal(p.ID, cred.ID) {
			row = p
		}
	}
	if row == nil {
		httpx.WriteError(w, errVerify)
		return
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		s.internal(w, r, "encode credential", err)
		return
	}
	now := s.now()
	if err := s.st.UpdatePasskeyUse(ctx, sess.UserID(), cred.ID, credJSON, cred.Authenticator.SignCount, now); err != nil {
		s.internal(w, r, "record use", err)
		return
	}
	ns, err := s.sessions.MarkUnlocked(ctx, w, sess)
	if err != nil {
		if errors.Is(err, session.ErrNoSession) {
			httpx.WriteError(w, errUnauthenticated)
			return
		}
		s.internal(w, r, "mark unlocked", err)
		return
	}
	if cer.Purpose != "" {
		if err := s.st.PutPasskeyGrant(ctx, ns.IDHash(), cer.Purpose, cer.Target, now.Add(GrantTTL)); err != nil {
			s.internal(w, r, "store grant", err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, UnlockResponse{
		WrappedPrivkey: b64.EncodeToString(row.WrappedPrivkey),
		CredentialID:   b64.EncodeToString(row.ID),
		UserHandle:     b64.EncodeToString(u.handle),
	})
}

// Summary is one entry of GET /api/passkeys.
type Summary struct {
	ID         string `json:"id"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at"`
}

// List answers GET /api/passkeys.
func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if sess == nil {
		return
	}
	rows, err := s.st.Passkeys(r.Context(), sess.UserID())
	if err != nil {
		s.internal(w, r, "list", err)
		return
	}
	out := make([]Summary, 0, len(rows))
	for _, p := range rows {
		e := Summary{ID: b64.EncodeToString(p.ID), CreatedAt: p.CreatedAt.Unix()}
		if p.LastUsedAt != nil {
			v := p.LastUsedAt.Unix()
			e.LastUsedAt = &v
		}
		out = append(out, e)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"passkeys": out})
}

// Delete answers DELETE /api/passkeys/{id}. It consumes the session's
// "delete" grant for exactly this passkey (403 reauth_required without one)
// and refuses to leave fewer than Required passkeys.
func (s *Service) Delete(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r, false)
	if sess == nil {
		return
	}
	ctx := r.Context()
	id, ok := decodeCredentialID(r.PathValue("id"))
	if !ok {
		httpx.WriteError(w, errNotFound)
		return
	}
	if _, err := s.st.TakePasskeyGrant(ctx, sess.IDHash(), store.GrantDelete, id, s.now()); errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, errReauth)
		return
	} else if err != nil {
		s.internal(w, r, "take grant", err)
		return
	}
	switch err := s.st.DeletePasskey(ctx, sess.UserID(), id, Required); {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteError(w, errNotFound)
	case errors.Is(err, store.ErrTooFewPasskeys):
		httpx.WriteError(w, errTooFew)
	case err != nil:
		s.internal(w, r, "delete", err)
	default:
		s.log.WarnContext(ctx, "passkey deleted", "user", sess.UserID())
		w.WriteHeader(http.StatusNoContent)
	}
}

// describe extracts the developer detail of a go-webauthn error for logs.
func describe(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe.Type + ": " + pe.Details + " " + pe.DevInfo
	}
	return err.Error()
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
