// Package passkeytest is a software WebAuthn authenticator for tests. It
// answers the creation and assertion options produced by the passkey
// service with ES256 credentials, attestation "none", authenticator data
// with configurable UP/UV/BE/BS flags and a client data JSON whose origin and
// challenge can be overridden for negative tests.
package passkeytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

var b64 = base64.RawURLEncoding

// Authenticator flags (WebAuthn §6.1).
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
)

// Credential is a credential created by the authenticator.
type Credential struct {
	ID         []byte
	Key        *ecdsa.PrivateKey
	UserHandle []byte
	RPID       string
	Counter    uint32
	// Synced credentials (BE+BS, counter always 0) model passkey providers.
	Synced bool
}

// Authenticator creates and exercises credentials for one origin.
type Authenticator struct {
	Origin string
}

// Options override what the authenticator would normally produce.
type Options struct {
	Origin    string // client data origin (default: Authenticator.Origin)
	Challenge []byte // client data challenge (default: from the options)
	NoUV      bool   // clear the UV flag
	NoPRF     bool   // registration: omit the PRF client extension output
	Counter   *uint32
	Type      string // client data type override
}

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) clientData(typ string, challenge []byte, o Options) []byte {
	if o.Type != "" {
		typ = o.Type
	}
	origin := a.Origin
	if o.Origin != "" {
		origin = o.Origin
	}
	if o.Challenge != nil {
		challenge = o.Challenge
	}
	cd, _ := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   b64.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	return cd
}

// Register answers creation options (the JSON body of register/begin) and
// returns the credential JSON for register/finish.
func (a *Authenticator) Register(optionsJSON []byte, synced bool, o Options) (json.RawMessage, *Credential, error) {
	var opts creationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, nil, err
	}
	pk := opts.PublicKey
	challenge, err := b64.DecodeString(pk.Challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("challenge: %w", err)
	}
	handle, err := b64.DecodeString(pk.User.ID)
	if err != nil || len(handle) == 0 {
		return nil, nil, errors.New("user.id missing")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	c := &Credential{ID: make([]byte, 32), Key: key, UserHandle: handle, RPID: pk.RP.ID, Synced: synced}
	_, _ = rand.Read(c.ID)
	for _, ex := range pk.ExcludeCredentials {
		if id, _ := b64.DecodeString(ex.ID); bytes.Equal(id, c.ID) {
			return nil, nil, errors.New("excluded")
		}
	}

	flags := byte(FlagUP | FlagUV | FlagAT)
	if synced {
		flags |= FlagBE | FlagBS
	}
	if o.NoUV {
		flags &^= FlagUV
	}
	ecdh, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, nil, err
	}
	raw := ecdh.Bytes() // 0x04 || X || Y
	cose := encodeCBOR(map[any]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	rpHash := sha256.Sum256([]byte(pk.RP.ID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, flags)
	auth = binary.BigEndian.AppendUint32(auth, c.counter(o))
	auth = append(auth, make([]byte, 16)...)                      // AAGUID
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(c.ID))) //nolint:gosec // 32-byte IDs
	auth = append(auth, c.ID...)
	auth = append(auth, cose...)
	att := encodeCBOR(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": auth})

	ext := map[string]any{"prf": map[string]any{"enabled": true}}
	if o.NoPRF {
		ext = map[string]any{}
	}
	out, err := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(c.ID),
		"rawId": b64.EncodeToString(c.ID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", challenge, o)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults":  ext,
		"authenticatorAttachment": "platform",
	})
	return out, c, err
}

func (c *Credential) counter(o Options) uint32 {
	if o.Counter != nil {
		return *o.Counter
	}
	if c.Synced {
		return 0
	}
	c.Counter++
	return c.Counter
}

// Assert answers assertion options (the JSON body of unlock/begin) with c
// and returns the credential JSON for unlock/finish.
func (a *Authenticator) Assert(c *Credential, optionsJSON []byte, o Options) (json.RawMessage, error) {
	var opts requestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, err
	}
	challenge, err := b64.DecodeString(opts.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}
	flags := byte(FlagUP | FlagUV)
	if c.Synced {
		flags |= FlagBE | FlagBS
	}
	if o.NoUV {
		flags &^= FlagUV
	}
	rpHash := sha256.Sum256([]byte(c.RPID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, flags)
	auth = binary.BigEndian.AppendUint32(auth, c.counter(o))
	cd := a.clientData("webauthn.get", challenge, o)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.Key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":    b64.EncodeToString(c.ID),
		"rawId": b64.EncodeToString(c.ID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.UserHandle),
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
}

// encodeCBOR encodes the small subset of CBOR (RFC 8949) WebAuthn needs:
// maps (keys sorted canonically), text and byte strings, and integers.
func encodeCBOR(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case map[any]any:
		type kv struct{ k, v []byte }
		entries := make([]kv, 0, len(x))
		for k, val := range x {
			entries = append(entries, kv{encodeCBOR(k), encodeCBOR(val)})
		}
		sort.Slice(entries, func(i, j int) bool {
			a, b := entries[i].k, entries[j].k
			if len(a) != len(b) {
				return len(a) < len(b)
			}
			return string(a) < string(b)
		})
		out := cborHead(5, uint64(len(entries)))
		for _, e := range entries {
			out = append(append(out, e.k...), e.v...)
		}
		return out
	}
	panic(fmt.Sprintf("cbor: unsupported %T", v))
}

func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{m | 25}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{m | 26}, uint32(n)) //nolint:gosec // test sizes fit in 32 bits
	}
}

// Confirm answers the confirmation challenge of a register/begin body
// (`{"confirm": {"challenge": …}}`) with the newly created credential c, as
// the browser does right after create(). It returns the assertion JSON for
// the "confirm" field of register/finish.
func (a *Authenticator) Confirm(c *Credential, beginJSON []byte, o Options) (json.RawMessage, error) {
	var b struct {
		Confirm struct {
			Challenge string `json:"challenge"`
		} `json:"confirm"`
	}
	if err := json.Unmarshal(beginJSON, &b); err != nil {
		return nil, err
	}
	opts, err := json.Marshal(map[string]any{"publicKey": map[string]any{"challenge": b.Confirm.Challenge, "rpId": c.RPID}})
	if err != nil {
		return nil, err
	}
	return a.Assert(c, opts, o)
}
