// Package seal provides authenticated encryption for server-side secrets
// (encrypted refresh tokens, the sealed OIDC state cookie) and derives
// purpose-specific subkeys from the instance master key.
//
// Every purpose gets its own HKDF-SHA256 subkey so that a ciphertext produced
// for one purpose can never be opened in another context, even before
// associated data is considered.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// HKDF info strings. Never reuse one for a different purpose.
const (
	InfoRefreshToken = "dropr/v1 refresh-token"
	InfoOIDCCookie   = "dropr/v1 oidc-state-cookie"
	InfoIPHash       = "dropr/v1 ip-hash"
)

// KeySize is the size of the master key and of every derived key.
const KeySize = 32

// ErrOpen is returned for any decryption failure. It deliberately carries no
// detail.
var ErrOpen = errors.New("seal: message authentication failed")

// Derive returns the 32-byte subkey of master for the given purpose.
func Derive(master []byte, info string) ([]byte, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("seal: master key must be %d bytes, got %d", KeySize, len(master))
	}
	return hkdf.Key(sha256.New, master, nil, info, KeySize)
}

// AEAD is AES-256-GCM with a random 96-bit nonce prepended to the output.
// Random nonces are safe here: each key encrypts far fewer than 2^32
// messages over its lifetime.
type AEAD struct {
	aead cipher.AEAD
}

// New returns an AEAD for a 32-byte key.
func New(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("seal: key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &AEAD{aead: a}, nil
}

// NewDerived derives the subkey for info from master and returns its AEAD.
func NewDerived(master []byte, info string) (*AEAD, error) {
	k, err := Derive(master, info)
	if err != nil {
		return nil, err
	}
	return New(k)
}

// Seal encrypts and authenticates plaintext bound to aad.
func (a *AEAD) Seal(plaintext, aad []byte) []byte {
	return a.aead.Seal(nil, nil, plaintext, aad) //nolint:gosec // G407 false positive: NewGCMWithRandomNonce generates the nonce
}

// Open authenticates and decrypts a message produced by Seal with the same aad.
func (a *AEAD) Open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < a.aead.Overhead() {
		return nil, ErrOpen
	}
	pt, err := a.aead.Open(nil, nil, ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
