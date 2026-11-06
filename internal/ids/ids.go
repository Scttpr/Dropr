// Package ids generates and validates the random identifiers and secrets
// used throughout Dropr.
//
// Public identifiers (links, uploads, users) are 128-bit values encoded as
// unpadded base64url (22 characters). Bearer secrets (session IDs, tokens)
// are 256-bit values (43 characters). Both come from crypto/rand.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	// IDBytes is the entropy of a public identifier.
	IDBytes = 16
	// IDLen is the encoded length of a public identifier.
	IDLen = 22
	// SecretBytes is the entropy of a bearer secret.
	SecretBytes = 32
	// SecretLen is the encoded length of a bearer secret.
	SecretLen = 43
)

var enc = base64.RawURLEncoding.Strict()

// New returns a fresh 128-bit identifier, base64url encoded.
func New() string { return random(IDBytes) }

// NewSecret returns a fresh 256-bit bearer secret, base64url encoded.
func NewSecret() string { return random(SecretBytes) }

func random(n int) string {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error on supported platforms
	// (Go 1.24+ aborts the program instead), so the error is ignored.
	_, _ = rand.Read(b)
	return enc.EncodeToString(b)
}

// Valid reports whether s is a canonically encoded 128-bit identifier.
func Valid(s string) bool { return valid(s, IDLen, IDBytes) }

// ValidSecret reports whether s is a canonically encoded 256-bit secret.
func ValidSecret(s string) bool { return valid(s, SecretLen, SecretBytes) }

func valid(s string, encLen, rawLen int) bool {
	if len(s) != encLen {
		return false
	}
	// Strict() rejects non-zero trailing bits, so each value has exactly
	// one accepted encoding.
	b, err := enc.DecodeString(s)
	return err == nil && len(b) == rawLen
}

// Hash returns SHA-256 of a bearer secret, the only form stored at rest.
func Hash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}
