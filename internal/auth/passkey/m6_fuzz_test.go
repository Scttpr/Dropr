package passkey

import (
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzDecodeCredentialID: the credential id of unlock/finish and DELETE
// /api/passkeys/{id} is attacker-controlled. Only canonical unpadded
// base64url within the WebAuthn length bounds is accepted.
func FuzzDecodeCredentialID(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("AAAAAAAAAAAAAAAAAAAAAB")
	f.Add("AAAAAAAAAAAAAAAAAAAAAA==")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, ok := decodeCredentialID(s)
		if !ok {
			return
		}
		if len(id) < minCredentialID || len(id) > maxCredentialID {
			t.Fatalf("accepted length %d", len(id))
		}
		// Go's base64 decoder skips CR/LF even in Strict mode; the decoded bytes
		// (what is compared and stored) are unaffected, so only those are tolerated.
		if base64.RawURLEncoding.EncodeToString(id) != strings.NewReplacer("\r", "", "\n", "").Replace(s) {
			t.Fatalf("accepted non-canonical encoding %q", s)
		}
	})
}
