package passkey

import (
	"testing"
)

// FuzzParseRegisterFinish checks the registration body parser never panics
// and only accepts well-sized key material.
func FuzzParseRegisterFinish(f *testing.F) {
	f.Add([]byte(`{"credential":{},"wrapped_privkey":"","pubkey":""}`))
	f.Add([]byte(`{"credential":{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}},` +
		`"wrapped_privkey":"` + b64.EncodeToString(make([]byte, 120)) + `","pubkey":"` + b64.EncodeToString(make([]byte, 32)) + `"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, wrapped, pub, err := ParseRegisterFinish(body)
		if err == nil && (len(wrapped) < MinWrappedPrivkey || len(wrapped) > MaxWrappedPrivkey || len(pub) != PubkeySize) {
			t.Fatalf("accepted wrapped=%d pub=%d", len(wrapped), len(pub))
		}
	})
}
