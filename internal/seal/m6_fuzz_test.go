package seal

import (
	"bytes"
	"testing"
)

// FuzzOpen feeds attacker-controlled ciphertexts (the sealed OIDC state
// cookie, encrypted refresh tokens read back from the DB) to Open: it must
// never panic, never authenticate anything but a genuine message under the
// right aad, and a single bit flip of a genuine message must always fail.
// (Seal draws a random nonce, so fuzz workers each hold a different genuine
// ciphertext; a successful Open is only legitimate for the known plaintext.)
func FuzzOpen(f *testing.F) {
	a, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	known := []byte(`{"s":"state","n":"nonce","v":"verifier","t":1}`)
	good := a.Seal(known, []byte("aad"))
	f.Add(good, []byte("aad"), uint16(0))
	f.Add([]byte{}, []byte{}, uint16(3))
	f.Add(make([]byte, 28), []byte("aad"), uint16(27))
	f.Fuzz(func(t *testing.T, ct, aad []byte, flip uint16) {
		if pt, err := a.Open(ct, aad); err == nil && (!bytes.Equal(pt, known) || string(aad) != "aad") {
			t.Fatalf("forged ciphertext opened: %x -> %q", ct, pt)
		}
		m := bytes.Clone(good)
		m[int(flip)%len(m)] ^= 1 << (flip % 8)
		if _, err := a.Open(m, []byte("aad")); err == nil {
			t.Fatal("bit-flipped ciphertext opened")
		}
		if _, err := a.Open(good, append([]byte("aad"), 0)); err == nil {
			t.Fatal("opened under a different aad")
		}
	})
}
