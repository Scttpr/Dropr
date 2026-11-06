package seal

import (
	"bytes"
	"testing"
)

func TestRoundTripAndBinding(t *testing.T) {
	t.Parallel()
	master := bytes.Repeat([]byte{7}, KeySize)
	a, err := NewDerived(master, InfoRefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDerived(master, InfoOIDCCookie)
	if err != nil {
		t.Fatal(err)
	}
	ct := a.Seal([]byte("secret"), []byte("aad"))
	pt, err := a.Open(ct, []byte("aad"))
	if err != nil || string(pt) != "secret" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	if _, err := a.Open(ct, []byte("other")); err == nil {
		t.Error("opened with wrong aad")
	}
	if _, err := b.Open(ct, []byte("aad")); err == nil {
		t.Error("opened with key of another purpose")
	}
	ct[len(ct)-1] ^= 1
	if _, err := a.Open(ct, []byte("aad")); err == nil {
		t.Error("opened tampered ciphertext")
	}
	if _, err := a.Open(nil, nil); err == nil {
		t.Error("opened empty")
	}
	if bytes.Equal(a.Seal([]byte("x"), nil), a.Seal([]byte("x"), nil)) {
		t.Error("nonce reuse")
	}
}

func TestBadKeys(t *testing.T) {
	t.Parallel()
	if _, err := Derive(make([]byte, 16), InfoIPHash); err == nil {
		t.Error("short master accepted")
	}
	if _, err := New(make([]byte, 31)); err == nil {
		t.Error("short key accepted")
	}
}
