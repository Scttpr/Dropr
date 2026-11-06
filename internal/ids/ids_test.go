package ids

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewIsValidAndUnique(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 1000 {
		id := New()
		if !Valid(id) {
			t.Fatalf("New() = %q not valid", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
		s := NewSecret()
		if !ValidSecret(s) || Valid(s) {
			t.Fatalf("NewSecret() = %q validity wrong", s)
		}
	}
}

func TestValidRejects(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"",
		"short",
		strings.Repeat("A", 21),
		strings.Repeat("A", 23),
		strings.Repeat("A", 21) + "B", // non-zero trailing bits: non-canonical
		strings.Repeat("A", 21) + "=",
		strings.Repeat("+", 22),
		strings.Repeat("/", 22),
		strings.Repeat("A", 20) + "\x00A",
	} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
	if !Valid(strings.Repeat("A", 21) + "Q") {
		t.Error("canonical id rejected")
	}
}

func TestHash(t *testing.T) {
	t.Parallel()
	if len(Hash("x")) != 32 || bytes.Equal(Hash("x"), Hash("y")) {
		t.Fatal("bad hash")
	}
}

func FuzzValid(f *testing.F) {
	f.Add(New())
	f.Add(NewSecret())
	f.Add("AAAAAAAAAAAAAAAAAAAAAB")
	f.Fuzz(func(t *testing.T, s string) {
		if Valid(s) {
			b, err := enc.DecodeString(s)
			if err != nil || len(b) != IDBytes || enc.EncodeToString(b) != s {
				t.Fatalf("accepted non-canonical %q", s)
			}
		}
		if ValidSecret(s) {
			b, err := enc.DecodeString(s)
			if err != nil || enc.EncodeToString(b) != s {
				t.Fatalf("accepted non-canonical secret %q", s)
			}
		}
	})
}
