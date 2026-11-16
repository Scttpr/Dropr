package audit

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRefs(t *testing.T) {
	t.Parallel()
	r := NewRefs(bytes.Repeat([]byte{1}, 32))
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	link := r.Link(id)
	if len(link) != 12 {
		t.Fatalf("length %d", len(link))
	}
	if _, err := hex.DecodeString(link); err != nil {
		t.Fatalf("not hex: %q", link)
	}
	if r.Link(id) != link || NewRefs(bytes.Repeat([]byte{1}, 32)).Link(id) != link {
		t.Error("reference not stable for one key")
	}
	if r.File(id) == link {
		t.Error("link and file references collide")
	}
	if NewRefs(bytes.Repeat([]byte{2}, 32)).Link(id) == link {
		t.Error("reference does not depend on the key")
	}
	if r.Link("BAAAAAAAAAAAAAAAAAAAAA") == link {
		t.Error("reference does not depend on the ID")
	}
	// Domain separation is not a prefix trick: "link" + "\x00" + id.
	if r.Link("x") == r.File("x") {
		t.Error("domain separation")
	}
}

func TestEvent(t *testing.T) {
	t.Parallel()
	if a := Event(ShareCreated); a.Key != "event" || a.Value.String() != "share.created" {
		t.Fatal(a)
	}
}

// The derivation is part of the log format: operators correlate references
// across releases, and `dropr log-ref` must keep matching old logs. A change
// here needs a release note.
func TestRefsForIsStable(t *testing.T) {
	t.Parallel()
	r, err := RefsFor(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Link("AAAAAAAAAAAAAAAAAAAAAA"); got != "897dde919087" {
		t.Errorf("link reference changed: %s", got)
	}
	if got := r.File("AAAAAAAAAAAAAAAAAAAAAA"); got != "14b6f2127af0" {
		t.Errorf("file reference changed: %s", got)
	}
	if _, err := RefsFor(make([]byte, 16)); err == nil {
		t.Error("short refresh key accepted")
	}
}
