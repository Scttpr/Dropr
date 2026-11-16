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
