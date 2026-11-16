package textclean

import (
	"testing"
	"unicode/utf8"
)

// Audit 2026-11 A03-1: display names are shown to anonymous uploaders, so
// bidi controls, invisible fillers and C1 controls are removed.
func TestDisplayText(t *testing.T) {
	t.Parallel()
	r := func(cps ...rune) string { return string(cps) }
	for _, c := range []struct{ in, want string }{
		{"Payroll" + r(0x202e) + "Dept", "PayrollDept"},                                                      // RLO
		{r(0x2066) + "Bob" + r(0x2069, ' ', 0x200f), "Bob"},                                                  // isolates, RLM
		{"A" + r(0x200b) + "l" + r(0xad) + "i" + r(0xfeff) + "ce", "Alice"},                                  // ZWSP, soft hyphen, BOM
		{"Bob" + r(0x3164, 0x2800, 0x115f), "Bob"},                                                           // Hangul fillers, Braille blank
		{"Bob" + r(0x85, 0x9b) + "31m", "Bob31m"},                                                            // C1 (NEL, CSI)
		{"Bob" + r(0x061c, 0x2028, 0x2029), "Bob"},                                                           // ALM, line/paragraph separators
		{" Ada" + r(0xa0, 0x2003, 0x3000) + " Lovelace" + r(0x2003), "Ada Lovelace"},                         // space runs collapse
		{r(0x1f469, 0x200d, 0x1f4bb) + " Dev" + r(0xfe0f), r(0x1f469, 0x200d, 0x1f4bb) + " Dev" + r(0xfe0f)}, // ZWJ, variation selector kept
		{"Zo" + r(0xeb, ' ', 0x3a9, ' ', 0x674e), "Zo" + r(0xeb, ' ', 0x3a9, ' ', 0x674e)},
		{"Drop\tand\nCare", "DropandCare"}, // C0 controls
		{"Drop\xffCare", "DropCare"},       // invalid UTF-8
		{r(0x200e, 0x7f, ' ', 0xa0), ""},   // nothing visible
	} {
		if got := DisplayText(c.in); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func FuzzDisplayText(f *testing.F) {
	for _, s := range []string{"", "Drop and Care", " a  b ", "a\u202eb", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := DisplayText(s)
		if !utf8.ValidString(out) || DisplayText(out) != out {
			t.Fatalf("DisplayText(%q) = %q: invalid or not idempotent", s, out)
		}
		for _, r := range out {
			if stripped(r) {
				t.Fatalf("DisplayText(%q) kept %U", s, r)
			}
		}
		if len(out) > 0 && (out[0] == ' ' || out[len(out)-1] == ' ') {
			t.Fatalf("DisplayText(%q) = %q: untrimmed", s, out)
		}
	})
}
