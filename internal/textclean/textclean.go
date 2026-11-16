// Package textclean makes untrusted text safe to show as a name: the
// provider-supplied display name of an account and the configured brand name.
package textclean

import (
	"strings"
	"unicode"
)

// DisplayText removes what must not reach a page as part of a name. It uses
// the character class of the web client's file-name sanitizer
// (web/src/crypto/meta.ts, audit I-4): controls (C0, DEL, C1) and
// default-ignorable code points (bidi marks, embeddings, overrides and
// isolates, zero-width and invisible separators, BOM, soft hyphen, Hangul
// fillers…) are removed, as are U+061C, U+2028/2029 and the Braille blank
// U+2800. ZWJ/ZWNJ, variation selectors and emoji tag characters are kept.
// Runs of spaces of any width collapse to one ASCII space, and leading and
// trailing spaces go (audit 2026-11 A03-1). Unlike the client, no NFC
// normalization is applied: the server has no Unicode normalization tables.
// Invalid UTF-8 is dropped. The length is not bounded: callers do that.
func DisplayText(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToValidUTF8(s, "") {
		switch {
		case stripped(r):
			continue
		case unicode.Is(unicode.Zs, r):
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// stripped reports whether r is removed from display text: \p{Cc},
// \p{Default_Ignorable_Code_Point} (derived as in DerivedCoreProperties.txt:
// Other_Default_Ignorable_Code_Point + Cf + Variation_Selector − White_Space −
// U+FFF9..FFFB − U+13430..1343F − Prepended_Concatenation_Mark), U+061C,
// U+2028, U+2029 and U+2800, minus the exceptions kept by the web client.
func stripped(r rune) bool {
	switch {
	case r == 0x200c || r == 0x200d, // ZWNJ, ZWJ
		unicode.Is(unicode.Variation_Selector, r),
		r >= 0xe0020 && r <= 0xe007f: // emoji tag characters
		return false
	case unicode.Is(unicode.Cc, r),
		r == 0x061c, r == 0x2028, r == 0x2029, r == 0x2800,
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
		return true
	case unicode.Is(unicode.Cf, r):
		return (r < 0xfff9 || r > 0xfffb) && (r < 0x13430 || r > 0x1343f) &&
			!unicode.Is(unicode.Prepended_Concatenation_Mark, r)
	}
	return false
}
