package review

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitize makes text from the session safe to print: control characters,
// escape sequences, and invisible or direction-changing characters are shown
// as escapes, so nothing can hide a line, rewrite the screen, or reorder what
// the user reads. Newlines and tabs stay. What is pushed is never sanitised:
// the user reviews the text, escapes visible, and the same bytes are sent.
func Sanitize(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}
