package launcher

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gwenneg/sealroom/internal/declare"
)

func TestAcceptDeclared(t *testing.T) {
	d := declare.Declaration{Network: []declare.Access{{Host: "api.example.com", Methods: []string{"GET"}, Paths: []string{"/v1/*"}, Why: "Reads notes\x1b[8m hidden"}}}
	for answer, want := range map[string]bool{"y\n": true, "yes\n": true, "\n": false, "n\n": false, "": false} {
		var out bytes.Buffer
		if got := acceptDeclared(d, Terminal{In: strings.NewReader(answer), Out: &out}); got != want {
			t.Errorf("answer %q: %v, want %v", answer, got, want)
		}
		if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), `\x1b[8m hidden`) {
			t.Errorf("the reason was not sanitised: %q", out.String())
		}
		if !strings.Contains(out.String(), "GET api.example.com/v1/*") {
			t.Errorf("the access was not shown: %q", out.String())
		}
	}
}
