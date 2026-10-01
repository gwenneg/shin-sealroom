package egress

import (
	"fmt"
	"strings"
	"testing"
)

// TestParPipelining: several requests in one write. The proxy reads them in
// turn, and each is checked on its own: a hostile request after an allowed
// one, or hidden in the body of one, is refused, and a refusal closes the
// connection so nothing after it is read.
func TestParPipelining(t *testing.T) {
	smuggled := "GET /admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	withBody := func(method, target, body string) string {
		return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n%s", method, target, len(body), body)
	}
	models := parUp{head: parHead("GET", "/v1/models", "example.com")}
	cases := []parCase{
		{name: "two allowed", raw: parReq1("GET", "/") + parReq1("GET", "/v1/models"),
			want: []parWant{parAllowed, parAllowed}, up: []parUp{parUpRoot, models}},
		{name: "ten allowed, in order", raw: strings.Repeat(parReq1("GET", "/")+parReq1("GET", "/v1/models"), 5),
			want: []parWant{parAllowed, parAllowed, parAllowed, parAllowed, parAllowed, parAllowed, parAllowed, parAllowed, parAllowed, parAllowed},
			up:   []parUp{parUpRoot, models, parUpRoot, models, parUpRoot, models, parUpRoot, models, parUpRoot, models}},
		{name: "allowed, then a dot-dot path", raw: parReq1("GET", "/") + parReq1("GET", "/raw/../v1/x"),
			want: []parWant{parAllowed, parRefusal(reasonPath)}, up: []parUp{parUpRoot}},
		{name: "allowed, then another host", raw: parReq1("GET", "/") + "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n",
			want: []parWant{parAllowed, parRefusal(reasonHost)}, up: []parUp{parUpRoot}},
		{name: "allowed, then the path of another host's rule", raw: parReq1("GET", "/") + smuggled,
			want: []parWant{parAllowed, parRefusal(reasonHost)}, up: []parUp{parUpRoot}},
		{name: "allowed, then absolute form", raw: parReq1("GET", "/") + parReq1("GET", "https://api.example.com/admin"),
			want: []parWant{parAllowed, parRefusal(reasonForm)}, up: []parUp{parUpRoot}},
		{name: "allowed, then the agent's own credential", raw: parReq1("GET", "/") + parReq1("GET", "/auth", "Authorization: Bearer sk-attacker"),
			want: []parWant{parAllowed, parRefusal(reasonCred)}, up: []parUp{parUpRoot}},
		{name: "allowed twice, then an upgrade", raw: parReq1("GET", "/") + parReq1("GET", "/") + parReq1("GET", "/", "Upgrade: h2c", "Connection: Upgrade"),
			want: []parWant{parAllowed, parAllowed, parRefusal(reasonForm)}, up: []parUp{parUpRoot, parUpRoot}},
		{name: "allowed, then a parse error", raw: parReq1("GET", "/") + parReq1("GET", "/", "X-Note : a") + parReq1("GET", "/"),
			want: []parWant{parAllowed, parGo(400)}, up: []parUp{parUpRoot}},
		{name: "refused, then allowed: nothing after a refusal is read", raw: parReq1("GET", "/v1/../v1/models") + parReq1("GET", "/"),
			want: []parWant{parRefusal(reasonPath)}},
		{name: "Connection close, then allowed: nothing after it is read", raw: parReq1("GET", "/", "Connection: close") + parReq1("GET", "/"),
			want: []parWant{parAllowed}, up: []parUp{parUpRoot}, closes: true},
		{name: "a request in a body is a body", raw: withBody("POST", "/v1/messages?beta=true", smuggled),
			want: []parWant{parAllowed},
			up:   []parUp{{head: parHead("POST", "/v1/messages?beta=true", "example.com", fmt.Sprintf("Content-Length: %d", len(smuggled))), body: smuggled}}},
		{name: "a request in a chunk is a body", raw: parPost + fmt.Sprintf("Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(smuggled), smuggled),
			want: []parWant{parAllowed},
			up:   []parUp{{head: parUpPostC.head, body: smuggled}}},
		{name: "a short Content-Length leaves a hostile request, checked on its own", raw: parPost + "Content-Length: 5\r\n\r\nhello" + smuggled,
			want: []parWant{parAllowed, parRefusal(reasonHost)}, up: []parUp{parUpPost5}},
		{name: "a short Content-Length leaves an allowed request, checked on its own", raw: parPost + "Content-Length: 5\r\n\r\nhello" + parReq1("GET", "/"),
			want: []parWant{parAllowed, parAllowed}, up: []parUp{parUpPost5, parUpRoot}},
		{name: "after the last chunk, a hostile request, checked on its own", raw: parPost + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" + smuggled,
			want: []parWant{parAllowed, parRefusal(reasonHost)}, up: []parUp{parUpPostC}},
		{name: "unframed bytes after a GET are the next request, CL.0", raw: parReq1("GET", "/") + smuggled,
			want: []parWant{parAllowed, parRefusal(reasonHost)}, up: []parUp{parUpRoot}},
		{name: "a GET with a body hiding a request, 0.CL", raw: withBody("GET", "/", smuggled),
			want: []parWant{parRefusal(reasonBody)}},
		{name: "a chunked GET hiding a request, TE.0", raw: parReq1("GET", "/", "Transfer-Encoding: chunked") + fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(smuggled), smuggled),
			want: []parWant{parRefusal(reasonBody)}},
		{name: "Expect with a body hiding a request", raw: parPost + fmt.Sprintf("Expect: 100-continue\r\nContent-Length: %d\r\n\r\n%s", len(smuggled), smuggled),
			want: []parWant{parRefusal(reasonForm)}},
		{name: "obfuscated Expect with a body hiding a request", raw: parPost + fmt.Sprintf("Expect: y 100-continue\r\nContent-Length: %d\r\n\r\n%s", len(smuggled), smuggled),
			want: []parWant{parRefusal(reasonForm)}},
		{name: "an h2c upgrade followed by a preface", raw: parReq1("GET", "/", "Upgrade: h2c", "Connection: Upgrade, HTTP2-Settings", "Http2-Settings: AAMAAABkAAQAoAAAAAIAAAAA") + "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
			want: []parWant{parRefusal(reasonForm)}},
		{name: "HEAD, then GET", raw: parReq1("HEAD", "/") + parReq1("GET", "/"), heads: []string{"HEAD"},
			want: []parWant{parAllowed, parAllowed}, up: []parUp{{head: parHead("HEAD", "/", "example.com")}, parUpRoot}},
		// Content-Length with chunked is refused and the connection closed,
		// as RFC 9112 6.1 requires; Go's server alone would read the next
		// request.
		{name: "CL.TE, the bytes after the last chunk read as a request", raw: parPost + "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + parReq1("GET", "/"),
			want: []parWant{parRefusedAny}},
	}
	parRun(t, cases)
}
