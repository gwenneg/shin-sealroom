package egress

// Table-driven wire tests: raw bytes from the agent, the answers it must read,
// and the exact requests the upstream must receive. docs/proxy-tests/parsing.md
// lists every case with its source.

import (
	"strings"
	"testing"
)

// parWant is one answer the agent must read.
type parWant struct {
	status int // 0: any refusal, a status of 400 or more
	// reason is the proxy's reason code for its own refusals; parByGo for a
	// refusal before any rule, by the proxy's strict reading of the wire or by
	// Go's HTTP server; "" for an answer from the upstream.
	reason string
}

// parByGo marks a refusal before any rule: by wireConn, which refuses a head
// before Go's parser reads it, with a 403 or a 431, or by Go's server.
const parByGo = "go"

var (
	parAllowed = parWant{status: 200}
	// parRefusedAny is a refusal of any kind: the spec requires one without
	// saying which layer gives it.
	parRefusedAny = parWant{}
)

func parRefusal(reason string) parWant { return parWant{status: 403, reason: reason} }
func parGo(status int) parWant         { return parWant{status: status, reason: parByGo} }

// parUp is one request the upstream must receive.
type parUp struct {
	head string
	body string
	// partial: the upstream must not receive the request whole, its body cut
	// before the end of its framing, so it never acts on it.
	partial bool
}

// parCase is one raw exchange.
type parCase struct {
	name  string
	sni   string // the TLS server name, example.com by default
	raw   string
	want  []parWant
	up    []parUp  // nil: nothing reaches the upstream
	heads []string // methods of the answers, for HEAD answers without a body
	// closes: the connection must be closed after the answers, even when the
	// last one was allowed.
	closes bool
}

// parRun runs every case on a proxy of its own, in parallel.
func parRun(t *testing.T, cases []parCase) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.name] {
			t.Fatalf("case %q twice", c.name)
		}
		seen[c.name] = true
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			parCheck(t, c)
		})
	}
}

func parCheck(t *testing.T, c parCase) {
	t.Helper()
	sni := c.sni
	if sni == "" {
		sni = "example.com"
	}
	e := parProxy(t, nil)
	ex := e.parSend(t, sni, c.raw, len(c.want), c.heads...)

	for i, w := range c.want {
		got := ex.Resps[i]
		switch {
		case w.reason == parByGo:
		case w.status == 0:
			if got.Status < 400 {
				t.Errorf("answer %d: %v, want a refusal", i+1, got)
			}
		case got.Status != w.status:
			t.Errorf("answer %d: %v, want status %d", i+1, got, w.status)
		}
		switch {
		case w.reason == parByGo:
			wire := (got.Status == 403 || got.Status == 431) && strings.HasPrefix(got.Body, "sealroom: refused (")
			if got.Status < 400 || strings.HasPrefix(got.Body, "sealroom") && !wire {
				t.Errorf("answer %d: %v, want a refusal before any rule", i+1, got)
			}
		case w.reason != "":
			if head := i < len(c.heads) && c.heads[i] == "HEAD"; !head && got.Body != parRefused(w.reason) {
				t.Errorf("answer %d: body %q, want %q", i+1, got.Body, parRefused(w.reason))
			}
		case w.status == 200:
			if got.Body != "ok" && !(i < len(c.heads) && c.heads[i] == "HEAD") {
				t.Errorf("answer %d: body %q, want the upstream's", i+1, got.Body)
			}
		}
		if got.Status >= 400 && !got.Close {
			t.Errorf("answer %d: a refusal left the connection open", i+1)
		}
	}
	for _, x := range ex.Extra {
		t.Errorf("an extra answer, from a request the case did not expect: %v", x)
	}
	last := c.want[len(c.want)-1]
	wantSentinel := (last.status == 200) && !c.closes
	if !t.Failed() && ex.SentinelAnswered != wantSentinel {
		if wantSentinel {
			t.Errorf("the connection did not read a next request after the answers")
		} else {
			t.Errorf("the connection read a next request, want it closed")
		}
	}

	reqs := e.up.parWaitIdle(len(c.up))
	if len(reqs) != len(c.up) {
		t.Errorf("the upstream received %d requests, want %d", len(reqs), len(c.up))
		for _, r := range reqs {
			t.Logf("upstream received %q body %q", r.Head, r.Body)
		}
	} else {
		for i, w := range c.up {
			r := reqs[i]
			if r.Head != w.head {
				t.Errorf("upstream request %d:\n got  %q\n want %q", i+1, r.Head, w.head)
			}
			if r.SNI != hostOf(w.head) {
				t.Errorf("upstream request %d: TLS server name %q, Host %q", i+1, r.SNI, hostOf(w.head))
			}
			switch {
			case w.partial && r.Complete:
				t.Errorf("upstream request %d arrived whole: body %q", i+1, r.Body)
			case !w.partial && !r.Complete:
				t.Errorf("upstream request %d arrived cut: body %q", i+1, r.Body)
			case !w.partial && r.Body != w.body:
				t.Errorf("upstream request %d: body %q, want %q", i+1, r.Body, w.body)
			}
		}
	}

	// Every answer of the proxy's own is one audit line; the sentinel is one
	// more refusal.
	allowed, refused := 0, 0
	for i, r := range ex.Resps {
		head := i < len(c.heads) && c.heads[i] == "HEAD"
		switch {
		case strings.HasPrefix(r.Body, "sealroom: refused"), head && r.Status >= 400 && c.want[i].reason != parByGo:
			refused++
		case r.Status < 400:
			allowed++
		}
	}
	if ex.SentinelAnswered {
		refused++
	}
	log := e.log.String()
	if n := strings.Count(log, `"decision":"allowed"`); n != allowed && !t.Failed() {
		t.Errorf("%d allowed decisions logged, want %d:\n%s", n, allowed, log)
	}
	if n := strings.Count(log, `"decision":"refused"`); n != refused && !t.Failed() {
		t.Errorf("%d refused decisions logged, want %d:\n%s", n, refused, log)
	}
}

// hostOf returns the Host of a raw head.
func hostOf(head string) string {
	if v := parHeaderValues(head, "Host"); len(v) == 1 {
		return v[0]
	}
	return ""
}

// parReq1 is a request with the usual Host for example.com, CRLF line ends,
// and headers given as whole lines.
func parReq1(method, target string, headers ...string) string {
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\nHost: example.com\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// Shorthands for the requests the upstream receives.
var (
	parUpRoot  = parUp{head: parHead("GET", "/", "example.com")}
	parUpPost5 = parUp{head: parHead("POST", "/v1/messages?beta=true", "example.com", "Content-Length: 5"), body: "hello"}
	parUpPostC = parUp{head: parHead("POST", "/v1/messages?beta=true", "example.com", "Transfer-Encoding: chunked"), body: "hello"}
)

const parPost = "POST /v1/messages?beta=true HTTP/1.1\r\nHost: example.com\r\n"

// TestParRequestLine: the request line, its method, target form and version.
func TestParRequestLine(t *testing.T) {
	parRun(t, []parCase{
		{name: "baseline", raw: parReq1("GET", "/"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "HEAD", raw: parReq1("HEAD", "/"), want: []parWant{parAllowed}, heads: []string{"HEAD"},
			up: []parUp{{head: parHead("HEAD", "/", "example.com")}}},
		{name: "HTTP/1.0", raw: "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n", want: []parWant{parRefusal(reasonForm)}},
		{name: "HTTP/1.2", raw: "GET / HTTP/1.2\r\nHost: example.com\r\n\r\n", want: []parWant{parRefusal(reasonForm)}},
		{name: "HTTP/2.0 in a request line", raw: "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(505)}},
		{name: "HTTP/0.9 version", raw: "GET / HTTP/0.9\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(505)}},
		{name: "HTTP/0.9 simple request", raw: "GET /\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "HTTP/2 preface", raw: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", want: []parWant{parRefusal(reasonForm)}},
		{name: "lowercase version", raw: "GET / http/1.1\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "version with a leading zero", raw: "GET / HTTP/01.1\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "version with two minor digits", raw: "GET / HTTP/1.10\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "space after the version", raw: "GET / HTTP/1.1 \r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "two spaces after the method", raw: "GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "tab as a separator", raw: "GET\t/ HTTP/1.1\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "extra field in the request line", raw: "GET / HTTP/1.1 x\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "lowercase method", raw: parReq1("get", "/"), want: []parWant{parRefusal(reasonForm)}},
		{name: "method with a byte outside token", raw: parReq1("G@T", "/"), want: []parWant{parGo(400)}},
		{name: "method TRACE", raw: parReq1("TRACE", "/"), want: []parWant{parRefusal(reasonNoRule)}},
		{name: "unknown method", raw: parReq1("GETX", "/"), want: []parWant{parRefusal(reasonNoRule)}},
		{name: "absolute form of the same host", raw: parReq1("GET", "https://example.com/"), want: []parWant{parRefusal(reasonForm)}},
		{name: "absolute form in http", raw: parReq1("GET", "http://example.com/"), want: []parWant{parRefusal(reasonForm)}},
		{name: "absolute form of another host", raw: parReq1("GET", "https://evil.example/"), want: []parWant{parRefusal(reasonForm)}},
		{name: "absolute form of a host only another rule allows", raw: parReq1("GET", "https://api.example.com/admin"), want: []parWant{parRefusal(reasonForm)}},
		{name: "opaque form", raw: parReq1("GET", "https:example.com/"), want: []parWant{parRefusal(reasonForm)}},
		{name: "asterisk form with GET", raw: parReq1("GET", "*"), want: []parWant{parRefusal(reasonForm)}},
		// Go's server would answer OPTIONS * itself, 200 and unaudited.
		{name: "asterisk form with OPTIONS", raw: parReq1("OPTIONS", "*"), want: []parWant{parRefusal(reasonForm)}},
		{name: "CONNECT in authority form", raw: "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", want: []parWant{parRefusal(reasonForm)}},
		{name: "CONNECT in origin form", raw: parReq1("CONNECT", "/"), want: []parWant{parRefusal(reasonForm)}},
		{name: "authority form with GET", raw: parReq1("GET", "example.com:443"), want: []parWant{parRefusal(reasonForm)}},
		{name: "query without a path", raw: parReq1("GET", "?a=b"), want: []parWant{parGo(400)}},
		{name: "empty target", raw: "GET  HTTP/1.1\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "NUL in the target", raw: parReq1("GET", "/\x00"), want: []parWant{parGo(400)}},
		{name: "tab in the target", raw: parReq1("GET", "/a\tb"), want: []parWant{parGo(400)}},
		{name: "DEL in the target", raw: parReq1("GET", "/a\x7fb"), want: []parWant{parGo(400)}},
		{name: "bare CR ending the request line", raw: "GET / HTTP/1.1\rHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "empty line before the request line", raw: "\r\n" + parReq1("GET", "/"), want: []parWant{parGo(400)}},
		// Bare LF ends lines for Go's server: wireConn refuses it first.
		{name: "bare LF line ends", raw: "GET / HTTP/1.1\nHost: example.com\n\n", want: []parWant{parRefusedAny}},
		{name: "bare LF ending the request line", raw: "GET / HTTP/1.1\nHost: example.com\r\n\r\n", want: []parWant{parRefusedAny}},
		{name: "bare LF ending the header section", raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\n", want: []parWant{parRefusedAny}},
		{name: "request line over the header limit", raw: parReq1("GET", "/raw/"+strings.Repeat("a", 70<<10)), want: []parWant{parGo(431)}},
	})
}

// TestParPath: the path must be canonical; every encoding, dot segment and
// separator another server could read differently is refused.
func TestParPath(t *testing.T) {
	refused := func(name, target string) parCase {
		return parCase{name: name, raw: parReq1("GET", target), want: []parWant{parRefusal(reasonPath)}}
	}
	noRule := func(name, target string) parCase {
		return parCase{name: name, raw: parReq1("GET", target), want: []parWant{parRefusal(reasonNoRule)}}
	}
	allowed := func(name, target string) parCase {
		return parCase{name: name, raw: parReq1("GET", target), want: []parWant{parAllowed}, up: []parUp{{head: parHead("GET", target, "example.com")}}}
	}
	cases := []parCase{
		allowed("exact path", "/v1/models"),
		allowed("one-segment wildcard", "/repos/o/r/contents"),
		allowed("one-segment wildcard with every allowed byte", "/repos/o/r/a-b.c_d~e:f@g"),
		allowed("three dots are a name, not a dot segment", "/repos/o/r/..."),
		allowed("trailing wildcard, several segments", "/raw/a/b/c.txt"),
		allowed("path of 2048 bytes", "/raw/"+strings.Repeat("a", 2043)),
		refused("path of 2049 bytes", "/raw/"+strings.Repeat("a", 2044)),
		refused("empty segment", "/v1//models"),
		refused("leading double slash", "//v1/models"),
		refused("network-path reference", "//evil.example/v1/models"),
		refused("trailing slash", "/v1/models/"),
		refused("trailing slash on a wildcard", "/repos/o/r/"),
		refused("dot segment", "/v1/./models"),
		refused("dot-dot segment", "/v1/../v1/models"),
		refused("trailing dot segment", "/v1/models/."),
		refused("trailing dot-dot segment", "/v1/models/.."),
		refused("dot-dot in a wildcard", "/repos/o/r/.."),
		refused("dot-dot under a trailing wildcard", "/raw/a/../../v1/models"),
		refused("root dot", "/."),
		refused("root dot-dot", "/.."),
		refused("encoded dot-dot", "/v1/%2e%2e/models"),
		refused("encoded dot-dot in capitals", "/v1/%2E%2E/models"),
		refused("half-encoded dot-dot", "/v1/.%2e/models"),
		refused("encoded dot", "/v1/%2e/models"),
		refused("encoded slash", "/v1%2fmodels"),
		refused("encoded slash in capitals", "/v1%2Fmodels"),
		refused("encoded backslash", "/v1%5cmodels"),
		refused("double-encoded dot-dot", "/v1/%252e%252e/models"),
		refused("double-encoded slash", "/v1%252fmodels"),
		refused("overlong UTF-8 dot, encoded", "/v1/%c0%ae%c0%ae/models"),
		refused("overlong UTF-8 slash, encoded", "/v1%c0%afmodels"),
		{name: "IIS unicode escape", raw: parReq1("GET", "/v1/%u002e%u002e/models"), want: []parWant{parGo(400)}},
		refused("encoded unreserved letters", "/%76%31/models"),
		refused("encoded NUL", "/v1/models%00"),
		refused("encoded space", "/v1/models%20"),
		refused("encoded question mark", "/v1/models%3fx=y"),
		refused("encoded number sign", "/v1/models%23x"),
		{name: "lone percent", raw: parReq1("GET", "/v1/%"), want: []parWant{parGo(400)}},
		refused("matrix parameter", "/v1/models;x=y"),
		refused("empty matrix parameter", "/v1/models;"),
		refused("Tomcat dot-dot-semicolon", "/v1/..;/models"),
		refused("semicolon in a wildcard", "/repos/o/r/..;"),
		refused("jsessionid", "/v1/models;jsessionid=x"),
		refused("Envoy dot-dot with a parameter", "/raw/a/..;x=y/b"),
		refused("backslash", `/v1\models`),
		refused("backslash dot-dot", `/raw/a\..\..\v1`),
		refused("raw UTF-8", "/v1/mod\xc3\xa9ls"),
		refused("fullwidth slash", "/v1\xef\xbc\x8fmodels"),
		refused("raw overlong UTF-8 slash", "/v1\xc0\xafmodels"),
		refused("raw Latin-1 byte", "/v1/models\xff"),
		refused("plus", "/v1/a+b"),
		refused("comma", "/v1/a,b"),
		refused("equals", "/v1/a=b"),
		refused("asterisk", "/repos/o/r/*"),
		refused("exclamation mark", "/v1/a!b"),
		refused("dollar", "/v1/a$b"),
		refused("ampersand", "/v1/a&b"),
		refused("apostrophe", "/v1/a'b"),
		refused("parentheses", "/v1/a(b)"),
		refused("double quote", `/v1/a"b`),
		refused("angle brackets", "/v1/<a>"),
		refused("braces", "/v1/{a}"),
		refused("pipe", "/v1/a|b"),
		refused("caret", "/v1/a^b"),
		refused("backquote", "/v1/a`b"),
		refused("square brackets", "/v1/[a]"),
		noRule("other letter case", "/V1/models"),
		noRule("trailing dot in a name", "/v1/models."),
		noRule("trailing tilde in a name", "/v1/models~"),
		noRule("two segments for a one-segment wildcard", "/repos/o/r/a/b"),
		noRule("no segment for a trailing wildcard", "/raw"),
		noRule("at sign first", "/@evil.example/v1/models"),
		{name: "fragment", raw: parReq1("GET", "/v1/models#x"), want: []parWant{parRefusal(reasonForm)}},
		{name: "invalid escape", raw: parReq1("GET", "/v1/%zz"), want: []parWant{parGo(400)}},
	}
	parRun(t, cases)
}

// TestParQuery: the query is name=value pairs, matched exactly or by the
// strict check, and forwarded as the same bytes.
func TestParQuery(t *testing.T) {
	refused := func(name, query string) parCase {
		return parCase{name: name, raw: parReq1("GET", "/v1/models?"+query), want: []parWant{parRefusal(reasonQuery)}}
	}
	allowed := func(name, query string) parCase {
		return parCase{name: name, raw: parReq1("GET", "/v1/models?"+query), want: []parWant{parAllowed},
			up: []parUp{{head: parHead("GET", "/v1/models?"+query, "example.com")}}}
	}
	post := func(name, query string, want parWant) parCase {
		c := parCase{name: name, raw: "POST /v1/messages?" + query + " HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello", want: []parWant{want}}
		if want.status == 200 {
			c.up = []parUp{parUpPost5}
		}
		return c
	}
	parRun(t, []parCase{
		post("the exact query of a rule", "beta=true", parAllowed),
		post("the exact query, encoded", "beta=%74rue", parRefusal(reasonNoRule)),
		post("the exact query in capitals", "beta=TRUE", parRefusal(reasonNoRule)),
		post("the exact query and another pair", "beta=true&x=y", parRefusal(reasonNoRule)),
		post("the exact query twice", "beta=true&beta=true", parRefusal(reasonNoRule)),
		post("the exact query with another value after", "beta=true&beta=false", parRefusal(reasonNoRule)),
		post("the exact name in capitals", "Beta=true", parRefusal(reasonNoRule)),
		{name: "no query where a rule wants one", raw: "POST /v1/messages HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello", want: []parWant{parRefusal(reasonNoRule)}},
		allowed("one pair", "a=b"),
		allowed("empty value", "a="),
		allowed("several pairs", "a=b&c=d&e=f"),
		allowed("unreserved bytes", "a-b.c_d~e=F-G.H_I~J0"),
		allowed("encoded slash, forwarded encoded", "path=a%2Fb"),
		allowed("encoded separators, forwarded encoded", "a=b%26c%3Dd"),
		allowed("query of 2048 bytes", "a="+strings.Repeat("b", 2046)),
		// Bytes above 0x7f escaped: the spec's "printable" is read here as
		// what a search query in UTF-8 needs; see the report.
		allowed("escaped UTF-8", "q=%C3%A9"),
		refused("query of 2049 bytes", "a="+strings.Repeat("b", 2047)),
		refused("empty query", ""),
		refused("name without value", "a"),
		refused("empty name", "=b"),
		refused("trailing ampersand", "a=b&"),
		refused("empty pair", "a=b&&c=d"),
		refused("two equals signs", "a==b"),
		refused("semicolon separator", "a=b;c=d"),
		refused("plus", "a=b+c"),
		refused("slash", "a=b/c"),
		refused("colon", "a=b:c"),
		refused("at sign", "a=b@c"),
		refused("question mark", "a=b?c=d"),
		refused("comma", "a=b,c"),
		refused("asterisk", "a=*"),
		refused("invalid escape", "a=%zz"),
		refused("truncated escape", "a=%2"),
		refused("lone percent", "a=%"),
		refused("encoded NUL", "a=%00"),
		refused("encoded CRLF", "a=%0d%0a"),
		refused("encoded tab", "a=%09"),
		// DEL is a control byte.
		refused("encoded DEL", "a=%7F"),
		refused("raw UTF-8", "a=\xc3\xa9"),
		{name: "fragment after the query", raw: parReq1("GET", "/v1/models?a=b#c"), want: []parWant{parRefusal(reasonForm)}},
	})
}

// TestParHost: the Host header must be exactly the TLS server name.
func TestParHost(t *testing.T) {
	get := func(name, host string, want parWant) parCase {
		c := parCase{name: name, raw: "GET / HTTP/1.1\r\nHost:" + host + "\r\n\r\n", want: []parWant{want}}
		if want.status == 200 {
			c.up = []parUp{parUpRoot}
		}
		return c
	}
	parRun(t, []parCase{
		get("the server name", " example.com", parAllowed),
		get("port 443", " example.com:443", parAllowed),
		get("no space", "example.com", parAllowed),
		get("spaces around", "   example.com   ", parAllowed),
		get("port 80", " example.com:80", parRefusal(reasonHost)),
		get("port 8443", " example.com:8443", parRefusal(reasonHost)),
		get("empty port", " example.com:", parRefusal(reasonHost)),
		get("port 443 with a leading zero", " example.com:0443", parRefusal(reasonHost)),
		get("port 443 twice", " example.com:443:443", parRefusal(reasonHost)),
		get("port alone", " :443", parRefusal(reasonHost)),
		get("capitals", " EXAMPLE.COM", parRefusal(reasonHost)),
		get("one capital", " Example.com", parRefusal(reasonHost)),
		get("trailing dot", " example.com.", parRefusal(reasonHost)),
		get("trailing dot and port", " example.com.:443", parRefusal(reasonHost)),
		get("userinfo", " user@example.com", parGo(400)),
		get("userinfo naming another host", " example.com@evil.example", parGo(400)),
		get("IPv6 loopback", " [::1]", parRefusal(reasonHost)),
		get("IPv4 loopback", " 127.0.0.1", parRefusal(reasonHost)),
		get("the proxy's address", " 10.9.8.7", parRefusal(reasonHost)),
		get("metadata address", " 169.254.169.254", parRefusal(reasonHost)),
		get("two hosts with a comma", " example.com,evil.example", parRefusal(reasonHost)),
		get("two hosts with a space", " example.com evil.example", parGo(400)),
		get("empty", " ", parRefusal(reasonHost)),
		get("encoded dot", " example%2ecom", parRefusal(reasonHost)),
		get("punycode", " xn--exmple-cua.com", parRefusal(reasonHost)),
		get("Cyrillic homograph", " ex\xd0\xb0mple.com", parGo(400)),
		get("another allowed host", " api.example.com", parRefusal(reasonHost)),
		get("a subdomain", " a.example.com", parRefusal(reasonHost)),
		get("a parent", " com", parRefusal(reasonHost)),
		{name: "lowercase header name", raw: "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n", want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "missing", raw: "GET / HTTP/1.1\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "twice the same", raw: "GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "twice, another host second", raw: "GET / HTTP/1.1\r\nHost: example.com\r\nHost: evil.example\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "twice in two cases", raw: "GET / HTTP/1.1\r\nHost: example.com\r\nhost: api.example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "continued on a folded line", raw: "GET / HTTP/1.1\r\nHost: example.com\r\n :443\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "space before the colon", raw: "GET / HTTP/1.1\r\nHost : example.com\r\n\r\n", want: []parWant{parGo(400)}},
		{name: "path of another host's rule", raw: "GET /admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n", want: []parWant{parRefusal(reasonHost)}},
		{name: "another server name, this Host", sni: "api.example.com", raw: parReq1("GET", "/"), want: []parWant{parRefusal(reasonHost)}},
		{name: "the second host on its own name", sni: "api.example.com", raw: "GET /admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			want: []parWant{parAllowed}, up: []parUp{{head: parHead("GET", "/admin", "api.example.com")}}},
		{name: "X-Forwarded-Host is never forwarded", raw: parReq1("GET", "/", "X-Forwarded-Host: evil.example"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "Forwarded is never forwarded", raw: parReq1("GET", "/", "Forwarded: host=evil.example"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "X-Original-URL is never forwarded", raw: parReq1("GET", "/", "X-Original-Url: /admin"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "X-Rewrite-URL is never forwarded", raw: parReq1("GET", "/", "X-Rewrite-Url: /admin"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "X-HTTP-Method-Override is never forwarded", raw: parReq1("GET", "/", "X-Http-Method-Override: DELETE"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "x-middleware-subrequest is never forwarded", raw: parReq1("GET", "/", "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
	})
}

// TestParHeaders: names, values, duplicates and folding.
func TestParHeaders(t *testing.T) {
	models := func(name string, headers []string, want parWant, forwarded ...string) parCase {
		c := parCase{name: name, raw: parReq1("GET", "/v1/models", headers...), want: []parWant{want}}
		if want.status == 200 {
			c.up = []parUp{{head: parHead("GET", "/v1/models", "example.com", forwarded...)}}
		}
		return c
	}
	cases := []parCase{
		models("a listed header is forwarded", []string{"X-Note: a"}, parAllowed, "X-Note: a"),
		models("listed headers are forwarded, in Go's order", []string{"X-Note: a", "Accept: */*"}, parAllowed, "Accept: */*", "X-Note: a"),
		models("an unlisted header is dropped", []string{"X-Secret: s"}, parAllowed),
		models("a name in capitals is the same header", []string{"X-NOTE: a"}, parAllowed, "X-Note: a"),
		models("a name in lowercase is the same header", []string{"x-note: a"}, parAllowed, "X-Note: a"),
		models("spaces around a value are not part of it", []string{"X-Note:    a   "}, parAllowed, "X-Note: a"),
		models("tab inside a value", []string{"X-Note: a\tb"}, parAllowed, "X-Note: a\tb"),
		models("an empty value is not forwarded", []string{"X-Note:"}, parAllowed),
		models("a value of 8 KiB", []string{"X-Note: " + strings.Repeat("v", 8<<10)}, parAllowed, "X-Note: "+strings.Repeat("v", 8<<10)),
		models("a hundred headers", parMany(100), parAllowed),
		models("a thousand headers", parMany(1000), parGo(431)),
		models("twice", []string{"X-Note: a", "X-Note: a"}, parRefusal(reasonHeader)),
		models("twice in two cases", []string{"X-Note: a", "x-note: b"}, parRefusal(reasonHeader)),
		models("an unlisted header twice", []string{"X-Other: a", "X-OTHER: b"}, parRefusal(reasonHeader)),
		models("Accept twice, as a list would be merged", []string{"Accept: a", "Accept: b"}, parRefusal(reasonHeader)),
		models("credential header twice in two cases", []string{"Authorization: Bearer " + testPlaceholder, "authorization: Bearer " + testPlaceholder}, parRefusal(reasonHeader)),
		models("underscore in a name", []string{"X_Note: a"}, parRefusal(reasonHeader)),
		models("underscore in a credential name", []string{"X-Api_Key: k"}, parRefusal(reasonHeader)),
		models("UTF-8 in a value", []string{"X-Note: \xc3\xa9"}, parRefusal(reasonHeader)),
		models("Latin-1 byte in a value", []string{"X-Note: \xff"}, parRefusal(reasonHeader)),
		models("DEL in a value", []string{"X-Note: a\x7fb"}, parGo(400)),
		models("control byte in a value", []string{"X-Note: a\x01b"}, parGo(400)),
		models("NUL in a value", []string{"X-Note: a\x00b"}, parGo(400)),
		models("bare CR in a value", []string{"X-Note: a\rb"}, parGo(400)),
		models("bare CR then a byte, SPILL.TERM", []string{"X-Note: a\rX-Other: b"}, parGo(400)),
		models("DEL in a name", []string{"X\x7fNote: a"}, parGo(400)),
		models("UTF-8 in a name", []string{"X\xc3\xa9: a"}, parGo(400)),
		models("empty name", []string{": a"}, parGo(400)),
		models("no colon", []string{"X-Note"}, parGo(400)),
		models("space before the colon", []string{"X-Note : a"}, parGo(400)),
		models("tab before the colon", []string{"X-Note\t: a"}, parGo(400)),
		models("space inside a name", []string{"X Note: a"}, parGo(400)),
		{name: "whitespace before the first header", raw: "GET / HTTP/1.1\r\n Host: example.com\r\n\r\n", want: []parWant{parGo(400)}},
		// Go's server would unfold obsolete line folding: wireConn refuses it.
		models("folded value", []string{"X-Note: a", " b"}, parRefusedAny),
		models("folded value with a tab", []string{"X-Note: a", "\tb"}, parRefusedAny),
		models("folded empty first line", []string{"X-Note:", " a"}, parRefusedAny),
		{name: "folded credential, as the placeholder", raw: parReq1("GET", "/auth", "Authorization: Bearer", " "+testPlaceholder), want: []parWant{parRefusedAny}},
		{name: "header section of 70 KiB", raw: parReq1("GET", "/", "X-Pad: "+strings.Repeat("a", 70<<10)), want: []parWant{parGo(431)}},
		// Go's server reads 4 KiB beyond MaxHeaderBytes; wireConn does not.
		{name: "header section of 66 KiB", raw: parReq1("GET", "/", "X-Pad: "+strings.Repeat("a", 66000)), want: []parWant{parGo(431)}},
	}
	// Every byte Go's server takes in a name, as a token, and the proxy
	// refuses.
	for _, b := range "!#$%&'*+.^`|~" {
		cases = append(cases, models("name with "+string(b), []string{"X" + string(b) + "Note: a"}, parRefusal(reasonHeader)))
	}
	parRun(t, cases)
}

// parMany is n distinct headers no rule forwards.
func parMany(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "X-Pad-" + strings.Repeat("a", i/26) + string(rune('a'+i%26)) + ": v"
	}
	return out
}

// TestParConnection: Connection, Upgrade, Expect and the other hop-by-hop
// headers.
func TestParConnection(t *testing.T) {
	root := func(name string, headers []string, want parWant) parCase {
		c := parCase{name: name, raw: parReq1("GET", "/", headers...), want: []parWant{want}}
		if want.status == 200 {
			c.up = []parUp{parUpRoot}
		}
		return c
	}
	post := func(name string, headers []string, want parWant) parCase {
		c := parCase{name: name, raw: parPost + strings.Join(headers, "\r\n") + "\r\nContent-Length: 5\r\n\r\nhello", want: []parWant{want}}
		if want.status == 200 {
			c.up = []parUp{parUpPost5}
		}
		return c
	}
	parRun(t, []parCase{
		root("keep-alive", []string{"Connection: keep-alive"}, parAllowed),
		root("Keep-Alive in capitals", []string{"Connection: Keep-Alive"}, parAllowed),
		{name: "close", raw: parReq1("GET", "/", "Connection: close"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}, closes: true},
		root("naming a listed header", []string{"Connection: X-Note"}, parRefusal(reasonHeader)),
		root("close and a header", []string{"Connection: close, X-Note"}, parRefusal(reasonHeader)),
		root("keep-alive and close", []string{"Connection: keep-alive, close"}, parRefusal(reasonHeader)),
		root("twice", []string{"Connection: keep-alive", "Connection: close"}, parRefusal(reasonHeader)),
		root("naming Upgrade", []string{"Connection: Upgrade"}, parRefusal(reasonHeader)),
		root("naming TE", []string{"Connection: TE"}, parRefusal(reasonHeader)),
		root("naming Host", []string{"Connection: Host"}, parRefusal(reasonHeader)),
		root("naming a credential header", []string{"Connection: Authorization"}, parRefusal(reasonHeader)),
		root("Keep-Alive is not forwarded", []string{"Keep-Alive: timeout=5"}, parAllowed),
		root("Proxy-Connection is not forwarded", []string{"Proxy-Connection: keep-alive"}, parAllowed),
		root("TE is not forwarded", []string{"Te: trailers"}, parAllowed),
		root("HTTP2-Settings alone is not forwarded", []string{"Http2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"}, parAllowed),
		root("h2c upgrade", []string{"Upgrade: h2c", "Connection: Upgrade, HTTP2-Settings", "Http2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"}, parRefusal(reasonForm)),
		root("h2c upgrade without Connection", []string{"Upgrade: h2c"}, parRefusal(reasonForm)),
		root("WebSocket upgrade", []string{"Upgrade: websocket", "Connection: Upgrade", "Sec-Websocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-Websocket-Version: 13"}, parRefusal(reasonForm)),
		root("upgrade to HTTP/2.0", []string{"Upgrade: HTTP/2.0"}, parRefusal(reasonForm)),
		root("empty Upgrade asks for nothing", []string{"Upgrade:"}, parAllowed),
		post("Expect 100-continue", []string{"Expect: 100-continue"}, parRefusal(reasonForm)),
		post("Expect in another case", []string{"Expect: 100-Continue"}, parRefusal(reasonForm)),
		post("obfuscated Expect", []string{"Expect: y 100-continue"}, parRefusal(reasonForm)),
		post("Expect of something else", []string{"Expect: 200-ok"}, parGo(417)),
		post("Expect folded", []string{"Expect:", " 100-continue"}, parRefusal(reasonHeader)),
		post("Expect twice", []string{"Expect: 100-continue", "Expect: 100-continue"}, parRefusal(reasonHeader)),
		post("empty Expect, as git sends", []string{"Expect:"}, parAllowed),
		root("Expect on GET", []string{"Expect: 100-continue"}, parRefusal(reasonForm)),
		root("Trailer declared without a body", []string{"Trailer: X-Note"}, parAllowed),
	})
}

// TestParExpectNoInterim: a refused Expect never makes the proxy send 100
// Continue, which would let the agent send a body the proxy then reads as a
// request.
func TestParExpectNoInterim(t *testing.T) {
	e := parProxy(t, nil)
	ex := e.parSend(t, "example.com", parPost+"Expect: 100-continue\r\nContent-Length: 30\r\n\r\n", 1)
	if strings.Contains(ex.Raw, "100 Continue") || !strings.HasPrefix(ex.Raw, "HTTP/1.1 403") {
		t.Errorf("the agent read %q", ex.Raw)
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("the upstream received %d requests", n)
	}
}

// TestParFraming: Content-Length, Transfer-Encoding and chunked bodies.
func TestParFraming(t *testing.T) {
	post := func(name, headers, body string, want parWant, up ...parUp) parCase {
		return parCase{name: name, raw: parPost + headers + "\r\n" + body, want: []parWant{want}, up: up}
	}
	chunked := "Transfer-Encoding: chunked\r\n"
	cut := parUp{head: parUpPostC.head, partial: true}
	inspect := func(name, body string, want parWant, up ...parUp) parCase {
		return parCase{name: name, raw: "POST /v1/inspect HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + body, want: []parWant{want}, up: up}
	}
	inspected := parUp{head: parHead("POST", "/v1/inspect", "example.com", "Content-Length: 7"), body: `{"a":1}`}
	parRun(t, []parCase{
		post("Content-Length", "Content-Length: 5\r\n", "hello", parAllowed, parUpPost5),
		post("Content-Length with leading zeros", "Content-Length: 005\r\n", "hello", parRefusal(reasonBody)),
		post("Content-Length 0", "Content-Length: 0\r\n", "", parAllowed, parUp{head: parHead("POST", "/v1/messages?beta=true", "example.com", "Content-Length: 0")}),
		post("no framing", "", "", parAllowed, parUp{head: parHead("POST", "/v1/messages?beta=true", "example.com", "Content-Length: 0")}),
		post("chunked", chunked, "5\r\nhello\r\n0\r\n\r\n", parAllowed, parUpPostC),
		post("chunked in several chunks", chunked, "2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n", parAllowed, parUpPostC),
		post("chunk size with leading zeros", chunked, "0005\r\nhello\r\n0000\r\n\r\n", parAllowed, parUpPostC),
		post("chunk size in capitals", chunked, "A\r\nhellohello\r\n0\r\n\r\n", parAllowed,
			parUp{head: parUpPostC.head, body: "hellohello"}),
		post("chunk extension", chunked, "5;ext=1\r\nhello\r\n0\r\n\r\n", parRefusal(reasonBody), parUp{head: parUpPostC.head, partial: true}),
		post("chunked in capitals", "Transfer-Encoding: CHUNKED\r\n", "5\r\nhello\r\n0\r\n\r\n", parRefusal(reasonBody)),
		post("chunked after a tab", "Transfer-Encoding:\tchunked\r\n", "5\r\nhello\r\n0\r\n\r\n", parAllowed, parUpPostC),
		post("Content-Length over the body limit", "Content-Length: 67108865\r\n", "", parWant{status: 413, reason: reasonTooLarge}),
		post("Content-Length with a plus sign", "Content-Length: +5\r\n", "hello", parGo(400)),
		post("negative Content-Length", "Content-Length: -5\r\n", "hello", parGo(400)),
		post("Content-Length list", "Content-Length: 5, 5\r\n", "hello", parGo(400)),
		post("hexadecimal Content-Length", "Content-Length: 0x5\r\n", "hello", parGo(400)),
		post("Content-Length with an exponent", "Content-Length: 5e0\r\n", "hello", parGo(400)),
		post("Content-Length overflowing 64 bits", "Content-Length: 18446744073709551621\r\n", "hello", parGo(400)),
		post("empty Content-Length", "Content-Length:\r\n", "", parGo(400)),
		post("two different Content-Lengths", "Content-Length: 5\r\nContent-Length: 6\r\n", "hello", parGo(400)),
		// Go's server would merge the same Content-Length twice into one.
		post("the same Content-Length twice", "Content-Length: 5\r\nContent-Length: 5\r\n", "hello", parRefusedAny),
		post("the same Content-Length in two cases", "Content-length: 5\r\nContent-Length: 5\r\n", "hello", parRefusedAny),
		// Content-Length and Transfer-Encoding together: Go alone would drop
		// Content-Length and keep the connection open.
		post("Content-Length and chunked", "Content-Length: 5\r\n"+chunked, "5\r\nhello\r\n0\r\n\r\n", parRefusedAny),
		post("chunked and Content-Length", chunked+"Content-Length: 5\r\n", "5\r\nhello\r\n0\r\n\r\n", parRefusedAny),
		// Go alone would read a folded Transfer-Encoding as chunked.
		post("folded Transfer-Encoding", "Transfer-Encoding:\r\n chunked\r\n", "5\r\nhello\r\n0\r\n\r\n", parRefusedAny),
		post("chunked twice in one header", "Transfer-Encoding: chunked, chunked\r\n", "5\r\nhello\r\n0\r\n\r\n", parGo(501)),
		post("chunked in two headers", chunked+chunked, "5\r\nhello\r\n0\r\n\r\n", parGo(501)),
		post("identity", "Transfer-Encoding: identity\r\n", "", parGo(501)),
		post("gzip", "Transfer-Encoding: gzip\r\n", "", parGo(501)),
		post("gzip then chunked", "Transfer-Encoding: gzip, chunked\r\n", "5\r\nhello\r\n0\r\n\r\n", parGo(501)),
		post("chunked then gzip", "Transfer-Encoding: chunked, gzip\r\n", "5\r\nhello\r\n0\r\n\r\n", parGo(501)),
		post("chunked with a parameter", "Transfer-Encoding: chunked;q=1\r\n", "5\r\nhello\r\n0\r\n\r\n", parGo(501)),
		post("a near-chunked coding", "Transfer-Encoding: xchunked\r\n", "5\r\nhello\r\n0\r\n\r\n", parGo(501)),
		post("chunked with a vertical tab", "Transfer-Encoding: \x0bchunked\r\n", "5\r\nhello\r\n0\r\n\r\n", parGo(400)),
		post("Trailer declared on a chunked body", chunked+"Trailer: X-Note\r\n", "5\r\nhello\r\n0\r\nX-Note: a\r\n\r\n", parRefusal(reasonHeader)),
		// Go's server would read an undeclared trailer section and drop it:
		// wireConn cuts the body before its end.
		post("trailer section on a chunked body", chunked, "5\r\nhello\r\n0\r\nX-Note: a\r\n\r\n", parRefusal(reasonBody), cut),
		post("Transfer-Encoding in a trailer", chunked, "5\r\nhello\r\n0\r\nTransfer-Encoding: x\r\n\r\n", parRefusal(reasonBody), cut),
		// Whitespace after a chunk size is not in RFC 9112's grammar.
		post("space after a chunk size", chunked, "5 \r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		// Malformed chunks: the request has been forwarded with its head, so
		// the upstream must never receive a whole body.
		post("bare LF after a chunk size, CVE-2025-22871", chunked, "5\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("bare LF after chunk data", chunked, "5\r\nhello\n0\r\n\r\n", parRefusedAny, cut),
		post("bare CR after chunk data", chunked, "5\r\nhello\r0\r\n\r\n", parRefusedAny, cut),
		post("chunk data longer than its size, TERM.SPILL", chunked, "5\r\nhelloXX\r\n0\r\n\r\n", parRefusedAny, cut),
		post("chunk data shorter than its size", chunked, "6\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("bare LF in a chunk extension, TERM.EXT", chunked, "5;\nxx\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("control byte in a chunk extension, EXT.TERM", chunked, "5;a\x01b\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("quoted CRLF in a chunk extension", chunked, "5;a=\"\r\n\"\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("hexadecimal prefix in a chunk size", chunked, "0x5\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("negative chunk size", chunked, "-5\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("chunk size overflowing 64 bits", chunked, "10000000000000005\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("empty chunk size", chunked, "\r\nhello\r\n0\r\n\r\n", parRefusedAny, cut),
		post("chunked body ended by an empty line, go#64517", chunked, "5\r\nhello\r\n\r\n", parRefusedAny, cut),
		inspect("inspected chunked body, forwarded with its length", "7\r\n{\"a\":1}\r\n0\r\n\r\n", parAllowed, inspected),
		inspect("inspected chunked body, malformed", "7\n{\"a\":1}\r\n0\r\n\r\n", parRefusal(reasonBody)),
		// As above, a trailer section on an inspected body.
		inspect("inspected chunked body with a trailer section", "7\r\n{\"a\":1}\r\n0\r\nX-Note: a\r\n\r\n", parRefusedAny),
		{name: "Content-Length on GET", raw: parReq1("GET", "/", "Content-Length: 5") + "hello", want: []parWant{parRefusal(reasonBody)}},
		{name: "Content-Length 0 on GET", raw: parReq1("GET", "/", "Content-Length: 0"), want: []parWant{parAllowed}, up: []parUp{parUpRoot}},
		{name: "chunked on GET, TE.0", raw: parReq1("GET", "/", "Transfer-Encoding: chunked") + "0\r\n\r\n", want: []parWant{parRefusal(reasonBody)}},
		{name: "Content-Length on HEAD", raw: parReq1("HEAD", "/", "Content-Length: 1") + "X", want: []parWant{parRefusal(reasonBody)}, heads: []string{"HEAD"}},
		{name: "chunked on HEAD", raw: parReq1("HEAD", "/", "Transfer-Encoding: chunked") + "0\r\n\r\n", want: []parWant{parRefusal(reasonBody)}, heads: []string{"HEAD"}},
		{name: "body on DELETE", raw: parReq1("DELETE", "/item", "Content-Length: 5") + "hello", want: []parWant{parAllowed},
			up: []parUp{{head: parHead("DELETE", "/item", "example.com", "Content-Length: 5"), body: "hello"}}},
		{name: "PUT without a body", raw: parReq1("PUT", "/upload"), want: []parWant{parAllowed},
			up: []parUp{{head: parHead("PUT", "/upload", "example.com", "Content-Length: 0")}}},
	})
}

// TestParParseRefusalsAudited: the spec logs one line per decision,
// parse-level refusals included. Go's server refuses some requests before
// the proxy sees them.
func TestParParseRefusalsAudited(t *testing.T) {
	for name, raw := range map[string]string{
		"space before a colon":     parReq1("GET", "/", "X-Note : a"),
		"two Host headers":         "GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
		"unknown coding":           parPost + "Transfer-Encoding: gzip\r\n\r\n",
		"header section too large": parReq1("GET", "/", "X-Pad: "+strings.Repeat("a", 70<<10)),
	} {
		t.Run(name, func(t *testing.T) {
			e := parProxy(t, nil)
			ex := e.parSend(t, "example.com", raw, 1)
			if ex.Resps[0].Status < 400 {
				t.Fatalf("answer %v", ex.Resps[0])
			}
			// One audit line, as for any refusal.
			if !strings.Contains(e.log.String(), `"decision":"refused"`) {
				t.Errorf("a refusal by Go's server left no audit line; the agent read %v", ex.Resps[0])
			}
		})
	}
}
