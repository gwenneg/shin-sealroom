package egress

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// creHeaderRules are a model endpoint that adds the user's bearer token, one
// that adds an API key, a read that adds nothing, and an upload whose body
// is not inspected. X-Note stands for any header a rule forwards.
func creHeaderRules() (Secrets, []Rule) {
	secrets := Secrets{Values: map[string]string{"claude": creSecret, "github": creGitHubSecret}}
	return secrets, []Rule{
		{Method: "POST", Host: "example.com", Path: "/v1/messages", Query: AnyQuery, Headers: []string{"Content-Type", "User-Agent", "X-Note"},
			Credential: &Credential{Secret: "claude", Header: "Authorization", Scheme: "Bearer"}},
		{Method: "POST", Host: "example.com", Path: "/v1/key", Headers: []string{"Content-Type"},
			Credential: &Credential{Secret: "claude", Header: "X-Api-Key"}},
		{Method: "GET", Host: "example.com", Path: "/repos/**", Query: AnyQuery, Headers: []string{"Accept", "User-Agent", "X-Note"}},
		{Method: "POST", Host: "example.com", Path: "/upload", Headers: []string{"Content-Type"}},
	}
}

// creRawPost is a model request as Go's parser reads it, with extra raw
// header lines.
func creRawPost(lines ...string) func(t *testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		raw := "POST /v1/messages HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
		for _, l := range lines {
			raw += l + "\r\n"
		}
		return creRaw(t, "example.com", raw+"\r\n{}")
	}
}

func creB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestCreHeaderForms: every form of a credential header but the placeholder
// exactly as Claude Code and the GitHub CLI send it refuses the request, in
// any letter case of the name, any scheme, any spacing, and any mix with
// the placeholder. Each request goes through Go's own parser first.
func TestCreHeaderForms(t *testing.T) {
	const ph = testPlaceholder
	secrets, rules := creHeaderRules()
	userBearer := creHeaderIs("Authorization", "Bearer "+creSecret)
	for _, c := range []creCase{
		{name: "CRE-001 the placeholder as Claude Code sends it", req: creRawPost("Authorization: Bearer " + ph), want: creForwarded, check: userBearer},
		{name: "CRE-001 the placeholder as the GitHub CLI sends it", req: creRawPost("Authorization: token " + ph), want: creForwarded, check: userBearer},
		{name: "CRE-001 the placeholder as an API key", req: creRawPost("X-Api-Key: " + ph), want: creForwarded, check: func(t *testing.T, s *creSeen) {
			userBearer(t, s)
			creNoHeader("X-Api-Key")(t, s)
		}},
		{name: "CRE-002 the attacker's key in a lowercase name", req: creRawPost("authorization: Bearer sk-ant-oat01-attacker"), want: reasonCred},
		{name: "CRE-002 the attacker's key in a capital name", req: creRawPost("AUTHORIZATION: Bearer sk-ant-oat01-attacker"), want: reasonCred},
		{name: "CRE-002 the attacker's key in a mixed-case X-Api-Key", req: creRawPost("x-API-kEy: sk-ant-api03-attacker"), want: reasonCred},
		{name: "CRE-003 a lowercase scheme", req: creRawPost("Authorization: bearer " + ph), want: reasonCred},
		{name: "CRE-003 a capital scheme", req: creRawPost("Authorization: BEARER " + ph), want: reasonCred},
		{name: "CRE-003 Token with a capital", req: creRawPost("Authorization: Token " + ph), want: reasonCred},
		{name: "CRE-003 the placeholder in capitals", req: creRawPost("Authorization: Bearer " + strings.ToUpper(ph)), want: reasonCred},
		{name: "CRE-004 two spaces after the scheme", req: creRawPost("Authorization: Bearer  " + ph), want: reasonCred},
		{name: "CRE-004 a tab after the scheme", req: creRawPost("Authorization: Bearer\t" + ph), want: reasonCred},
		{name: "CRE-004 no space after the scheme", req: creRawPost("Authorization: Bearer" + ph), want: reasonCred},
		{name: "CRE-004 a scheme and no token", req: creRawPost("Authorization: Bearer"), want: reasonCred},
		{name: "CRE-004 an empty value", req: creRawPost("Authorization: "), want: reasonCred},
		// Go's parser trims the spaces and tabs around a value: what remains
		// is exactly the placeholder, dropped, so nothing of the agent's
		// passes.
		{name: "CRE-005 spaces before the value, trimmed by the parser", req: creRawPost("Authorization:    Bearer " + ph), want: creForwarded, check: userBearer},
		{name: "CRE-005 a tab after the value, trimmed by the parser", req: creRawPost("Authorization: Bearer " + ph + "\t"), want: creForwarded, check: userBearer},
		{name: "CRE-006 a second scheme after a comma", req: creRawPost("Authorization: Bearer " + ph + ", Bearer sk-ant-oat01-attacker"), want: reasonCred},
		{name: "CRE-006 a second token after a space", req: creRawPost("Authorization: Bearer " + ph + " sk-ant-oat01-attacker"), want: reasonCred},
		{name: "CRE-006 the placeholder with a suffix", req: creRawPost("Authorization: Bearer " + ph + ".sk-ant-oat01-attacker"), want: reasonCred},
		{name: "CRE-006 the placeholder with a prefix", req: creRawPost("Authorization: Bearer sk-ant-oat01-attacker" + ph), want: reasonCred},
		{name: "CRE-006 the placeholder twice", req: creRawPost("Authorization: Bearer " + ph + ph), want: reasonCred},
		{name: "CRE-007 Basic with the attacker's GitHub token", req: creRawPost("Authorization: Basic " + creB64("x-access-token:ghp_attacker")), want: reasonCred},
		{name: "CRE-007 Basic with the placeholder", req: creRawPost("Authorization: Basic " + creB64("x-access-token:"+ph)), want: reasonCred},
		{name: "CRE-007 Digest", req: creRawPost(`Authorization: Digest username="a", realm="r", nonce="n", uri="/", response="0"`), want: reasonCred},
		{name: "CRE-007 Negotiate", req: creRawPost("Authorization: Negotiate YIIBhgYGKwYBBQUCoIIBejCCAXag"), want: reasonCred},
		{name: "CRE-007 AWS SigV4", req: creRawPost("Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261001/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0"), want: reasonCred},
		{name: "CRE-008 two Authorization headers", req: creRawPost("Authorization: Bearer "+ph, "Authorization: Bearer sk-ant-oat01-attacker"), want: reasonHeader},
		{name: "CRE-008 the same name in two cases", req: creRawPost("Authorization: Bearer "+ph, "authorization: Bearer sk-ant-oat01-attacker"), want: reasonHeader},
		{name: "CRE-008 the placeholder and the attacker's API key", req: creRawPost("Authorization: Bearer "+ph, "X-Api-Key: sk-ant-api03-attacker"), want: reasonCred},
		{name: "CRE-008 a scheme in X-Api-Key", req: creRawPost("X-Api-Key: Bearer " + ph), want: reasonCred},
		{name: "CRE-009 Proxy-Authorization with the placeholder", req: creRawPost("Proxy-Authorization: Bearer " + ph), want: reasonCred},
		{name: "CRE-009 a claude.ai session cookie", req: creRawPost("Cookie: sessionKey=sk-ant-sid01-attacker"), want: reasonCred},
		{name: "CRE-009 the placeholder as a cookie", req: creRawPost("Cookie: " + ph), want: reasonCred},
		{name: "CRE-009 Private-Token", req: creRawPost("Private-Token: glpat-attacker"), want: reasonCred},
		{name: "CRE-009 X-Goog-Api-Key", req: creRawPost("X-Goog-Api-Key: AIzaSyAttacker"), want: reasonCred},
		{name: "CRE-009 X-Goog-User-Project", req: creRawPost("X-Goog-User-Project: attacker-project"), want: reasonCred},
		{name: "CRE-009 X-Goog-Iam-Authorization-Token", req: creRawPost("X-Goog-Iam-Authorization-Token: attacker"), want: reasonCred},
		{name: "CRE-009 X-Amz-Security-Token", req: creRawPost("X-Amz-Security-Token: attacker"), want: reasonCred},
		{name: "CRE-009 X-Auth-Token", req: creRawPost("X-Auth-Token: attacker"), want: reasonCred},
		{name: "CRE-010 Connection naming Authorization", req: creRawPost("Authorization: Bearer "+ph, "Connection: Authorization"), want: reasonHeader},
		{name: "CRE-010 Connection naming X-Api-Key", req: creRawPost("Connection: close, X-Api-Key"), want: reasonHeader},
	} {
		t.Run(c.name, func(t *testing.T) { creRun(t, c, secrets, rules...) })
	}
}

// TestCreHeaderParser: header lines Go's parser refuses never reach the
// proxy's checks; one it accepts, such as a folded line it joins into one
// value, never turns into a credential the upstream reads.
func TestCreHeaderParser(t *testing.T) {
	for name, line := range map[string]string{
		"CRE-011 a space before the colon":      "Authorization : Bearer sk-ant-oat01-attacker",
		"CRE-011 a tab before the colon":        "Authorization\t: Bearer sk-ant-oat01-attacker",
		"CRE-011 a folded line":                 "X-Note: a\r\n Authorization: Bearer sk-ant-oat01-attacker",
		"CRE-011 a NUL in the name":             "Author\x00ization: Bearer sk-ant-oat01-attacker",
		"CRE-011 a line ending in a bare LF":    "Authorization: Bearer x\nX-Api-Key: sk-ant-api03-attacker",
		"CRE-011 a name with no value or colon": "Authorization",
	} {
		t.Run(name, func(t *testing.T) {
			raw := "POST /v1/messages HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n" + line + "\r\n\r\n{}"
			r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err == nil {
				// Accepted by the parser: then the proxy must refuse it.
				secrets, rules := creHeaderRules()
				p, seen := creProxy(t, secrets, rules...)
				w := creServeRaw(p, r)
				// Accepted, the line cannot have become a credential: either
				// the proxy refuses, or the only credential upstream is the
				// one it adds.
				if seen.hits != 0 {
					if got := seen.header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+creSecret || seen.header.Get("X-Api-Key") != "" {
						t.Errorf("the parser accepted %q, and the upstream received Authorization %q (%d %q)", line, got, w.Code, w.Body.String())
					}
				}
			}
		})
	}
}

// TestCreSecretPlacement: the placeholder anywhere but a credential header,
// or one of the user's real secrets anywhere in the head of the request,
// refuses it.
func TestCreSecretPlacement(t *testing.T) {
	const ph = testPlaceholder
	secrets, rules := creHeaderRules()
	model := func(set func(r *http.Request)) func(t *testing.T) *http.Request {
		return creWith("POST", "https://example.com/v1/messages", "{}", set)
	}
	for _, c := range []creCase{
		{name: "CRE-012 the placeholder in a forwarded header", req: model(creHeader("X-Note", ph)), want: reasonCred},
		{name: "CRE-012 the placeholder inside a forwarded header", req: model(creHeader("User-Agent", "claude-cli/2.1 ("+ph+")")), want: reasonCred},
		{name: "CRE-012 the placeholder in a header no rule forwards", req: model(creHeader("X-Unlisted", ph)), want: reasonCred},
		{name: "CRE-013 the user's Claude credential in a forwarded header", req: model(creHeader("User-Agent", creSecret)), want: reasonCred},
		{name: "CRE-013 the user's GitHub token in a header no rule forwards", req: model(creHeader("X-Unlisted", "token "+creGitHubSecret)), want: reasonCred},
		{name: "CRE-013 the user's Claude credential as the attacker's key", req: model(creHeader("X-Api-Key", creSecret)), want: reasonCred},
		{name: "CRE-013 the user's GitHub token in Authorization", req: creTarget("GET", "example.com", "/repos/o/r", creHeader("Authorization", "token "+creGitHubSecret)), want: reasonCred},
		{name: "CRE-014 the placeholder as a path segment", req: creTarget("GET", "example.com", "/repos/"+ph+"/r", nil), want: reasonCred},
		{name: "CRE-014 the placeholder inside a path segment", req: creTarget("GET", "example.com", "/repos/o/x"+ph+"x", nil), want: reasonCred},
		{name: "CRE-014 the placeholder as a query name", req: creTarget("GET", "example.com", "/repos/o/r?"+ph+"=1", nil), want: reasonCred},
		{name: "CRE-015 the user's GitHub token as a path segment", req: creTarget("GET", "example.com", "/repos/"+creGitHubSecret+"/r", nil), want: reasonCred},
		{name: "CRE-015 the user's Claude credential in the query", req: creTarget("GET", "example.com", "/repos/o/r?q="+creSecret, nil), want: reasonCred},
		{name: "CRE-015 the user's GitHub token as access_token", req: creTarget("GET", "example.com", "/repos/o/r?access_token="+creGitHubSecret, nil), want: reasonCred},
		{name: "CRE-016 the base64 of a secret in a forwarded header", req: model(creHeader("X-Note", creB64(creSecret))), want: creForwarded,
			limit: "an encoding of a secret cannot be recognized in general; the agent never holds a real secret, so it has none to encode"},
		{name: "CRE-016 a secret reversed in a forwarded header", req: model(creHeader("X-Note", creReverse(creSecret))), want: creForwarded,
			limit: "an encoding of a secret cannot be recognized in general; the agent never holds a real secret, so it has none to encode"},
		{name: "CRE-016 a credential of the agent's own in a forwarded header", req: model(creHeader("X-Note", "Bearer sk-ant-oat01-attacker")), want: creForwarded,
			limit: "a rule's forwarded headers are chosen because the service reads no credential in them; the proxy cannot recognize every token format"},
		{name: "CRE-017 a secret in a body that is not inspected", req: creWith("POST", "https://example.com/upload", creSecret, nil), want: creForwarded,
			limit: "bodies pass untouched; the agent never holds a real secret to put in one"},
		{name: "CRE-017 a secret in a Messages API body", req: model(func(r *http.Request) {
			b := `{"messages":[{"role":"user","content":"` + creSecret + `"}]}`
			r.Body, r.ContentLength = creBody(b), int64(len(b))
		}), want: creForwarded, limit: "what the model sees reaches the user's own account, as the threat model says"},
	} {
		t.Run(c.name, func(t *testing.T) { creRun(t, c, secrets, rules...) })
	}
}

// TestCreEncodedSecretInQuery: the query may hold percent-escapes, which the
// upstream decodes, so the proxy looks for the placeholder and the
// user's secrets in the decoded query as well as the raw target. An escaped secret is still the
// secret to the service that reads it, so the decoded query is searched too.
func TestCreEncodedSecretInQuery(t *testing.T) {
	secrets, rules := creHeaderRules()
	for _, c := range []creCase{
		{name: "CRE-018 the user's GitHub token with one byte escaped", req: creTarget("GET", "example.com", "/repos/o/r?q=%67"+creGitHubSecret[1:], nil), want: reasonCred},
		{name: "CRE-018 the user's Claude credential fully escaped", req: creTarget("GET", "example.com", "/repos/o/r?q="+creEscapeAll(creSecret), nil), want: reasonCred},
		{name: "CRE-018 the placeholder with one byte escaped", req: creTarget("GET", "example.com", "/repos/o/r?q=%73"+testPlaceholder[1:], nil), want: reasonCred},
	} {
		t.Run(c.name, func(t *testing.T) { creRun(t, c, secrets, rules...) })
	}
}

// TestCreOnlyTheProxysCredential: the upstream receives the rule's
// credential, set by the proxy, and nothing the agent sent in its place;
// headers that change a request's meaning at the service are dropped.
func TestCreOnlyTheProxysCredential(t *testing.T) {
	const ph = testPlaceholder
	secrets, rules := creHeaderRules()
	for _, c := range []creCase{
		{name: "CRE-019 a bearer placeholder on an API key rule", req: creWith("POST", "https://example.com/v1/key", "{}", creHeader("Authorization", "Bearer "+ph)),
			want: creForwarded, check: func(t *testing.T, s *creSeen) {
				creHeaderIs("X-Api-Key", creSecret)(t, s)
				creNoHeader("Authorization")(t, s)
			}},
		{name: "CRE-019 the placeholder on a rule with no credential", req: creTarget("GET", "example.com", "/repos/o/r", func(r *http.Request) {
			r.Header.Set("Authorization", "token "+ph)
			r.Header.Set("X-Api-Key", ph)
		}), want: creForwarded, check: creNoHeader("Authorization", "X-Api-Key")},
		{name: "CRE-020 method overrides and forwarding headers", req: creTarget("GET", "example.com", "/repos/o/r", func(r *http.Request) {
			for _, h := range []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"} {
				r.Header.Set(h, "DELETE")
			}
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Original-Url", "X-Rewrite-Url", "Forwarded", "X-Real-Ip"} {
				r.Header.Set(h, "attacker.example")
			}
			r.Header.Set("X-Github-Otp", "123456")
			r.Header.Set("Anthropic-Api-Key", "sk-ant-api03-attacker")
			r.Header.Set("X-Anthropic-Api-Key", "sk-ant-api03-attacker")
		}), want: creForwarded, check: func(t *testing.T, s *creSeen) {
			if s.method != "GET" {
				t.Errorf("the upstream received %s", s.method)
			}
			for name := range s.header {
				switch name {
				case "Accept-Encoding", "User-Agent", "Content-Length":
				default:
					t.Errorf("the upstream received %s", name)
				}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) { creRun(t, c, secrets, rules...) })
	}
}

func creReverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func creEscapeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString("%" + strings.ToUpper(hexByte(s[i])))
	}
	return b.String()
}

func hexByte(c byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[c>>4], digits[c&15]})
}
