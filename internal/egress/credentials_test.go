package egress

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const realSecret = "sk-real-secret-0123456789"

// TestCredentialRefusals: anything credential-like but the placeholder, in a
// credential header, refuses the request; so does the placeholder or a real
// secret anywhere else.
func TestCredentialRefusals(t *testing.T) {
	p, _ := upstreamWith(t, true, Secrets{Values: map[string]string{"key": realSecret}},
		func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("a refused request reached upstream: %v", r.Header)
		},
		Rule{Method: "POST", Host: "example.com", Path: "/v1/messages", Query: AnyQuery, Headers: []string{"X-Note"},
			Credential: &Credential{Secret: "key", Header: "X-Api-Key"}})
	for name, set := range map[string]func(r *http.Request){
		"the agent's own key":                  func(r *http.Request) { r.Header.Set("X-Api-Key", "sk-ant-attacker") },
		"the agent's own bearer token":         func(r *http.Request) { r.Header.Set("Authorization", "Bearer sk-ant-oat01-attacker") },
		"the placeholder and another key":      func(r *http.Request) { r.Header.Set("X-Api-Key", testPlaceholder+"x") },
		"a cookie":                             func(r *http.Request) { r.Header.Set("Cookie", "session=1") },
		"a Google API key":                     func(r *http.Request) { r.Header.Set("X-Goog-Api-Key", "AIza-attacker") },
		"another billing project":              func(r *http.Request) { r.Header.Set("X-Goog-User-Project", "attacker") },
		"the placeholder in another header":    func(r *http.Request) { r.Header.Set("X-Note", "copy "+testPlaceholder) },
		"the real secret in a header":          func(r *http.Request) { r.Header.Set("X-Note", realSecret) },
		"the placeholder in the query":         func(r *http.Request) { r.RequestURI = "/v1/messages?k=" + testPlaceholder },
		"the real secret in the query":         func(r *http.Request) { r.RequestURI = "/v1/messages?k=" + realSecret },
		"Basic with the placeholder":           func(r *http.Request) { r.Header.Set("Authorization", "Basic "+testPlaceholder) },
		"the real secret escaped in the query": func(r *http.Request) { r.RequestURI = "/v1/messages?k=%73" + realSecret[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			r := agentRequest("POST", "https://example.com/v1/messages", strings.NewReader("{}"))
			set(r)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), reasonCred) {
				t.Errorf("got %d %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestCredentialSchemes(t *testing.T) {
	for _, c := range []struct {
		scheme, want string
	}{
		{"", realSecret},
		{"Bearer", "Bearer " + realSecret},
		{"token", "token " + realSecret},
		{"basic-x-access-token", "Basic eC1hY2Nlc3MtdG9rZW46c2stcmVhbC1zZWNyZXQtMDEyMzQ1Njc4OQ=="},
	} {
		var got string
		p, _ := upstreamWith(t, true, Secrets{Values: map[string]string{"s": realSecret}},
			func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") },
			Rule{Method: "GET", Host: "example.com", Path: "/", Credential: &Credential{Secret: "s", Header: "Authorization", Scheme: c.scheme}})
		r := agentRequest("GET", "https://example.com/", nil)
		r.Header.Set("Authorization", "token "+testPlaceholder) // as the GitHub CLI sends it
		p.ServeHTTP(httptest.NewRecorder(), r)
		if got != c.want {
			t.Errorf("scheme %q: upstream got %q, want %q", c.scheme, got, c.want)
		}
	}
}

// TestPlaceholderDroppedWithoutCredential: a rule that adds no credential
// still accepts the placeholder the GitHub CLI always sends, and forwards no
// credential at all.
func TestPlaceholderDroppedWithoutCredential(t *testing.T) {
	var got http.Header
	p, _ := upstream(t, func(w http.ResponseWriter, r *http.Request) { got = r.Header },
		Rule{Method: "GET", Host: "example.com", Path: "/repos/**", Query: AnyQuery, Headers: []string{"Accept"}})
	r := agentRequest("GET", "https://example.com/repos/other/repo", nil)
	r.Header.Set("Authorization", "token "+testPlaceholder)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || got.Get("Authorization") != "" {
		t.Errorf("got %d, upstream Authorization %q", w.Code, got.Get("Authorization"))
	}
}

func TestNewRefusesMissingSecrets(t *testing.T) {
	cfg := Config{Placeholder: testPlaceholder, Rules: []Rule{{Method: "GET", Host: "example.com", Path: "/", Credential: &Credential{Secret: "s", Header: "X-Api-Key"}}}}
	if _, err := New(cfg, Secrets{}, io.Discard); err == nil {
		t.Error("a rule with no secret was accepted")
	}
	if _, err := New(cfg, Secrets{Values: map[string]string{"s": "x" + testPlaceholder}}, io.Discard); err == nil {
		t.Error("a secret holding the placeholder was accepted")
	}
	cfg.Rules[0].Credential = &Credential{Secret: Google, Header: "Authorization", Scheme: "Bearer"}
	if _, err := New(cfg, Secrets{}, io.Discard); err == nil {
		t.Error("a Google rule with no Google credentials was accepted")
	}
}

// TestMessages: Anthropic's server-side tools that fetch or run anything,
// MCP servers and content fetched by URL are refused; web search and Claude Code's own tools pass,
// and an allowed body is forwarded as the same bytes.
func TestMessages(t *testing.T) {
	var forwarded string
	p, _ := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
	}, Rule{Method: "POST", Host: "example.com", Path: "/v1/messages", Query: AnyQuery, Headers: []string{"Content-Type"}, InspectMessages: true})
	send := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, agentRequest("POST", "https://example.com/v1/messages?beta=true", strings.NewReader(body)))
		return w
	}
	allowed := `{"model":"m","tools":[{"name":"Bash","input_schema":{}},{"type":"web_search_20250305","name":"web_search"},{"type":"web_search_20260209","name":"web_search","allowed_callers":["direct"]},{"type":"text_editor_20250728","name":"str_replace_based_edit_tool"}],"messages":[{"role":"user","content":"hi"}]}`
	if w := send(allowed); w.Code != 200 || forwarded != allowed {
		t.Errorf("an allowed request: %d, forwarded %q", w.Code, forwarded)
	}
	for name, body := range map[string]string{
		"web fetch":                 `{"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}`,
		"code execution":            `{"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}`,
		"an MCP toolset":            `{"tools":[{"type":"mcp_toolset","mcp_server_name":"x"}]}`,
		"MCP servers":               `{"mcp_servers":[{"type":"url","url":"https://evil.example/mcp"}]}`,
		"tools repeated":            `{"tools":[{"type":"web_fetch_20250910"}],"tools":[]}`,
		"a type repeated in a tool": `{"tools":[{"type":"web_fetch_20250910","type":"web_search_20250305"}]}`,
		"a key repeated deeper":     `{"messages":[{"role":"user","role":"assistant"}]}`,
		"tools hidden by Tools":     `{"tools":[{"type":"web_fetch_20250910"}],"Tools":[]}`,
		"a type hidden by Type":     `{"tools":[{"type":"web_fetch_20250910","Type":"web_search_20250305"}]}`,
		"a tool type not a string":  `{"tools":[{"type":["web_fetch_20250910"]}]}`,
		"not JSON":                  `tools: web_fetch`,
		"two JSON values":           `{} {"tools":[{"type":"web_fetch_20250910"}]}`,
	} {
		if w := send(body); w.Code != http.StatusForbidden {
			t.Errorf("%s: got %d %q", name, w.Code, w.Body.String())
		}
	}
}

// fakeGoogle is a token endpoint that hands out a token, and the proxy's
// client options to reach it as oauth2.googleapis.com.
func fakeGoogle(t *testing.T, tokenRequests *[]string) options {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		*tokenRequests = append(*tokenRequests, r.Host+r.URL.Path+" "+r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json") // as Google's endpoint answers
		json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.minted", "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return options{
		roots: roots,
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
}

func TestGoogleTokens(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	serviceAccount, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com", "private_key": pemKey, "token_uri": googleTokenURL})
	userLogin := []byte(`{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"refresh"}`)

	for name, c := range map[string]struct {
		creds []byte
		grant string
	}{
		"a service account": {serviceAccount, "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"a user login":      {userLogin, "refresh_token"},
	} {
		t.Run(name, func(t *testing.T) {
			var requests []string
			o := fakeGoogle(t, &requests)
			client := upstreamClient(o)
			// The fake endpoint's certificate is for example.com; the real
			// one is reached under its own name.
			client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: o.roots, ServerName: "example.com"}
			ts, err := GoogleTokens(c.creds, client)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			p, _ := upstreamWith(t, true, Secrets{Google: ts}, func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") },
				Rule{Method: "POST", Host: "example.com", Path: "/v1/projects/p/**", Credential: &Credential{Secret: Google, Header: "Authorization", Scheme: "Bearer"}})
			for range 2 {
				p.ServeHTTP(httptest.NewRecorder(), agentRequest("POST", "https://example.com/v1/projects/p/x:streamRawPredict", strings.NewReader("{}")))
			}
			if got != "Bearer ya29.minted" {
				t.Errorf("upstream got %q", got)
			}
			if len(requests) != 1 || !strings.HasSuffix(requests[0], c.grant) || !strings.HasPrefix(requests[0], "oauth2.googleapis.com/token") {
				t.Errorf("token requests %v, want one %s to Google's endpoint, the token reused", requests, c.grant)
			}
		})
	}

	for name, creds := range map[string]string{
		"another kind":             `{"type":"external_account"}`,
		"another token endpoint":   `{"type":"service_account","client_email":"a","private_key":"k","token_uri":"https://evil.example/token"}`,
		"a login without a secret": `{"type":"authorized_user","client_id":"id"}`,
		"not JSON":                 `nope`,
	} {
		if _, err := GoogleTokens([]byte(creds), &http.Client{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
