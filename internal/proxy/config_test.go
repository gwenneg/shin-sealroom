package proxy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gwenneg/sealroom/internal/sandbox"
)

type parsedRule struct {
	Host    string   `json:"host"`
	Methods []string `json:"methods"`
	Paths   []string `json:"paths"`
}

type parsedSecret struct {
	Source  struct{ Type, Var string } `json:"source"`
	Replace *struct {
		ProxyValue   string   `json:"proxy_value"`
		MatchHeaders []string `json:"match_headers"`
		Require      bool     `json:"require"`
	} `json:"replace"`
	Inject *struct{ Header, Formatter string } `json:"inject"`
	Rules  []parsedRule                        `json:"rules"`
}

type parsedConfig struct {
	DNS        map[string]any `json:"dns"`
	Proxy      map[string]any `json:"proxy"`
	Metrics    map[string]any `json:"metrics"`
	TLS        map[string]any `json:"tls"`
	Transforms []struct {
		Name   string          `json:"name"`
		Config json.RawMessage `json:"config"`
	} `json:"transforms"`
}

func parse(t *testing.T, r Run) (parsedConfig, map[string]any) {
	t.Helper()
	b, err := Config(r)
	if err != nil {
		t.Fatal(err)
	}
	var cfg parsedConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return cfg, raw
}

func transformsNamed(t *testing.T, cfg parsedConfig, name string) []json.RawMessage {
	var out []json.RawMessage
	for _, tr := range cfg.Transforms {
		if tr.Name == name {
			out = append(out, tr.Config)
		}
	}
	return out
}

// TestConfigRules pins what the agent can reach and where the user's
// credentials may be added. It must only ever change together with the
// design and the threat model.
func TestConfigRules(t *testing.T) {
	for _, auth := range []ClaudeAuth{Subscription, APIKey} {
		header, other := "Authorization", "X-Api-Key"
		if auth == APIKey {
			header, other = other, header
		}
		t.Run(header, func(t *testing.T) {
			cfg, raw := parse(t, Run{ProxyIP: "172.30.0.2", Repo: "owner/repo", Claude: auth})

			for key := range raw {
				if !slices.Contains([]string{"dns", "proxy", "metrics", "tls", "transforms"}, key) {
					t.Errorf("unexpected top-level section %q: management, control plane and others stay off", key)
				}
			}
			if _, ok := cfg.Proxy["tunnel_listen"]; ok {
				t.Error("the explicit tunnel listener must stay off")
			}
			if cfg.Metrics["listen"] != "127.0.0.1:9090" {
				t.Errorf("metrics listen on %v, want the proxy's loopback", cfg.Metrics["listen"])
			}

			names := make([]string, len(cfg.Transforms))
			for i, tr := range cfg.Transforms {
				names[i] = tr.Name
			}
			wantOrder := []string{"allowlist", "header_allowlist", "secrets", "header_allowlist"}
			if !slices.Equal(names, wantOrder) {
				t.Fatalf("transforms %v, want %v: GitHub headers are dropped before credentials are added, the model API's after", names, wantOrder)
			}

			var allow struct {
				Domains []string     `json:"domains"`
				CIDRs   []string     `json:"cidrs"`
				Rules   []parsedRule `json:"rules"`
			}
			if err := json.Unmarshal(cfg.Transforms[0].Config, &allow); err != nil {
				t.Fatal(err)
			}
			if len(allow.Domains) > 0 || len(allow.CIDRs) > 0 {
				t.Error("the allowlist must use method and path rules only, never whole domains or address ranges")
			}
			want := map[string]bool{"api.anthropic.com": true, "api.github.com": true, "raw.githubusercontent.com": true, "github.com": true}
			for _, r := range allow.Rules {
				if !want[r.Host] {
					t.Errorf("host %q is allowed", r.Host)
				}
				if len(r.Methods) == 0 || len(r.Paths) == 0 {
					t.Errorf("rule for %s allows every method or every path", r.Host)
				}
				for _, p := range r.Paths {
					if r.Host == "api.anthropic.com" && strings.Contains(p, "files") {
						t.Errorf("the Files API is reachable: %s", p)
					}
					if r.Host == "github.com" && !strings.HasPrefix(p, "/owner/repo") {
						t.Errorf("github.com path %q is outside the run's repository", p)
					}
				}
				if r.Host == "api.github.com" || r.Host == "raw.githubusercontent.com" {
					for _, m := range r.Methods {
						if m != "GET" && m != "HEAD" {
							t.Errorf("%s allows %s", r.Host, m)
						}
					}
				}
			}

			var gh struct {
				Headers []string     `json:"headers"`
				Rules   []parsedRule `json:"rules"`
			}
			if err := json.Unmarshal(cfg.Transforms[1].Config, &gh); err != nil {
				t.Fatal(err)
			}
			for _, h := range gh.Headers {
				if strings.EqualFold(h, "Authorization") || strings.EqualFold(h, "X-Api-Key") || strings.HasPrefix(h, "/") {
					t.Errorf("GitHub keeps the agent's header %q", h)
				}
			}

			var secrets struct {
				Secrets []parsedSecret `json:"secrets"`
			}
			if err := json.Unmarshal(cfg.Transforms[2].Config, &secrets); err != nil {
				t.Fatal(err)
			}
			for _, s := range secrets.Secrets {
				switch s.Source.Var {
				case ClaudeCredentialEnv:
					if s.Replace == nil || !s.Replace.Require || s.Replace.ProxyValue != sandbox.Placeholder {
						t.Error("the Claude credential must replace the placeholder, and require it")
					}
					if s.Replace != nil && !slices.Equal(s.Replace.MatchHeaders, []string{header}) {
						t.Errorf("the Claude credential goes in %v, want %s only", s.Replace.MatchHeaders, header)
					}
					if len(s.Rules) != 1 || s.Rules[0].Host != "api.anthropic.com" {
						t.Errorf("the Claude credential can reach %v", s.Rules)
					}
				case GitHubTokenEnv:
					for _, r := range s.Rules {
						for _, p := range r.Paths {
							if p != "/repos/owner/repo" && !strings.HasPrefix(p, "/repos/owner/repo/") && !strings.HasPrefix(p, "/owner/repo") {
								t.Errorf("the GitHub token is added outside the run's repository: %s%s", r.Host, p)
							}
						}
						if len(r.Paths) == 0 {
							t.Errorf("the GitHub token is added on every path of %s", r.Host)
						}
					}
				default:
					t.Errorf("unexpected secret %q", s.Source.Var)
				}
			}

			var model struct {
				Headers []string     `json:"headers"`
				Rules   []parsedRule `json:"rules"`
			}
			if err := json.Unmarshal(cfg.Transforms[3].Config, &model); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(model.Headers, header) || slices.Contains(model.Headers, other) {
				t.Errorf("the model API keeps %v, want %s and not %s", model.Headers, header, other)
			}
		})
	}
}

func TestValidRepo(t *testing.T) {
	for _, repo := range []string{"owner/repo", "Red-Hat/notifications-gw", "o/a.b_c-d"} {
		if !ValidRepo(repo) {
			t.Errorf("%q refused", repo)
		}
	}
	for _, repo := range []string{"", "owner", "a/b/c", "../x", "o/..", "o/.", "o/r*", "o/r?", " o/r", "o/r\n", "-o/r", "o/r#x", "o/r%2f"} {
		if ValidRepo(repo) {
			t.Errorf("%q accepted", repo)
		}
		if _, err := Config(Run{ProxyIP: "172.30.0.2", Repo: repo}); err == nil {
			t.Errorf("Config accepted %q", repo)
		}
	}
}

func TestEnvFile(t *testing.T) {
	b, err := EnvFile(Env{Claude: "sk-ant-oat-x", GitHub: "ghp_x"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("env file has %d lines, want the two credentials", len(lines))
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "IRON_") || !strings.HasPrefix(l, "SEALROOM_") {
			t.Errorf("env file line %q", l)
		}
	}
	for _, bad := range []string{"", "a\nIRON_MANAGEMENT_LISTEN=:1", "a\rb", "a\x00b"} {
		if _, err := EnvFile(Env{Claude: bad, GitHub: "ghp_x"}); err == nil {
			t.Errorf("credential %q accepted", bad)
		}
	}
}

func TestNewCA(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || !cert.MaxPathLenZero {
		t.Error("the CA must be a CA that cannot sign another CA")
	}
	if cert.NotAfter.After(now.Add(CALifetime)) {
		t.Errorf("the CA is valid until %v, more than %v", cert.NotAfter, CALifetime)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("the CA is not self-signed: %v", err)
	}
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("CA key is %T, want ECDSA", key)
	}
	other, _, _ := NewCA(now)
	if string(other) == string(certPEM) {
		t.Error("two runs got the same CA")
	}
}

// TestConfigRulesVertex pins the rules with Vertex: Claude's models in the
// user's project and region only, a Google token added there only, and no
// Anthropic API at all.
func TestConfigRulesVertex(t *testing.T) {
	cfg, _ := parse(t, Run{ProxyIP: "172.30.0.2", Repo: "owner/repo", Claude: Vertex, VertexProject: "my-project", VertexRegion: "us-east5"})
	names := make([]string, len(cfg.Transforms))
	for i, tr := range cfg.Transforms {
		names[i] = tr.Name
	}
	if want := []string{"allowlist", "header_allowlist", "header_allowlist", "gcp_auth", "secrets"}; !slices.Equal(names, want) {
		t.Fatalf("transforms %v, want %v: headers dropped before the Google token is added", names, want)
	}
	model := parsedRule{
		Host: "us-east5-aiplatform.googleapis.com", Methods: []string{"POST"},
		Paths: []string{"/v1/projects/my-project/locations/us-east5/publishers/anthropic/models/*"},
	}
	var allow struct{ Rules []parsedRule }
	json.Unmarshal(cfg.Transforms[0].Config, &allow)
	found := false
	for _, r := range allow.Rules {
		if r.Host == "api.anthropic.com" {
			t.Error("the Anthropic API is reachable with Vertex")
		}
		if strings.Contains(r.Host, "googleapis.com") {
			found = true
			if r.Host != model.Host || !slices.Equal(r.Methods, model.Methods) || !slices.Equal(r.Paths, model.Paths) {
				t.Errorf("Google rule %+v, want %+v", r, model)
			}
		}
	}
	if !found {
		t.Error("the model on Vertex is not allowed")
	}

	var headers struct {
		Headers []string
		Rules   []parsedRule
	}
	json.Unmarshal(cfg.Transforms[2].Config, &headers)
	if len(headers.Rules) != 1 || headers.Rules[0].Host != model.Host {
		t.Errorf("the model's header rules are %+v", headers.Rules)
	}
	for _, h := range headers.Headers {
		l := strings.ToLower(h)
		if l == "authorization" || l == "x-api-key" || strings.HasPrefix(l, "x-goog") {
			t.Errorf("the agent's %q reaches Google", h)
		}
	}

	var gcp struct {
		CredentialsProvider struct{ Type string } `json:"credentials_provider"`
		Scopes              []string
		Rules               []parsedRule
	}
	json.Unmarshal(cfg.Transforms[3].Config, &gcp)
	if gcp.CredentialsProvider.Type != "workload_identity" {
		t.Errorf("credentials from %q, want the mounted Application Default Credentials", gcp.CredentialsProvider.Type)
	}
	if len(gcp.Rules) != 1 || gcp.Rules[0].Host != model.Host || !slices.Equal(gcp.Rules[0].Paths, model.Paths) {
		t.Errorf("the Google token is added on %+v, want the model's paths alone", gcp.Rules)
	}

	var secrets struct{ Secrets []parsedSecret }
	json.Unmarshal(cfg.Transforms[4].Config, &secrets)
	for _, sec := range secrets.Secrets {
		if sec.Source.Var != GitHubTokenEnv {
			t.Errorf("secret %q with Vertex, want the GitHub token only", sec.Source.Var)
		}
	}

	global, _ := parse(t, Run{ProxyIP: "172.30.0.2", Repo: "owner/repo", Claude: Vertex, VertexProject: "my-project", VertexRegion: "global"})
	json.Unmarshal(global.Transforms[0].Config, &allow)
	if !slices.ContainsFunc(allow.Rules, func(r parsedRule) bool { return r.Host == "aiplatform.googleapis.com" }) {
		t.Error("the global region does not use the global endpoint")
	}
}

func TestValidVertex(t *testing.T) {
	for _, ok := range [][2]string{{"my-project", "us-east5"}, {"rh-ai-123456", "europe-west1"}, {"proj-x1", "global"}} {
		if !ValidVertex(ok[0], ok[1]) {
			t.Errorf("%v refused", ok)
		}
	}
	for _, bad := range [][2]string{{"", "us-east5"}, {"My-Project", "us-east5"}, {"p/../x", "us-east5"}, {"proj*", "us-east5"}, {"my-project", ""}, {"my-project", "us-east5/x"}, {"my-project", "evil.com#"}, {"my-project", "us-east5\n"}} {
		if ValidVertex(bad[0], bad[1]) {
			t.Errorf("%q accepted", bad)
		}
		if _, err := Config(Run{ProxyIP: "172.30.0.2", Repo: "o/r", Claude: Vertex, VertexProject: bad[0], VertexRegion: bad[1]}); err == nil {
			t.Errorf("Config accepted %q", bad)
		}
	}
}

func TestEnvFileVertex(t *testing.T) {
	b, err := EnvFile(Env{Claude: "ignored", GitHub: "ghp_x", Vertex: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); strings.Contains(got, ClaudeCredentialEnv) || !strings.Contains(got, GoogleCredentialsEnv+"="+GoogleCredentialsPath+"\n") {
		t.Errorf("env file %q, want the GitHub token and the path of the Google credentials", got)
	}
}
