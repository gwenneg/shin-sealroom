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
	b, err := EnvFile("sk-ant-oat-x", "ghp_x")
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
		if _, err := EnvFile(bad, "ghp_x"); err == nil {
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
