package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gwenneg/sealroom/internal/egress"
	"github.com/gwenneg/sealroom/internal/sandbox"
)

func rules(t *testing.T, r Run) egress.Config {
	t.Helper()
	b, err := Config(r)
	if err != nil {
		t.Fatal(err)
	}
	var cfg egress.Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestConfigRules pins what the agent can reach and where the user's
// credentials are added. It must only ever change together with the design,
// the threat model and docs/proxy.md.
func TestConfigRules(t *testing.T) {
	for _, auth := range []ClaudeAuth{Subscription, APIKey, Vertex} {
		cfg := rules(t, Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: auth, VertexProject: "my-project", VertexRegion: "us-east5"})
		if cfg.Placeholder != sandbox.Placeholder {
			t.Errorf("placeholder %q", cfg.Placeholder)
		}
		firstAnonymous := -1
		for i, r := range cfg.Rules {
			switch {
			case r.Host == "api.github.com" && r.Method != "GET" && r.Method != "HEAD":
				t.Errorf("a write on the GitHub API: %+v", r)
			case strings.Contains(r.Path, "receive-pack"):
				t.Errorf("a push: %+v", r)
			case r.Host == "api.anthropic.com" && auth == Vertex:
				t.Errorf("the Anthropic API with Vertex: %+v", r)
			case strings.HasSuffix(r.Host, "googleapis.com") && auth != Vertex:
				t.Errorf("Google without Vertex: %+v", r)
			}
			if c := r.Credential; c != nil {
				switch c.Secret {
				case GitHubTokenEnv:
					if !strings.HasPrefix(r.Path, "/repos/owner/repo") && !strings.HasPrefix(r.Path, "/owner/repo") {
						t.Errorf("the GitHub token outside the run's repository: %s %s", r.Host, r.Path)
					}
					if firstAnonymous >= 0 {
						t.Errorf("a rule with the GitHub token after an anonymous one, which would match first: %+v", r)
					}
				case ClaudeCredentialEnv:
					want := egress.Credential{Secret: ClaudeCredentialEnv, Header: "Authorization", Scheme: "Bearer"}
					if auth == APIKey {
						want = egress.Credential{Secret: ClaudeCredentialEnv, Header: "X-Api-Key"}
					}
					if *c != want || r.Host != "api.anthropic.com" {
						t.Errorf("the Claude credential as %+v on %s", c, r.Host)
					}
				case egress.Google:
					if r.Host != "us-east5-aiplatform.googleapis.com" || r.Path != "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models/*" {
						t.Errorf("the Google token on %s %s", r.Host, r.Path)
					}
				default:
					t.Errorf("unknown secret %q", c.Secret)
				}
			} else if r.Host == "api.github.com" && firstAnonymous < 0 {
				firstAnonymous = i
			}
			if r.Path == "/v1/messages" || strings.HasSuffix(r.Path, "/models/*") {
				if !r.InspectMessages {
					t.Errorf("model requests not inspected: %+v", r)
				}
			}
		}
	}
	global := rules(t, Run{ProxyIP: "10.0.0.2", Repo: "o/r", Claude: Vertex, VertexProject: "my-project", VertexRegion: "global"})
	if !slices.ContainsFunc(global.Rules, func(r egress.Rule) bool { return r.Host == "aiplatform.googleapis.com" }) {
		t.Error("the global region does not use the global endpoint")
	}
}

// TestConfigDeclared: what a plugin declares is allowed, and never given a
// credential.
func TestConfigDeclared(t *testing.T) {
	cfg := rules(t, Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Declared: []Allow{
		{Host: "api.example.com", Methods: []string{"GET"}, Paths: []string{"/v1/*"}},
		{Host: "github.com", Methods: []string{"GET", "POST"}, Paths: []string{"/o/v.git/info/refs", "/o/v.git/git-upload-pack"}},
	}})
	found := 0
	for _, r := range cfg.Rules {
		if r.Host == "api.example.com" || strings.HasPrefix(r.Path, "/o/v.git") {
			found++
			if r.Credential != nil {
				t.Errorf("a declared access with a credential: %+v", r)
			}
		}
	}
	if found != 5 {
		t.Errorf("%d declared rules, want 5", found)
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
		if !strings.HasPrefix(l, "SEALROOM_") {
			t.Errorf("env file line %q", l)
		}
	}
	for _, bad := range []string{"", "a\nSEALROOM_EXTRA=1", "a\rb", "a\x00b"} {
		if _, err := EnvFile(Env{Claude: bad, GitHub: "ghp_x"}); err == nil {
			t.Errorf("credential %q accepted", bad)
		}
	}
}

func TestNewCA(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := NewCA(now, []string{"api.example.com"})
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
	other, _, _ := NewCA(now, []string{"api.example.com"})
	if string(other) == string(certPEM) {
		t.Error("two runs got the same CA")
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

// TestCANameConstraints: a certificate the run's CA signs for a name outside
// the run's hosts does not verify, whoever holds the key.
func TestCANameConstraints(t *testing.T) {
	certPEM, keyPEM, err := NewCA(time.Now(), []string{"api.example.com", "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(certPEM)
	ca, _ := x509.ParseCertificate(cb.Bytes)
	kb, _ := pem.Decode(keyPEM)
	key, _ := x509.ParsePKCS8PrivateKey(kb.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, ok := range map[string]bool{"api.example.com": true, "github.com": true, "evil.example": false, "example.com": false} {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name})
		if (err == nil) != ok {
			t.Errorf("%s: verified %v, want %v (%v)", name, err == nil, ok, err)
		}
	}
	if _, _, err := NewCA(time.Now(), nil); err == nil {
		t.Error("a CA for no name was created")
	}
}
