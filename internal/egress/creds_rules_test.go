package egress_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"

	"github.com/gwenneg/sealroom/internal/egress"
	"github.com/gwenneg/sealroom/internal/proxy"
	"github.com/gwenneg/sealroom/internal/sandbox"
)

// The user's credentials in these tests.
const (
	creClaude = "sk-ant-oat01-user-rules-0123456789"
	creGitHub = "ghp_userRulesToken0123456789"
	creGoogle = "ya29.user-minted-token"
)

// creRulesProxy is the proxy with the run's real rules, from proxy.Config,
// every upstream reaching one recording server.
func creRulesProxy(t *testing.T, run proxy.Run) (*egress.Proxy, *creUpstreamSeen) {
	t.Helper()
	b, err := proxy.Config(run)
	if err != nil {
		t.Fatal(err)
	}
	var cfg egress.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	secrets := egress.Secrets{Values: map[string]string{proxy.GitHubTokenEnv: creGitHub}}
	if run.Claude == proxy.Vertex {
		secrets.Google = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: creGoogle, TokenType: "Bearer"})
	} else {
		secrets.Values[proxy.ClaudeCredentialEnv] = creClaude
	}
	seen := &creUpstreamSeen{}
	return egress.CreUpstream(t, cfg, secrets, seen.record), seen
}

type creUpstreamSeen struct {
	mu     sync.Mutex
	hits   int
	host   string
	header http.Header
	body   string
}

func (s *creUpstreamSeen) record(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	s.host, s.header, s.body = r.Host, r.Header.Clone(), string(b)
}

// creRuleCase is a request on the run's real rules and what the upstream
// must receive: the credential headers exactly, "" for none.
type creRuleCase struct {
	name, method, host, target, body string
	header                           map[string]string
	authorization, apiKey            string
	limit                            string
}

func creRunRules(t *testing.T, run proxy.Run, cases []creRuleCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, seen := creRulesProxy(t, run)
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			r := httptest.NewRequest(c.method, "https://"+c.host+"/", body)
			r.RequestURI = c.target
			for k, v := range c.header {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != http.StatusOK || seen.hits != 1 || seen.host != c.host {
				t.Fatalf("want forwarded to %s, got %d %q with %d upstream requests", c.host, w.Code, w.Body.String(), seen.hits)
			}
			if got := seen.header.Values("Authorization"); c.authorization == "" && len(got) != 0 || c.authorization != "" && (len(got) != 1 || got[0] != c.authorization) {
				t.Errorf("the upstream received Authorization %q, want %q", got, c.authorization)
			}
			if got := seen.header.Values("X-Api-Key"); c.apiKey == "" && len(got) != 0 || c.apiKey != "" && (len(got) != 1 || got[0] != c.apiKey) {
				t.Errorf("the upstream received X-Api-Key %q, want %q", got, c.apiKey)
			}
			for name := range seen.header {
				if strings.HasPrefix(name, "X-Goog") || strings.Contains(name, "Override") || name == "Cookie" {
					t.Errorf("the upstream received %s", name)
				}
			}
			if c.body != "" && seen.body != c.body {
				t.Errorf("the body was changed: %q", seen.body)
			}
			if c.limit != "" {
				t.Logf("documented limit: %s", c.limit)
			}
		})
	}
}

// TestCreRulesGitHubToken: the user's GitHub token reaches only the run's
// repository, by its exact path. GitHub reads owner and repository names
// in any letter case, so a case variant is the same repository to GitHub:
// it must be read anonymously, never with the token, and that holds for
// every near name of the repository.
func TestCreRulesGitHubToken(t *testing.T) {
	ph := sandbox.Placeholder
	bearer := "Bearer " + creGitHub
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+creGitHub))
	gh := map[string]string{"Authorization": "token " + ph, "X-Http-Method-Override": "DELETE"}
	git := map[string]string{"Git-Protocol": "version=2", "Content-Type": "application/x-git-upload-pack-request"}
	creRunRules(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo"}, []creRuleCase{
		{name: "CRE-044 the run's repository", method: "GET", host: "api.github.com", target: "/repos/owner/repo", header: gh, authorization: bearer},
		{name: "CRE-044 a read under the run's repository", method: "GET", host: "api.github.com", target: "/repos/owner/repo/contents/README.md?ref=main", header: gh, authorization: bearer},
		{name: "CRE-044 HEAD on the run's repository", method: "HEAD", host: "api.github.com", target: "/repos/owner/repo/branches", header: gh, authorization: bearer},
		{name: "CRE-045 the owner in capitals", method: "GET", host: "api.github.com", target: "/repos/OWNER/repo/contents", header: gh},
		{name: "CRE-045 the repository in capitals", method: "GET", host: "api.github.com", target: "/repos/owner/REPO/contents", header: gh},
		{name: "CRE-045 both in mixed case", method: "GET", host: "api.github.com", target: "/repos/Owner/Repo", header: gh},
		{name: "CRE-045 the .git suffix", method: "GET", host: "api.github.com", target: "/repos/owner/repo.git/contents", header: gh},
		{name: "CRE-045 a longer repository name", method: "GET", host: "api.github.com", target: "/repos/owner/repo2/contents", header: gh},
		{name: "CRE-045 a repository of the same name elsewhere", method: "GET", host: "api.github.com", target: "/repos/attacker/repo/contents", header: gh},
		{name: "CRE-045 the owner alone", method: "GET", host: "api.github.com", target: "/repos/owner", header: gh},
		{name: "CRE-045 the API root", method: "GET", host: "api.github.com", target: "/", header: gh},
		{name: "CRE-046 a compare across forks", method: "GET", host: "api.github.com", target: "/repos/owner/repo/compare/main...attacker:repo:main", header: gh, authorization: bearer,
			limit: "a read under the run's repository may name a fork of the same network; it reads, with the user's token, what the user can read, and writes nothing"},
		{name: "CRE-046 the agent's own token in the query of an anonymous read", method: "GET", host: "api.github.com", target: "/repos/attacker/repo?access_token=ghp_attacker", header: gh,
			limit: "GitHub no longer accepts a token in the query string, and the proxy cannot recognize every token format in a query"},
		{name: "CRE-047 a fetch of the run's repository", method: "GET", host: "github.com", target: "/owner/repo/info/refs?service=git-upload-pack", header: git, authorization: basic},
		{name: "CRE-047 a fetch of the run's repository with .git", method: "POST", host: "github.com", target: "/owner/repo.git/git-upload-pack", body: "0014command=ls-refs\n0000", header: git, authorization: basic},
		{name: "CRE-048 raw content of the run's repository", method: "GET", host: "raw.githubusercontent.com", target: "/owner/repo/main/README.md", header: gh},
		{name: "CRE-048 raw content carrying data in its path", method: "GET", host: "raw.githubusercontent.com", target: "/attacker/repo/main/c2VjcmV0LWNvZGU", header: gh,
			limit: "an anonymous read's path is the agent's choice; Sealroom relies on GitHub not showing raw reads to the content's owner"},
	})
}

// TestCreRulesClaudeCredential: the user's Claude credential is added in its
// one header, and nothing the agent sends in either credential header
// reaches Anthropic.
func TestCreRulesClaudeCredential(t *testing.T) {
	ph := sandbox.Placeholder
	body := `{"model":"claude-x","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	both := map[string]string{"Authorization": "Bearer " + ph, "X-Api-Key": ph, "Content-Type": "application/json", "Anthropic-Beta": "oauth-2025-04-20"}
	creRunRules(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: proxy.Subscription}, []creRuleCase{
		{name: "CRE-049 a subscription token", method: "POST", host: "api.anthropic.com", target: "/v1/messages?beta=true", body: body, header: both, authorization: "Bearer " + creClaude},
		{name: "CRE-049 a subscription token on count_tokens", method: "POST", host: "api.anthropic.com", target: "/v1/messages/count_tokens?beta=true", body: body, header: both, authorization: "Bearer " + creClaude},
	})
	creRunRules(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: proxy.APIKey}, []creRuleCase{
		{name: "CRE-049 an API key", method: "POST", host: "api.anthropic.com", target: "/v1/messages", body: body, header: both, apiKey: creClaude},
		{name: "CRE-049 an API key on the policy endpoint", method: "GET", host: "api.anthropic.com", target: "/api/claude_code/settings", header: both, apiKey: creClaude},
	})
}

// TestCreRulesVertexToken: the Google token the proxy mints reaches only
// Anthropic's models in the user's project and region, and no Google
// header of the agent's, such as a project to bill, comes with it.
func TestCreRulesVertexToken(t *testing.T) {
	body := `{"anthropic_version":"vertex-2023-10-16","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	h := map[string]string{"Content-Type": "application/json", "X-Goog-Request-Params": "project=attacker-project", "X-Http-Method-Override": "GET", "X-Server-Timeout": "600"}
	base := "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models/"
	creRunRules(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: proxy.Vertex, VertexProject: "my-project", VertexRegion: "us-east5"}, []creRuleCase{
		{name: "CRE-050 a model in the user's project", method: "POST", host: "us-east5-aiplatform.googleapis.com", target: base + "claude-sonnet-4-5@20250929:streamRawPredict", body: body, header: h, authorization: "Bearer " + creGoogle},
		{name: "CRE-050 counting tokens", method: "POST", host: "us-east5-aiplatform.googleapis.com", target: base + "count-tokens:rawPredict", body: body, header: h, authorization: "Bearer " + creGoogle},
		{name: "CRE-051 another method on an Anthropic model", method: "POST", host: "us-east5-aiplatform.googleapis.com", target: base + "claude-x:generateContent", body: body, header: h, authorization: "Bearer " + creGoogle,
			limit: "the model segment is one wildcard, so any method on an Anthropic model passes; it stays in the user's project and region, and is inspected"},
	})
}

// creRefusal is a request the run's real rules must refuse before any
// upstream sees it, with the reason the agent is told.
type creRefusal struct {
	name, method, host, target, body string
	header                           map[string]string
	reason                           string
}

func creRunRefusals(t *testing.T, run proxy.Run, cases []creRefusal) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, seen := creRulesProxy(t, run)
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			r := httptest.NewRequest(c.method, "https://"+c.host+"/", body)
			r.RequestURI = c.target
			for k, v := range c.header {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "("+c.reason+")") || seen.hits != 0 {
				t.Errorf("want refused (%s), got %d %q with %d upstream requests", c.reason, w.Code, w.Body.String(), seen.hits)
			}
		})
	}
}

// TestCreRulesGitHubWrites: no rule writes to GitHub, with the user's token
// or without. The push happens on the host, after the user's review.
func TestCreRulesGitHubWrites(t *testing.T) {
	gh := map[string]string{"Authorization": "token " + sandbox.Placeholder, "Content-Type": "application/json"}
	git := map[string]string{"Content-Type": "application/x-git-receive-pack-request"}
	pr := `{"title":"t","head":"attacker:main","base":"main"}`
	creRunRefusals(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo"}, []creRefusal{
		{name: "CRE-052 a pull request on the run's repository", method: "POST", host: "api.github.com", target: "/repos/owner/repo/pulls", body: pr, header: gh, reason: "no-rule"},
		{name: "CRE-052 an issue on the run's repository", method: "POST", host: "api.github.com", target: "/repos/owner/repo/issues", body: `{"title":"t"}`, header: gh, reason: "no-rule"},
		{name: "CRE-052 a comment on another repository", method: "POST", host: "api.github.com", target: "/repos/attacker/repo/issues/1/comments", body: `{"body":"x"}`, header: gh, reason: "no-rule"},
		{name: "CRE-052 a file written through the API", method: "PUT", host: "api.github.com", target: "/repos/owner/repo/contents/x", body: `{"message":"m","content":"eA=="}`, header: gh, reason: "no-rule"},
		{name: "CRE-052 a ref updated", method: "PATCH", host: "api.github.com", target: "/repos/owner/repo/git/refs/heads/main", body: `{"sha":"0"}`, header: gh, reason: "no-rule"},
		{name: "CRE-052 the repository deleted", method: "DELETE", host: "api.github.com", target: "/repos/owner/repo", header: gh, reason: "no-rule"},
		{name: "CRE-052 a gist", method: "POST", host: "api.github.com", target: "/gists", body: `{"files":{"a":{"content":"x"}}}`, header: gh, reason: "no-rule"},
		{name: "CRE-052 GraphQL", method: "POST", host: "api.github.com", target: "/graphql", body: `{"query":"mutation{}"}`, header: gh, reason: "no-rule"},
		{name: "CRE-052 the user's own profile", method: "GET", host: "api.github.com", target: "/user", header: gh, reason: "no-rule"},
		{name: "CRE-052 a push's ref advertisement", method: "GET", host: "github.com", target: "/owner/repo/info/refs?service=git-receive-pack", header: git, reason: "no-rule"},
		{name: "CRE-052 a push", method: "POST", host: "github.com", target: "/owner/repo.git/git-receive-pack", body: "0000", header: git, reason: "no-rule"},
		{name: "CRE-052 a fetch of another repository", method: "GET", host: "github.com", target: "/attacker/repo/info/refs?service=git-upload-pack", header: git, reason: "no-rule"},
		{name: "CRE-052 a POST to raw content", method: "POST", host: "raw.githubusercontent.com", target: "/owner/repo/main/x", body: "x", reason: "no-rule"},
		{name: "CRE-052 an upload host", method: "POST", host: "uploads.github.com", target: "/repos/owner/repo/releases/1/assets?name=x", body: "x", header: gh, reason: "host"},
	})
}

// TestCreRulesAnthropicEndpoints: only the Messages API and Claude Code's
// policies are reached with the user's Claude credential: no file upload,
// batch, admin or other endpoint, and no other query.
func TestCreRulesAnthropicEndpoints(t *testing.T) {
	ph := sandbox.Placeholder
	h := map[string]string{"Authorization": "Bearer " + ph, "Content-Type": "application/json"}
	body := `{"model":"m","max_tokens":1,"messages":[]}`
	creRunRefusals(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: proxy.Subscription}, []creRefusal{
		{name: "CRE-053 a file uploaded to the Files API", method: "POST", host: "api.anthropic.com", target: "/v1/files", body: "x", header: h, reason: "no-rule"},
		{name: "CRE-053 the Files API listed", method: "GET", host: "api.anthropic.com", target: "/v1/files", header: h, reason: "no-rule"},
		{name: "CRE-053 a message batch", method: "POST", host: "api.anthropic.com", target: "/v1/messages/batches", body: `{"requests":[]}`, header: h, reason: "no-rule"},
		{name: "CRE-053 a skill uploaded", method: "POST", host: "api.anthropic.com", target: "/v1/skills", body: "x", header: h, reason: "no-rule"},
		{name: "CRE-053 the models listed", method: "GET", host: "api.anthropic.com", target: "/v1/models", header: h, reason: "no-rule"},
		{name: "CRE-053 an admin endpoint", method: "GET", host: "api.anthropic.com", target: "/v1/organizations/api_keys", header: h, reason: "no-rule"},
		{name: "CRE-053 OAuth", method: "POST", host: "api.anthropic.com", target: "/v1/oauth/token", body: `{"grant_type":"refresh_token"}`, header: h, reason: "no-rule"},
		{name: "CRE-053 another query", method: "POST", host: "api.anthropic.com", target: "/v1/messages?beta=false", body: body, header: h, reason: "no-rule"},
		{name: "CRE-053 a second query parameter", method: "POST", host: "api.anthropic.com", target: "/v1/messages?beta=true&x=y", body: body, header: h, reason: "no-rule"},
		{name: "CRE-053 a GET on the Messages API", method: "GET", host: "api.anthropic.com", target: "/v1/messages", header: h, reason: "no-rule"},
		{name: "CRE-053 the policies written", method: "POST", host: "api.anthropic.com", target: "/api/claude_code/settings", body: "{}", header: h, reason: "no-rule"},
		{name: "CRE-053 the console", method: "GET", host: "console.anthropic.com", target: "/", header: h, reason: "host"},
		{name: "CRE-053 claude.ai", method: "GET", host: "claude.ai", target: "/", header: h, reason: "host"},
	})
	// With Vertex, Anthropic's own API is not reached at all. A host no rule
	// names is refused as such: in a run, no certificate is minted for it.
	creRunRefusals(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: proxy.Vertex, VertexProject: "my-project", VertexRegion: "us-east5"}, []creRefusal{
		{name: "CRE-053 Anthropic's API in a Vertex run", method: "POST", host: "api.anthropic.com", target: "/v1/messages", body: body, header: h, reason: "host"},
	})
}

// TestCreRulesVertexScope: the minted Google token reaches Anthropic's
// models in the user's project and region only: no other project, region,
// publisher, Google API, or query.
func TestCreRulesVertexScope(t *testing.T) {
	h := map[string]string{"Authorization": "Bearer " + sandbox.Placeholder, "Content-Type": "application/json"}
	body := `{"anthropic_version":"vertex-2023-10-16","max_tokens":1,"messages":[]}`
	host := "us-east5-aiplatform.googleapis.com"
	model := "/publishers/anthropic/models/claude-x:streamRawPredict"
	creRunRefusals(t, proxy.Run{ProxyIP: "10.0.0.2", Repo: "owner/repo", Claude: proxy.Vertex, VertexProject: "my-project", VertexRegion: "us-east5"}, []creRefusal{
		{name: "CRE-054 another project", method: "POST", host: host, target: "/v1/projects/attacker-project/locations/us-east5" + model, body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 another region in the path", method: "POST", host: host, target: "/v1/projects/my-project/locations/europe-west1" + model, body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 another region's host", method: "POST", host: "europe-west1-aiplatform.googleapis.com", target: "/v1/projects/my-project/locations/us-east5" + model, body: body, header: h, reason: "host"},
		{name: "CRE-054 the global host", method: "POST", host: "aiplatform.googleapis.com", target: "/v1/projects/my-project/locations/us-east5" + model, body: body, header: h, reason: "host"},
		{name: "CRE-054 another publisher", method: "POST", host: host, target: "/v1/projects/my-project/locations/us-east5/publishers/google/models/gemini:generateContent", body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 a v1beta1 path", method: "POST", host: host, target: "/v1beta1/projects/my-project/locations/us-east5" + model, body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 a deeper path", method: "POST", host: host, target: "/v1/projects/my-project/locations/us-east5" + model + "/x", body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 a query", method: "POST", host: host, target: "/v1/projects/my-project/locations/us-east5" + model + "?alt=sse", body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 a key in the query", method: "POST", host: host, target: "/v1/projects/my-project/locations/us-east5" + model + "?key=AIzaAttacker", body: body, header: h, reason: "no-rule"},
		{name: "CRE-054 a GET on the model", method: "GET", host: host, target: "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models/claude-x", header: h, reason: "no-rule"},
		{name: "CRE-054 the project's endpoints", method: "GET", host: host, target: "/v1/projects/my-project/locations/us-east5/endpoints", header: h, reason: "no-rule"},
		{name: "CRE-054 Cloud Storage", method: "GET", host: "storage.googleapis.com", target: "/b/my-bucket/o", header: h, reason: "host"},
		{name: "CRE-054 the token endpoint", method: "POST", host: "oauth2.googleapis.com", target: "/token", body: "grant_type=x", header: h, reason: "host"},
		{name: "CRE-054 a URL image to Vertex", method: "POST", host: host, target: "/v1/projects/my-project/locations/us-east5" + model,
			body: `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://attacker.example/x"}}]}]}`, header: h, reason: "server-tool"},
	})
}
