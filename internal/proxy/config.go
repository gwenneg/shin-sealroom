// Package proxy writes the proxy's rules and the run's certificate authority.
// The rules are the heart of Sealroom's defence: what the agent can reach,
// and where the user's credentials may be added. TestConfigRules pins them.
package proxy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/gwenneg/sealroom/internal/sandbox"
)

// Paths inside the proxy container.
const (
	ConfigPath = "/etc/sealroom/proxy.yaml"
	CACertPath = "/etc/sealroom/ca.crt"
	CAKeyPath  = "/etc/sealroom/ca.key"
	// GoogleCredentialsPath holds the user's Google credentials, with Vertex.
	GoogleCredentialsPath = sandbox.GoogleCredentialsDst
)

// The variables of the proxy's environment file. The file holds nothing
// else: iron-proxy reads variables starting with IRON_ as overrides of its
// configuration, so no other name may ever reach it.
const (
	ClaudeCredentialEnv = "SEALROOM_CLAUDE_CREDENTIAL"
	GitHubTokenEnv      = "SEALROOM_GITHUB_TOKEN"
	// GoogleCredentialsEnv points Google's libraries in the proxy at the
	// user's credentials, with Vertex.
	GoogleCredentialsEnv = "GOOGLE_APPLICATION_CREDENTIALS"
)

// ClaudeAuth is how the user reaches Claude.
type ClaudeAuth int

const (
	// Subscription is a Claude subscription token, sent as a bearer token.
	Subscription ClaudeAuth = iota
	// APIKey is an Anthropic API key, sent in the X-Api-Key header.
	APIKey
	// Vertex is Claude on Google Vertex AI: the proxy mints Google access
	// tokens from the user's credentials.
	Vertex
)

// Run holds what the rules depend on.
type Run struct {
	ProxyIP string     // the proxy's address on the internal network
	Repo    string     // owner/repo, the repository of the run
	Claude  ClaudeAuth // how the user reaches Claude
	// With Vertex, the only project and region the model may be reached in.
	VertexProject, VertexRegion string
	// Declared is what the plugin declares it needs and the user accepted,
	// validated by internal/declare. It only adds allowed requests: no
	// credential is ever added to them.
	Declared []Allow
}

// Allow is one kind of request the plugin declared.
type Allow struct {
	Host           string
	Methods, Paths []string
}

var (
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	projectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	regionPattern  = regexp.MustCompile(`^(global|[a-z]+-[a-z]+[0-9]{1,2})$`)
)

// ValidRepo reports whether repo is an owner/repo that is safe to write into
// a path rule: no wildcard, no dot segment, nothing but GitHub's characters.
func ValidRepo(repo string) bool {
	if !repoPattern.MatchString(repo) {
		return false
	}
	name := repo[strings.IndexByte(repo, '/')+1:]
	return name != "." && name != ".."
}

// ValidVertex reports whether a Google Cloud project ID and a Vertex region
// are safe to write into a host and a path rule.
func ValidVertex(project, region string) bool {
	return projectPattern.MatchString(project) && regionPattern.MatchString(region)
}

// VertexHost returns the Vertex AI endpoint of a region.
func VertexHost(region string) string {
	if region == "global" {
		return "aiplatform.googleapis.com"
	}
	return region + "-aiplatform.googleapis.com"
}

// rule matches requests by host, and optionally by method and path.
type rule struct {
	Host    string   `json:"host"`
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

type transform struct {
	Name   string `json:"name"`
	Config any    `json:"config"`
}

// modelHeaders are what Claude Code sends to the model, and all that reaches
// it besides a credential of the user's.
var modelHeaders = []string{"Content-Type", "Accept", "Accept-Encoding", "User-Agent", "/^anthropic-.*$/", "/^x-stainless-.*$/", "/^x-claude-.*$/", "X-App"}

// Config returns the proxy's configuration for a run. It is JSON, which is
// valid YAML, so writing it needs no dependency.
func Config(r Run) ([]byte, error) {
	if !ValidRepo(r.Repo) {
		return nil, fmt.Errorf("repository %q is not a valid owner/repo", r.Repo)
	}
	if r.ProxyIP == "" {
		return nil, fmt.Errorf("the proxy has no address")
	}
	if r.Claude == Vertex && !ValidVertex(r.VertexProject, r.VertexRegion) {
		return nil, fmt.Errorf("Vertex project %q and region %q are not valid", r.VertexProject, r.VertexRegion)
	}
	repo := "/repos/" + r.Repo
	git := []string{
		"/" + r.Repo + "/info/refs", "/" + r.Repo + "/git-upload-pack",
		"/" + r.Repo + ".git/info/refs", "/" + r.Repo + ".git/git-upload-pack",
	}

	allow := []rule{
		{Host: "api.github.com", Methods: []string{"GET", "HEAD"}, Paths: []string{"/", "/user", "/repos/*"}},
		{Host: "raw.githubusercontent.com", Methods: []string{"GET"}, Paths: []string{"/*"}},
		// Fetching the repository of the run; git sends a POST to read.
		{Host: "github.com", Methods: []string{"GET", "POST"}, Paths: git},
	}
	secrets := []map[string]any{
		// The user's GitHub token, added to reads of the run's repository only.
		{
			"source": map[string]any{"type": "env", "var": GitHubTokenEnv},
			"inject": map[string]any{"header": "Authorization", "formatter": "Bearer {{ .Value }}"},
			"rules":  []rule{{Host: "api.github.com", Methods: []string{"GET", "HEAD"}, Paths: []string{repo, repo + "/*"}}},
		},
		{
			"source": map[string]any{"type": "env", "var": GitHubTokenEnv},
			"inject": map[string]any{"header": "Authorization", "formatter": `Basic {{ base64 "x-access-token:" .Value }}`},
			"rules":  []rule{{Host: "github.com", Methods: []string{"GET", "POST"}, Paths: git}},
		},
	}
	transforms := []transform{
		{"allowlist", nil}, // filled below
		// On GitHub, every header the agent sends is dropped but these, so
		// no credential of its own ever reaches GitHub.
		{"header_allowlist", map[string]any{
			"headers": []string{"Accept", "Accept-Encoding", "User-Agent", "Content-Type", "Git-Protocol", "X-GitHub-Api-Version"},
			"rules":   []rule{{Host: "api.github.com"}, {Host: "raw.githubusercontent.com"}, {Host: "github.com"}},
		}},
	}

	if r.Claude == Vertex {
		// Claude's models in the user's project and region, nowhere else,
		// so no request can reach a project of anyone else's.
		model := rule{
			Host:    VertexHost(r.VertexRegion),
			Methods: []string{"POST"},
			Paths:   []string{"/v1/projects/" + r.VertexProject + "/locations/" + r.VertexRegion + "/publishers/anthropic/models/*"},
		}
		allow = append(allow, model)
		transforms = append(transforms,
			// Only what Claude Code sends: no credential, API key or billing
			// project of the agent's own reaches Google.
			transform{"header_allowlist", map[string]any{"headers": modelHeaders, "rules": []rule{{Host: model.Host}}}},
			// An access token minted from the user's credentials, added to
			// the model's requests only.
			transform{"gcp_auth", map[string]any{
				"credentials_provider": map[string]any{"type": "workload_identity"},
				"scopes":               []string{"https://www.googleapis.com/auth/cloud-platform"},
				"rules":                []rule{model},
			}},
			transform{"secrets", map[string]any{"secrets": secrets}},
		)
	} else {
		claudeHeader := "Authorization"
		if r.Claude == APIKey {
			claudeHeader = "X-Api-Key"
		}
		allow = append(allow,
			rule{Host: "api.anthropic.com", Methods: []string{"POST"}, Paths: []string{"/v1/messages", "/v1/messages/count_tokens"}},
			// Read-only policies that organizations set for Claude Code.
			rule{Host: "api.anthropic.com", Methods: []string{"GET"}, Paths: []string{"/api/claude_code/policy_limits", "/api/claude_code/settings"}},
		)
		// The user's Claude credential replaces the placeholder, and a
		// request without the placeholder is refused.
		secrets = append([]map[string]any{{
			"source":  map[string]any{"type": "env", "var": ClaudeCredentialEnv},
			"replace": map[string]any{"proxy_value": sandbox.Placeholder, "match_headers": []string{claudeHeader}, "require": true},
			"rules":   []rule{{Host: "api.anthropic.com"}},
		}}, secrets...)
		transforms = append(transforms,
			transform{"secrets", map[string]any{"secrets": secrets}},
			// On the model API, only what Claude Code sends and the credential
			// header of the user's kind of credential survive.
			transform{"header_allowlist", map[string]any{
				"headers": append(slices.Clone(modelHeaders), claudeHeader),
				"rules":   []rule{{Host: "api.anthropic.com"}},
			}},
		)
	}
	for _, d := range r.Declared {
		allow = append(allow, rule{Host: d.Host, Methods: d.Methods, Paths: d.Paths})
	}
	transforms[0].Config = map[string]any{"rules": allow}

	cfg := map[string]any{
		"dns": map[string]any{"listen": ":53", "proxy_ip": r.ProxyIP},
		"proxy": map[string]any{
			"http_listen":  ":80",
			"https_listen": ":443",
			// The default of 1 MiB silently truncates long conversations.
			"max_request_body_bytes":           64 << 20,
			"upstream_response_header_timeout": "10m",
		},
		// Out of the agent's reach, on the proxy's own loopback.
		"metrics":    map[string]any{"listen": "127.0.0.1:9090"},
		"tls":        map[string]any{"mode": "mitm", "ca_cert": CACertPath, "ca_key": CAKeyPath},
		"transforms": transforms,
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// Env is what the proxy's environment file holds.
type Env struct {
	Claude string // the Claude credential, empty with Vertex
	GitHub string
	Vertex bool // point Google's libraries at the mounted credentials
}

// EnvFile returns the proxy's environment file: the credentials, and nothing
// else. A value with a newline is refused, since it would add a variable.
func EnvFile(e Env) ([]byte, error) {
	vars := [][2]string{{GitHubTokenEnv, e.GitHub}}
	if e.Vertex {
		vars = append(vars, [2]string{GoogleCredentialsEnv, GoogleCredentialsPath})
	} else {
		vars = append([][2]string{{ClaudeCredentialEnv, e.Claude}}, vars...)
	}
	var b strings.Builder
	for _, kv := range vars {
		if kv[1] == "" {
			return nil, fmt.Errorf("%s is empty", kv[0])
		}
		if strings.ContainsAny(kv[1], "\r\n\x00") {
			return nil, fmt.Errorf("%s contains a newline or NUL", kv[0])
		}
		fmt.Fprintf(&b, "%s=%s\n", kv[0], kv[1])
	}
	return []byte(b.String()), nil
}
