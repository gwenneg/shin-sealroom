// Package proxy writes the proxy's rules and the run's certificate authority.
// The rules are the heart of Sealroom's defence: what the agent can reach,
// and where the user's credentials may be added. TestConfigRules pins them.
package proxy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/gwenneg/sealroom/internal/sandbox"
)

// Paths inside the proxy container.
const (
	ConfigPath = "/etc/sealroom/proxy.yaml"
	CACertPath = "/etc/sealroom/ca.crt"
	CAKeyPath  = "/etc/sealroom/ca.key"
)

// The variables of the proxy's environment file. The file holds nothing
// else: iron-proxy reads variables starting with IRON_ as overrides of its
// configuration, so no other name may ever reach it.
const (
	ClaudeCredentialEnv = "SEALROOM_CLAUDE_CREDENTIAL"
	GitHubTokenEnv      = "SEALROOM_GITHUB_TOKEN"
)

// ClaudeAuth is how the user reaches Claude.
type ClaudeAuth int

const (
	// Subscription is a Claude subscription token, sent as a bearer token.
	Subscription ClaudeAuth = iota
	// APIKey is an Anthropic API key, sent in the X-Api-Key header.
	APIKey
)

// Run holds what the rules depend on.
type Run struct {
	ProxyIP string     // the proxy's address on the internal network
	Repo    string     // owner/repo, the repository of the run
	Claude  ClaudeAuth // how the user reaches Claude
}

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// ValidRepo reports whether repo is an owner/repo that is safe to write into
// a path rule: no wildcard, no dot segment, nothing but GitHub's characters.
func ValidRepo(repo string) bool {
	if !repoPattern.MatchString(repo) {
		return false
	}
	name := repo[strings.IndexByte(repo, '/')+1:]
	return name != "." && name != ".."
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

// Config returns the proxy's configuration for a run. It is JSON, which is
// valid YAML, so writing it needs no dependency.
func Config(r Run) ([]byte, error) {
	if !ValidRepo(r.Repo) {
		return nil, fmt.Errorf("repository %q is not a valid owner/repo", r.Repo)
	}
	if r.ProxyIP == "" {
		return nil, fmt.Errorf("the proxy has no address")
	}
	repo := "/repos/" + r.Repo
	git := []string{
		"/" + r.Repo + "/info/refs", "/" + r.Repo + "/git-upload-pack",
		"/" + r.Repo + ".git/info/refs", "/" + r.Repo + ".git/git-upload-pack",
	}

	claudeHeader := "Authorization"
	if r.Claude == APIKey {
		claudeHeader = "X-Api-Key"
	}

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
		"metrics": map[string]any{"listen": "127.0.0.1:9090"},
		"tls":     map[string]any{"mode": "mitm", "ca_cert": CACertPath, "ca_key": CAKeyPath},
		"transforms": []transform{
			{"allowlist", map[string]any{"rules": []rule{
				{Host: "api.anthropic.com", Methods: []string{"POST"}, Paths: []string{"/v1/messages", "/v1/messages/count_tokens"}},
				// Read-only policies that organizations set for Claude Code.
				{Host: "api.anthropic.com", Methods: []string{"GET"}, Paths: []string{"/api/claude_code/policy_limits", "/api/claude_code/settings"}},
				{Host: "api.github.com", Methods: []string{"GET", "HEAD"}, Paths: []string{"/", "/user", "/repos/*"}},
				{Host: "raw.githubusercontent.com", Methods: []string{"GET"}, Paths: []string{"/*"}},
				// Fetching the repository of the run; git sends a POST to read.
				{Host: "github.com", Methods: []string{"GET", "POST"}, Paths: git},
			}}},
			// On GitHub, every header the agent sends is dropped but these, so
			// no credential of its own ever reaches GitHub.
			{"header_allowlist", map[string]any{
				"headers": []string{"Accept", "Accept-Encoding", "User-Agent", "Content-Type", "Git-Protocol", "X-GitHub-Api-Version"},
				"rules":   []rule{{Host: "api.github.com"}, {Host: "raw.githubusercontent.com"}, {Host: "github.com"}},
			}},
			{"secrets", map[string]any{"secrets": []map[string]any{
				// The user's Claude credential replaces the placeholder, and a
				// request without the placeholder is refused.
				{
					"source":  map[string]any{"type": "env", "var": ClaudeCredentialEnv},
					"replace": map[string]any{"proxy_value": sandbox.Placeholder, "match_headers": []string{claudeHeader}, "require": true},
					"rules":   []rule{{Host: "api.anthropic.com"}},
				},
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
			}}},
			// On the model API, only what Claude Code sends and the credential
			// header of the user's kind of credential survive.
			{"header_allowlist", map[string]any{
				"headers": []string{"Content-Type", "Accept", "Accept-Encoding", "User-Agent", claudeHeader, "/^anthropic-.*$/", "/^x-stainless-.*$/", "/^x-claude-.*$/", "X-App"},
				"rules":   []rule{{Host: "api.anthropic.com"}},
			}},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// EnvFile returns the proxy's environment file: the credentials, and nothing
// else. A value with a newline is refused, since it would add a variable.
func EnvFile(claudeCredential, githubToken string) ([]byte, error) {
	var b strings.Builder
	for _, kv := range [][2]string{{ClaudeCredentialEnv, claudeCredential}, {GitHubTokenEnv, githubToken}} {
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
