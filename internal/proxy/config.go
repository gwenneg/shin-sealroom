// Package proxy writes the proxy's rules for a run and the run's certificate
// authority. The rules are the heart of Sealroom's defence: what the agent
// can reach, and where the user's credentials may be added. TestConfigRules
// pins them, and docs/proxy.md specifies the proxy that enforces them.
package proxy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/gwenneg/sealroom/internal/egress"
	"github.com/gwenneg/sealroom/internal/sandbox"
)

// Paths inside the proxy container.
const (
	ConfigPath = "/etc/sealroom/proxy.json"
	CACertPath = "/etc/sealroom/ca.crt"
	CAKeyPath  = "/etc/sealroom/ca.key"
	// GoogleCredentialsPath holds the user's Google credentials, with Vertex.
	GoogleCredentialsPath = sandbox.GoogleCredentialsDst
)

// The variables of the proxy's environment file, and nothing else.
const (
	ClaudeCredentialEnv  = "SEALROOM_CLAUDE_CREDENTIAL"
	GitHubTokenEnv       = "SEALROOM_GITHUB_TOKEN"
	GoogleCredentialsEnv = egress.GoogleCredentialsEnv
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
	regionPattern  = regexp.MustCompile(`^(global|us|eu|[a-z]+-[a-z]+[0-9]{1,2})$`)
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

// VertexHost returns the Vertex AI endpoint of a region: the global one, a
// multi-region one, or a region's own.
func VertexHost(region string) string {
	switch region {
	case "global":
		return "aiplatform.googleapis.com"
	case "us", "eu":
		return "aiplatform." + region + ".rep.googleapis.com"
	}
	return region + "-aiplatform.googleapis.com"
}

// The headers each destination receives, from what Claude Code, git and the
// GitHub CLI send. Every other header is dropped, and credentials are only
// ever added by the proxy.
var (
	claudeHeaders = []string{
		"Accept", "Accept-Encoding", "Content-Type", "User-Agent",
		"Anthropic-Version", "Anthropic-Beta", "Anthropic-Dangerous-Direct-Browser-Access",
		"X-App", "X-Claude-Code-Session-Id",
		"X-Stainless-Arch", "X-Stainless-Lang", "X-Stainless-Os", "X-Stainless-Package-Version",
		"X-Stainless-Retry-Count", "X-Stainless-Runtime", "X-Stainless-Runtime-Version", "X-Stainless-Timeout",
	}
	gitHubAPIHeaders = []string{"Accept", "Accept-Encoding", "Content-Type", "User-Agent", "X-Github-Api-Version", "Time-Zone"}
	gitHeaders       = []string{"Accept", "Accept-Encoding", "Accept-Language", "Content-Type", "Content-Encoding", "User-Agent", "Git-Protocol", "Pragma"}
	rawHeaders       = []string{"Accept", "Accept-Encoding", "User-Agent"}
	declaredHeaders  = []string{"Accept", "Accept-Encoding", "Accept-Language", "Content-Type", "User-Agent"}
)

// Config returns the proxy's rules for a run, as JSON. The first rule that
// matches a request decides it, so the rules of the run's repository, which
// add the user's GitHub token, come before the anonymous reads of any other.
func Config(r Run) ([]byte, error) {
	if !ValidRepo(r.Repo) {
		return nil, fmt.Errorf("repository %q is not a valid owner/repo", r.Repo)
	}
	if r.ProxyIP == "" {
		return nil, fmt.Errorf("the proxy has no address")
	}
	var rules []egress.Rule
	add := func(method, host, path, query string, headers []string, cred *egress.Credential, inspect bool) {
		rules = append(rules, egress.Rule{Method: method, Host: host, Path: path, Query: query, Headers: headers, Credential: cred, InspectMessages: inspect})
	}

	switch r.Claude {
	case Vertex:
		if !ValidVertex(r.VertexProject, r.VertexRegion) {
			return nil, fmt.Errorf("Vertex project %q and region %q are not valid", r.VertexProject, r.VertexRegion)
		}
		// Claude's models in the user's project and region, nowhere else.
		google := &egress.Credential{Secret: egress.Google, Header: "Authorization", Scheme: "Bearer"}
		add("POST", VertexHost(r.VertexRegion), "/v1/projects/"+r.VertexProject+"/locations/"+r.VertexRegion+"/publishers/anthropic/models/*", "", claudeHeaders, google, true)
	default:
		claude := &egress.Credential{Secret: ClaudeCredentialEnv, Header: "Authorization", Scheme: "Bearer"}
		if r.Claude == APIKey {
			claude = &egress.Credential{Secret: ClaudeCredentialEnv, Header: "X-Api-Key"}
		}
		for _, q := range []string{"beta=true", ""} {
			add("POST", "api.anthropic.com", "/v1/messages", q, claudeHeaders, claude, true)
			add("POST", "api.anthropic.com", "/v1/messages/count_tokens", q, claudeHeaders, claude, true)
		}
		// Read-only policies that organizations set for Claude Code.
		add("GET", "api.anthropic.com", "/api/claude_code/policy_limits", "", claudeHeaders, claude, false)
		add("GET", "api.anthropic.com", "/api/claude_code/settings", "", claudeHeaders, claude, false)
	}

	// GitHub: the user's token on reads of the run's repository only.
	token := &egress.Credential{Secret: GitHubTokenEnv, Header: "Authorization", Scheme: "Bearer"}
	for _, m := range []string{"GET", "HEAD"} {
		add(m, "api.github.com", "/repos/"+r.Repo, egress.AnyQuery, gitHubAPIHeaders, token, false)
		add(m, "api.github.com", "/repos/"+r.Repo+"/**", egress.AnyQuery, gitHubAPIHeaders, token, false)
	}
	git := &egress.Credential{Secret: GitHubTokenEnv, Header: "Authorization", Scheme: "basic-x-access-token"}
	for _, base := range []string{"/" + r.Repo, "/" + r.Repo + ".git"} {
		add("GET", "github.com", base+"/info/refs", "service=git-upload-pack", gitHeaders, git, false)
		add("POST", "github.com", base+"/git-upload-pack", "", gitHeaders, git, false)
	}
	// Anonymous reads of any other repository, and of raw files.
	for _, m := range []string{"GET", "HEAD"} {
		add(m, "api.github.com", "/", "", gitHubAPIHeaders, nil, false)
		add(m, "api.github.com", "/repos/**", egress.AnyQuery, gitHubAPIHeaders, nil, false)
	}
	add("GET", "raw.githubusercontent.com", "/**", "", rawHeaders, nil, false)

	for _, d := range r.Declared {
		for _, m := range d.Methods {
			for _, p := range d.Paths {
				query, headers := egress.AnyQuery, declaredHeaders
				if d.Host == "github.com" {
					headers, query = gitHeaders, ""
					if strings.HasSuffix(p, "/info/refs") {
						query = "service=git-upload-pack"
					}
				}
				add(m, d.Host, p, query, headers, nil, false)
			}
		}
	}

	cfg := egress.Config{Placeholder: sandbox.Placeholder, Rules: rules}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// Env is what the proxy's environment file holds.
type Env struct {
	Claude string // the Claude credential, empty with Vertex
	GitHub string
	Vertex bool // point the proxy at the mounted Google credentials
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
