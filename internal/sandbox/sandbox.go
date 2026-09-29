// Package sandbox holds every restriction of Sealroom's containers, in one
// place. It only builds the arguments passed to Podman or Docker; it starts
// nothing. TestArgsSeal pins the restrictions: never weaken it to make a
// change pass.
package sandbox

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The agent's user, matching the agent image.
const (
	AgentUID = 10001
	AgentGID = 10001
)

// Paths inside the agent container.
const (
	PluginDir = "/plugin"
	RepoDir   = "/src"
	WorkDir   = "/work"
	OutDir    = "/out"
	CACert    = "/etc/sealroom/ca.crt"
)

// Placeholder is the only value the agent holds for any credential. The proxy
// swaps it for the real one, and refuses requests that do not carry it.
const Placeholder = "sealroom-placeholder"

// Limits applied to both containers.
const (
	Memory    = "4g"
	CPUs      = "2"
	PidsLimit = "512"
)

// Network is the internal network between the agent and the proxy.
type Network struct {
	Name   string
	Subnet string // for example 172.30.0.0/24
}

// CreateArgs returns the arguments that create the network. It is internal:
// no gateway to the outside, so the proxy is the only way out.
func (n Network) CreateArgs() []string {
	return []string{"network", "create", "--internal", "--subnet", n.Subnet, n.Name}
}

// Proxy describes the proxy container.
type Proxy struct {
	Name     string
	Image    string // pinned by digest
	Network  Network
	IP       string // the proxy's address on the internal network
	Config   string // host path of the proxy's configuration
	CACert   string // host path of the run's CA certificate
	CAKey    string // host path of the run's CA key
	EnvFile  string // host path of the credentials, read by the proxy only
	Outbound string // the network that reaches the internet
}

// RunArgs returns the arguments that start the proxy on the internal network.
// ConnectArgs then attaches it to the outbound network: Docker takes a single
// network at start.
func (p Proxy) RunArgs() ([]string, error) {
	for _, path := range []string{p.Config, p.CACert, p.CAKey, p.EnvFile} {
		if err := checkHostPath(path); err != nil {
			return nil, err
		}
	}
	args := []string{
		"run", "--detach", "--rm", "--pull", "never",
		"--name", p.Name,
		"--network", p.Network.Name, "--ip", p.IP,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		// The proxy answers DNS and HTTPS on low ports without any capability.
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
		"--memory", Memory, "--cpus", CPUs, "--pids-limit", PidsLimit,
		"--env-file", p.EnvFile,
		"--mount", readOnly(p.Config, "/etc/sealroom/proxy.yaml"),
		"--mount", readOnly(p.CACert, "/etc/sealroom/ca.crt"),
		"--mount", readOnly(p.CAKey, "/etc/sealroom/ca.key"),
		p.Image,
		"-config", "/etc/sealroom/proxy.yaml",
	}
	return args, nil
}

// ConnectArgs returns the arguments that attach the proxy to the outbound
// network.
func (p Proxy) ConnectArgs() []string {
	return []string{"network", "connect", p.Outbound, p.Name}
}

// Agent describes the agent container.
type Agent struct {
	Name    string
	Image   string // pinned by digest
	Network Network
	ProxyIP string
	Plugin  string // host path, mounted read-only
	Repo    string // host path of the clone, mounted read-only and copied inside
	CACert  string // host path of the run's CA certificate, public
	Out     string // host path of the output directory, the only writable mount
	Env     map[string]string
	Command []string
}

// allowedEnv lists the environment variables the agent may receive. Every
// credential variable carries the placeholder, never a real value.
var allowedEnv = map[string]bool{
	"CLAUDE_CODE_OAUTH_TOKEN": true, "ANTHROPIC_API_KEY": true, "GH_TOKEN": true,
	"CLAUDE_CODE_USE_VERTEX": true, "CLOUD_ML_REGION": true, "ANTHROPIC_VERTEX_PROJECT_ID": true,
	"TERM": true, "COLORTERM": true,
	"GIT_AUTHOR_NAME": true, "GIT_AUTHOR_EMAIL": true, "GIT_COMMITTER_NAME": true, "GIT_COMMITTER_EMAIL": true,
}

// credentialEnv lists the variables that may only ever hold the placeholder.
var credentialEnv = map[string]bool{"CLAUDE_CODE_OAUTH_TOKEN": true, "ANTHROPIC_API_KEY": true, "GH_TOKEN": true}

// RunArgs returns the arguments that start the agent interactively.
func (a Agent) RunArgs() ([]string, error) {
	for _, path := range []string{a.Plugin, a.Repo, a.CACert, a.Out} {
		if err := checkHostPath(path); err != nil {
			return nil, err
		}
	}
	args := []string{
		"run", "--rm", "--interactive", "--tty", "--pull", "never",
		"--name", a.Name,
		"--network", a.Network.Name,
		"--dns", a.ProxyIP,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", AgentUID, AgentGID),
		"--memory", Memory, "--cpus", CPUs, "--pids-limit", PidsLimit,
		"--tmpfs", "/tmp",
		"--tmpfs", fmt.Sprintf("/home/agent:uid=%d,gid=%d", AgentUID, AgentGID),
		"--tmpfs", fmt.Sprintf("%s:uid=%d,gid=%d", WorkDir, AgentUID, AgentGID),
		"--mount", readOnly(a.Plugin, PluginDir),
		"--mount", readOnly(a.Repo, RepoDir),
		"--mount", readOnly(a.CACert, CACert),
		"--mount", fmt.Sprintf("type=bind,src=%s,dst=%s", a.Out, OutDir),
		// Claude Code, curl and git trust the proxy's CA, and nothing else.
		"--env", "NODE_EXTRA_CA_CERTS=" + CACert,
		"--env", "SSL_CERT_FILE=" + CACert,
		"--env", "GIT_SSL_CAINFO=" + CACert,
	}
	// Sorted, so the arguments are the same on every run.
	for _, k := range slices.Sorted(maps.Keys(a.Env)) {
		v := a.Env[k]
		if !allowedEnv[k] {
			return nil, fmt.Errorf("environment variable %s is not allowed in the agent", k)
		}
		if credentialEnv[k] && v != Placeholder {
			return nil, fmt.Errorf("%s may only hold the placeholder in the agent", k)
		}
		if strings.ContainsAny(v, "\n\x00") {
			return nil, fmt.Errorf("environment variable %s has a newline or NUL", k)
		}
		args = append(args, "--env", k+"="+v)
	}
	args = append(args, a.Image)
	return append(args, a.Command...), nil
}

func readOnly(src, dst string) string {
	return fmt.Sprintf("type=bind,src=%s,dst=%s,readonly", src, dst)
}

// checkHostPath refuses a path that is not absolute and clean, or that would
// change the meaning of a --mount option.
func checkHostPath(path string) error {
	switch {
	case path == "":
		return errors.New("a host path is empty")
	case !filepath.IsAbs(path) || filepath.Clean(path) != path:
		return fmt.Errorf("host path %q is not absolute and clean", path)
	case path == "/":
		return errors.New("the root directory cannot be mounted")
	case strings.ContainsAny(path, ",=\n\x00"):
		return fmt.Errorf("host path %q contains a character that changes the meaning of a mount option", path)
	}
	// The home directory or one of its parents would hand the plugin everything under it.
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(path, home); err == nil && !strings.HasPrefix(rel, "..") {
			return fmt.Errorf("host path %q is the home directory or one of its parents", path)
		}
	}
	return nil
}
