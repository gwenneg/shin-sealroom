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

// GoogleCredentialsDst is where the proxy finds the user's Google
// credentials, with Vertex. internal/proxy points Google's libraries at it.
const GoogleCredentialsDst = "/etc/sealroom/google-credentials.json"

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
	Relabel  bool   // Podman: label the mounted files for SELinux
	// GoogleCredentials is the host path of a copy of the user's Google
	// credentials, with Vertex; empty otherwise.
	GoogleCredentials string
}

// RunArgs returns the arguments that start the proxy on the internal network.
// ConnectArgs then attaches it to the outbound network: Docker takes a single
// network at start.
func (p Proxy) RunArgs() ([]string, error) {
	paths := []string{p.Config, p.CACert, p.CAKey, p.EnvFile}
	if p.GoogleCredentials != "" {
		paths = append(paths, p.GoogleCredentials)
	}
	for _, path := range paths {
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
		"--mount", bind(p.Config, "/etc/sealroom/proxy.yaml", true, label(p.Relabel, private)),
		"--mount", bind(p.CACert, "/etc/sealroom/ca.crt", true, label(p.Relabel, shared)),
		"--mount", bind(p.CAKey, "/etc/sealroom/ca.key", true, label(p.Relabel, private)),
	}
	if p.GoogleCredentials != "" {
		args = append(args, "--mount", bind(p.GoogleCredentials, GoogleCredentialsDst, true, label(p.Relabel, private)))
	}
	return append(args, p.Image, "-config", "/etc/sealroom/proxy.yaml"), nil
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
	// TTY attaches the agent to the user's terminal. Without it, the agent
	// runs with no input, as in tests.
	TTY bool
	// Relabel, with Podman, labels the mounted files for SELinux.
	Relabel bool
}

// allowedEnv lists the environment variables the agent may receive. Every
// credential variable carries the placeholder, never a real value.
var allowedEnv = map[string]bool{
	"CLAUDE_CODE_OAUTH_TOKEN": true, "ANTHROPIC_API_KEY": true, "GH_TOKEN": true,
	"CLAUDE_CODE_USE_VERTEX": true, "CLAUDE_CODE_SKIP_VERTEX_AUTH": true, "CLOUD_ML_REGION": true, "ANTHROPIC_VERTEX_PROJECT_ID": true,
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
		"run", "--rm", "--pull", "never",
		"--name", a.Name,
		"--network", a.Network.Name,
		"--dns", a.ProxyIP,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", AgentUID, AgentGID),
		"--memory", Memory, "--cpus", CPUs, "--pids-limit", PidsLimit,
		// Writable by the agent's user, the only user in the container.
		// Podman's --tmpfs has no uid option, so the mode does it on both runtimes.
		"--tmpfs", "/tmp",
		"--tmpfs", "/home/agent:mode=1777",
		"--tmpfs", WorkDir + ":mode=1777",
		"--mount", bind(a.Plugin, PluginDir, true, label(a.Relabel, private)),
		"--mount", bind(a.Repo, RepoDir, true, label(a.Relabel, private)),
		"--mount", bind(a.CACert, CACert, true, label(a.Relabel, shared)),
		"--mount", bind(a.Out, OutDir, false, label(a.Relabel, private)),
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
	if a.TTY {
		args = append(args, "--interactive", "--tty")
	}
	args = append(args, a.Image)
	return append(args, a.Command...), nil
}

// SELinux labels for Podman's relabel mount option. Relabeling changes the
// labels of the files on the host, so only files of the run directory are
// ever mounted: never the user's own.
const (
	// private: only this container can read the files.
	private = "private"
	// shared: every container that mounts them can, for the run's CA
	// certificate, which the proxy and the agent both read.
	shared = "shared"
)

func label(relabel bool, kind string) string {
	if relabel {
		return kind
	}
	return ""
}

func bind(src, dst string, readOnly bool, relabel string) string {
	m := fmt.Sprintf("type=bind,src=%s,dst=%s", src, dst)
	if readOnly {
		m += ",readonly"
	}
	if relabel != "" {
		m += ",relabel=" + relabel
	}
	return m
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

// Cleanup describes the container that empties the output directory after
// the review. What the agent wrote there belongs to the agent's user on
// Linux, or to a subordinate user with rootless Podman, so the user cannot
// remove it directly. It runs as the agent's user, with no network.
type Cleanup struct {
	Name    string
	Image   string // the agent image
	Out     string // host path of the output directory
	Relabel bool   // Podman: label the mount for SELinux
}

// RunArgs returns the arguments that empty the output directory.
func (c Cleanup) RunArgs() ([]string, error) {
	if err := checkHostPath(c.Out); err != nil {
		return nil, err
	}
	return []string{
		"run", "--rm", "--pull", "never",
		"--name", c.Name,
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", AgentUID, AgentGID),
		"--memory", Memory, "--cpus", CPUs, "--pids-limit", PidsLimit,
		"--mount", bind(c.Out, OutDir, false, label(c.Relabel, private)),
		"--entrypoint", "/usr/bin/find",
		c.Image,
		OutDir, "-mindepth", "1", "-delete",
	}, nil
}
