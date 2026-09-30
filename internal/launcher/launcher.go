// Package launcher runs a sealed session: it prepares the run on the host,
// starts the proxy and the agent, attaches the agent to the user's terminal,
// and removes what it started when the session ends.
package launcher

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/gwenneg/sealroom/internal/container"
	"github.com/gwenneg/sealroom/internal/proxy"
	"github.com/gwenneg/sealroom/internal/sandbox"
)

// Options is what the user asks for.
type Options struct {
	Plugin     string // the plugin's directory on the host
	Repo       string // owner/repo
	Prompt     string // an optional first prompt, such as the plugin's command
	ProxyImage string
	AgentImage string
}

// Credentials are the user's, handed to the proxy only.
type Credentials struct {
	Claude     string
	ClaudeAuth proxy.ClaudeAuth
	GitHub     string
}

// Terminal is where the session runs.
type Terminal struct {
	In       io.Reader
	Out, Err io.Writer
	TTY      bool // In is the user's terminal
}

// Result says where a session left its output.
type Result struct {
	RunDir   string
	OutDir   string
	ExitCode int
}

// Run runs one sealed session and removes the proxy and the networks when it
// ends, whatever the outcome.
func Run(rt container.Runtime, opts Options, creds Credentials, term Terminal) (Result, error) {
	if !proxy.ValidRepo(opts.Repo) {
		return Result{}, fmt.Errorf("%q is not an owner/repo", opts.Repo)
	}
	if strings.HasPrefix(opts.Prompt, "-") {
		// It would reach Claude Code as an option, not as a prompt.
		return Result{}, errors.New("the prompt cannot start with a dash")
	}
	plugin, err := resolveDir(opts.Plugin)
	if err != nil {
		return Result{}, fmt.Errorf("plugin: %w", err)
	}

	id := newID()
	runDir, err := makeRunDir(id)
	if err != nil {
		return Result{}, err
	}
	res := Result{RunDir: runDir, OutDir: filepath.Join(runDir, "out"), ExitCode: -1}
	fmt.Fprintf(term.Err, "sealroom: preparing the run in %s\n", runDir)

	// The agent mounts Sealroom's copy, never the user's plugin directory.
	pluginCopy := filepath.Join(runDir, "plugin")
	if err := copyPlugin(plugin, pluginCopy); err != nil {
		return res, fmt.Errorf("copying the plugin: %w", err)
	}

	src := filepath.Join(runDir, "src")
	clone := exec.Command("git", "clone", "--quiet", "https://github.com/"+opts.Repo, src)
	clone.Stdout, clone.Stderr = term.Err, term.Err
	if err := clone.Run(); err != nil {
		return res, fmt.Errorf("cloning %s: %w", opts.Repo, err)
	}

	network, ip, err := createNetwork(rt, "sealroom-"+id)
	if err != nil {
		return res, err
	}
	defer rt.Run("network", "rm", network.Name)
	outbound := "sealroom-" + id + "-out"
	if _, err := rt.Run("network", "create", outbound); err != nil {
		return res, err
	}
	defer rt.Run("network", "rm", outbound)

	if err := writeProxyFiles(runDir, ip, opts.Repo, creds); err != nil {
		return res, err
	}
	p := sandbox.Proxy{
		Name: "sealroom-" + id + "-proxy", Image: opts.ProxyImage, Network: network, IP: ip,
		Config: filepath.Join(runDir, "proxy.yaml"), CACert: filepath.Join(runDir, "ca.crt"),
		CAKey: filepath.Join(runDir, "ca.key"), EnvFile: filepath.Join(runDir, "proxy.env"), Outbound: outbound,
		Relabel: relabel(rt),
	}
	args, err := p.RunArgs()
	if err != nil {
		return res, err
	}
	if _, err := rt.Run(args...); err != nil {
		return res, fmt.Errorf("starting the proxy: %w", err)
	}
	// The proxy leaves the internal network before the network is removed.
	defer rt.Run("rm", "--force", p.Name)
	if _, err := rt.Run(p.ConnectArgs()...); err != nil {
		return res, err
	}
	if err := waitListening(rt, p.Name); err != nil {
		return res, err
	}

	a := sandbox.Agent{
		Name: "sealroom-" + id + "-agent", Image: opts.AgentImage, Network: network, ProxyIP: ip,
		Plugin: pluginCopy, Repo: src, CACert: p.CACert, Out: res.OutDir, Relabel: relabel(rt),
		Env: agentEnv(creds.ClaudeAuth), Command: agentCommand(opts.Prompt), TTY: term.TTY,
	}
	args, err = a.RunArgs()
	if err != nil {
		return res, err
	}
	fmt.Fprintln(term.Err, "sealroom: starting the sealed session")
	// Ctrl-C belongs to the session while it runs: the terminal sends it to
	// the agent, and the launcher must live on to clean up.
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	res.ExitCode, err = rt.Interactive(term.In, term.Out, term.Err, args...)
	return res, err
}

// relabel reports whether the mounts get SELinux labels: with Podman, which
// ignores them where SELinux is off. Docker's --mount has no such option, and
// Docker does not confine containers with SELinux unless its daemon is set to.
func relabel(rt container.Runtime) bool {
	return filepath.Base(rt.Bin) == "podman"
}

// agentEnv holds placeholders only, never a credential.
func agentEnv(auth proxy.ClaudeAuth) map[string]string {
	env := map[string]string{"GH_TOKEN": sandbox.Placeholder}
	if auth == proxy.APIKey {
		env["ANTHROPIC_API_KEY"] = sandbox.Placeholder
	} else {
		env["CLAUDE_CODE_OAUTH_TOKEN"] = sandbox.Placeholder
	}
	for _, k := range []string{"TERM", "COLORTERM"} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	for k, key := range map[string]string{"NAME": "user.name", "EMAIL": "user.email"} {
		if v := gitConfig(key); v != "" {
			env["GIT_AUTHOR_"+k] = v
			env["GIT_COMMITTER_"+k] = v
		}
	}
	return env
}

func agentCommand(prompt string) []string {
	cmd := []string{"--plugin-dir", sandbox.PluginDir}
	if prompt != "" {
		cmd = append(cmd, prompt)
	}
	return cmd
}

func gitConfig(key string) string {
	out, err := exec.Command("git", "config", "--get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func resolveDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", real)
	}
	return real, nil
}

func newID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// makeRunDir creates the run's directory under the user's cache directory,
// which Colima shares with its virtual machine. Only the user can enter it;
// the output directory inside is writable by the agent's user.
func makeRunDir(id string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "sealroom", "runs", id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		return "", err
	}
	// The agent runs as its own user, which must write here.
	return dir, os.Chmod(out, 0o777)
}

// writeProxyFiles writes the rules, the CA and the credentials. The proxy
// runs as its own user, so the files it reads are readable by all; the run
// directory around them is the user's alone. The credentials file is read
// by the runtime's command line, as the user.
func writeProxyFiles(dir, ip, repo string, creds Credentials) error {
	cfg, err := proxy.Config(proxy.Run{ProxyIP: ip, Repo: repo, Claude: creds.ClaudeAuth})
	if err != nil {
		return err
	}
	cert, key, err := proxy.NewCA(time.Now())
	if err != nil {
		return err
	}
	env, err := proxy.EnvFile(creds.Claude, creds.GitHub)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"proxy.yaml", cfg, 0o644}, {"ca.crt", cert, 0o644}, {"ca.key", key, 0o644}, {"proxy.env", env, 0o600}} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// createNetwork creates the internal network on a random private subnet,
// trying another one when a subnet is already taken.
func createNetwork(rt container.Runtime, name string) (sandbox.Network, string, error) {
	var last error
	for range 8 {
		b := make([]byte, 1)
		rand.Read(b)
		n := sandbox.Network{Name: name, Subnet: fmt.Sprintf("10.213.%d.0/24", b[0])}
		if _, err := rt.Run(n.CreateArgs()...); err != nil {
			last = err
			continue
		}
		return n, fmt.Sprintf("10.213.%d.2", b[0]), nil
	}
	return sandbox.Network{}, "", fmt.Errorf("creating the internal network: %w", last)
}

func waitListening(rt container.Runtime, name string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := rt.Combined("logs", name)
		if strings.Contains(logs, "https proxy starting") {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("the proxy did not start listening in time")
}
