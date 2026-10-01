// Package launcher runs a sealed session: it prepares the run on the host,
// starts the proxy and the agent, attaches the agent to the user's terminal,
// and removes what it started when the session ends.
package launcher

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"github.com/gwenneg/sealroom/internal/declare"
	"github.com/gwenneg/sealroom/internal/proxy"
	"github.com/gwenneg/sealroom/internal/publish"
	"github.com/gwenneg/sealroom/internal/review"
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
	Claude     string // empty with Vertex
	ClaudeAuth proxy.ClaudeAuth
	GitHub     string
	Vertex     *Vertex // with proxy.Vertex
}

// Vertex is how the user reaches Claude on Google Vertex AI.
type Vertex struct {
	Project, Region string
	Credentials     string // the host path of the user's Google credentials
}

// Terminal is where the session runs.
type Terminal struct {
	In       io.Reader
	Out, Err io.Writer
	TTY      bool // In is the user's terminal
}

// Result says where a session left its output.
type Result struct {
	Repo     string // owner/repo, as the user asked
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
	res := Result{Repo: opts.Repo, RunDir: runDir, OutDir: filepath.Join(runDir, "out"), ExitCode: -1}
	fmt.Fprintf(term.Err, "sealroom: preparing the run in %s\n", runDir)

	// The agent mounts Sealroom's copy, never the user's plugin directory.
	pluginCopy := filepath.Join(runDir, "plugin")
	if err := copyPlugin(plugin, pluginCopy); err != nil {
		return res, fmt.Errorf("copying the plugin: %w", err)
	}

	// What the plugin declares it needs, read from Sealroom's copy, shown to
	// the user, and allowed only on their yes.
	declared, err := declare.Read(pluginCopy)
	if err != nil {
		return res, fmt.Errorf("the plugin's declaration: %w", err)
	}
	if len(declared.Network) > 0 && !acceptDeclared(declared, term) {
		return res, errors.New("the plugin's declared access was not accepted")
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

	if err := writeProxyFiles(runDir, ip, opts.Repo, creds, declared); err != nil {
		return res, err
	}
	// The copy of the user's Google credentials leaves the disk with the run.
	defer os.Remove(filepath.Join(runDir, "google-credentials.json"))
	p := sandbox.Proxy{
		Name: "sealroom-" + id + "-proxy", Image: opts.ProxyImage, Network: network, IP: ip,
		Config: filepath.Join(runDir, "proxy.json"), CACert: filepath.Join(runDir, "ca.crt"),
		CAKey: filepath.Join(runDir, "ca.key"), EnvFile: filepath.Join(runDir, "proxy.env"), Outbound: outbound,
		Relabel: relabel(rt),
	}
	if creds.ClaudeAuth == proxy.Vertex {
		p.GoogleCredentials = filepath.Join(runDir, "google-credentials.json")
	}
	args, err := p.RunArgs()
	if err != nil {
		return res, err
	}
	// The CA's key is needed only while the proxy runs: it leaves the disk
	// once the proxy is removed, which the deferred calls below do first.
	defer os.Remove(p.CAKey)
	_, err = rt.Run(args...)
	// The runtime read the credentials when it created the container: they
	// leave the disk now, whatever the outcome.
	os.Remove(p.EnvFile)
	if err != nil {
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
		Plugin: pluginCopy, Repo: src, CACert: p.CACert, Hosts: filepath.Join(runDir, "hosts"), Out: res.OutDir, Relabel: relabel(rt),
		Env: agentEnv(creds), Command: agentCommand(opts.Prompt), TTY: term.TTY,
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

// acceptDeclared shows what the plugin declares it needs, sanitised, and asks
// the user whether to allow it for this run.
func acceptDeclared(d declare.Declaration, term Terminal) bool {
	fmt.Fprintln(term.Out, "=== The plugin asks for more network access than Sealroom allows by default ===")
	for _, a := range d.Network {
		fmt.Fprintf(term.Out, "- %s %s%s\n  why: %s\n", strings.Join(a.Methods, ","), a.Host, review.Sanitize(strings.Join(a.Paths, ", "+a.Host)), review.Sanitize(a.Why))
	}
	fmt.Fprintln(term.Out, "No credential of yours is ever added to these requests, and what the plugin sends there leaves your machine.")
	return ask(bufio.NewReader(term.In), term.Out, "Allow this for this run? [y/N] ")
}

// relabel reports whether the mounts get SELinux labels: with Podman, which
// ignores them where SELinux is off. Docker's --mount has no such option, and
// Docker does not confine containers with SELinux unless its daemon is set to.
func relabel(rt container.Runtime) bool {
	return filepath.Base(rt.Bin) == "podman"
}

// agentEnv holds placeholders only, never a credential. With Vertex, Claude
// Code sends no Google credential at all: the proxy adds the token.
func agentEnv(creds Credentials) map[string]string {
	env := map[string]string{"GH_TOKEN": sandbox.Placeholder}
	switch creds.ClaudeAuth {
	case proxy.Vertex:
		env["CLAUDE_CODE_USE_VERTEX"] = "1"
		env["CLAUDE_CODE_SKIP_VERTEX_AUTH"] = "1"
		env["ANTHROPIC_VERTEX_PROJECT_ID"] = creds.Vertex.Project
		env["CLOUD_ML_REGION"] = creds.Vertex.Region
	case proxy.APIKey:
		env["ANTHROPIC_API_KEY"] = sandbox.Placeholder
	default:
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

// RunsDir is where the runs' directories are: under the user's cache
// directory, which Colima shares with its virtual machine on macOS.
func RunsDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "sealroom", "runs"), nil
}

// makeRunDir creates the run's directory. Only the user can enter it; the
// output directory inside is writable by the agent's user.
func makeRunDir(id string) (string, error) {
	runs, err := RunsDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(runs, id)
	if err := os.MkdirAll(runs, 0o700); err != nil {
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
func writeProxyFiles(dir, ip, repo string, creds Credentials, declared declare.Declaration) error {
	run := proxy.Run{ProxyIP: ip, Repo: repo, Claude: creds.ClaudeAuth}
	for _, a := range declared.Network {
		run.Declared = append(run.Declared, proxy.Allow{Host: a.Host, Methods: a.Methods, Paths: a.Paths})
	}
	if creds.ClaudeAuth == proxy.Vertex {
		if creds.Vertex == nil {
			return errors.New("Vertex without a project, a region and credentials")
		}
		run.VertexProject, run.VertexRegion = creds.Vertex.Project, creds.Vertex.Region
	}
	cfg, err := proxy.Config(run)
	if err != nil {
		return err
	}
	hosts, err := proxy.Hosts(cfg)
	if err != nil {
		return err
	}
	cert, key, err := proxy.NewCA(time.Now(), hosts)
	if err != nil {
		return err
	}
	env, err := proxy.EnvFile(proxy.Env{Claude: creds.Claude, GitHub: creds.GitHub, Vertex: creds.ClaudeAuth == proxy.Vertex})
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"proxy.json", cfg, 0o644}, {"ca.crt", cert, 0o644}, {"ca.key", key, 0o644}, {"proxy.env", env, 0o600}, {"hosts", []byte(sandbox.Hosts), 0o644}}
	if creds.ClaudeAuth == proxy.Vertex {
		// A copy: the mount is relabeled for SELinux, which must never touch
		// the user's own file.
		google, err := readGoogleCredentials(creds.Vertex.Credentials)
		if err != nil {
			return err
		}
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{"google-credentials.json", google, 0o644})
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// readGoogleCredentials reads the user's Application Default Credentials and
// checks they are a user login or a service account key, the kinds the
// proxy can mint tokens from.
func readGoogleCredentials(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("Google credentials: %w (run gcloud auth application-default login)", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, fmt.Errorf("Google credentials %s: not a credentials file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kind struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &kind); err != nil || (kind.Type != "authorized_user" && kind.Type != "service_account") {
		return nil, fmt.Errorf("Google credentials %s: want a user login (gcloud auth application-default login) or a service account key", path)
	}
	return b, nil
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
		if strings.Contains(logs, "sealroom proxy listening") {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("the proxy did not start listening in time")
}

// Outcome is how a review ended.
type Outcome int

const (
	// Unchanged: the session changed nothing.
	Unchanged Outcome = iota
	// Kept: nothing was pushed, and the branch stays in the run's clone.
	Kept
	// Published: the branch is pushed and its pull request open.
	Published
)

// Review applies what the session changed to a branch of the host's clone,
// shows it to the user, and on their yes pushes it and opens the pull
// request with their own GitHub login. The output directory is emptied
// whatever the outcome.
func Review(rt container.Runtime, res Result, agentImage string, gh publish.GitHub, term Terminal) (Outcome, error) {
	defer emptyOutput(rt, res, agentImage, term)
	out, err := review.Read(res.OutDir)
	if err != nil {
		return Kept, fmt.Errorf("reading the session's output: %w", err)
	}
	if len(out.Patch) == 0 {
		fmt.Fprintln(term.Err, "sealroom: the session changed nothing.")
		return Unchanged, nil
	}
	src := filepath.Join(res.RunDir, "src")
	branch, err := review.Apply(src, out, "sealroom/"+filepath.Base(res.RunDir))
	if err != nil {
		return Kept, err
	}
	// Without a pull request from the session, the last commit's message
	// makes one, shown before the question like any other.
	pr := out.PR
	if pr == nil {
		pr = &review.PullRequest{Title: gitOutput(src, "log", "-1", "--format=%s"), Body: gitOutput(src, "log", "-1", "--format=%b")}
	}
	if err := review.Show(term.Out, src, branch, pr); err != nil {
		return Kept, err
	}
	answers := bufio.NewReader(term.In)
	if ask(answers, term.Out, "Show the full diff? [y/N] ") {
		if err := review.Diff(term.Out, src); err != nil {
			return Kept, err
		}
	}
	notPushed := func() (Outcome, error) {
		fmt.Fprintf(term.Err, "sealroom: nothing was pushed. The branch %s is in %s, until sealroom clean removes it.\n", review.Sanitize(branch), src)
		return Kept, nil
	}
	if !ask(answers, term.Out, fmt.Sprintf("Push %s and open this pull request on %s? [y/N] ", review.Sanitize(branch), res.Repo)) {
		return notPushed()
	}

	req := publish.Request{Repo: res.Repo, Clone: src, Branch: branch, Title: pr.Title, Body: pr.Body, Base: pr.Base, Draft: pr.Draft, Dir: res.RunDir}
	target, err := publish.Choose(gh, req)
	if err != nil {
		return Kept, err
	}
	if target.Fork && !publish.ForkExists(gh, req, target) {
		if !ask(answers, term.Out, fmt.Sprintf("You cannot push to %s. Create your fork %s? [y/N] ", res.Repo, target.PushTo)) {
			return notPushed()
		}
		if err := publish.CreateFork(gh, req); err != nil {
			return Kept, fmt.Errorf("creating your fork: %w", err)
		}
		// GitHub creates a fork in the background.
		for i := 0; i < 30 && !publish.ForkExists(gh, req, target); i++ {
			time.Sleep(2 * time.Second)
		}
	}
	if err := publish.Push(req, target); err != nil {
		return Kept, fmt.Errorf("pushing %s to %s: %w", branch, target.PushTo, err)
	}
	base, err := publish.Base(gh, req, func(b string) bool { return review.ValidBranch(src, b) })
	if err != nil {
		return Kept, err
	}
	url, err := publish.OpenPullRequest(gh, req, target, base)
	if err != nil {
		return Kept, fmt.Errorf("opening the pull request (the branch is pushed to %s): %w", target.PushTo, err)
	}
	fmt.Fprintf(term.Out, "sealroom: pull request opened: %s\n", strings.TrimSpace(url))
	return Published, nil
}

func gitOutput(repo string, args ...string) string {
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func ask(in *bufio.Reader, out io.Writer, question string) bool {
	fmt.Fprint(out, question)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

// emptyOutput removes what the agent wrote, through a container: on Linux it
// belongs to the agent's user.
func emptyOutput(rt container.Runtime, res Result, agentImage string, term Terminal) {
	c := sandbox.Cleanup{Name: "sealroom-" + filepath.Base(res.RunDir) + "-cleanup", Image: agentImage, Out: res.OutDir, Relabel: relabel(rt)}
	args, err := c.RunArgs()
	if err == nil {
		_, err = rt.Run(args...)
	}
	if err != nil {
		fmt.Fprintf(term.Err, "sealroom: could not empty %s: %v\n", res.OutDir, err)
	}
}

// RemoveRun removes a run's directory. What the agent wrote belongs to its
// user on Linux, so when the user cannot remove it, the output directory is
// emptied through the cleanup container first.
func RemoveRun(rt container.Runtime, dir, agentImage string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	c := sandbox.Cleanup{Name: "sealroom-" + filepath.Base(dir) + "-cleanup", Image: agentImage, Out: filepath.Join(dir, "out"), Relabel: relabel(rt)}
	if args, err := c.RunArgs(); err == nil {
		rt.Run(args...)
	}
	return os.RemoveAll(dir)
}
