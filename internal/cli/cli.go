// Package cli parses Sealroom's command line and dispatches to the launcher.
// It holds no launcher logic.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"

	"github.com/gwenneg/sealroom/internal/container"
	creds "github.com/gwenneg/sealroom/internal/credentials"
	"github.com/gwenneg/sealroom/internal/launcher"
	"github.com/gwenneg/sealroom/internal/proxy"
	"github.com/gwenneg/sealroom/internal/publish"
)

// Version is set at build time with -ldflags "-X ...cli.Version=v1.2.3".
var Version = "dev"

// Exit codes.
const (
	OK      = 0
	Failure = 1
	Usage   = 2
)

const usage = `Sealroom runs an AI agent plugin or skill in a sealed container, with your
credentials held by a proxy outside it.

Usage:
  sealroom login               save your Claude credential in the keychain
  sealroom logout              remove it
  sealroom run <plugin> --repo <owner/repo> [--prompt <text>]
                               run a plugin on a repository, sealed
  sealroom version             print the version

Your Claude credential is a subscription token (claude setup-token) or an
Anthropic API key. It is only ever handed to the proxy.

Environment:
  CLAUDE_CODE_OAUTH_TOKEN      a subscription token, used instead of the keychain
  ANTHROPIC_API_KEY            or an API key
  SEALROOM_RUNTIME             podman or docker; Podman first when both are installed
  SEALROOM_PROXY_IMAGE         the proxy image, sealroom-proxy:dev by default
  SEALROOM_AGENT_IMAGE         the agent image, sealroom-agent:dev by default

Your GitHub token comes from the GitHub CLI's login (gh auth token).

Exit codes:
  0  ok      1  failure      2  usage
`

// session runs a sealed session; tests replace it.
var session = func(opts launcher.Options) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("sealroom run needs a terminal: the session is interactive")
	}
	creds, err := credentials()
	if err != nil {
		return err
	}
	rt, err := container.Detect()
	if err != nil {
		return err
	}
	term := launcher.Terminal{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, TTY: true}
	res, err := launcher.Run(rt, opts, creds, term)
	if err != nil {
		return err
	}
	return launcher.Review(rt, res, opts.AgentImage, publish.CLI{}, term)
}

// Run executes the command line args, writing to stdout and stderr, and
// returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return Usage
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "sealroom %s\n", Version)
		return OK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return OK
	case "run":
		return run(args[1:], stderr)
	case "login":
		return login(stdout, stderr)
	case "logout":
		return logout(stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return Usage
	}
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "the repository to work on, as owner/repo")
	prompt := fs.String("prompt", "", "a first prompt for Claude Code, such as the plugin's command")
	// The plugin comes first, so the flags after it are parsed separately.
	if len(args) == 0 || len(args[0]) == 0 || args[0][0] == '-' {
		fmt.Fprint(stderr, "sealroom run takes a plugin, then --repo\n\n"+usage)
		return Usage
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *repo == "" {
		fmt.Fprint(stderr, "sealroom run takes a plugin, then --repo\n\n"+usage)
		return Usage
	}
	opts := launcher.Options{
		Plugin: args[0], Repo: *repo, Prompt: *prompt,
		ProxyImage: envOr("SEALROOM_PROXY_IMAGE", "sealroom-proxy:dev"),
		AgentImage: envOr("SEALROOM_AGENT_IMAGE", "sealroom-agent:dev"),
	}
	if err := session(opts); err != nil {
		fmt.Fprintf(stderr, "sealroom: %v\n", err)
		return Failure
	}
	return OK
}

// credentials finds the user's Claude credential, in the environment or the
// keychain, and their GitHub token, from the GitHub CLI. They go to the
// proxy only.
func credentials() (launcher.Credentials, error) {
	var c launcher.Credentials
	var err error
	if c.Claude, c.ClaudeAuth, err = creds.Load(creds.System()); err != nil {
		return c, err
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return c, errors.New("no GitHub token: log in with gh auth login")
	}
	c.GitHub = strings.TrimSpace(string(out))
	return c, nil
}

func login(stdout, stderr io.Writer) int {
	kc := creds.System()
	if kc == nil {
		fmt.Fprintln(stderr, "sealroom: no keychain here (on Linux, secret-tool and a Secret Service such as GNOME Keyring). Set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY instead.")
		return Failure
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(stderr, "sealroom: login needs a terminal, to read the credential without showing it")
		return Failure
	}
	fmt.Fprint(stdout, "Paste a Claude subscription token (from claude setup-token) or an Anthropic API key. It will not be shown: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stdout)
	if err != nil {
		fmt.Fprintf(stderr, "sealroom: %v\n", err)
		return Failure
	}
	kind, err := creds.Save(kc, string(secret))
	if err != nil {
		fmt.Fprintf(stderr, "sealroom: %v\n", err)
		return Failure
	}
	what := "subscription token"
	if kind == proxy.APIKey {
		what = "API key"
	}
	fmt.Fprintf(stdout, "Saved your Claude %s in the keychain.\n", what)
	return OK
}

func logout(stdout, stderr io.Writer) int {
	kc := creds.System()
	if kc == nil {
		fmt.Fprintln(stderr, "sealroom: no keychain here, so nothing is saved")
		return OK
	}
	if err := creds.Remove(kc); err != nil {
		fmt.Fprintf(stderr, "sealroom: %v\n", err)
		return Failure
	}
	fmt.Fprintln(stdout, "Removed your Claude credential from the keychain.")
	return OK
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
