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
	"github.com/gwenneg/sealroom/internal/launcher"
	"github.com/gwenneg/sealroom/internal/proxy"
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
  sealroom run <plugin> --repo <owner/repo> [--prompt <text>]
                               run a plugin on a repository, sealed
  sealroom version             print the version

Environment:
  CLAUDE_CODE_OAUTH_TOKEN      a Claude subscription token, from claude setup-token
  ANTHROPIC_API_KEY            or an Anthropic API key
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
	res, err := launcher.Run(rt, opts, creds, launcher.Terminal{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, TTY: true})
	if res.RunDir != "" {
		fmt.Fprintf(os.Stderr, "sealroom: the session ended. Its output is in %s\n", res.OutDir)
	}
	return err
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

// credentials reads the user's Claude credential from the environment and
// their GitHub token from the GitHub CLI. They go to the proxy only.
func credentials() (launcher.Credentials, error) {
	var c launcher.Credentials
	switch {
	case os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "":
		c.Claude, c.ClaudeAuth = os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"), proxy.Subscription
	case os.Getenv("ANTHROPIC_API_KEY") != "":
		c.Claude, c.ClaudeAuth = os.Getenv("ANTHROPIC_API_KEY"), proxy.APIKey
	default:
		return c, errors.New("set CLAUDE_CODE_OAUTH_TOKEN (from claude setup-token) or ANTHROPIC_API_KEY")
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return c, errors.New("no GitHub token: log in with gh auth login")
	}
	c.GitHub = strings.TrimSpace(string(out))
	return c, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
