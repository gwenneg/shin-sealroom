// Package cli parses Sealroom's command line and dispatches to the launcher.
// It holds no launcher logic.
package cli

import (
	"flag"
	"fmt"
	"io"
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
  sealroom run <plugin> --repo <owner/repo>   run a plugin on a repository, sealed
  sealroom version                            print the version

Exit codes:
  0  ok      1  failure      2  usage
`

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
	// The plugin comes first, so the flags after it are parsed separately.
	if len(args) == 0 || len(args[0]) == 0 || args[0][0] == '-' {
		fmt.Fprint(stderr, "sealroom run takes a plugin, then --repo\n\n"+usage)
		return Usage
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *repo == "" {
		fmt.Fprint(stderr, "sealroom run takes a plugin, then --repo\n\n"+usage)
		return Usage
	}
	fmt.Fprintln(stderr, "sealroom run is not implemented yet")
	return Failure
}
