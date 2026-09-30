// Package publish pushes a reviewed branch and opens its pull request, on
// the host, with the user's own GitHub login, after the user's yes. The
// values it sends come from the session, so each is passed to git and gh as
// a single --flag=value argument, which can never be read as another option.
package publish

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Request is what to publish.
type Request struct {
	Repo   string // owner/repo, the user's choice, never the session's
	Clone  string // the host's clone, holding the reviewed branch
	Branch string // validated by internal/review
	Title  string
	Body   string
	Base   string // may be empty or invalid: the default branch is used
	Draft  bool
	Dir    string // where the pull request's body is written for gh
}

// Target says where the branch goes.
type Target struct {
	PushTo string // owner/repo the branch is pushed to
	Head   string // the pull request's head: branch, or owner:branch for a fork
	Fork   bool
}

// GitHub is the GitHub CLI; tests replace it.
type GitHub interface {
	Output(args ...string) (string, error)
	Run(args ...string) error
}

// Choose decides where to push: the repository itself when the user can
// push to it, otherwise the user's fork of the same name.
func Choose(gh GitHub, req Request) (Target, error) {
	canPush, err := gh.Output("api", "repos/"+req.Repo, "--jq", ".permissions.push")
	if err != nil {
		return Target{}, fmt.Errorf("reading your permission on %s: %w", req.Repo, err)
	}
	if strings.TrimSpace(canPush) == "true" {
		return Target{PushTo: req.Repo, Head: req.Branch}, nil
	}
	me, err := gh.Output("api", "user", "--jq", ".login")
	if err != nil {
		return Target{}, fmt.Errorf("reading your GitHub login: %w", err)
	}
	me = strings.TrimSpace(me)
	name := req.Repo[strings.IndexByte(req.Repo, '/')+1:]
	return Target{PushTo: me + "/" + name, Head: me + ":" + req.Branch, Fork: true}, nil
}

// ForkExists reports whether target is a fork of the repository.
func ForkExists(gh GitHub, req Request, target Target) bool {
	parent, err := gh.Output("api", "repos/"+target.PushTo, "--jq", ".parent.full_name // empty")
	return err == nil && strings.TrimSpace(parent) == req.Repo
}

// CreateFork forks the repository into the user's account.
func CreateFork(gh GitHub, req Request) error {
	return gh.Run("repo", "fork", req.Repo, "--clone=false")
}

// Push pushes the branch, never forcing, with the GitHub CLI's login as the
// only credential helper.
func Push(req Request, target Target) error {
	ref := "refs/heads/" + req.Branch
	cmd := exec.Command("git", "-C", req.Clone,
		"-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
		"push", "--", "https://github.com/"+target.PushTo, ref+":"+ref)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// PullRequestArgs returns the arguments of gh pr create. Every value is one
// --flag=value argument.
func PullRequestArgs(req Request, target Target, base, bodyFile string) []string {
	args := []string{"pr", "create",
		"--repo=" + req.Repo, "--head=" + target.Head, "--base=" + base,
		"--title=" + req.Title, "--body-file=" + bodyFile}
	if req.Draft {
		args = append(args, "--draft")
	}
	return args
}

// OpenPullRequest opens the pull request and returns what gh printed, its
// address. The body is written to a file as is: what the user reviewed.
func OpenPullRequest(gh GitHub, req Request, target Target, base string) (string, error) {
	if strings.TrimSpace(req.Title) == "" {
		return "", errors.New("the pull request has no title")
	}
	bodyFile := filepath.Join(req.Dir, "pull-request-body.md")
	if err := os.WriteFile(bodyFile, []byte(req.Body), 0o600); err != nil {
		return "", err
	}
	defer os.Remove(bodyFile)
	return gh.Output(PullRequestArgs(req, target, base, bodyFile)...)
}

// Base returns the pull request's base: the session's when it is a branch of
// the repository, its default branch otherwise.
func Base(gh GitHub, req Request, valid func(string) bool) (string, error) {
	if req.Base != "" && valid(req.Base) {
		if _, err := gh.Output("api", "repos/"+req.Repo+"/branches/"+url.PathEscape(req.Base), "--jq", ".name"); err == nil {
			return req.Base, nil
		}
	}
	def, err := gh.Output("api", "repos/"+req.Repo, "--jq", ".default_branch")
	if err != nil {
		return "", fmt.Errorf("reading the default branch of %s: %w", req.Repo, err)
	}
	return strings.TrimSpace(def), nil
}

// CLI is the GitHub CLI on the host.
type CLI struct{}

// Output runs gh and returns its standard output.
func (CLI) Output(args ...string) (string, error) {
	var stderr strings.Builder
	cmd := exec.Command("gh", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// Run runs gh with its output on the terminal.
func (CLI) Run(args ...string) error {
	cmd := exec.Command("gh", args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}
