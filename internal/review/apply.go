package review

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Apply creates a branch in the host's clone and applies the session's
// commits to it with git am. The clone is the host's own, which the agent
// only ever had read-only, so no git configuration or hook from the session
// runs on the host. It returns the branch: the session's when its name is
// valid and free, fallback otherwise.
func Apply(repo string, out Output, fallback string) (string, error) {
	if err := checkPaths(repo, out.Patch); err != nil {
		return "", err
	}
	branch := out.Branch
	if !ValidBranch(repo, branch) || git(repo, nil, "rev-parse", "--quiet", "--verify", "refs/heads/"+branch) == nil {
		branch = fallback
	}
	if err := git(repo, nil, "switch", "--quiet", "--create", branch); err != nil {
		return "", err
	}
	if err := git(repo, out.Patch, "am", "--quiet"); err != nil {
		git(repo, nil, "am", "--abort")
		return "", fmt.Errorf("applying the session's changes: %w", err)
	}
	return branch, nil
}

// ValidBranch reports whether name is a branch name git accepts, which
// cannot be read as an option.
func ValidBranch(repo, name string) bool {
	return name != "" && !strings.HasPrefix(name, "-") &&
		git(repo, nil, "check-ref-format", "--branch", name) == nil
}

// checkPaths lists every path the patch touches, without applying it, and
// refuses any under a .git directory: a file written into .git/hooks would
// run on the host at the next git command, the push included.
func checkPaths(repo string, patch []byte) error {
	var stdout bytes.Buffer
	cmd := exec.Command("git", "-C", repo, "apply", "--numstat", "-z", "-")
	cmd.Stdin, cmd.Stdout = bytes.NewReader(patch), &stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reading the session's changes: %w", err)
	}
	for _, field := range strings.FieldsFunc(stdout.String(), func(r rune) bool { return r == 0 || r == '\t' }) {
		for _, part := range strings.Split(field, "/") {
			if strings.EqualFold(strings.TrimRight(part, ". "), ".git") {
				return fmt.Errorf("the session's changes touch %q, under a .git directory", field)
			}
		}
	}
	return nil
}

func git(repo string, stdin []byte, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.New(strings.TrimSpace("git " + args[0] + ": " + err.Error() + ": " + stderr.String()))
	}
	return nil
}
