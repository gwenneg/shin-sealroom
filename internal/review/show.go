package review

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Show prints what the session changed on branch, and the pull request it
// prepared, all sanitised.
func Show(w io.Writer, repo, branch string, pr *PullRequest) error {
	log, err := output(repo, "log", "--no-color", "--stat", "--format=%n%h %s%n%n%b", "origin/HEAD..HEAD")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "=== What the session changed, on branch %s ===\n%s\n", Sanitize(branch), Sanitize(log))
	if pr != nil {
		draft := ""
		if pr.Draft {
			draft = " (draft)"
		}
		fmt.Fprintf(w, "=== The pull request it prepared%s ===\nTitle: %s\nBase:  %s\n\n%s\n\n", draft, Sanitize(pr.Title), Sanitize(pr.Base), Sanitize(pr.Body))
	}
	return nil
}

// Diff prints the full diff of what the session changed, sanitised, in a
// pager when w is the terminal.
func Diff(w io.Writer, repo string) error {
	diff, err := output(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "origin/HEAD..HEAD")
	if err != nil {
		return err
	}
	return page(w, Sanitize(diff))
}

// page shows text in a pager when there is one, since a diff can be long.
// The text is sanitised already, so the pager needs no raw control codes.
func page(w io.Writer, text string) error {
	pager, err := exec.LookPath("less")
	if err != nil || w != os.Stdout {
		_, err := io.WriteString(w, text)
		return err
	}
	cmd := exec.Command(pager, "--quit-if-one-screen", "--no-init")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewBufferString(text), os.Stdout, os.Stderr
	return cmd.Run()
}

func output(repo string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return string(out), nil
}
