// Package review reads what a sealed session left in its output directory,
// applies it to the host's clone, and shows it to the user. Everything in
// the output directory was written by the agent, so it is untrusted input:
// read as regular files only, size-limited, validated, and sanitised before
// it reaches the terminal.
package review

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// Limits on what the session can leave.
const (
	MaxPatchBytes = 16 << 20
	MaxBodyBytes  = 64 << 10
	MaxLineBytes  = 256
)

// PullRequest is what the agent asked for with gh pr create.
type PullRequest struct {
	Title, Body, Base string
	Draft             bool
}

// Output is what a session left.
type Output struct {
	Patch  []byte
	Branch string       // the session's branch, not yet validated
	PR     *PullRequest // nil when the agent did not ask for one
}

// Read reads a session's output directory. A path that is not a regular
// file, a symbolic link among them, is refused: the agent could point one at
// a file of the host's.
func Read(dir string) (Output, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Output{}, err
	}
	defer root.Close()

	var out Output
	if out.Patch, err = readFile(root, "changes.patch", MaxPatchBytes); err != nil {
		return Output{}, err
	}
	branch, err := readFile(root, "branch", MaxLineBytes)
	if err != nil {
		return Output{}, err
	}
	out.Branch = firstLine(branch)

	if _, err := root.Lstat("pr"); errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err := isDir(root, "pr"); err != nil {
		return Output{}, err
	}
	pr := &PullRequest{}
	for _, f := range []struct {
		name  string
		limit int64
		set   func([]byte)
	}{
		{"pr/title", MaxLineBytes, func(b []byte) { pr.Title = firstLine(b) }},
		{"pr/body", MaxBodyBytes, func(b []byte) { pr.Body = string(b) }},
		{"pr/base", MaxLineBytes, func(b []byte) { pr.Base = firstLine(b) }},
	} {
		b, err := readFile(root, f.name, f.limit)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Output{}, err
		}
		f.set(b)
	}
	if info, err := root.Lstat("pr/draft"); err == nil {
		if !info.Mode().IsRegular() {
			return Output{}, errors.New("pr/draft is not a regular file")
		}
		pr.Draft = true
	}
	out.PR = pr
	return out, nil
}

func readFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Checked again on the open file, and read no further than the limit.
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return b, nil
}

func isDir(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", name)
	}
	return nil
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(s)
}
