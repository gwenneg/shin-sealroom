// Package container finds the container runtime and runs its commands. It
// knows nothing about what it starts: every argument comes from
// internal/sandbox.
package container

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Runtime is Podman or Docker, used through its command line.
type Runtime struct {
	Bin string // the command, such as "podman" or "docker"
}

// Detect returns the runtime named by SEALROOM_RUNTIME, or else Podman, or
// else Docker, whichever is found first on the PATH.
func Detect() (Runtime, error) {
	if name := os.Getenv("SEALROOM_RUNTIME"); name != "" {
		if name != "podman" && name != "docker" {
			return Runtime{}, fmt.Errorf("SEALROOM_RUNTIME is %q, want podman or docker", name)
		}
		if _, err := exec.LookPath(name); err != nil {
			return Runtime{}, fmt.Errorf("SEALROOM_RUNTIME is %s, which is not on the PATH", name)
		}
		return Runtime{Bin: name}, nil
	}
	for _, name := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(name); err == nil {
			return Runtime{Bin: name}, nil
		}
	}
	return Runtime{}, errors.New("neither podman nor docker is on the PATH")
}

// Run runs a command and returns its standard output. On failure, the error
// carries the command's standard error.
func (r Runtime) Run(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(r.Bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", r.Bin, args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Interactive runs a command attached to the given terminal and returns its
// exit code.
func (r Runtime) Interactive(stdin io.Reader, stdout, stderr io.Writer, args ...string) (int, error) {
	cmd := exec.Command(r.Bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// Combined runs a command and returns its standard output and error together,
// as for a container's logs.
func (r Runtime) Combined(args ...string) (string, error) {
	out, err := exec.Command(r.Bin, args...).CombinedOutput()
	return string(out), err
}
