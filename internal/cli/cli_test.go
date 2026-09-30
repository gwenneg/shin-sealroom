package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gwenneg/sealroom/internal/launcher"
)

func TestRun(t *testing.T) {
	session = func(o launcher.Options) error {
		if o.Repo == "o/fails" {
			return errors.New("the session failed")
		}
		return nil
	}
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no arguments", nil, Usage, "", "Usage:"},
		{"version", []string{"version"}, OK, "sealroom dev", ""},
		{"help", []string{"--help"}, OK, "Usage:", ""},
		{"run without a plugin", []string{"run"}, Usage, "", "takes a plugin"},
		{"run with a flag first", []string{"run", "--repo", "o/r"}, Usage, "", "takes a plugin"},
		{"run without a repository", []string{"run", "plugin"}, Usage, "", "takes a plugin"},
		{"run with an extra argument", []string{"run", "plugin", "--repo", "o/r", "extra"}, Usage, "", "takes a plugin"},
		{"run", []string{"run", "plugin", "--repo", "o/r"}, OK, "", ""},
		{"run with a prompt", []string{"run", "plugin", "--repo", "o/r", "--prompt", "/plugin:start"}, OK, "", ""},
		{"run that fails", []string{"run", "plugin", "--repo", "o/fails"}, Failure, "", "the session failed"},
		{"unknown command", []string{"frobnicate"}, Usage, "", `unknown command "frobnicate"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Run(tt.args, &stdout, &stderr)
			if got != tt.wantCode {
				t.Errorf("exit code %d, want %d", got, tt.wantCode)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout %q does not contain %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunOptions(t *testing.T) {
	var got launcher.Options
	session = func(o launcher.Options) error { got = o; return nil }
	t.Setenv("SEALROOM_AGENT_IMAGE", "agent@sha256:x")
	Run([]string{"run", "./p", "--repo", "o/r", "--prompt", "/p:start"}, &bytes.Buffer{}, &bytes.Buffer{})
	want := launcher.Options{Plugin: "./p", Repo: "o/r", Prompt: "/p:start", ProxyImage: "sealroom-proxy:dev", AgentImage: "agent@sha256:x"}
	if got != want {
		t.Errorf("options %+v, want %+v", got, want)
	}
}
