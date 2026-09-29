package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
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
		{"run not implemented", []string{"run", "plugin", "--repo", "o/r"}, Failure, "", "not implemented"},
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
