package e2e

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gwenneg/sealroom/internal/container"
	"github.com/gwenneg/sealroom/internal/launcher"
	"github.com/gwenneg/sealroom/internal/proxy"
)

// TestHostile runs whole sealed sessions with a deliberately hostile stand-in
// for Claude Code, derived from the real agent image, and asserts that every
// way out is contained and every attempt to hurt the host through the
// session's output is refused. The stand-in writes one result line per
// attempt into the repository, so the results return to the host in the
// session's patch. docs/proxy-tests/end-to-end.md documents each attempt,
// with its source and its expected outcome.
//
// If an attempt ever succeeds where it should not, the matching assertion
// stays failing on purpose: that is a finding, not a test to weaken.
func TestHostile(t *testing.T) {
	if os.Getenv("SEALROOM_E2E") != "1" {
		t.Skip("set SEALROOM_E2E=1 to run against a real container runtime")
	}
	rt := container.Runtime{Bin: runtime()}
	agentImage := os.Getenv("SEALROOM_AGENT_IMAGE")
	if agentImage == "" {
		agentImage = "sealroom-agent:dev"
	}
	proxyImage := os.Getenv("SEALROOM_PROXY_IMAGE")
	if proxyImage == "" {
		proxyImage = "sealroom-proxy:dev"
	}
	// The hostile stand-in, built on the real agent image exactly as
	// testdata/agent is: the plugin's code runs as the agent's user.
	image := "sealroom-agent-hostile:" + suffix()
	must(t, "build", "--quiet", "--build-arg", "AGENT_IMAGE="+agentImage, "-t", image, "testdata/hostile")
	t.Cleanup(func() { rt.Run("rmi", image) })

	t.Run("the catalogue, through a whole session", func(t *testing.T) {
		hosProbe(t, rt, image, proxyImage)
	})
	t.Run("a symlinked pull-request body is refused", func(t *testing.T) {
		hosReviewRefuses(t, rt, image, proxyImage, "symlink", "not a regular file")
	})
	t.Run("an over-sized patch is refused whole", func(t *testing.T) {
		hosReviewRefuses(t, rt, image, proxyImage, "hugepatch", "larger than")
	})
}

// hosProbe runs the full catalogue session, asserts every result line the
// stand-in wrote, then runs the review and checks that the hostile pull
// request is sanitised, that nothing reaches GitHub, and that the host, the
// run directory and the containers are as expected afterwards.
func hosProbe(t *testing.T, rt container.Runtime, image, proxyImage string) {
	res := hosRun(t, rt, image, proxyImage, "probe")

	patch, err := os.ReadFile(filepath.Join(res.OutDir, "changes.patch"))
	if err != nil {
		t.Fatal(err)
	}
	// Each attempt and the only outcome that proves containment. A different
	// value is a finding: the assertion must stay failing.
	want := map[string]string{
		// No route out but the proxy: an unknown name does not resolve, a raw
		// address has no route, there is no plain-HTTP listener and no other
		// port, and IPv6 has no route either.
		"egress-arbitrary-https": "000",
		"egress-plain-http":      "000",
		"egress-raw-ip-https":    "000",
		"egress-ipv6":            "000",
		"egress-http-to-proxy":   "000",
		"egress-proxy-alt-port":  "000",
		"tcp-proxy-ssh":          "blocked",
		"tcp-proxy-http":         "blocked",
		"tcp-gateway":            "blocked",
		"tcp-metadata":           "blocked",
		"udp-external-dns":       "blocked",
		// DNS carries nothing out: only the run's own hosts resolve, and only
		// to the proxy.
		"dns-exfil":                    "unresolved",
		"dns-host-docker-internal":     "unresolved",
		"dns-host-containers-internal": "unresolved",
		"dns-metadata":                 "unresolved",
		"hosts-entries":                "0",
		"dns-allowed-control":          "resolved",
		// No credential, no secret, no privilege: a non-root user with no
		// capabilities, only placeholders, and neither the CA key nor the
		// proxy's config nor a runtime socket in reach.
		"uid":                   "10001",
		"caps":                  "CapEff:0000000000000000",
		"credential-vars":       "2",
		"placeholders":          "2",
		"real-secrets-env":      "0",
		"ca-key-readable":       "no",
		"proxy-config-readable": "no",
		"docker-socket":         "absent",
		// The proxy is the only exit and it holds the credentials: the
		// placeholder is swapped (the service's 401), a credential of the
		// agent's own is refused (403), the Files API and server-side tools
		// are refused.
		"model-placeholder": "401",
		"model-own-key":     "403",
		"files-api":         "403",
		"server-side-tool":  "403",
		// GitHub: a read of the run's repository carries the user's token (its
		// 401 for the fake token), a credential of the agent's own is refused,
		// and every write is refused.
		"run-repo-read":        "401",
		"other-repo-own-token": "403",
		"github-write-issue":   "403",
		"github-graphql":       "403",
		"github-gist":          "403",
		"other-git-fetch":      "403",
		"attacker-git-push":    "403",
		// Resource limits are in place, and an over-limit allocation is denied.
		"pids-max":      "512",
		"memory-max":    "4294967296",
		"mem-overlimit": "blocked",
		// Nothing writes to the host but the output directory.
		"write-etc":            "blocked",
		"write-usr":            "blocked",
		"write-repo-mount":     "blocked",
		"write-proc-sysrq":     "blocked",
		"cgroup-release-agent": "blocked",
		"out-writable":         "yes",
		"mknod-device":         "blocked",
		"hardlink-ca":          "blocked",
		"fifo-created":         "yes",
	}
	for k, v := range want {
		if !strings.Contains(string(patch), "+"+k+"="+v+"\n") {
			t.Errorf("attempt %q: want %q in the session's patch; the line was:\n%s", k, k+"="+v, hosLine(patch, k))
		}
	}

	// The review: yes to the full diff, no to the push. Nothing may reach
	// GitHub (noGitHub fails the test if it is called), and the branch is
	// kept.
	var shown bytes.Buffer
	outcome, err := launcher.Review(rt, res, image, noGitHub{t},
		launcher.Terminal{In: strings.NewReader("y\nn\n"), Out: &shown, Err: &shown})
	if err != nil {
		t.Fatalf("review: %v\n%s", err, &shown)
	}
	if outcome != launcher.Kept {
		t.Errorf("outcome %v, want the branch kept after a no", outcome)
	}
	s := shown.String()
	// The hostile title, body, commit message and diff are shown with every
	// escape and direction-changing character rendered as text.
	for _, w := range []string{`\x1b[8m`, `\x1b[2J`, `\u202e`, `\x1b[31m`, "Base:  --web"} {
		if !strings.Contains(s, w) {
			t.Errorf("the review did not show %q sanitised:\n%s", w, s)
		}
	}
	if strings.ContainsRune(s, 0x1b) {
		t.Error("a raw escape byte reached the terminal: the review did not sanitise it")
	}
	if strings.ContainsRune(s, 0x202e) {
		t.Error("a raw direction-changing character reached the terminal")
	}

	// The patch applied to the host's own clone, on a branch, with the file.
	src := filepath.Join(res.RunDir, "src")
	if err := exec.Command("git", "-C", src, "cat-file", "-e", "hostile/attempts:sealroom-hostile.txt").Run(); err != nil {
		t.Errorf("the session's commit is not on the host clone's branch: %v", err)
	}

	// The output directory is emptied, including the planted FIFO.
	if entries, err := os.ReadDir(res.OutDir); err != nil || len(entries) != 0 {
		t.Errorf("the output directory was not emptied: %v, %v", entries, err)
	}
	// The run's secrets left the disk.
	for _, name := range []string{"proxy.env", "ca.key"} {
		if _, err := os.Stat(filepath.Join(res.RunDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still on disk: %v", name, err)
		}
	}
	// No container or network is left behind.
	id := filepath.Base(res.RunDir)
	if out := must(t, "ps", "--all", "--quiet", "--filter", "name=sealroom-"+id); strings.TrimSpace(out) != "" {
		t.Errorf("containers left behind: %s", out)
	}
	if out := must(t, "network", "ls", "--quiet", "--filter", "name=sealroom-"+id); strings.TrimSpace(out) != "" {
		t.Errorf("networks left behind: %s", out)
	}
}

// hosReviewRefuses runs a session whose stand-in plants a hostile object in
// the output directory, then asserts the host's review refuses it with want
// in the error, reaches GitHub not at all, and still empties the output.
func hosReviewRefuses(t *testing.T, rt container.Runtime, image, proxyImage, mode, want string) {
	res := hosRun(t, rt, image, proxyImage, mode)
	var shown bytes.Buffer
	outcome, err := launcher.Review(rt, res, image, noGitHub{t},
		launcher.Terminal{In: strings.NewReader(""), Out: &shown, Err: &shown})
	if err == nil {
		t.Fatalf("the review accepted hostile output (%s): outcome %v\n%s", mode, outcome, &shown)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("the review failed with %q, want a refusal mentioning %q", err, want)
	}
	if entries, err := os.ReadDir(res.OutDir); err != nil || len(entries) != 0 {
		t.Errorf("the output directory was not emptied after the refusal: %v, %v", entries, err)
	}
}

// hosRun prepares and runs one sealed session with the hostile stand-in,
// answering nothing, and registers the run's removal. mode selects what the
// stand-in does; the launcher passes it as the session's prompt.
func hosRun(t *testing.T, rt container.Runtime, image, proxyImage, mode string) launcher.Result {
	t.Helper()
	plugin := filepath.Join(workDir(t), "plugin")
	if err := os.Mkdir(plugin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The review applies the session's commit with the host's git.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_COMMITTER_NAME", "hostile-e2e")
	t.Setenv("GIT_COMMITTER_EMAIL", "hostile@sealroom.invalid")
	var log bytes.Buffer
	res, err := launcher.Run(rt,
		launcher.Options{Plugin: plugin, Repo: "octocat/Hello-World", Prompt: mode, ProxyImage: proxyImage, AgentImage: image},
		launcher.Credentials{Claude: "sk-ant-oat01-sealroom-e2e-fake", ClaudeAuth: proxy.Subscription, GitHub: "ghp_sealroomE2EFakeToken"},
		launcher.Terminal{In: strings.NewReader(""), Out: io.Discard, Err: &log})
	if res.RunDir != "" {
		t.Cleanup(func() { launcher.RemoveRun(rt, res.RunDir, image) })
	}
	if err != nil {
		t.Fatalf("run (%s): %v\n%s", mode, err, &log)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the session (%s) exited with %d:\n%s", mode, res.ExitCode, &log)
	}
	return res
}

// hosLine returns the patch's line for a result key, for a readable failure.
func hosLine(patch []byte, key string) string {
	for _, line := range strings.Split(string(patch), "\n") {
		if strings.HasPrefix(line, "+"+key+"=") {
			return line
		}
	}
	return "(the key is absent from the patch)"
}
