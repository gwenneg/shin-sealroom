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

// TestSession runs a whole sealed session with a stand-in for Claude Code
// that probes the way out from inside the agent, and checks what it saw and
// that the session leaves no container or network behind.
func TestSession(t *testing.T) {
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
	testImage := "sealroom-agent-e2e:" + suffix()
	must(t, "build", "--quiet", "--build-arg", "AGENT_IMAGE="+agentImage, "-t", testImage, "testdata/agent")
	t.Cleanup(func() { rt.Run("rmi", testImage) })

	plugin := filepath.Join(workDir(t), "plugin")
	if err := os.Mkdir(plugin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The review applies the session's commit with the host's git.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_COMMITTER_NAME", "e2e")
	t.Setenv("GIT_COMMITTER_EMAIL", "e2e@sealroom.invalid")
	var log bytes.Buffer
	res, err := launcher.Run(rt,
		launcher.Options{Plugin: plugin, Repo: "octocat/Hello-World", ProxyImage: proxyImage, AgentImage: testImage},
		launcher.Credentials{Claude: "sk-ant-oat01-sealroom-e2e-fake", ClaudeAuth: proxy.Subscription, GitHub: "ghp_sealroomE2EFakeToken"},
		launcher.Terminal{In: strings.NewReader(""), Out: io.Discard, Err: &log})
	if res.RunDir != "" {
		// What the agent wrote is owned by its user on Linux: removed from a container.
		t.Cleanup(func() {
			rt.Run("run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", "rm",
				"--mount", "type=bind,src="+res.OutDir+",dst=/out"+strings.Replace(probeLabel(), "shared", "private", 1), testImage, "-rf", "/out/branch", "/out/changes.patch")
			os.RemoveAll(res.RunDir)
		})
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, &log)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the session exited with %d:\n%s", res.ExitCode, &log)
	}

	patch, err := os.ReadFile(filepath.Join(res.OutDir, "changes.patch"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"+model=401",              // the fake subscription token reached Anthropic
		"+other-host=403",         // refused by the proxy
		"+run-repository=401",     // the fake GitHub token was added
		"+credential-variables=2", // the Claude token and the GitHub token...
		"+placeholders=2",         // ...both placeholders
	} {
		if !strings.Contains(string(patch), want+"\n") {
			t.Errorf("the session did not see %q:\n%s", want, patch)
		}
	}

	// The review, answering no to the full diff.
	var shown bytes.Buffer
	if err := launcher.Review(rt, res, testImage, launcher.Terminal{In: strings.NewReader("n\n"), Out: &shown, Err: &shown}); err != nil {
		t.Fatalf("review: %v\n%s", err, &shown)
	}
	for _, want := range []string{"Record what the sealed session saw", "Title: Sealed session results", "Base:  master", "nothing was pushed"} {
		if !strings.Contains(shown.String(), want) {
			t.Errorf("the review did not show %q:\n%s", want, &shown)
		}
	}
	src := filepath.Join(res.RunDir, "src")
	if b, err := exec.Command("git", "-C", src, "log", "-1", "--format=%s", "e2e-branch").Output(); err != nil || strings.TrimSpace(string(b)) != "Record what the sealed session saw" {
		t.Errorf("the session's commit is not on e2e-branch in the host's clone: %q, %v", b, err)
	}
	if entries, err := os.ReadDir(res.OutDir); err != nil || len(entries) != 0 {
		t.Errorf("the output directory was not emptied: %v, %v", entries, err)
	}

	id := filepath.Base(res.RunDir)
	if out := must(t, "ps", "--all", "--quiet", "--filter", "name=sealroom-"+id); strings.TrimSpace(out) != "" {
		t.Errorf("containers left behind: %s", out)
	}
	if out := must(t, "network", "ls", "--quiet", "--filter", "name=sealroom-"+id); strings.TrimSpace(out) != "" {
		t.Errorf("networks left behind: %s", out)
	}
}
