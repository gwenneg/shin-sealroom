package e2e

import (
	"bytes"
	"io"
	"os"
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

	id := filepath.Base(res.RunDir)
	if out := must(t, "ps", "--all", "--quiet", "--filter", "name=sealroom-"+id); strings.TrimSpace(out) != "" {
		t.Errorf("containers left behind: %s", out)
	}
	if out := must(t, "network", "ls", "--quiet", "--filter", "name=sealroom-"+id); strings.TrimSpace(out) != "" {
		t.Errorf("networks left behind: %s", out)
	}
}
