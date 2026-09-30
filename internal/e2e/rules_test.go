// Package e2e runs Sealroom's pieces against a real container runtime and the
// real services. It is skipped unless SEALROOM_E2E=1.
package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gwenneg/sealroom/internal/proxy"
	"github.com/gwenneg/sealroom/internal/sandbox"
)

// CurlImage sends the probes from the agent's network.
const CurlImage = "docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"

func runtime() string {
	if r := os.Getenv("CONTAINER_RUNTIME"); r != "" {
		return r
	}
	return "docker"
}

func must(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(runtime(), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", runtime(), strings.Join(args, " "), err, out)
	}
	return string(out)
}

// workDir returns a directory the container runtime can mount: under the
// user's cache directory, since Colima only shares the home directory.
func workDir(t *testing.T) string {
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cache, "sealroom-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// probeLabel lets the probes read the CA certificate under SELinux.
func probeLabel() string {
	if runtime() == "podman" {
		return ",relabel=shared"
	}
	return ""
}

func suffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TestProxyRules starts the proxy image with the rules of a run and probes
// it from the agent's network: every refusal must come from the proxy, every
// allowed request must reach the real service, and the user's credentials
// must be added exactly where the rules say.
func TestProxyRules(t *testing.T) {
	if os.Getenv("SEALROOM_E2E") != "1" {
		t.Skip("set SEALROOM_E2E=1 to run against a real container runtime")
	}
	image := os.Getenv("SEALROOM_PROXY_IMAGE")
	if image == "" {
		image = "sealroom-proxy:dev"
	}
	const runRepo, otherRepo = "cli/cli", "golang/go"

	dir := workDir(t)
	cfg, err := proxy.Config(proxy.Run{ProxyIP: "172.29.0.2", Repo: runRepo, Claude: proxy.Subscription})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := proxy.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Fake credentials: a request that carries one gets a 401 from the real
	// service, which proves the proxy added it.
	env, err := proxy.EnvFile("sk-ant-oat01-sealroom-e2e-fake", "ghp_sealroomE2EFakeToken")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"proxy.yaml": cfg, "ca.crt": certPEM, "ca.key": keyPEM, "proxy.env": env}
	for name, data := range files {
		// The proxy runs as its own user, so it must be able to read them;
		// the directory itself is private to the user.
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	s := suffix()
	internal := sandbox.Network{Name: "sealroom-e2e-" + s, Subnet: "172.29.0.0/24"}
	outbound := "sealroom-e2e-out-" + s
	must(t, internal.CreateArgs()...)
	t.Cleanup(func() { exec.Command(runtime(), "network", "rm", internal.Name).Run() })
	must(t, "network", "create", outbound)
	t.Cleanup(func() { exec.Command(runtime(), "network", "rm", outbound).Run() })

	p := sandbox.Proxy{
		Name: "sealroom-e2e-proxy-" + s, Image: image, Network: internal, IP: "172.29.0.2",
		Config: filepath.Join(dir, "proxy.yaml"), CACert: filepath.Join(dir, "ca.crt"),
		CAKey: filepath.Join(dir, "ca.key"), EnvFile: filepath.Join(dir, "proxy.env"), Outbound: outbound,
		Relabel: runtime() == "podman",
	}
	args, err := p.RunArgs()
	if err != nil {
		t.Fatal(err)
	}
	must(t, args...)
	t.Cleanup(func() { exec.Command(runtime(), "rm", "-f", p.Name).Run() })
	must(t, p.ConnectArgs()...)
	for i := 0; i < 40 && !strings.Contains(must(t, "logs", p.Name), "https proxy starting"); i++ {
		time.Sleep(250 * time.Millisecond)
	}

	// probe returns the status and whether the answer came from the real
	// service: GitHub always sets a request ID and Anthropic's edge a Cloudflare
	// ray ID, while the proxy's own refusals carry neither.
	probe := func(t *testing.T, curlArgs ...string) (string, bool) {
		t.Helper()
		args := append([]string{"run", "--rm", "--pull", "never", "--network", internal.Name, "--dns", p.IP,
			"--mount", "type=bind,src=" + p.CACert + ",dst=/ca.crt,readonly" + probeLabel(), CurlImage,
			"-s", "-o", "/dev/null", "--cacert", "/ca.crt", "--max-time", "30",
			"-w", "%{http_code} %header{x-github-request-id}%header{request-id}%header{cf-ray}"}, curlArgs...)
		out := strings.Fields(must(t, args...))
		if len(out) == 0 {
			t.Fatalf("no answer to %v", curlArgs)
		}
		return out[0], len(out) > 1
	}

	placeholder := "authorization: Bearer " + sandbox.Placeholder
	message := `{"model":"claude-haiku-4-5-20251001","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`
	claude := []string{"-H", "anthropic-version: 2023-06-01", "-H", "content-type: application/json", "-d", message}
	const refused, withCredential, withoutCredential = "refused", "credential added", "no credential"
	tests := []struct {
		name string
		want string
		args []string
	}{
		{"the model, with the placeholder", withCredential, append([]string{"https://api.anthropic.com/v1/messages", "-H", placeholder}, claude...)},
		{"the model, with a key of its own", refused, append([]string{"https://api.anthropic.com/v1/messages", "-H", "authorization: Bearer sk-ant-attacker"}, claude...)},
		{"the model, with the placeholder and a key of its own", withCredential, append([]string{"https://api.anthropic.com/v1/messages", "-H", placeholder, "-H", "x-api-key: sk-ant-attacker"}, claude...)},
		{"the Files API", refused, []string{"-X", "POST", "https://api.anthropic.com/v1/files", "-H", placeholder}},
		{"a read on the run's repository", withCredential, []string{"https://api.github.com/repos/" + runRepo}},
		{"a read on another repository", withoutCredential, []string{"https://api.github.com/repos/" + otherRepo}},
		{"a read on another repository, with a token of its own", withoutCredential, []string{"https://api.github.com/repos/" + otherRepo, "-H", "authorization: Bearer ghp_attacker"}},
		{"a write on the run's repository", refused, []string{"-X", "POST", "https://api.github.com/repos/" + runRepo + "/issues", "-d", "{}"}},
		{"GraphQL", refused, []string{"-X", "POST", "https://api.github.com/graphql", "-d", "{}"}},
		{"a git fetch of the run's repository", withCredential, []string{"https://github.com/" + runRepo + "/info/refs?service=git-upload-pack"}},
		{"a git fetch of another repository", refused, []string{"https://github.com/" + otherRepo + "/info/refs?service=git-upload-pack"}},
		{"a git push to the run's repository", refused, []string{"-X", "POST", "https://github.com/" + runRepo + "/git-receive-pack"}},
		{"another host", refused, []string{"https://example.com/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, upstream := probe(t, tt.args...)
			switch tt.want {
			case refused:
				if code != "403" || upstream {
					t.Errorf("got %s (from the service: %v), want a refusal by the proxy", code, upstream)
				}
			case withCredential:
				if code != "401" || !upstream {
					t.Errorf("got %s (from the service: %v), want the service's 401 for the fake credential", code, upstream)
				}
			case withoutCredential:
				if !upstream || code == "401" {
					t.Errorf("got %s (from the service: %v), want an answer from the service with no credential", code, upstream)
				}
			}
		})
	}
}
