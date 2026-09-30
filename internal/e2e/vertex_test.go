package e2e

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gwenneg/sealroom/internal/proxy"
	"github.com/gwenneg/sealroom/internal/sandbox"
)

// TestProxyRulesVertex starts the proxy image with Vertex rules and fake
// Google credentials, which can never mint a token. The proxy's own log then
// tells how far each request went: a request to the user's project passes
// the allowlist and fails only when the token is minted, while any other
// project or region, and the Anthropic API, are refused by the allowlist.
func TestProxyRulesVertex(t *testing.T) {
	if os.Getenv("SEALROOM_E2E") != "1" {
		t.Skip("set SEALROOM_E2E=1 to run against a real container runtime")
	}
	image := os.Getenv("SEALROOM_PROXY_IMAGE")
	if image == "" {
		image = "sealroom-proxy:dev"
	}
	const project, region = "sealroom-e2e", "us-east5"

	dir := workDir(t)
	cfg, err := proxy.Config(proxy.Run{ProxyIP: "172.28.0.2", Repo: "cli/cli", Claude: proxy.Vertex, VertexProject: project, VertexRegion: region})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := proxy.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, err := proxy.EnvFile(proxy.Env{GitHub: "ghp_sealroomE2EFakeToken", Vertex: true})
	if err != nil {
		t.Fatal(err)
	}
	google := `{"type":"authorized_user","client_id":"sealroom-e2e","client_secret":"fake","refresh_token":"fake"}`
	for name, data := range map[string][]byte{"proxy.yaml": cfg, "ca.crt": certPEM, "ca.key": keyPEM, "proxy.env": env, "google-credentials.json": []byte(google)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	s := suffix()
	internal := sandbox.Network{Name: "sealroom-e2e-" + s, Subnet: "172.28.0.0/24"}
	outbound := "sealroom-e2e-out-" + s
	must(t, internal.CreateArgs()...)
	t.Cleanup(func() { exec.Command(runtime(), "network", "rm", internal.Name).Run() })
	must(t, "network", "create", outbound)
	t.Cleanup(func() { exec.Command(runtime(), "network", "rm", outbound).Run() })
	p := sandbox.Proxy{
		Name: "sealroom-e2e-proxy-" + s, Image: image, Network: internal, IP: "172.28.0.2",
		Config: filepath.Join(dir, "proxy.yaml"), CACert: filepath.Join(dir, "ca.crt"),
		CAKey: filepath.Join(dir, "ca.key"), EnvFile: filepath.Join(dir, "proxy.env"), Outbound: outbound,
		GoogleCredentials: filepath.Join(dir, "google-credentials.json"),
		Relabel:           runtime() == "podman",
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

	send := func(url string) {
		t.Helper()
		must(t, "run", "--rm", "--pull", "never", "--network", internal.Name, "--dns", p.IP,
			"--mount", "type=bind,src="+p.CACert+",dst=/ca.crt,readonly"+probeLabel(), CurlImage,
			"-s", "-o", "/dev/null", "--cacert", "/ca.crt", "--max-time", "30", "-X", "POST", "-d", "{}",
			"-H", "authorization: Bearer ya29.agent-own-token", url)
	}
	model := "/v1/projects/" + project + "/locations/" + region + "/publishers/anthropic/models/claude-sonnet:streamRawPredict"
	tests := []struct {
		name, host, path, wantRejectedBy string
	}{
		{"the model in the user's project", region + "-aiplatform.googleapis.com", model, "gcp_auth"},
		{"another project", region + "-aiplatform.googleapis.com", strings.Replace(model, project, "someone-else", 1), "allowlist"},
		{"another region", "europe-west1-aiplatform.googleapis.com", strings.ReplaceAll(model, region, "europe-west1"), "allowlist"},
		{"another publisher", region + "-aiplatform.googleapis.com", strings.Replace(model, "anthropic", "google", 1), "allowlist"},
		{"Google's token endpoint", "oauth2.googleapis.com", "/token", "allowlist"},
		{"the Anthropic API", "api.anthropic.com", "/v1/messages", "allowlist"},
	}
	for _, tt := range tests {
		send("https://" + tt.host + tt.path)
	}
	logs := must(t, "logs", p.Name)
	decisions := rejections(t, logs)
	if len(decisions) == 0 {
		t.Fatalf("no request in the proxy's log:\n%s", logs)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decisions[tt.host+tt.path]; got != tt.wantRejectedBy {
				t.Errorf("rejected by %q, want %q", got, tt.wantRejectedBy)
			}
		})
	}
}

// rejections maps each request of the proxy's log to the transform that
// rejected it.
func rejections(t *testing.T, logs string) map[string]string {
	t.Helper()
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(logs))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var entry struct {
			Audit struct {
				Host string `json:"host"`
				Path string `json:"path"`
			} `json:"audit"`
			RejectedBy string `json:"rejected_by"`
		}
		if json.Unmarshal(sc.Bytes(), &entry) == nil && entry.Audit.Host != "" {
			out[entry.Audit.Host+entry.Audit.Path] = entry.RejectedBy
		}
	}
	return out
}
