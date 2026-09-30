package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var network = Network{Name: "sealroom-test", Subnet: "172.30.0.0/24"}

func testProxy(t *testing.T) Proxy {
	dir := t.TempDir()
	return Proxy{
		Name: "sealroom-proxy", Image: "proxy@sha256:abc", Network: network, IP: "172.30.0.2",
		Config: filepath.Join(dir, "proxy.yaml"), CACert: filepath.Join(dir, "ca.crt"),
		CAKey: filepath.Join(dir, "ca.key"), EnvFile: filepath.Join(dir, "proxy.env"), Outbound: "sealroom-out",
	}
}

func testAgent(t *testing.T) Agent {
	dir := t.TempDir()
	return Agent{
		Name: "sealroom-agent", Image: "agent@sha256:def", Network: network, ProxyIP: "172.30.0.2",
		Plugin: filepath.Join(dir, "plugin"), Repo: filepath.Join(dir, "src"),
		CACert: filepath.Join(dir, "ca.crt"), Out: filepath.Join(dir, "out"),
		Env:     map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": Placeholder, "GH_TOKEN": Placeholder, "TERM": "xterm-256color"},
		Command: []string{"claude"},
	}
}

// pairs returns the option-value pairs of args, so a test can look for a
// flag with its exact value.
func pairs(args []string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		out = append(out, args[i]+" "+args[i+1])
	}
	return out
}

// forbidden lists options that would break the seal of either container.
var forbidden = []string{
	"--privileged", "--cap-add", "--device", "--volume", "-v", "--volumes-from",
	"--pid", "--ipc", "--uts", "--userns", "--network=host", "--net", "--add-host",
	"--security-opt=seccomp=unconfined", "--publish", "-p", "--publish-all", "-P",
}

func checkForbidden(t *testing.T, args []string) {
	t.Helper()
	for _, a := range args {
		for _, f := range forbidden {
			if a == f || strings.HasPrefix(a, f+"=") {
				t.Errorf("forbidden option %q in %v", a, args)
			}
		}
		if strings.Contains(a, "unconfined") || a == "host" || strings.Contains(a, "label=disable") || strings.Contains(a, "label:disable") {
			t.Errorf("forbidden value %q in %v", a, args)
		}
	}
}

// TestArgsSeal pins every restriction of both containers. It must only ever
// change together with the design and the threat model.
func TestArgsSeal(t *testing.T) {
	t.Run("network", func(t *testing.T) {
		if !slices.Contains(network.CreateArgs(), "--internal") {
			t.Error("the network between the agent and the proxy must be internal")
		}
	})

	t.Run("proxy", func(t *testing.T) {
		p := testProxy(t)
		args, err := p.RunArgs()
		if err != nil {
			t.Fatal(err)
		}
		checkForbidden(t, args)
		want := []string{
			"--pull never", "--network " + network.Name, "--ip 172.30.0.2", "--cap-drop ALL",
			"--security-opt no-new-privileges", "--memory " + Memory, "--cpus " + CPUs, "--pids-limit " + PidsLimit,
			"--env-file " + p.EnvFile,
		}
		for _, w := range want {
			if !slices.Contains(pairs(args), w) {
				t.Errorf("proxy is missing %q", w)
			}
		}
		if !slices.Contains(args, "--read-only") {
			t.Error("proxy root must be read-only")
		}
		for _, m := range mounts(args) {
			if !strings.HasSuffix(m, ",readonly") {
				t.Errorf("proxy mount %q must be read-only", m)
			}
		}
		if n := len(mounts(args)); n != 3 {
			t.Errorf("proxy has %d mounts, want the config, the CA certificate and the CA key", n)
		}
	})

	t.Run("agent", func(t *testing.T) {
		a := testAgent(t)
		args, err := a.RunArgs()
		if err != nil {
			t.Fatal(err)
		}
		checkForbidden(t, args)
		want := []string{
			"--pull never", "--network " + network.Name, "--dns 172.30.0.2", "--cap-drop ALL",
			"--security-opt no-new-privileges", "--user 10001:10001",
			"--memory " + Memory, "--cpus " + CPUs, "--pids-limit " + PidsLimit,
		}
		for _, w := range want {
			if !slices.Contains(pairs(args), w) {
				t.Errorf("agent is missing %q", w)
			}
		}
		if !slices.Contains(args, "--read-only") {
			t.Error("agent root must be read-only")
		}
		if slices.Contains(args, "--env-file") {
			t.Error("the agent must never receive an env file: credentials go to the proxy only")
		}
		wantMounts := map[string]bool{
			"type=bind,src=" + a.Plugin + ",dst=" + PluginDir + ",readonly": true,
			"type=bind,src=" + a.Repo + ",dst=" + RepoDir + ",readonly":     true,
			"type=bind,src=" + a.CACert + ",dst=" + CACert + ",readonly":    true,
			"type=bind,src=" + a.Out + ",dst=" + OutDir:                     true,
		}
		got := mounts(args)
		if len(got) != len(wantMounts) {
			t.Errorf("agent mounts %v, want exactly %v", got, wantMounts)
		}
		for _, m := range got {
			if !wantMounts[m] {
				t.Errorf("unexpected agent mount %q", m)
			}
		}
	})
}

func TestCleanupSeal(t *testing.T) {
	c := Cleanup{Name: "sealroom-cleanup", Image: "agent@sha256:def", Out: filepath.Join(t.TempDir(), "out")}
	args, err := c.RunArgs()
	if err != nil {
		t.Fatal(err)
	}
	checkForbidden(t, args)
	for _, w := range []string{"--pull never", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges", "--user 10001:10001"} {
		if !slices.Contains(pairs(args), w) {
			t.Errorf("cleanup is missing %q", w)
		}
	}
	if !slices.Contains(args, "--read-only") {
		t.Error("cleanup root must be read-only")
	}
	if got := mounts(args); len(got) != 1 || got[0] != "type=bind,src="+c.Out+",dst="+OutDir {
		t.Errorf("cleanup mounts %v, want the output directory alone", got)
	}
	c.Out = "/"
	if _, err := c.RunArgs(); err == nil {
		t.Error("cleanup accepted the root directory")
	}
}

func mounts(args []string) []string {
	var out []string
	for i, a := range args {
		if a == "--mount" && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

func TestAgentEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"a real credential", map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-real"}, "may only hold the placeholder"},
		{"a real GitHub token", map[string]string{"GH_TOKEN": "ghp_real"}, "may only hold the placeholder"},
		{"a variable outside the list", map[string]string{"GITHUB_TOKEN": Placeholder}, "not allowed"},
		{"a newline", map[string]string{"TERM": "xterm\nEVIL=1"}, "newline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAgent(t)
			a.Env = tt.env
			if _, err := a.RunArgs(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestHostPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	bad := map[string]string{
		"empty":          "",
		"relative":       "plugin",
		"not clean":      "/tmp/a/../b",
		"root":           "/",
		"home":           home,
		"parent of home": filepath.Dir(home),
		"comma":          "/tmp/a,dst=/etc",
		"equals":         "/tmp/a=b",
		"newline":        "/tmp/a\nb",
	}
	for name, path := range bad {
		t.Run(name, func(t *testing.T) {
			a := testAgent(t)
			a.Plugin = path
			if _, err := a.RunArgs(); err == nil {
				t.Errorf("path %q was accepted", path)
			}
		})
	}
	t.Run("under home", func(t *testing.T) {
		if err := checkHostPath(filepath.Join(home, "project")); err != nil {
			t.Errorf("a directory under home was refused: %v", err)
		}
	})
}

func TestAgentTTY(t *testing.T) {
	a := testAgent(t)
	a.TTY = true
	args, err := a.RunArgs()
	if err != nil {
		t.Fatal(err)
	}
	checkForbidden(t, args)
	image := slices.Index(args, a.Image)
	if !slices.Contains(args[:image], "--interactive") || !slices.Contains(args[:image], "--tty") {
		t.Error("an agent on the user's terminal must get --interactive and --tty before its image")
	}
}

// TestRelabel checks the SELinux labels of every mount with Podman: private
// to the container, except the CA certificate that both containers read.
func TestRelabel(t *testing.T) {
	p := testProxy(t)
	p.Relabel = true
	pargs, err := p.RunArgs()
	if err != nil {
		t.Fatal(err)
	}
	a := testAgent(t)
	a.Relabel = true
	aargs, err := a.RunArgs()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{pargs, aargs} {
		checkForbidden(t, args)
		for _, m := range mounts(args) {
			want := ",relabel=private"
			if strings.Contains(m, "dst="+CACert+",") || strings.Contains(m, "dst=/etc/sealroom/ca.crt,") {
				want = ",relabel=shared"
			}
			if !strings.HasSuffix(m, want) {
				t.Errorf("mount %q, want it to end with %q", m, want)
			}
		}
	}
	for _, m := range mounts(aargs) {
		if strings.Contains(m, "dst="+OutDir) && strings.Contains(m, "readonly") {
			t.Errorf("the output directory must stay writable: %q", m)
		}
	}
}

func TestProxyGoogleCredentials(t *testing.T) {
	p := testProxy(t)
	p.GoogleCredentials = filepath.Join(t.TempDir(), "google-credentials.json")
	args, err := p.RunArgs()
	if err != nil {
		t.Fatal(err)
	}
	checkForbidden(t, args)
	want := "type=bind,src=" + p.GoogleCredentials + ",dst=" + GoogleCredentialsDst + ",readonly"
	if !slices.Contains(mounts(args), want) || len(mounts(args)) != 4 {
		t.Errorf("proxy mounts %v, want the three and %s", mounts(args), want)
	}
	if slices.Index(args, p.Image) < slices.Index(args, want) {
		t.Error("the mount comes after the image, where it would be an argument of the proxy")
	}
	p.GoogleCredentials = "/"
	if _, err := p.RunArgs(); err == nil {
		t.Error("the root directory was accepted as the Google credentials")
	}
}
