package declare

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `{"network": [
  {"host": "api.example.com", "methods": ["GET"], "paths": ["/v1/*"], "why": "Reads release notes"},
  {"host": "github.com", "methods": ["GET", "POST"], "paths": ["/konflux-ci/renovate-config-validator-action.git/info/refs", "/konflux-ci/renovate-config-validator-action.git/git-upload-pack"], "why": "Finds the validator's latest commit"}
]}`

func TestParse(t *testing.T) {
	d, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Network) != 2 || d.Network[0].Host != "api.example.com" {
		t.Errorf("parsed %+v", d)
	}
}

func TestParseRefuses(t *testing.T) {
	access := func(host, method, path string) string {
		return `{"network": [{"host": "` + host + `", "methods": ["` + method + `"], "paths": ["` + path + `"], "why": "x"}]}`
	}
	for name, doc := range map[string]string{
		"an unknown field":        `{"network": [], "credentials": "please"}`,
		"two values":              `{"network": []} {"network": []}`,
		"the Anthropic API":       access("api.anthropic.com", "POST", "/v1/files"),
		"another Anthropic host":  access("console.anthropic.com", "GET", "/"),
		"Vertex":                  access("us-east5-aiplatform.googleapis.com", "POST", "/v1/projects/x/*"),
		"Google's token endpoint": access("oauth2.googleapis.com", "POST", "/token"),
		"a push to GitHub":        access("github.com", "POST", "/attacker/repo.git/git-receive-pack"),
		"a web page of GitHub":    access("github.com", "GET", "/attacker/repo/data-in-the-path"),
		"a write on the API":      access("api.github.com", "POST", "/repos/attacker/repo/issues"),
		"a read on the API":       access("api.github.com", "GET", "/repos/*"),
		"a DELETE on git":         access("github.com", "DELETE", "/o/r.git/info/refs"),
		"an IP address":           access("169.254.169.254", "GET", "/"),
		"localhost":               access("localhost", "GET", "/"),
		"a local name":            access("printer.local", "GET", "/"),
		"an internal name":        access("metadata.google.internal", "GET", "/"),
		"a port":                  access("example.com:8080", "GET", "/"),
		"a wildcard host":         access("*.example.com", "GET", "/"),
		"a capital":               access("Example.com", "GET", "/"),
		"an unknown method":       access("example.com", "CONNECT", "/"),
		"a relative path":         access("example.com", "GET", "v1"),
		"a dot-dot path":          access("example.com", "GET", "/a/../b"),
		"a query in the path":     access("example.com", "GET", "/a?b=c"),
		"no methods":              `{"network": [{"host": "example.com", "methods": [], "paths": ["/"], "why": "x"}]}`,
		"no paths":                `{"network": [{"host": "example.com", "methods": ["GET"], "paths": [], "why": "x"}]}`,
		"no reason":               `{"network": [{"host": "example.com", "methods": ["GET"], "paths": ["/"], "why": " "}]}`,
		"a reason too long":       `{"network": [{"host": "example.com", "methods": ["GET"], "paths": ["/"], "why": "` + strings.Repeat("x", maxWhy+1) + `"}]}`,
		"too many accesses":       `{"network": [` + strings.TrimSuffix(strings.Repeat(`{"host": "example.com", "methods": ["GET"], "paths": ["/"], "why": "x"},`, maxEntries+1), ",") + `]}`,
		"too large":               `{"network": []}` + strings.Repeat(" ", maxBytes),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	if d, err := Read(dir); err != nil || len(d.Network) != 0 {
		t.Errorf("a plugin without a declaration: %+v, %v", d, err)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte(valid), 0o644)
	if d, err := Read(dir); err != nil || len(d.Network) != 2 {
		t.Errorf("read %+v, %v", d, err)
	}
	// A link, to a file of the user's, is never followed.
	other := filepath.Join(t.TempDir(), "elsewhere.json")
	os.WriteFile(other, []byte(valid), 0o644)
	os.Remove(filepath.Join(dir, FileName))
	os.Symlink(other, filepath.Join(dir, FileName))
	if _, err := Read(dir); err == nil {
		t.Error("a linked declaration was read")
	}
}
