// Package declare reads what a plugin declares it needs beyond Sealroom's
// defaults, from sealroom.json at the plugin's root. The file comes from the
// plugin, so it is untrusted input: size-limited, parsed strictly, and
// validated before anything from it reaches the proxy's rules or the user's
// terminal. A declaration only adds allowed requests, never a credential.
package declare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// FileName is the declaration's file, at the plugin's root.
const FileName = "sealroom.json"

// Limits on a declaration.
const (
	maxBytes   = 16 << 10
	maxEntries = 20
	maxWhy     = 200
)

// Access is one kind of request the plugin needs.
type Access struct {
	Host    string   `json:"host"`
	Methods []string `json:"methods"`
	Paths   []string `json:"paths"`
	Why     string   `json:"why"`
}

// Declaration is what a plugin declares.
type Declaration struct {
	Network []Access `json:"network"`
}

var (
	hostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	pathPattern = regexp.MustCompile(`^/[A-Za-z0-9/_.~*@:+-]{0,255}$`)
	methods     = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
)

// credentialHosts are where the proxy adds the user's credentials. A plugin
// can never open them. On GitHub, it can only add git fetches, which never
// carry the user's token outside the run's repository.
var credentialHosts = []string{"api.anthropic.com", "claude.ai", "anthropic.com"}

var gitHubHosts = []string{"github.com", "api.github.com", "raw.githubusercontent.com"}

// Read reads the plugin's declaration. A plugin without one declares
// nothing.
func Read(pluginDir string) (Declaration, error) {
	root, err := os.OpenRoot(pluginDir)
	if err != nil {
		return Declaration{}, err
	}
	defer root.Close()
	info, err := root.Lstat(FileName)
	if errors.Is(err, os.ErrNotExist) {
		return Declaration{}, nil
	}
	if err != nil {
		return Declaration{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return Declaration{}, fmt.Errorf("%s must be a regular file of at most %d bytes", FileName, maxBytes)
	}
	f, err := root.Open(FileName)
	if err != nil {
		return Declaration{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return Declaration{}, err
	}
	return Parse(b)
}

// Parse parses and validates a declaration.
func Parse(b []byte) (Declaration, error) {
	if len(b) > maxBytes {
		return Declaration{}, fmt.Errorf("%s is larger than %d bytes", FileName, maxBytes)
	}
	var d Declaration
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Declaration{}, fmt.Errorf("%s: %w", FileName, err)
	}
	if dec.More() {
		return Declaration{}, fmt.Errorf("%s: more than one JSON value", FileName)
	}
	if len(d.Network) > maxEntries {
		return Declaration{}, fmt.Errorf("%s declares more than %d accesses", FileName, maxEntries)
	}
	for i, a := range d.Network {
		if err := check(a); err != nil {
			return Declaration{}, fmt.Errorf("%s, access %d: %w", FileName, i+1, err)
		}
	}
	return d, nil
}

func check(a Access) error {
	switch {
	case !hostPattern.MatchString(a.Host):
		return fmt.Errorf("host %q must be a plain DNS name: no address, port, wildcard or capital", a.Host)
	case a.Host == "localhost" || strings.HasSuffix(a.Host, ".localhost") || strings.HasSuffix(a.Host, ".internal") || strings.HasSuffix(a.Host, ".local"):
		return fmt.Errorf("host %q is a local name", a.Host)
	case slices.Contains(credentialHosts, a.Host) || strings.HasSuffix(a.Host, ".anthropic.com") || strings.HasSuffix(a.Host, ".googleapis.com"):
		return fmt.Errorf("host %q is where Sealroom adds the user's credentials, which a plugin can never open", a.Host)
	case len(a.Methods) == 0 || len(a.Paths) == 0:
		return errors.New("methods and paths are required: an access is never a whole host")
	case strings.TrimSpace(a.Why) == "" || len(a.Why) > maxWhy:
		return fmt.Errorf("why is required, in at most %d bytes", maxWhy)
	}
	for _, m := range a.Methods {
		if !slices.Contains(methods, m) {
			return fmt.Errorf("method %q is not one of %v", m, methods)
		}
	}
	for _, p := range a.Paths {
		if !pathPattern.MatchString(p) || slices.Contains(strings.Split(p, "/"), "..") {
			return fmt.Errorf("path %q must start with / and hold no dot-dot segment or unusual character", p)
		}
	}
	if slices.Contains(gitHubHosts, a.Host) {
		// Only git fetches, of any public repository: the defaults already
		// allow the API's and raw files' reads, and a page of github.com
		// could carry data in its path to a repository's traffic insights.
		if a.Host != "github.com" {
			return fmt.Errorf("on %s, Sealroom's defaults already allow every read, and nothing more can be declared", a.Host)
		}
		for _, p := range a.Paths {
			if !strings.HasSuffix(p, "/info/refs") && !strings.HasSuffix(p, "/git-upload-pack") {
				return fmt.Errorf("on github.com, only git fetches can be declared: %s is not one", p)
			}
		}
		for _, m := range a.Methods {
			if m != "GET" && m != "POST" {
				return fmt.Errorf("on github.com, a git fetch is a GET and a POST: %s is not one", m)
			}
		}
	}
	return nil
}
