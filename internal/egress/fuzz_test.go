package egress

import (
	"bufio"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

// FuzzCheckRequest sends raw requests through Go's HTTP parser, as the
// proxy's server reads them, and checks that whatever the checks accept is in
// its one canonical form: no path or host the proxy and a server could read
// differently ever reaches a rule.
func FuzzCheckRequest(f *testing.F) {
	for _, seed := range []string{
		"GET /v1/messages?beta=true HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST /o/r.git/git-upload-pack HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"GET /v1/%2e%2e/files HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET /a//b;c HTTP/1.1\r\nHost: example.com.\r\n\r\n",
		"GET http://evil/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: example.com:443\r\nConnection: x-api-key\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return
		}
		r.TLS = &tls.ConnectionState{ServerName: "example.com"}
		path, query, ref := checkRequest(r, "example.com")
		if ref != nil {
			return
		}
		switch {
		case !strings.HasPrefix(r.RequestURI, "/"):
			t.Fatalf("accepted target %q", r.RequestURI)
		case strings.ContainsAny(path, "%;\\#?") || strings.Contains(path, "//"):
			t.Fatalf("accepted path %q", path)
		case strings.Contains(path+"/", "/./") || strings.Contains(path+"/", "/../"):
			t.Fatalf("accepted a dot segment in %q", path)
		case path+map[bool]string{true: "?" + query}[query != "" || strings.HasSuffix(r.RequestURI, "?")] != r.RequestURI:
			t.Fatalf("path %q and query %q are not the target %q", path, query, r.RequestURI)
		case strings.TrimSuffix(r.Host, ":443") != "example.com":
			t.Fatalf("accepted host %q", r.Host)
		case r.URL.Path != path:
			t.Fatalf("Go reads the path as %q, the proxy as %q", r.URL.Path, path)
		}
		for name, values := range r.Header {
			if len(values) != 1 || strings.ContainsAny(values[0], "\r\n\x00") {
				t.Fatalf("accepted header %s %q", name, values)
			}
		}
		// Matching never panics on what is accepted.
		Config{Rules: []Rule{{Method: "GET", Host: "example.com", Path: "/v1/**"}}}.match(r.Method, "example.com", path, query)
	})
}
