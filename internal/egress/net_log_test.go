package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// netCheckLines checks that every line of the log is one JSON object of the
// entry's fields, holding no raw control byte a terminal would act on.
func netCheckLines(t *testing.T, log *netLog) []map[string]any {
	t.Helper()
	entries := log.netEntries(t)
	for _, line := range strings.Split(strings.TrimSuffix(log.String(), "\n"), "\n") {
		if !utf8.ValidString(line) {
			t.Errorf("line is not UTF-8: %q", line)
		}
		for _, r := range line {
			if r < 0x20 {
				t.Errorf("raw control %U in %q", r, line)
				break
			}
			// Go's JSON encoder leaves U+0080 to U+009F as they are. U+009B is
			// CSI, which terminals that honor C1 controls act on.
			if r >= 0x80 && r <= 0x9f {
				t.Errorf("raw C1 control %U in %q", r, line)
				break
			}
		}
	}
	allowed := []string{"time", "decision", "reason", "status", "method", "host", "target"}
	for _, e := range entries {
		for k := range e {
			if !slices.Contains(allowed, k) {
				t.Errorf("unexpected field %q in %v", k, e)
			}
		}
		if ts, _ := e["time"].(string); ts == "" {
			t.Errorf("no time in %v", e)
		} else if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			t.Errorf("time %q: %v", ts, err)
		}
	}
	return entries
}

// TestNetAuditOneLinePerDecision: on real sockets, an allowed request, a
// refused one and a refused handshake are one line each, in order, with
// their reason codes.
func TestNetAuditOneLinePerDecision(t *testing.T) {
	rig, agent, _ := netTLSRig(t)
	if c, err := agent.netDial("evil.example", nil); err == nil {
		c.Close()
		t.Fatal("handshake for evil.example")
	}
	netWaitLogHost(t, rig.log, "evil.example")
	c, err := agent.netDial(netHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	for _, raw := range []string{
		"GET /x HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n",
		"GET /y HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n",
	} {
		if _, _, _, err := netExchange(c, br, raw); err != nil {
			t.Fatal(err)
		}
	}
	entries := netCheckLines(t, rig.log)
	if len(entries) != 3 {
		t.Fatalf("%d lines: %s", len(entries), rig.log)
	}
	want := []struct{ decision, reason, host, target string }{
		{"refused", "tls-server-name", "evil.example", ""},
		{"allowed", "", netHost, "/x"},
		{"refused", reasonNoRule, netHost, "/y"},
	}
	for i, w := range want {
		e := entries[i]
		if e["decision"] != w.decision || (w.reason != "" && e["reason"] != w.reason) || e["host"] != w.host || (w.target != "" && e["target"] != w.target) {
			t.Errorf("line %d: %v, want %+v", i, e, w)
		}
	}
}

// TestNetAuditEscapes: whatever bytes the agent puts in a target, a method
// or a server name, each decision stays one JSON line, and no raw control
// byte reaches the log, where a terminal showing it would act on it.
// Sources: CWE-117 (log injection), CVE-2021-44228's lesson that logged
// input is attacker input.
func TestNetAuditEscapes(t *testing.T) {
	cases := map[string]func(*http.Request){
		"newline and a forged line": func(r *http.Request) {
			r.RequestURI = "/x\n{\"decision\":\"allowed\",\"status\":200}"
		},
		"CR LF":               func(r *http.Request) { r.RequestURI = "/x\r\nX: y" },
		"ANSI escape":         func(r *http.Request) { r.RequestURI = "/\x1b[2J\x1b[31mred" },
		"C1 CSI":              func(r *http.Request) { r.RequestURI = "/\u009b2J" },
		"NUL":                 func(r *http.Request) { r.RequestURI = "/x\x00y" },
		"invalid UTF-8":       func(r *http.Request) { r.RequestURI = "/\xff\xfe\xc0\xaf" },
		"line separators":     func(r *http.Request) { r.RequestURI = "/  " },
		"quotes and slashes":  func(r *http.Request) { r.RequestURI = `/x","decision":"allowed` + `\` },
		"method with newline": func(r *http.Request) { r.Method = "GET\n{\"decision\":\"allowed\"}" },
		"host with newline":   func(r *http.Request) { r.Host = "evil\n{\"decision\":\"allowed\"}" },
		"cut inside a rune":   func(r *http.Request) { r.RequestURI = "/" + strings.Repeat("a", 510) + "é" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			log := &netLog{}
			pp, err := newProxy(Config{Placeholder: testPlaceholder, Rules: []Rule{netGet("/x")}}, Secrets{}, log, options{})
			if err != nil {
				t.Fatal(err)
			}
			r := agentRequest("GET", "https://"+netHost+"/x", nil)
			edit(r)
			pp.ServeHTTP(httptest.NewRecorder(), r)
			entries := netCheckLines(t, log)
			if len(entries) != 1 || entries[0]["decision"] != "refused" {
				t.Errorf("%d entries: %s", len(entries), log)
			}
		})
	}
}

// TestNetAuditHandshakeNames: hostile server names are logged as one
// escaped line each, bounded to 255 bytes.
func TestNetAuditHandshakeNames(t *testing.T) {
	rig, agent, _ := netTLSRig(t)
	for name, sni := range map[string]string{
		"forged line":             "evil\n{\"decision\":\"allowed\",\"host\":\"" + netHost + "\"}",
		"ANSI escape":             "\x1b[2Jevil.example",
		"long":                    strings.Repeat("a.", 400) + "example",
		"long, cut inside a rune": strings.Repeat("a", 254) + "é.example",
		"C1 CSI":                  "\u009b2Jevil.example",
	} {
		t.Run(name, func(t *testing.T) {
			if c, err := agent.netDial(sni, func(c *tls.Config) { c.InsecureSkipVerify = true }); err == nil {
				c.Close()
				t.Fatal("handshake succeeded")
			}
		})
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) && strings.Count(rig.log.String(), "\n") < 5; {
		time.Sleep(10 * time.Millisecond)
	}
	entries := netCheckLines(t, rig.log)
	if len(entries) != 5 {
		t.Errorf("%d lines: %s", len(entries), rig.log)
	}
	for _, e := range entries {
		if h, _ := e["host"].(string); len(h) > 255+3 {
			t.Errorf("host of %d bytes", len(h))
		}
	}
}

// TestNetAuditLineBounded: a refused request's line is bounded whatever the
// agent sends. The target is cut at 512 bytes and a server name at 255, but
// the Host and the method are logged whole, up to the 64 KiB of headers.
func TestNetAuditLineBounded(t *testing.T) {
	rig, agent, _ := netTLSRig(t)
	for name, raw := range map[string]string{
		"a 60 KiB Host":   "GET /x HTTP/1.1\r\nHost: " + strings.Repeat("a", 60<<10) + ".example\r\n\r\n",
		"a 60 KiB method": strings.Repeat("G", 60<<10) + " /x HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n",
		"a 60 KiB target": "GET /" + strings.Repeat("a", 60<<10) + " HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			before := len(rig.log.String())
			c, err := agent.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			resp, _, _, err := netExchange(c, bufio.NewReader(c), raw)
			if err != nil {
				t.Fatal(err)
			}
			line := rig.log.String()[before:]
			if line == "" {
				t.Fatalf("no line for a %d", resp.StatusCode)
			}
			if len(line) > 2048 {
				t.Errorf("a %d-byte audit line for one refused request", len(line))
			}
		})
	}
}

// TestNetAuditNoSecrets: no credential ever reaches the log, wherever the
// request carries it: a header, the query, the path. An agent may learn a
// real secret from an upstream that echoes it (redaction is not built), and
// sending it back in a target would write it to the proxy's log, which
// outlives the run's secret files.
func TestNetAuditNoSecrets(t *testing.T) {
	const secret = "ghp_realsecret0123456789abcdef"
	ca := netNewCA(t)
	srv := netUpstream(t, ca.netLeaf(t, nil, netHost), false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for name, edit := range map[string]func(*http.Request){
		"allowed, with the placeholder": func(r *http.Request) { r.Header.Set("Authorization", "token "+testPlaceholder) },
		"in a header":                   func(r *http.Request) { r.Header.Set("X-Note", secret) },
		"in Authorization":              func(r *http.Request) { r.Header.Set("Authorization", "token "+secret) },
		"in the query":                  func(r *http.Request) { r.RequestURI = "/x?k=" + secret },
		"in the path":                   func(r *http.Request) { r.RequestURI = "/x/" + secret },
	} {
		t.Run(name, func(t *testing.T) {
			rig := netProxy(t, ca.pool, srv.Listener.Addr().String(), Secrets{Values: map[string]string{"gh": secret}},
				Rule{Method: "GET", Host: netHost, Path: "/x", Query: AnyQuery, Headers: []string{"X-Note"},
					Credential: &Credential{Secret: "gh", Header: "Authorization", Scheme: "token"}})
			r := agentRequest("GET", "https://"+netHost+"/x", nil)
			edit(r)
			rig.p.ServeHTTP(httptest.NewRecorder(), r)
			if strings.Contains(rig.log.String(), secret) {
				t.Errorf("the real secret is in the audit log: %s", rig.log)
			}
		})
	}
}

// TestNetRefusalEchoesNothing: a refusal's body is fixed, whatever the
// request held, so it can carry nothing back into the agent's context.
// Source: Squid CVE-2025-62168 (credentials in error pages).
func TestNetRefusalEchoesNothing(t *testing.T) {
	rig := netHTTPRig(t, false, nil, netGet("/x"))
	for _, target := range []string{"/<script>alert(1)</script>", "/x?token=" + testPlaceholder, "/" + strings.Repeat("a", 3000), "/x/../y"} {
		r := agentRequest("GET", "https://"+netHost+"/x", nil)
		r.RequestURI = target
		r.Header.Set("X-Echo", "echo-me")
		w := httptest.NewRecorder()
		rig.p.ServeHTTP(w, r)
		body, _ := io.ReadAll(w.Body)
		if !strings.HasPrefix(string(body), "sealroom: refused (") || len(body) > 64 || strings.Contains(string(body), "echo-me") ||
			w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || w.Header().Get("Connection") != "close" {
			t.Errorf("%s: %d %v %q", target, w.Code, w.Header(), body)
		}
	}
}
