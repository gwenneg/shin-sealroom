package egress

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
	"golang.org/x/oauth2"
)

// Limits.
const (
	MaxBodyBytes       = 64 << 20
	maxHeaderBytes     = 64 << 10
	upstreamWaitLimit  = 10 * time.Minute
	readHeaderDeadline = 30 * time.Second
	idleDeadline       = 2 * time.Minute
	maxConnections     = 256
)

// droppedResponseHeaders never reach the agent, beyond the hop-by-hop ones.
var droppedResponseHeaders = map[string]struct{}{"Set-Cookie": {}, "Alt-Svc": {}}

// Proxy serves one run's rules.
type Proxy struct {
	cfg     Config
	allowed map[string]bool
	clients map[string]*http.Transport
	secrets map[string]string
	google  oauth2.TokenSource

	logMu sync.Mutex
	log   io.Writer
}

// options are for tests only: production always uses the system roots, the
// public-address check and port 443.
type options struct {
	roots   *x509.CertPool
	control func(network, address string, c syscall.RawConn) error
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

// Secrets are the user's credentials, by the name rules give them, and the
// source of Google access tokens when a rule needs one.
type Secrets struct {
	Values map[string]string
	Google oauth2.TokenSource
}

// New checks the config and the secrets, and prepares one upstream client
// per host.
func New(cfg Config, secrets Secrets, log io.Writer) (*Proxy, error) {
	return newProxy(cfg, secrets, log, options{control: controlDial})
}

// UpstreamClient is the HTTP client for the proxy's own requests, such as
// minting Google tokens: the same address checks and certificate
// verification as forwarded requests, and no redirect.
func UpstreamClient() *http.Client {
	return upstreamClient(options{control: controlDial})
}

func upstreamClient(o options) *http.Client {
	return &http.Client{
		Transport:     newTransport("", o),
		Timeout:       time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func newTransport(serverName string, o options) *http.Transport {
	dial := o.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, Control: o.control}).DialContext
	}
	return &http.Transport{
		Proxy:                 nil, // never an outbound proxy from the environment
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.roots, ServerName: serverName},
		ForceAttemptHTTP2:     true,
		DisableCompression:    true, // bodies pass untouched, never decompressed
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: upstreamWaitLimit,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
		// A hostile upstream's headers are held in memory before any check.
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
}

func newProxy(cfg Config, secrets Secrets, log io.Writer, o options) (*Proxy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for _, r := range cfg.Rules {
		switch {
		case r.Credential == nil:
		case r.Credential.Secret == Google && secrets.Google == nil:
			return nil, errors.New("a rule needs Google tokens, and there are no Google credentials")
		case r.Credential.Secret != Google && secrets.Values[r.Credential.Secret] == "":
			return nil, fmt.Errorf("a rule needs the secret %q, which is empty", r.Credential.Secret)
		}
	}
	for name, v := range secrets.Values {
		if strings.Contains(v, cfg.Placeholder) || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("the secret %q holds the placeholder or a newline", name)
		}
	}
	p := &Proxy{cfg: cfg, allowed: map[string]bool{}, clients: map[string]*http.Transport{}, secrets: secrets.Values, google: secrets.Google, log: log}
	for _, host := range cfg.Hosts() {
		p.allowed[host] = true
		// One transport per host: no upstream connection is ever shared
		// between destinations.
		p.clients[host] = newTransport(host, o)
	}
	return p, nil
}

// ServeHTTP handles one request from the agent.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := r.TLS
	if wc, ok := r.Context().Value(wireKey{}).(*wireConn); ok {
		if ref := wc.next(); ref != nil {
			p.refuseWire(w, ref)
			return
		}
		cs := wc.tls.ConnectionState()
		state = &cs
	}
	if state == nil || !p.allowed[state.ServerName] {
		p.refuse(w, r, refuse(reasonHost, "no TLS server name the rules allow"), http.StatusForbidden)
		return
	}
	host := state.ServerName
	path, query, ref := checkRequest(r, host)
	if ref != nil {
		p.refuse(w, r, ref, http.StatusForbidden)
		return
	}
	rule, err := p.cfg.match(r.Method, host, path, query)
	if err != nil {
		p.refuse(w, r, &refusal{reasonNoRule, err}, http.StatusForbidden)
		return
	}
	if r.ContentLength > MaxBodyBytes {
		p.refuse(w, r, refuse(reasonTooLarge, "%d bytes", r.ContentLength), http.StatusRequestEntityTooLarge)
		return
	}
	secrets := make([]string, 0, len(p.secrets))
	for _, v := range p.secrets {
		secrets = append(secrets, v)
	}
	if ref := checkCredentials(r, p.cfg.Placeholder, secrets); ref != nil {
		p.refuse(w, r, ref, http.StatusForbidden)
		return
	}

	// The outbound request is built from the checked parts alone: the rule's
	// host, the exact path and query that were matched, and the rule's
	// headers. Nothing else from the inbound request is copied.
	out := &http.Request{
		Method:        r.Method,
		URL:           &url.URL{Scheme: "https", Host: rule.Host, Path: path, RawQuery: query},
		Host:          rule.Host,
		Header:        http.Header{},
		ContentLength: r.ContentLength,
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
	out = out.WithContext(r.Context())
	for _, name := range rule.Headers {
		if v := r.Header.Get(name); v != "" {
			out.Header.Set(name, v)
		}
	}
	var inbound *readErr
	if r.ContentLength != 0 {
		inbound = &readErr{ReadCloser: http.MaxBytesReader(w, r.Body, MaxBodyBytes)}
		out.Body = inbound
		if rule.InspectMessages {
			// Read whole, checked, and forwarded as the same bytes.
			b, ref := checkMessages(out.Body)
			if ref != nil {
				status := http.StatusForbidden
				if ref.reason == reasonTooLarge {
					status = http.StatusRequestEntityTooLarge
				}
				p.refuse(w, r, ref, status)
				return
			}
			out.Body, out.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		}
	}
	// The user's credential is added last, to the request being sent, never
	// taken from or written into anything the agent sent.
	if c := rule.Credential; c != nil {
		secret := p.secrets[c.Secret]
		if c.Secret == Google {
			tok, err := p.google.Token()
			if err != nil || tok.AccessToken == "" {
				p.refuse(w, r, refuse(reasonToken, "no Google access token: %v", err), http.StatusBadGateway)
				return
			}
			secret = tok.AccessToken
		}
		out.Header.Set(c.Header, credentialValue(c, secret))
	}

	// RoundTrip, not a client: redirects are never followed, and each next
	// request from the agent is checked like any other.
	resp, err := p.clients[rule.Host].RoundTrip(out)
	if err != nil {
		var tooLarge *http.MaxBytesError
		var denied, malformed *refusal
		switch {
		case inbound != nil && wireRefusedBody(r, inbound.err, &malformed):
			// The agent's own body was malformed, not the upstream's answer.
			p.refuse(w, r, malformed, http.StatusForbidden)
		case errors.As(err, &tooLarge):
			p.refuse(w, r, refuse(reasonTooLarge, "more than %d bytes", MaxBodyBytes), http.StatusRequestEntityTooLarge)
		case errors.As(err, &denied):
			p.refuse(w, r, denied, http.StatusForbidden)
		default:
			p.refuse(w, r, refuse(reasonUpstream, "%v", err), http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()
	// Go's transport handles the informational responses that precede the
	// real one; a 101 ends the exchange with a protocol switch nobody asked
	// for, since upgrades are refused.
	if resp.StatusCode < 200 {
		p.refuse(w, r, refuse(reasonUpstream, "status %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	connectionListed := map[string]bool{}
	for _, v := range resp.Header.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			connectionListed[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range resp.Header {
		_, hop := hopByHop[name]
		_, dropped := droppedResponseHeaders[name]
		if hop || dropped || connectionListed[name] {
			continue
		}
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	p.audit(r, host, "allowed", "", resp.StatusCode)
	stream(w, resp.Body)
}

// wireRefusedBody reports whether the agent's body was cut for its own
// malformed framing, and why: from the error the body read ended with, or,
// when Go's body reader replaced that error with its own, from the
// connection.
func wireRefusedBody(r *http.Request, err error, ref **refusal) bool {
	if err == nil {
		return false
	}
	if errors.As(err, ref) {
		return true
	}
	if wc, ok := r.Context().Value(wireKey{}).(*wireConn); ok {
		if *ref = wc.refusedBody(); *ref != nil {
			return true
		}
	}
	return false
}

// readErr keeps the error a body read ended with.
type readErr struct {
	io.ReadCloser
	err error
}

func (b *readErr) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// stream copies a response as it arrives, flushing every read, so Claude's
// server-sent events and keep-alives pass without delay. Trailers are never
// copied.
func stream(w http.ResponseWriter, body io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush()
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			// A response cut off upstream must not end cleanly toward the
			// agent: aborting closes the connection without the final chunk,
			// so a truncated pack or file never looks whole.
			panic(http.ErrAbortHandler)
		}
	}
}

// refuseWire answers a request whose head was refused before Go's parser
// read it. Nothing of that head is trusted, so none of it is logged.
func (p *Proxy) refuseWire(w http.ResponseWriter, ref *refusal) {
	status := http.StatusForbidden
	if ref.reason == reasonTooLarge {
		status = http.StatusRequestHeaderFieldsTooLarge
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	io.WriteString(w, "sealroom: refused ("+ref.reason+")\n")
	p.writeEntry(entry{Time: time.Now().UTC().Format(time.RFC3339Nano), Decision: "refused", Reason: ref.reason, Status: status})
}

// refuse answers a refused request with a fixed body naming the reason,
// echoing nothing from the request, and logs it.
func (p *Proxy) refuse(w http.ResponseWriter, r *http.Request, ref *refusal, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	io.WriteString(w, "sealroom: refused ("+ref.reason+")\n")
	p.audit(r, "", "refused", ref.reason, status)
}

// entry is one line of the audit log. It never holds a header value or a
// body, so no credential can reach the log.
type entry struct {
	Time     string `json:"time"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Status   int    `json:"status"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	Target   string `json:"target"`
}

func (p *Proxy) audit(r *http.Request, host, decision, reason string, status int) {
	if host == "" {
		host = r.Host
	}
	p.writeEntry(entry{
		Time: time.Now().UTC().Format(time.RFC3339Nano), Decision: decision, Reason: reason, Status: status,
		Method: p.logged(r.Method, 32), Host: p.logged(host, 255), Target: p.logged(r.RequestURI, 512),
	})
}

// logged is what the log holds of a value the agent chose: at most max
// bytes, and nothing at all if it holds the placeholder or a secret, raw or
// percent-decoded, since an agent could read the log back.
func (p *Proxy) logged(v string, max int) string {
	forms := []string{v}
	if d, err := url.PathUnescape(v); err == nil {
		forms = append(forms, d)
	}
	if d, err := url.QueryUnescape(v); err == nil {
		forms = append(forms, d)
	}
	for _, f := range forms {
		if strings.Contains(f, p.cfg.Placeholder) {
			return "(withheld: a credential)"
		}
		for _, s := range p.secrets {
			if s != "" && strings.Contains(f, s) {
				return "(withheld: a credential)"
			}
		}
	}
	if len(v) > max {
		v = v[:max]
	}
	return v
}

// writeEntry writes one line of the log. encoding/json leaves the C1
// controls, U+0080 to U+009F, unescaped, and some terminals act on them when
// the user reads the log: they are escaped too.
func (p *Proxy) writeEntry(e entry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	var out bytes.Buffer
	for i := 0; i < len(b); i++ {
		if b[i] == 0xc2 && i+1 < len(b) && b[i+1] >= 0x80 && b[i+1] <= 0x9f {
			fmt.Fprintf(&out, `\u%04x`, b[i+1])
			i++
			continue
		}
		out.WriteByte(b[i])
	}
	out.WriteByte('\n')
	p.logMu.Lock()
	defer p.logMu.Unlock()
	p.log.Write(out.Bytes())
}

// auditHandshake logs a TLS handshake refused for its server name: a
// decision like any other, though no HTTP was read.
func (p *Proxy) auditHandshake(name string, err error) {
	p.writeEntry(entry{Time: time.Now().UTC().Format(time.RFC3339Nano), Decision: "refused", Reason: "tls-server-name", Host: p.logged(name, 255)})
}

// Serve answers the agent's DNS on dns and its HTTPS on tlsListener, as
// proxyIP, with certificates signed by the run's CA, until tlsListener is
// closed.
func (p *Proxy) Serve(dns net.PacketConn, tlsListener net.Listener, ca *x509.Certificate, key crypto.Signer, proxyIP netip.Addr) error {
	if !proxyIP.Is4() {
		return errors.New("the proxy's address must be an IPv4 one")
	}
	c, err := newCerts(ca, key, p.allowed)
	if err != nil {
		return err
	}
	c.refused = p.auditHandshake
	go serveDNS(dns, p.allowed, proxyIP)
	srv := p.newServer(c)
	ln := tls.NewListener(netutil.LimitListener(tlsListener, maxConnections), srv.TLSConfig)
	return srv.Serve(wireListener{ln})
}

// newServer is the HTTPS server for the agent.
func (p *Proxy) newServer(c *certs) *http.Server {
	return &http.Server{
		Handler: p,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: c.get,
			NextProtos:     []string{"http/1.1"},
			// A resumed handshake skips GetCertificate, so a session from an
			// allowed name could resume under any other.
			SessionTicketsDisabled: true,
		},
		// An empty map turns HTTP/2 off: the agent speaks HTTP/1.1 only.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		// Every connection passes through wireConn, which hides the TLS
		// connection from Go's server: the proxy reaches it through the
		// request's context.
		ConnContext: wireContext,
		// "OPTIONS *" would be answered by Go's server itself.
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            readHeaderDeadline,
		IdleTimeout:                  idleDeadline,
		MaxHeaderBytes:               maxHeaderBytes,
		// Connection-level errors, such as a refused handshake, are not
		// requests: they stay out of the audit log.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}
