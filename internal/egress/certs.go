package egress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// certs mints the certificates the proxy shows the agent, one per allowed
// host, and none for any other name: a handshake for a name no rule allows
// fails before any HTTP is read.
type certs struct {
	ca      *x509.Certificate
	key     crypto.Signer
	allowed map[string]bool

	mu    sync.Mutex
	cache map[string]*tls.Certificate

	// refused is told of every handshake refused, for the audit log.
	refused func(name string, err error)
}

func newCerts(ca *x509.Certificate, key crypto.Signer, allowed map[string]bool) (*certs, error) {
	if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("the CA certificate cannot sign certificates")
	}
	return &certs{ca: ca, key: key, allowed: allowed, cache: map[string]*tls.Certificate{}}, nil
}

// get is the TLS server's GetCertificate. It refuses a missing name, an
// address, a trailing dot, a non-lowercase or punycode name, and any name
// the rules do not allow.
func (c *certs) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := c.lookup(hello.ServerName)
	if err != nil && c.refused != nil {
		c.refused(hello.ServerName, err)
	}
	return cert, err
}

func (c *certs) lookup(name string) (*tls.Certificate, error) {
	switch {
	case name == "":
		return nil, errors.New("no server name")
	case name != strings.ToLower(name) || strings.HasSuffix(name, ".") || strings.Contains(name, "xn--"):
		return nil, fmt.Errorf("server name %q is not in canonical form", name)
	case !c.allowed[name]:
		return nil, fmt.Errorf("server name %q is not allowed", name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.cache[name]; ok && time.Now().Before(cert.Leaf.NotAfter) {
		return cert, nil
	}
	cert, err := c.mint(name)
	if err != nil {
		return nil, err
	}
	c.cache[name] = cert
	return cert, nil
}

func (c *certs) mint(name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(24 * time.Hour)
	if notAfter.After(c.ca.NotAfter) {
		notAfter = c.ca.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
