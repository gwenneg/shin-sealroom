package egress

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// GoogleCredentialsEnv names the file of the user's Google credentials, when
// a rule needs Google tokens.
const GoogleCredentialsEnv = "GOOGLE_APPLICATION_CREDENTIALS"

// Main runs the proxy in its container: the run's rules from configPath, the
// run's CA, and the secrets the rules name, read from the environment. It
// answers DNS on port 53 and HTTPS on port 443 as ip, and logs to log.
func Main(configPath, caCertPath, caKeyPath, ip string, log io.Writer) error {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("the proxy's configuration: %w", err)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("the proxy's address: %w", err)
	}
	ca, key, err := readCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}
	secrets := Secrets{Values: map[string]string{}}
	for _, r := range cfg.Rules {
		switch {
		case r.Credential == nil:
		case r.Credential.Secret == Google:
			if secrets.Google != nil {
				continue
			}
			creds, err := os.ReadFile(os.Getenv(GoogleCredentialsEnv))
			if err != nil {
				return fmt.Errorf("the Google credentials: %w", err)
			}
			if secrets.Google, err = GoogleTokens(creds, UpstreamClient()); err != nil {
				return err
			}
		default:
			secrets.Values[r.Credential.Secret] = os.Getenv(r.Credential.Secret)
		}
	}
	p, err := New(cfg, secrets, log)
	if err != nil {
		return err
	}
	dns, err := net.ListenPacket("udp4", ":53")
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp4", ":443")
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "{\"msg\":\"sealroom proxy listening\",\"rules\":%d}\n", len(cfg.Rules))
	return p.Serve(dns, ln, ca, key, addr)
}

func readCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("the CA certificate and key must be PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("the CA key must be PKCS #8: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("the CA key cannot sign")
	}
	return cert, key, nil
}
