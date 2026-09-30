// Package credentials finds the user's Claude credential: in the environment,
// or in the operating system's keychain, where `sealroom login` saves it. It
// is only ever handed to the proxy.
package credentials

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gwenneg/sealroom/internal/proxy"
)

// Kind is how the user reaches Claude.
type Kind = proxy.ClaudeAuth

// The keychain accounts, one per kind of credential. Saving one removes the
// other, so only one credential is ever saved.
const (
	service             = "sealroom"
	subscriptionAccount = "claude-subscription"
	apiKeyAccount       = "anthropic-api-key"
)

// Keychain saves secrets in the operating system's keychain.
type Keychain interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// ErrNotFound means the keychain holds no such secret.
var ErrNotFound = errors.New("not found in the keychain")

var credentialPattern = regexp.MustCompile(`^sk-ant-(oat|api)[0-9]{2}-[A-Za-z0-9_-]{16,512}$`)

// Parse checks a credential and tells which kind it is: a subscription token
// from `claude setup-token`, or an API key. The strict character set also
// keeps a credential from ever carrying a newline or a space into a file or
// a keychain command.
func Parse(credential string) (Kind, error) {
	credential = strings.TrimSpace(credential)
	m := credentialPattern.FindStringSubmatch(credential)
	switch {
	case m == nil:
		return 0, errors.New("this is neither a Claude subscription token (sk-ant-oat…, from claude setup-token) nor an Anthropic API key (sk-ant-api…)")
	case m[1] == "oat":
		return proxy.Subscription, nil
	default:
		return proxy.APIKey, nil
	}
}

func account(kind Kind) string {
	if kind == proxy.APIKey {
		return apiKeyAccount
	}
	return subscriptionAccount
}

// Save saves the credential in the keychain, replacing any saved before.
func Save(kc Keychain, credential string) (Kind, error) {
	credential = strings.TrimSpace(credential)
	kind, err := Parse(credential)
	if err != nil {
		return 0, err
	}
	if err := kc.Set(service, account(kind), credential); err != nil {
		return 0, err
	}
	other := subscriptionAccount
	if kind == proxy.Subscription {
		other = apiKeyAccount
	}
	if err := kc.Delete(service, other); err != nil && !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	return kind, nil
}

// Remove removes any saved credential.
func Remove(kc Keychain) error {
	for _, a := range []string{subscriptionAccount, apiKeyAccount} {
		if err := kc.Delete(service, a); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// Load returns the user's Claude credential: from CLAUDE_CODE_OAUTH_TOKEN or
// ANTHROPIC_API_KEY when set, for scripts, otherwise from the keychain.
func Load(kc Keychain) (string, Kind, error) {
	for _, env := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			kind, err := Parse(v)
			if err != nil {
				return "", 0, fmt.Errorf("%s: %w", env, err)
			}
			return v, kind, nil
		}
	}
	if kc == nil {
		return "", 0, errors.New("no Claude credential: set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY, since no keychain is available here")
	}
	for _, a := range []string{subscriptionAccount, apiKeyAccount} {
		v, err := kc.Get(service, a)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		kind, err := Parse(v)
		if err != nil {
			return "", 0, fmt.Errorf("the credential saved in the keychain: %w", err)
		}
		return v, kind, nil
	}
	return "", 0, errors.New("no Claude credential: run sealroom login")
}
