package credentials

import (
	"strings"
	"testing"

	"github.com/gwenneg/sealroom/internal/proxy"
)

type fakeKeychain map[string]string

func (f fakeKeychain) Get(service, account string) (string, error) {
	v, ok := f[service+"/"+account]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f fakeKeychain) Set(service, account, secret string) error {
	f[service+"/"+account] = secret
	return nil
}

func (f fakeKeychain) Delete(service, account string) error {
	if _, ok := f[service+"/"+account]; !ok {
		return ErrNotFound
	}
	delete(f, service+"/"+account)
	return nil
}

const (
	token  = "sk-ant-oat01-abcdefghijklmnop_QRSTUVWXYZ-0123456789"
	apiKey = "sk-ant-api03-abcdefghijklmnop_QRSTUVWXYZ-0123456789"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]Kind{token: proxy.Subscription, apiKey: proxy.APIKey, "  " + token + "\n": proxy.Subscription} {
		if got, err := Parse(in); err != nil || got != want {
			t.Errorf("Parse(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "sk-ant-oat01-short", "ghp_abcdefghijklmnopqrstuvwxyz", token + " -w other", token + "\nIRON_X=1", "sk-ant-xyz01-abcdefghijklmnopqrstuv", strings.Replace(token, "_", "'", 1)} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted it", bad)
		}
	}
}

func TestSaveKeepsOne(t *testing.T) {
	kc := fakeKeychain{}
	if kind, err := Save(kc, apiKey); err != nil || kind != proxy.APIKey {
		t.Fatal(kind, err)
	}
	if kind, err := Save(kc, " "+token+"\n"); err != nil || kind != proxy.Subscription {
		t.Fatal(kind, err)
	}
	if len(kc) != 1 || kc["sealroom/claude-subscription"] != token {
		t.Errorf("keychain holds %v, want the subscription token alone, trimmed", kc)
	}
	if _, err := Save(kc, "not a credential"); err == nil || len(kc) != 1 {
		t.Error("an invalid credential was saved")
	}
	if err := Remove(kc); err != nil || len(kc) != 0 {
		t.Errorf("remove left %v, %v", kc, err)
	}
}

func TestLoad(t *testing.T) {
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	kc := fakeKeychain{}
	if _, _, err := Load(kc); err == nil || !strings.Contains(err.Error(), "sealroom login") {
		t.Errorf("an empty keychain: %v", err)
	}
	Save(kc, apiKey)
	if v, kind, err := Load(kc); err != nil || v != apiKey || kind != proxy.APIKey {
		t.Errorf("from the keychain: %q, %v, %v", v, kind, err)
	}
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", token)
	if v, kind, err := Load(kc); err != nil || v != token || kind != proxy.Subscription {
		t.Errorf("the environment first: %q, %v, %v", v, kind, err)
	}
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "garbage")
	if _, _, err := Load(kc); err == nil {
		t.Error("an invalid credential in the environment was used")
	}
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	if _, _, err := Load(nil); err == nil || !strings.Contains(err.Error(), "no keychain") {
		t.Errorf("no keychain: %v", err)
	}
}
