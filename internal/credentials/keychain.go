package credentials

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// System returns the operating system's keychain: the login Keychain on
// macOS, the Secret Service on Linux (GNOME Keyring, KWallet), or nil when
// there is none. A secret never appears in a command's arguments, where any
// process could read it: both tools receive it on their standard input.
func System() Keychain {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err == nil {
			return macOS{}
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil {
			return secretService{}
		}
	}
	return nil
}

type macOS struct{}

func (macOS) Get(service, account string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading the keychain: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (macOS) Set(service, account, secret string) error {
	// Interactive mode reads the command from standard input. The secret was
	// checked by Parse: it holds no space, quote or newline.
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s -w %s\n", service, account, "Sealroom", secret))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil || stderr.Len() > 0 {
		return fmt.Errorf("saving in the keychain: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (macOS) Delete(service, account string) error {
	err := exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return ErrNotFound
	}
	return err
}

type secretService struct{}

func (secretService) Get(service, account string) (string, error) {
	out, err := exec.Command("secret-tool", "lookup", "service", service, "account", account).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(out) == 0 {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading the Secret Service: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (secretService) Set(service, account, secret string) error {
	cmd := exec.Command("secret-tool", "store", "--label=Sealroom", "service", service, "account", account)
	cmd.Stdin = strings.NewReader(secret)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("saving in the Secret Service: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (secretService) Delete(service, account string) error {
	// secret-tool clear succeeds whether or not the secret existed.
	return exec.Command("secret-tool", "clear", "service", service, "account", account).Run()
}
