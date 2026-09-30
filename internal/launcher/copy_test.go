package launcher

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyPlugin(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "skills", "setup"), 0o755)
	os.WriteFile(filepath.Join(src, "skills", "setup", "SKILL.md"), []byte("skill"), 0o600)
	os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh"), 0o700)
	os.MkdirAll(filepath.Join(src, ".git", "objects"), 0o755)
	os.WriteFile(filepath.Join(src, ".git", "config"), []byte("x"), 0o644)
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("do not copy"), 0o600)
	os.Symlink(secret, filepath.Join(src, "link"))

	dst := filepath.Join(t.TempDir(), "plugin")
	if err := copyPlugin(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "skills", "setup", "SKILL.md")); err != nil || string(b) != "skill" {
		t.Errorf("SKILL.md not copied: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dst, "skills", "setup", "SKILL.md")); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("SKILL.md is not readable by the agent: %v", info.Mode())
	}
	if info, err := os.Stat(filepath.Join(dst, "run.sh")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("run.sh did not stay executable: %v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); !os.IsNotExist(err) {
		t.Error(".git was copied")
	}
	info, err := os.Lstat(filepath.Join(dst, "link"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was not copied as a link: %v", err)
	}
	if target, _ := os.Readlink(filepath.Join(dst, "link")); target != secret {
		t.Errorf("the link points to %q", target)
	}
}

func TestCopyPluginRefusesSpecialFiles(t *testing.T) {
	src, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(src)
	l, err := net.Listen("unix", filepath.Join(src, "s"))
	if err != nil {
		t.Skip("no unix sockets here")
	}
	defer l.Close()
	if err := copyPlugin(src, filepath.Join(t.TempDir(), "plugin")); err == nil {
		t.Error("a socket in the plugin was accepted")
	}
}
