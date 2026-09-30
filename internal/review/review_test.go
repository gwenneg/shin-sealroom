package review

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "changes.patch"), "the patch")
	write(t, filepath.Join(dir, "branch"), "feature\nignored")
	write(t, filepath.Join(dir, "pr", "title"), "The title\nsecond line")
	write(t, filepath.Join(dir, "pr", "body"), "The body")
	write(t, filepath.Join(dir, "pr", "draft"), "")
	out, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Patch) != "the patch" || out.Branch != "feature" {
		t.Errorf("read %+v", out)
	}
	if out.PR == nil || out.PR.Title != "The title" || out.PR.Body != "The body" || !out.PR.Draft || out.PR.Base != "" {
		t.Errorf("pull request %+v", out.PR)
	}
}

func TestReadWithoutPullRequest(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "changes.patch"), "")
	write(t, filepath.Join(dir, "branch"), "main")
	out, err := Read(dir)
	if err != nil || out.PR != nil {
		t.Errorf("read %+v, %v", out, err)
	}
}

// TestReadRefusesLinks: a link the agent planted must never make the host
// read one of its own files, which would then be shown, or posted.
func TestReadRefusesLinks(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "id_ed25519")
	write(t, secret, "PRIVATE KEY")
	elsewhere := t.TempDir()
	write(t, filepath.Join(elsewhere, "title"), "PRIVATE")

	for name, plant := range map[string]func(dir string){
		"the body": func(dir string) {
			os.MkdirAll(filepath.Join(dir, "pr"), 0o755)
			os.Symlink(secret, filepath.Join(dir, "pr", "body"))
		},
		"the patch": func(dir string) {
			os.Remove(filepath.Join(dir, "changes.patch"))
			os.Symlink(secret, filepath.Join(dir, "changes.patch"))
		},
		"the pr directory": func(dir string) { os.Symlink(elsewhere, filepath.Join(dir, "pr")) },
		"the branch": func(dir string) {
			os.Remove(filepath.Join(dir, "branch"))
			os.Symlink(secret, filepath.Join(dir, "branch"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, "changes.patch"), "p")
			write(t, filepath.Join(dir, "branch"), "b")
			plant(dir)
			out, err := Read(dir)
			if err == nil {
				t.Errorf("a link was followed: %+v", out)
			}
			if strings.Contains(string(out.Patch)+out.Branch, "PRIVATE") || (out.PR != nil && strings.Contains(out.PR.Title+out.PR.Body, "PRIVATE")) {
				t.Error("the host's file was read")
			}
		})
	}
}

func TestReadLimits(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "changes.patch"), "p")
	write(t, filepath.Join(dir, "branch"), strings.Repeat("b", MaxLineBytes+1))
	if _, err := Read(dir); err == nil {
		t.Error("an oversized branch file was accepted")
	}
	write(t, filepath.Join(dir, "branch"), "b")
	write(t, filepath.Join(dir, "pr", "body"), strings.Repeat("x", MaxBodyBytes+1))
	if _, err := Read(dir); err == nil {
		t.Error("an oversized body was accepted")
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"plain\ttext\n":             "plain\ttext\n",
		"hide\x1b[8mthis":           `hide\x1b[8mthis`,
		"back\rover":                `back\x0dover`,
		"reorder\u202eevil":         "reorder\\u202eevil",
		"zero\u200bwidth":           "zero\\u200bwidth",
		"c1\u009bcontrol":           `c1\x9bcontrol`,
		"bad\xffbyte":               `bad\xffbyte`,
		"accents: café, naïve, 日本語": "accents: café, naïve, 日本語",
	} {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// repoWithOrigin returns a clone whose origin has one commit, as the
// launcher's clone is.
func repoWithOrigin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "--bare", "-b", "main", filepath.Join(dir, "origin.git"))
	run("clone", "-q", filepath.Join(dir, "origin.git"), filepath.Join(dir, "seed"))
	write(t, filepath.Join(dir, "seed", "README"), "hello\n")
	run("-C", filepath.Join(dir, "seed"), "add", ".")
	run("-C", filepath.Join(dir, "seed"), "commit", "-q", "-m", "first")
	run("-C", filepath.Join(dir, "seed"), "push", "-q", "origin", "main")
	run("clone", "-q", filepath.Join(dir, "origin.git"), filepath.Join(dir, "clone"))
	// A session's commit, as a patch.
	write(t, filepath.Join(dir, "seed", "README"), "hello, sealed\n")
	run("-C", filepath.Join(dir, "seed"), "commit", "-q", "-a", "-m", "Change the greeting")
	return filepath.Join(dir, "clone")
}

func sessionPatch(t *testing.T, clone string) []byte {
	t.Helper()
	cmd := exec.Command("git", "-C", filepath.Join(filepath.Dir(clone), "seed"), "format-patch", "--stdout", "HEAD~1..HEAD")
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestApply(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
	clone := repoWithOrigin(t)
	branch, err := Apply(clone, Output{Patch: sessionPatch(t, clone), Branch: "greeting"}, "sealroom/fallback")
	if err != nil {
		t.Fatal(err)
	}
	if branch != "greeting" {
		t.Errorf("branch %q, want the session's", branch)
	}
	if b, _ := os.ReadFile(filepath.Join(clone, "README")); string(b) != "hello, sealed\n" {
		t.Errorf("README is %q", b)
	}
}

func TestApplyFallsBackForBadBranches(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
	for _, bad := range []string{"", "main", "-c", "a..b", "bad name", "x\x1by"} {
		clone := repoWithOrigin(t)
		branch, err := Apply(clone, Output{Patch: sessionPatch(t, clone), Branch: bad}, "sealroom/fallback")
		if err != nil {
			t.Fatalf("%q: %v", bad, err)
		}
		if branch != "sealroom/fallback" {
			t.Errorf("branch %q from %q, want the fallback", branch, bad)
		}
	}
}

// TestApplyRefusesGitDirectory: a file written under .git/hooks would run on
// the host at the next git command, the push included.
func TestApplyRefusesGitDirectory(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	clone := repoWithOrigin(t)
	for _, path := range []string{".git/hooks/pre-push", "sub/.git/config", ".GIT/hooks/pre-push"} {
		patch := "From 0 Mon Sep 17 00:00:00 2001\nFrom: t <t@t>\nSubject: [PATCH] hook\n\n---\n" +
			"diff --git a/" + path + " b/" + path + "\nnew file mode 100755\n--- /dev/null\n+++ b/" + path + "\n@@ -0,0 +1 @@\n+echo pwned\n"
		if _, err := Apply(clone, Output{Patch: []byte(patch), Branch: "hook"}, "sealroom/fallback"); err == nil {
			t.Errorf("a patch writing %s was applied", path)
		}
		if _, err := os.Stat(filepath.Join(clone, ".git", "hooks", "pre-push")); err == nil {
			t.Fatal("a hook was written")
		}
	}
}
