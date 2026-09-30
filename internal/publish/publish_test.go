package publish

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// fakeGitHub answers gh api calls from a table and records every call.
type fakeGitHub struct {
	answers map[string]string // joined arguments -> output; missing means an error
	calls   [][]string
	body    string // the pull request body, read when gh is called
}

func (f *fakeGitHub) Output(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	if out, ok := f.answers[strings.Join(args, " ")]; ok {
		return out, nil
	}
	if args[0] == "pr" {
		for _, a := range args {
			if name, ok := strings.CutPrefix(a, "--body-file="); ok {
				b, _ := os.ReadFile(name)
				f.body = string(b)
			}
		}
		return "https://github.com/o/r/pull/1\n", nil
	}
	return "", errors.New("not found")
}

func (f *fakeGitHub) Run(args ...string) error {
	f.calls = append(f.calls, args)
	return nil
}

func TestChoose(t *testing.T) {
	req := Request{Repo: "org/repo", Branch: "feature"}
	gh := &fakeGitHub{answers: map[string]string{"api repos/org/repo --jq .permissions.push": "true\n"}}
	target, err := Choose(gh, req)
	if err != nil || target != (Target{PushTo: "org/repo", Head: "feature"}) {
		t.Errorf("with push access: %+v, %v", target, err)
	}

	gh = &fakeGitHub{answers: map[string]string{
		"api repos/org/repo --jq .permissions.push": "false\n",
		"api user --jq .login":                      "me\n",
	}}
	target, err = Choose(gh, req)
	if err != nil || target != (Target{PushTo: "me/repo", Head: "me:feature", Fork: true}) {
		t.Errorf("without push access: %+v, %v", target, err)
	}
	gh.answers["api repos/me/repo --jq .parent.full_name // empty"] = "org/repo\n"
	if !ForkExists(gh, req, target) {
		t.Error("the fork was not found")
	}
	gh.answers["api repos/me/repo --jq .parent.full_name // empty"] = "someone/else\n"
	if ForkExists(gh, req, target) {
		t.Error("a repository forked from elsewhere was taken for the fork")
	}
}

// TestPullRequestArgs: every value from the session is one --flag=value
// argument, so none can be read as another option.
func TestPullRequestArgs(t *testing.T) {
	req := Request{Repo: "org/repo", Title: "--web", Draft: true}
	args := PullRequestArgs(req, Target{Head: "me:--delete"}, "-x", "/run/body.md")
	want := []string{"pr", "create", "--repo=org/repo", "--head=me:--delete", "--base=-x", "--title=--web", "--body-file=/run/body.md", "--draft"}
	if !slices.Equal(args, want) {
		t.Errorf("args %q, want %q", args, want)
	}
}

func TestBase(t *testing.T) {
	valid := func(s string) bool { return !strings.HasPrefix(s, "-") }
	gh := &fakeGitHub{answers: map[string]string{
		"api repos/org/repo --jq .default_branch":              "main\n",
		"api repos/org/repo/branches/release%2F1.0 --jq .name": "release/1.0\n",
	}}
	for base, want := range map[string]string{
		"release/1.0": "release/1.0", // a branch of the repository
		"":            "main",        // none recorded
		"-x":          "main",        // not a valid name
		"gone":        "main",        // not a branch of the repository
		"a#b?c":       "main",        // escaped in the API path, and absent
	} {
		got, err := Base(gh, Request{Repo: "org/repo", Base: base}, valid)
		if err != nil || got != want {
			t.Errorf("Base(%q) = %q, %v, want %q", base, got, err, want)
		}
	}
	for _, c := range gh.calls {
		if strings.ContainsAny(strings.Join(c, " "), "#?") {
			t.Errorf("an unescaped value reached the API path: %q", c)
		}
	}
}

func TestOpenPullRequest(t *testing.T) {
	dir := t.TempDir()
	gh := &fakeGitHub{}
	body := "exact\x1b[8mbytes\n"
	req := Request{Repo: "org/repo", Branch: "feature", Title: "The title", Body: body, Dir: dir}
	url, err := OpenPullRequest(gh, req, Target{Head: "feature"}, "main")
	if err != nil || !strings.Contains(url, "/pull/1") {
		t.Fatalf("%q, %v", url, err)
	}
	var bodyFile string
	for _, a := range gh.calls[len(gh.calls)-1] {
		if strings.HasPrefix(a, "--body-file=") {
			bodyFile = strings.TrimPrefix(a, "--body-file=")
		}
	}
	if bodyFile == "" || !strings.HasPrefix(bodyFile, dir) {
		t.Errorf("body file %q, want one in %s", bodyFile, dir)
	}
	if gh.body != body {
		t.Errorf("gh got the body %q, want the reviewed bytes %q", gh.body, body)
	}
	if _, err := os.Stat(bodyFile); !os.IsNotExist(err) {
		t.Error("the body file was left behind")
	}
	req.Title = "  "
	if _, err := OpenPullRequest(gh, req, Target{Head: "feature"}, "main"); err == nil {
		t.Error("a pull request without a title was opened")
	}
}
