package launcher

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gwenneg/sealroom/internal/container"
)

// fakeRuntime is a runtime whose ps reports no container.
func fakeRuntime(t *testing.T) container.Runtime {
	bin := filepath.Join(t.TempDir(), "fake-runtime")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return container.Runtime{Bin: bin}
}

func TestClean(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	runs, err := RunsDir()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && runs != filepath.Join(home, ".cache", "sealroom", "runs") {
		t.Fatalf("runs in %s", runs)
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	old := filepath.Join(runs, "20260920-120000-aaaaaaaa")
	recent := filepath.Join(runs, "20260930-120000-bbbbbbbb")
	stranger := filepath.Join(runs, "not-a-run")
	for _, d := range []string{old, recent, stranger} {
		os.MkdirAll(filepath.Join(d, "src"), 0o700)
	}
	// A link named like a run, pointing at something of the user's.
	precious := filepath.Join(home, "precious")
	os.MkdirAll(precious, 0o700)
	os.Symlink(precious, filepath.Join(runs, "20200101-000000-cccccccc"))

	var out bytes.Buffer
	if err := Clean(fakeRuntime(t), "agent", 7*24*time.Hour, now, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("the old run was kept")
	}
	for _, keep := range []string{recent, stranger, precious} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("%s was removed", keep)
		}
	}
	if err := Clean(fakeRuntime(t), "agent", 0, now, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(recent); !os.IsNotExist(err) {
		t.Error("--all kept a recent run")
	}
	if _, err := os.Stat(precious); err != nil {
		t.Error("--all followed a link out of the runs directory")
	}
}

func TestCleanSkipsRunsInUse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	runs, _ := RunsDir()
	run := filepath.Join(runs, "20200101-000000-dddddddd")
	os.MkdirAll(run, 0o700)
	bin := filepath.Join(t.TempDir(), "busy-runtime")
	os.WriteFile(bin, []byte("#!/bin/sh\necho 3f2a1b\n"), 0o755)
	var out bytes.Buffer
	if err := Clean(container.Runtime{Bin: bin}, "agent", 0, time.Now(), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(run); err != nil {
		t.Error("a run with containers was removed")
	}
}
