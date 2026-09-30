package launcher

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Limits on the plugin's copy.
const (
	maxPluginBytes = 1 << 30
	maxPluginFiles = 100_000
)

// copyPlugin copies the plugin into the run directory, so that what the
// agent mounts, and what Podman relabels for SELinux, is Sealroom's own copy
// and never the user's files. Symbolic links are copied as links and never
// followed, so no file outside the plugin is copied through one. Git
// metadata is skipped. Anything but a file, a directory or a link is refused.
func copyPlugin(src, dst string) error {
	var bytes int64
	files := 0
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" && path != src {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		files++
		if files > maxPluginFiles {
			return fmt.Errorf("the plugin has more than %d files", maxPluginFiles)
		}
		switch mode := info.Mode(); {
		case mode.IsDir():
			return os.MkdirAll(target, 0o755)
		case mode&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case mode.IsRegular():
			bytes += info.Size()
			if bytes > maxPluginBytes {
				return fmt.Errorf("the plugin is larger than %d bytes", maxPluginBytes)
			}
			// Executables stay executable, and everything is readable by
			// the agent's user.
			perm := os.FileMode(0o644)
			if mode&0o111 != 0 {
				perm = 0o755
			}
			return copyFile(path, target, perm)
		default:
			return fmt.Errorf("%s is neither a file, a directory nor a link", rel)
		}
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}
