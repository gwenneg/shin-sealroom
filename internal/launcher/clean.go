package launcher

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gwenneg/sealroom/internal/container"
)

// A run directory's name, as newID makes it. Nothing else under the runs
// directory is ever removed.
var runName = regexp.MustCompile(`^(\d{8}-\d{6})-[0-9a-f]{8}$`)

// Clean removes the runs' directories started before now minus olderThan,
// skipping any run whose containers still exist. It reports what it did.
func Clean(rt container.Runtime, agentImage string, olderThan time.Duration, now time.Time, w io.Writer) error {
	runs, err := RunsDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(runs)
	if os.IsNotExist(err) {
		fmt.Fprintln(w, "sealroom: no runs to clean.")
		return nil
	}
	if err != nil {
		return err
	}
	removed, kept := 0, 0
	for _, e := range entries {
		m := runName.FindStringSubmatch(e.Name())
		// A link or a file there is not Sealroom's: never followed or removed.
		if m == nil || e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		started, err := time.ParseInLocation("20060102-150405", m[1], time.UTC)
		if err != nil || now.Sub(started) < olderThan || inUse(rt, e.Name()) {
			kept++
			continue
		}
		if err := RemoveRun(rt, filepath.Join(runs, e.Name()), agentImage); err != nil {
			fmt.Fprintf(w, "sealroom: could not remove %s: %v\n", e.Name(), err)
			kept++
			continue
		}
		removed++
	}
	fmt.Fprintf(w, "sealroom: removed %d run(s), kept %d.\n", removed, kept)
	return nil
}

// inUse reports whether a run still has containers, running or not.
func inUse(rt container.Runtime, id string) bool {
	out, err := rt.Run("ps", "--all", "--quiet", "--filter", "name=sealroom-"+id+"-")
	return err != nil || strings.TrimSpace(out) != ""
}
