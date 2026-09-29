// Command sealroom runs an AI agent plugin or skill in a sealed container,
// with the user's credentials held by a proxy outside it. See docs/design.md.
package main

import (
	"os"

	"github.com/gwenneg/sealroom/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
