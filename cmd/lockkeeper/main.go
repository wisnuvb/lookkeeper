// Command lockkeeper monitors PostgreSQL health and, in later phases, migrates
// databases between servers.
package main

import (
	"context"
	"os"

	"github.com/wisnuvb/lockkeeper/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background(), cli.OSEnv(), os.Args[1:]))
}
