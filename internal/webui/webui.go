// Package webui embeds the built web interface (web/dist, copied here by `make web-embed`) so that
// the lockkeeper binary stays a single file with no Node and no CDN at runtime (ADR 0006).
//
// A fresh clone has no build output; dist holds only a placeholder, `go build` still works, and the
// server then explains how to build the UI instead of serving a blank page.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// FS returns the embedded UI rooted at its index.html.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil { // cannot happen: "dist" is part of the embed pattern
		panic(err)
	}
	return sub
}

// Built reports whether f contains a built UI (an index.html).
func Built(f fs.FS) bool {
	st, err := fs.Stat(f, "index.html")
	return err == nil && !st.IsDir()
}
