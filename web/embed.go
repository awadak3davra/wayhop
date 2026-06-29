// Package web embeds the built front-end assets so velinx ships as a single binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

// FS returns the embedded UI file system rooted at the dist directory.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// dist is embedded at build time; this cannot fail in a built binary.
		panic(err)
	}
	return sub
}
