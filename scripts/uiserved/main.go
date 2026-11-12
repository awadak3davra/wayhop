// Command uiserved prints the panel assets as the daemon serves them: every file under web/dist after
// internal/uimin has removed its comments, as one JSON object of path to text.
//
// The gates that measure what a browser downloads (the payload budget) read this instead of web/dist,
// so there is one implementation of the trimming and the number they report is the number on the wire.
//
//	go run ./scripts/uiserved > served.json
package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"os"

	"wayhop/internal/uimin"
	"wayhop/web"
)

func main() {
	ui := web.FS()
	out := map[string]string{}
	err := fs.WalkDir(ui, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(ui, p)
		if err != nil {
			return err
		}
		out[p] = string(uimin.Minify(p, b))
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		log.Fatal(err)
	}
}
