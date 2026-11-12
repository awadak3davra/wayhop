package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
	"testing/fstest"
)

// The pre-compressed representation is the trimmed source: a comment-only line is gone, the code and
// the line count are not.
func TestStaticGzipCacheDropsComments(t *testing.T) {
	code := strings.Repeat("f(1);\n", 300) // keeps the trimmed file above gzipMinBytes
	src := "// " + strings.Repeat("why this exists ", 100) + "\nconst a = 1; // trailing stays\n" +
		"const t = `\n// inside a template, so it is text\n`;\n" + code
	c := newStaticGzipCache(fstest.MapFS{"app.js": {Data: []byte(src)}})
	body, ok := c.get("app.js")
	if !ok {
		t.Fatal("app.js was not cached")
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	want := "\nconst a = 1; // trailing stays\nconst t = `\n// inside a template, so it is text\n`;\n" + code
	if string(got) != want {
		t.Fatalf("served %q\nwant   %q", got, want)
	}
}
