package uimin

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"wayhop/web"
)

func js(t *testing.T, src string) string {
	t.Helper()
	out, ok := stripJS([]byte(src))
	if !ok {
		t.Fatalf("scanner gave up on:\n%s", src)
	}
	return string(out)
}

func TestStripJSBlanksWholeLineCommentsOnly(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"whole line", "a();\n  // gone\nb();\n", "a();\n\nb();\n"},
		{"trailing stays", "a(); // kept\n", "a(); // kept\n"},
		{"first line", "// gone\na();", "\na();"},
		{"last line without a break", "a();\n// gone", "a();\n"},
		{"in a string", "x = '// kept';\ny = \"// kept\";\n", "x = '// kept';\ny = \"// kept\";\n"},
		{"url in a string", "u = 'http://a/b';\n", "u = 'http://a/b';\n"},
		{"inside a template", "t = `a\n// kept\nb`;\n// gone\n", "t = `a\n// kept\nb`;\n\n"},
		{"inside a substitution", "t = `a${\n// gone\nx}\n// kept\n`;\n", "t = `a${\n\nx}\n// kept\n`;\n"},
		{"nested template", "t = `a${ f(`\n// kept\n`) }\n// kept\n`;\n// gone\n", "t = `a${ f(`\n// kept\n`) }\n// kept\n`;\n\n"},
		{"object in a substitution", "t = `${ {a: {b: 1}}.a.b }\n// kept\n`;\n", "t = `${ {a: {b: 1}}.a.b }\n// kept\n`;\n"},
		{"escaped backtick", "t = `a\\`\n// kept\n`;\n", "t = `a\\`\n// kept\n`;\n"},
		{"regex with a backtick", "r = /`/;\n// gone\nt = `\n// kept\n`;\n", "r = /`/;\n\nt = `\n// kept\n`;\n"},
		{"regex with quotes", "r = x.replace(/[\"'`]/g, '');\n// gone\n", "r = x.replace(/[\"'`]/g, '');\n\n"},
		{"regex with slashes", "r = /^\\s*\\/\\//.test(l);\n// gone\n", "r = /^\\s*\\/\\//.test(l);\n\n"},
		{"regex after return", "return /'/.test(s);\n// gone\n", "return /'/.test(s);\n\n"},
		{"division", "a = b / c; d = '/';\n// gone\n", "a = b / c; d = '/';\n\n"},
		{"division after a call", "a = f(b) / 2 + g[1] / 3;\n// gone\n", "a = f(b) / 2 + g[1] / 3;\n\n"},
		{"block comment", "/* a\n// kept, it is inside the block\n*/ // kept\n// gone\n", "/* a\n// kept, it is inside the block\n*/ // kept\n\n"},
		{"line continuation in a string", "s = 'a\\\n// kept';\n// gone\n", "s = 'a\\\n// kept';\n\n"},
	}
	for _, c := range cases {
		if got := js(t, c.in); got != c.want {
			t.Errorf("%s:\n in  %q\n got %q\n want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestStripJSGivesUpRatherThanGuess(t *testing.T) {
	for name, src := range map[string]string{
		"open template":     "t = `a\n// x\n",
		"open substitution": "t = `a${ x \n",
		"open string":       "s = 'a\n';\n",
		"open block":        "/* a\n",
		"stray brace":       "}\n",
		"open brace":        "f = () => {\n",
		"regex to line end": "a = /abc\n",
	} {
		if _, ok := stripJS([]byte(src)); ok {
			t.Errorf("%s: scanned as clean, want the scanner to give up", name)
		}
		if got := Minify("x.js", []byte(src)); string(got) != src {
			t.Errorf("%s: Minify changed a file the scanner gave up on", name)
		}
	}
}

func TestStripCSS(t *testing.T) {
	in := "/* head\n   more */\n.a { color: red; } /* tail */\n.b::after { content: '/* kept */'; }\n"
	want := "\n\n.a { color: red; } \n.b::after { content: '/* kept */'; }\n"
	out, ok := stripCSS([]byte(in))
	if !ok || string(out) != want {
		t.Fatalf("got %q ok=%v\nwant %q", out, ok, want)
	}
	if _, ok := stripCSS([]byte(".a{} /* open")); ok {
		t.Fatal("an unterminated comment scanned as clean")
	}
}

func TestMinifyLeavesOtherFilesAlone(t *testing.T) {
	src := []byte("<!-- // not ours -->\n// x\n")
	if got := Minify("index.html", src); !bytes.Equal(got, src) {
		t.Fatalf("html was changed: %q", got)
	}
}

// TestEmbeddedPanel runs the real assets through Minify. It proves three things the synthetic cases
// cannot: every shipped file scans cleanly (a file that does not is served with its comments, silently,
// and the payload budget is what would notice), line numbers are preserved, and the only lines that
// differ are ones that held nothing but a comment.
func TestEmbeddedPanel(t *testing.T) {
	ui := web.FS()
	lineComment := regexp.MustCompile(`^\s*//`)
	var files, blanked int
	err := fs.WalkDir(ui, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		isJS, isCSS := strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".css")
		if !isJS && !isCSS {
			return nil
		}
		src, err := fs.ReadFile(ui, p)
		if err != nil {
			return err
		}
		files++
		var out []byte
		var ok bool
		if isJS {
			out, ok = stripJS(src)
		} else {
			out, ok = stripCSS(src)
		}
		if !ok {
			t.Errorf("%s: the scanner gave up, so this file ships with its comments", p)
			return nil
		}
		a, b := strings.Split(string(src), "\n"), strings.Split(string(out), "\n")
		if len(a) != len(b) {
			t.Errorf("%s: %d lines became %d", p, len(a), len(b))
			return nil
		}
		if !isJS {
			return nil
		}
		for i := range a {
			if a[i] == b[i] {
				continue
			}
			blanked++
			if b[i] != "" || !lineComment.MatchString(a[i]) {
				t.Errorf("%s:%d: changed a line that is not a whole-line comment:\n was %q\n now %q", p, i+1, a[i], b[i])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 10 || blanked < 1000 {
		t.Fatalf("looked at %d files and blanked %d lines: the walk or the scanner is not doing its job", files, blanked)
	}
}
