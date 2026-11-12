// Package uimin trims what a browser never reads from the embedded panel assets before they are
// compressed: whole-line // comments in JavaScript and /* */ comments in CSS.
//
// The panel ships its source as written, with no build step, and the source is commented heavily. That
// is right for the repository and wrong for the wire: measured on 0.5.9, comments were a third of what
// a first visit downloads (278 KB gzip, 187 KB without them), on a router whose uplink is the slow part.
//
// Two properties are kept on purpose:
//
//   - Line numbers do not move. A removed comment leaves its line break behind, so a stack trace from a
//     router names the same line the repository has.
//   - A file the scanner is not sure about is served untouched. The JavaScript scanner has to know
//     whether a line starts inside a template literal, where "//" is text and not a comment, and it
//     tells a regex from a division by the token before it. Anything it cannot close (a string or a
//     regex that runs into a line break, a template still open at the end) makes it give the file back
//     as it was.
package uimin

import (
	"bytes"
	"strings"
)

// Version changes whenever the output for the same input can change. It is folded into the panel's
// ETag, so a build that only changes this package still makes browsers refetch.
const Version = "1"

// Minify returns src with comments removed when name is a JavaScript or CSS file, and src itself in
// every other case, including a file the scanner could not follow.
func Minify(name string, src []byte) []byte {
	switch {
	case strings.HasSuffix(name, ".js"):
		if out, ok := stripJS(src); ok {
			return out
		}
	case strings.HasSuffix(name, ".css"):
		if out, ok := stripCSS(src); ok {
			return out
		}
	}
	return src
}

// regexAfterWord lists the keywords after which a "/" starts a regex. After any other word (a name, a
// number, this, super) it divides.
var regexAfterWord = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true,
	"yield": true, "await": true,
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// stripJS blanks every line that holds nothing but a // comment. ok is false when the source did not
// scan cleanly; the caller then serves the original.
func stripJS(src []byte) (out []byte, ok bool) {
	n := len(src)
	out = make([]byte, 0, n)
	var (
		i         int
		lineStart int    // offset in out where the current line begins
		lineBlank = true // nothing but spaces on this line so far, and the line began as code
		regexOK   = true // a "/" here would start a regex
		depth     int    // open braces in code
		tmpl      []int  // for each open ${ of a template: the brace depth that closes it
	)

	// template copies a template literal's text from i (just past the backtick or past the "}" that
	// ended a substitution) up to and including the closing backtick or the next "${".
	template := func() bool {
		for i < n {
			c := src[i]
			switch {
			case c == '\\':
				if i+1 >= n {
					return false
				}
				out = append(out, c, src[i+1])
				i += 2
			case c == '`':
				out = append(out, c)
				i++
				regexOK = false
				return true
			case c == '$' && i+1 < n && src[i+1] == '{':
				out = append(out, '$', '{')
				i += 2
				tmpl = append(tmpl, depth)
				depth++
				regexOK = true
				return true
			default:
				out = append(out, c)
				i++
			}
		}
		return false // the file ended inside a template
	}

	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			out = append(out, c)
			i++
			lineStart = len(out)
			lineBlank = true
		case c == ' ' || c == '\t' || c == '\r':
			out = append(out, c)
			i++
		case c == '/' && i+1 < n && src[i+1] == '/':
			end := bytes.IndexByte(src[i:], '\n')
			if end < 0 {
				end = n - i
			}
			if lineBlank {
				out = out[:lineStart] // the indentation goes with the comment
			} else {
				out = append(out, src[i:i+end]...)
			}
			i += end
		case c == '/' && i+1 < n && src[i+1] == '*':
			end := bytes.Index(src[i+2:], []byte("*/"))
			if end < 0 {
				return nil, false
			}
			out = append(out, src[i:i+2+end+2]...)
			i += 2 + end + 2
			lineStart = len(out) // whatever follows shares a line with the comment: never blank it
			lineBlank = false
		case c == '/' && regexOK:
			j, inClass := i+1, false
			for ; j < n; j++ {
				d := src[j]
				if d == '\n' {
					return nil, false
				}
				if d == '\\' {
					j++
					continue
				}
				if d == '[' {
					inClass = true
				} else if d == ']' {
					inClass = false
				} else if d == '/' && !inClass {
					break
				}
			}
			if j >= n {
				return nil, false
			}
			j++
			for j < n && isWordByte(src[j]) { // flags
				j++
			}
			out = append(out, src[i:j]...)
			i = j
			regexOK, lineBlank = false, false
		case c == '\'' || c == '"':
			j := i + 1
			for ; j < n && src[j] != c; j++ {
				if src[j] == '\n' {
					return nil, false
				}
				if src[j] == '\\' {
					j++
				}
			}
			if j >= n {
				return nil, false
			}
			out = append(out, src[i:j+1]...)
			i = j + 1
			regexOK, lineBlank = false, false
		case c == '`':
			out = append(out, c)
			i++
			if !template() {
				return nil, false
			}
			lineBlank = false
		case c == '{':
			out = append(out, c)
			i++
			depth++
			regexOK, lineBlank = true, false
		case c == '}':
			out = append(out, c)
			i++
			depth--
			lineBlank = false
			if k := len(tmpl); k > 0 && depth == tmpl[k-1] {
				tmpl = tmpl[:k-1]
				if !template() {
					return nil, false
				}
				break
			}
			if depth < 0 {
				return nil, false
			}
			regexOK = true
		case isWordByte(c):
			j := i + 1
			for j < n && isWordByte(src[j]) {
				j++
			}
			regexOK = regexAfterWord[string(src[i:j])]
			out = append(out, src[i:j]...)
			i = j
			lineBlank = false
		default:
			out = append(out, c)
			i++
			regexOK = c != ')' && c != ']'
			lineBlank = false
		}
	}
	if len(tmpl) != 0 || depth != 0 {
		return nil, false
	}
	return out, true
}

// stripCSS removes /* */ comments, keeping the line breaks inside them.
func stripCSS(src []byte) (out []byte, ok bool) {
	n := len(src)
	out = make([]byte, 0, n)
	for i := 0; i < n; {
		c := src[i]
		switch {
		case c == '"' || c == '\'':
			j := i + 1
			for ; j < n && src[j] != c; j++ {
				if src[j] == '\n' {
					return nil, false
				}
				if src[j] == '\\' {
					j++
				}
			}
			if j >= n {
				return nil, false
			}
			out = append(out, src[i:j+1]...)
			i = j + 1
		case c == '/' && i+1 < n && src[i+1] == '*':
			end := bytes.Index(src[i+2:], []byte("*/"))
			if end < 0 {
				return nil, false
			}
			for _, d := range src[i : i+2+end+2] {
				if d == '\n' {
					out = append(out, d)
				}
			}
			i += 2 + end + 2
		default:
			out = append(out, c)
			i++
		}
	}
	return out, true
}
