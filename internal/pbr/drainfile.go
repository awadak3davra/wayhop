package pbr

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// drainfile.go is the format of the two files the boot hold's shell drain reads (holdLoop): the
// plane's ipset restore file and the daemon's learned file. Both are ipset restore streams, and both
// start with one comment line, which `ipset restore` skips:
//
//	# wayhop-key <key> <adds>
//
// <key> identifies the content (16 hex digits of its SHA-256) and <adds> is how many `add` lines
// follow. The shell has no cheap way to tell that a file was replaced: no stat, no hash without a
// fork whose applet may be missing. With the key in the file it reads one line with a builtin, and
// its progress stamps name the key they belong to, so a stamp never outlives the content it
// describes. The count tells a whole file from a cut one.

// drainHeader is the first two words of the header line.
const drainHeader = "# wayhop-key"

// LearnedTrailer ends the learned file with its entry count, as the Go fill reads it; the shell
// drain checks it as well.
const LearnedTrailer = "# wayhop-learned "

// KeyedRestore returns an ipset restore stream under its drain header. A header already there is
// replaced, so the call is idempotent.
func KeyedRestore(body []byte) []byte {
	if HasDrainHeader(body) {
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			body = body[i+1:]
		} else {
			body = nil
		}
	}
	adds := 0
	for _, line := range bytes.Split(body, []byte("\n")) {
		// As the shell's `read` sees it: the first word of the line.
		if f := bytes.Fields(line); len(f) > 0 && string(f[0]) == "add" {
			adds++
		}
	}
	sum := sha256.Sum256(body)
	out := make([]byte, 0, len(body)+48)
	out = append(out, fmt.Sprintf("%s %x %d\n", drainHeader, sum[:8], adds)...)
	return append(out, body...)
}

// HasDrainHeader reports whether data starts with a drain header.
func HasDrainHeader(data []byte) bool {
	return bytes.HasPrefix(data, []byte(drainHeader+" "))
}
