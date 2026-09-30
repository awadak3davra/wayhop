// Package localtz finds the local time zone the way the router's own tools see it.
//
// Go takes the local zone from $TZ or /etc/localtime and understands only a compiled tzfile there;
// anything else quietly becomes UTC. Routers rarely have one. KeeneticOS links /etc/localtime to
// /var/TZ, which holds a POSIX TZ string ("<+03>-3"); OpenWrt keeps the string in /etc/TZ (a link to
// /tmp/TZ) and has a /tmp/localtime tzfile only when a zoneinfo package is installed. On both, `date`
// prints local time while a Go daemon prints UTC: measured on a Keenetic in UTC+3, a message about an
// outage the owner saw at 14:32 would have said 11:32.
//
// Location reads what the C library reads, in the same order, and understands the POSIX form too.
package localtz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrInvalid is returned for a value that is not a POSIX TZ string.
var ErrInvalid = errors.New("localtz: not a POSIX TZ string")

// Parse turns a POSIX TZ string ("CET-1CEST,M3.5.0,M10.5.0/3", "<+03>-3", "GMT0") into a Location.
//
// The standard library already evaluates these strings: a version 2 tzfile ends with one, and it
// governs every instant after the file's last transition. A tzfile with no transitions and that
// footer therefore means "this rule, always", so Parse builds that file in memory and lets
// time.LoadLocationFromTZData do the rest. No second implementation of the rule grammar to get wrong.
func Parse(tz string) (*time.Location, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" || strings.ContainsAny(tz, "\n\x00") {
		return nil, ErrInvalid
	}
	loc, err := time.LoadLocationFromTZData(tz, tzif(tz))
	if err != nil {
		return nil, ErrInvalid
	}
	// The loader does not reject a rule it cannot read: it falls back to the file's one zone, which
	// has no name. Every valid rule names its zone, so an empty name is the tell.
	if name, _ := time.Unix(0, 0).In(loc).Zone(); name == "" {
		return nil, ErrInvalid
	}
	return loc, nil
}

// tzif is a version 2 tzfile (RFC 8536) with one unnamed zone, no transitions, and tz as its footer.
func tzif(tz string) []byte {
	var b bytes.Buffer
	block := func() {
		b.WriteString("TZif2")
		b.Write(make([]byte, 15))
		// isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
		for _, n := range []uint32{0, 0, 0, 0, 1, 1} {
			_ = binary.Write(&b, binary.BigEndian, n)
		}
		// The one local time type (offset 0, not DST, designation 0) and its empty designation.
		b.Write([]byte{0, 0, 0, 0, 0, 0, 0})
	}
	block() // the version 1 data, which a version 2 reader skips
	block()
	b.WriteString("\n" + tz + "\n")
	return b.Bytes()
}

// Where the C library looks, as variables so a test can point them at fixtures. localtime is what
// glibc and musl read when $TZ is unset; tzFiles hold the POSIX string uClibc reads (Padavan) and
// OpenWrt keeps.
var (
	getenv    = os.LookupEnv
	readFile  = os.ReadFile
	localtime = "/etc/localtime"
	tzFiles   = []string{"/etc/TZ", "/tmp/TZ"}
)

// Load finds the local zone now. It never fails: with nothing readable it is Go's own time.Local,
// which is right wherever Go could read the zone itself (a desktop, a full Linux).
func Load() *time.Location {
	if tz, ok := getenv("TZ"); ok {
		if loc := fromTZ(tz); loc != nil {
			return loc
		}
		return time.Local
	}
	if loc := fromFile(localtime); loc != nil {
		return loc
	}
	for _, f := range tzFiles {
		if loc := fromFile(f); loc != nil {
			return loc
		}
	}
	return time.Local
}

// fromTZ reads $TZ the way the C library does: empty is UTC, a path is a file, anything else is a
// zone name where a zone database exists and a POSIX string where it does not.
func fromTZ(tz string) *time.Location {
	if tz == "" {
		return time.UTC
	}
	tz = strings.TrimPrefix(tz, ":")
	if strings.HasPrefix(tz, "/") {
		return fromFile(tz)
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		return loc
	}
	if loc, err := Parse(tz); err == nil {
		return loc
	}
	return nil
}

// fromFile reads a compiled tzfile or a one-line POSIX string; nil when the file is neither.
func fromFile(path string) *time.Location {
	data, err := readFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	if bytes.HasPrefix(data, []byte("TZif")) {
		if loc, err := time.LoadLocationFromTZData("Local", data); err == nil {
			return loc
		}
		return nil
	}
	if len(data) > 256 {
		return nil // a POSIX string is one short line; this is something else
	}
	if loc, err := Parse(string(data)); err == nil {
		return loc
	}
	return nil
}

// cacheFor bounds how stale Location may be: a zone changed in the router's settings applies within
// a minute, with no restart.
const cacheFor = time.Minute

var cache struct {
	sync.Mutex
	loc *time.Location
	at  time.Time
}

// Location is Load, read again at most once a minute, so it is cheap enough to call per timestamp.
func Location() *time.Location {
	cache.Lock()
	defer cache.Unlock()
	if cache.loc == nil || time.Since(cache.at) > cacheFor {
		cache.loc, cache.at = Load(), time.Now()
	}
	return cache.loc
}
