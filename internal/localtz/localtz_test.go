package localtz

import (
	"errors"
	"io/fs"
	"testing"
	"time"
	_ "time/tzdata" // the reference zones below, in the test binary only
)

// Every rule is checked against the zone database's own answer, hour by hour through a year that
// contains both DST changes, so a wrong rule, a wrong sign or an off-by-one at a switch shows up.
func TestParseAgreesWithTheZoneDatabase(t *testing.T) {
	for _, c := range []struct{ posix, zone string }{
		{"<+03>-3", "Europe/Minsk"},                          // KeeneticOS /var/TZ, measured
		{"MSK-3", "Europe/Moscow"},                           // OpenWrt's Moscow entry
		{"GMT0", "Etc/GMT"},                                  // OpenWrt's UTC entry, measured
		{"CET-1CEST,M3.5.0,M10.5.0/3", "Europe/Berlin"},      // DST switching at 02:00 and 03:00
		{"EET-2EEST,M3.5.0/3,M10.5.0/4", "Europe/Helsinki"},  // explicit switch times
		{"EST5EDT,M3.2.0,M11.1.0", "America/New_York"},       // west of Greenwich: positive offset
		{"AEST-10AEDT,M10.1.0,M4.1.0/3", "Australia/Sydney"}, // DST wraps the new year
		{"IST-5:30", "Asia/Kolkata"},                         // a half-hour offset
		{"<+0545>-5:45", "Asia/Kathmandu"},                   // quoted name with minutes
	} {
		loc, err := Parse(c.posix)
		if err != nil {
			t.Fatalf("%s: %v", c.posix, err)
		}
		ref, err := time.LoadLocation(c.zone)
		if err != nil {
			t.Fatal(err)
		}
		for at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); at.Year() == 2026; at = at.Add(time.Hour) {
			_, got := at.In(loc).Zone()
			_, want := at.In(ref).Zone()
			if got != want {
				t.Fatalf("%s at %s: offset %d, %s says %d", c.posix, at.Format(time.RFC3339), got, c.zone, want)
			}
		}
	}
}

func TestParseNamesTheZone(t *testing.T) {
	loc, _ := Parse("CET-1CEST,M3.5.0,M10.5.0/3")
	if name, _ := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC).In(loc).Zone(); name != "CEST" {
		t.Fatalf("summer name %q", name)
	}
	if name, _ := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).In(loc).Zone(); name != "CET" {
		t.Fatalf("winter name %q", name)
	}
	// Formatting is the point of all this: the router's wall clock, not UTC.
	loc, _ = Parse("<+03>-3\n")
	if got := time.Date(2026, 9, 24, 11, 32, 0, 0, time.UTC).In(loc).Format("15:04"); got != "14:32" {
		t.Fatalf("11:32 UTC reads %s in UTC+3", got)
	}
}

func TestParseRefusesWhatIsNotARule(t *testing.T) {
	for _, s := range []string{"", "  ", "X", "UTC", "<+03", "MSK-3\nMSK-4", "a\x00b", "M3.5.0"} {
		if loc, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v, %v", s, loc, err)
		}
	}
}

// fixture points Load at an in-memory filesystem and environment for the length of a test.
func fixture(t *testing.T, env map[string]string, files map[string]string) {
	t.Helper()
	oldEnv, oldRead := getenv, readFile
	t.Cleanup(func() { getenv, readFile = oldEnv, oldRead })
	getenv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	readFile = func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, fs.ErrNotExist
	}
}

func offsetIn(loc *time.Location, month time.Month) int {
	_, off := time.Date(2026, month, 1, 12, 0, 0, 0, time.UTC).In(loc).Zone()
	return off / 3600
}

func TestLoadReadsWhatTheRouterReads(t *testing.T) {
	berlin := string(tzif("CET-1CEST,M3.5.0,M10.5.0/3"))
	for _, c := range []struct {
		name       string
		env, files map[string]string
		jan, jul   int
	}{
		{"keenetic: /etc/localtime is a POSIX string", nil,
			map[string]string{"/etc/localtime": "<+03>-3\n"}, 3, 3},
		{"openwrt without zoneinfo: /etc/TZ", nil,
			map[string]string{"/etc/TZ": "EST5EDT,M3.2.0,M11.1.0\n"}, -5, -4},
		{"openwrt: /tmp/TZ when /etc/TZ is missing", nil,
			map[string]string{"/tmp/TZ": "MSK-3"}, 3, 3},
		{"a compiled tzfile wins over the strings", nil,
			map[string]string{"/etc/localtime": berlin, "/etc/TZ": "MSK-3"}, 1, 2},
		{"$TZ wins over the files", map[string]string{"TZ": "IST-5:30"},
			map[string]string{"/etc/localtime": "<+03>-3"}, 5, 5},
		{"$TZ as a zone name", map[string]string{"TZ": "Europe/Berlin"}, nil, 1, 2},
		{"$TZ as a path", map[string]string{"TZ": ":/opt/etc/localtime"},
			map[string]string{"/opt/etc/localtime": "<+03>-3"}, 3, 3},
		{"an empty $TZ is UTC", map[string]string{"TZ": ""},
			map[string]string{"/etc/localtime": "<+03>-3"}, 0, 0},
		{"garbage in /etc/localtime falls through", nil,
			map[string]string{"/etc/localtime": "not a zone", "/etc/TZ": "MSK-3"}, 3, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			fixture(t, c.env, c.files)
			loc := Load()
			if jan, jul := offsetIn(loc, time.January), offsetIn(loc, time.July); jan != c.jan || jul != c.jul {
				t.Fatalf("offsets %d/%d, want %d/%d", jan, jul, c.jan, c.jul)
			}
		})
	}
}

// With nothing to read, Go's own answer stands: on a desktop that is the right one.
func TestLoadFallsBackToGo(t *testing.T) {
	fixture(t, nil, nil)
	if loc := Load(); loc != time.Local {
		t.Fatalf("got %v", loc)
	}
	fixture(t, map[string]string{"TZ": "not/a/zone"}, nil)
	if loc := Load(); loc != time.Local {
		t.Fatalf("an unreadable $TZ: got %v", loc)
	}
}

func TestLocationIsCached(t *testing.T) {
	fixture(t, nil, map[string]string{"/etc/localtime": "<+03>-3"})
	cache.Lock()
	cache.loc = nil
	cache.Unlock()
	first := Location()
	fixture(t, nil, map[string]string{"/etc/localtime": "MSK-4"})
	if Location() != first {
		t.Fatal("re-read within the minute")
	}
	cache.Lock()
	cache.at = time.Now().Add(-2 * cacheFor)
	cache.Unlock()
	if offsetIn(Location(), time.July) != 4 {
		t.Fatal("not re-read after the minute")
	}
	cache.Lock()
	cache.loc = nil
	cache.Unlock()
}
