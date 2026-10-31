package store

import (
	"errors"
	"fmt"
)

// Rev is a write precondition: the revision of the ONE object being written, as the writer's copy
// had it (model.EndpointRev, GroupRev, RoutingListRev).
//
// The per-object writers replace a whole connection, group or routing list with what the caller sent.
// A form or a switch builds that from the object it loaded, so a page left open while another tab,
// device or script saved a newer version of it wrote the older one back with a 200 (QA-152): a
// connection's switch put back the server another tab had just changed. A write made At the
// revision its copy came from commits only while the stored object still has it.
//
// The revision is the object's own, not the profile's generation: a generation moves on every write
// anywhere, so any save, a new device group made from inside the form, or the hourly feed refresh
// made every open form stale and threw its input away.
//
// AnyRev, the zero value, commits whatever is stored: every write made before revisions existed, and
// every API caller that does not send one, keeps working as it did.
type Rev struct {
	tag string
	set bool
}

// AnyRev is the unconditional write.
var AnyRev Rev

// At is the write that commits only while the stored object's revision is still tag.
func At(tag string) Rev { return Rev{tag: tag, set: true} }

// ErrStale reports that a write made At a revision found the stored object changed (or gone) since:
// somebody else saved it in between. The write is refused, not merged.
var ErrStale = errors.New("changed since it was read")

// checkRev refuses a write made At a revision the stored object no longer has; found says whether
// the object exists, cur is its revision. Callers hold s.wmu, so no commit can slip between this
// comparison and the caller's publish.
func checkRev(rev Rev, found bool, cur string) error {
	if !rev.set {
		return nil
	}
	if !found {
		return fmt.Errorf("%w: it no longer exists", ErrStale)
	}
	if cur != rev.tag {
		return fmt.Errorf("%w: revision %s, the copy was %s", ErrStale, cur, rev.tag)
	}
	return nil
}

// Saved is what a write made through an At method reports: the object's revision before it (Was, ""
// when it is new) and after it (Rev), both read under the write's own lock. A client whose copy had
// Was saw everything up to this write, so it may take Rev for its copy without reloading.
type Saved struct{ Was, Rev string }
