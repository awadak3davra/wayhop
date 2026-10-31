//go:build !linux

package ctflush

// Open reports that there is no conntrack table to reach here.
func Open() (Table, error) { return nil, ErrUnsupported }
