//go:build !linux

package rtblackhole

// Open reports that there is no rtnetlink here.
func Open(table int) (Table, error) { return nil, ErrUnsupported }
