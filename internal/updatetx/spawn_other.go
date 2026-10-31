//go:build !linux

package updatetx

import "errors"

// Spawn is Linux-only: the supervisor drives a router's init script.
func Spawn(etc string, args ...string) error {
	return errors.New("the update supervisor runs only on the router")
}
