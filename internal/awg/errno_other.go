//go:build !linux

package awg

// errnoText off Linux names nothing. amneziawg-go's socket exists only on the router, and this
// platform's own table would name the Linux numbers wrongly - Windows reads 22 as "The device does not
// recognize the command" - so the number alone is the honest message.
func errnoText(int64) string { return "" }
