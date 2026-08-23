package keenetic

// Runner executes a bounded host command through an injected implementation. The remaining
// cutover and kernel-plane planners use this seam for pure fault tests; production native Apply
// does not use it and accepts mutations only through the strict transaction adapter.
type Runner interface {
	Run(stdin, name string, args ...string) (string, error)
}
