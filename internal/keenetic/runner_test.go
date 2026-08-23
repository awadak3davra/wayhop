package keenetic

import "strings"

type recRunner struct {
	calls []string
	err   error
}

func (r *recRunner) Run(_ string, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	return "", r.err
}
