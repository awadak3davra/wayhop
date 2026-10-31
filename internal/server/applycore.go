package server

import (
	"os"
)

// coreCheckStagePrefix names the candidate staged for `sing-box check`; boot sweeps the ones a crash
// left (removeStaleCoreTemps).
const coreCheckStagePrefix = ".wayhop-core-check-"

// stageExactCoreConfig writes the candidate beside the router config so `sing-box check` validates it
// under the same mount, permissions, and filesystem semantics as activation. The returned cleanup is
// always safe to call after a successful return.
func stageExactCoreConfig(dir string, config []byte) (string, func(), error) {
	staged, err := os.CreateTemp(dir, coreCheckStagePrefix+"*")
	if err != nil {
		return "", nil, err
	}
	stagedPath := staged.Name()
	cleanup := func() { _ = os.Remove(stagedPath) }
	fail := func(err error) (string, func(), error) {
		_ = staged.Close()
		cleanup()
		return "", nil, err
	}
	if err := staged.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := staged.Write(config); err != nil {
		return fail(err)
	}
	if err := staged.Sync(); err != nil {
		return fail(err)
	}
	if err := staged.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return stagedPath, cleanup, nil
}
