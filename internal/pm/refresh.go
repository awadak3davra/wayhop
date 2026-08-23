package pm

import (
	"context"
	"fmt"
)

// RefreshArgv is the exact native command that refreshes repository indexes without changing an
// installed package. The HTTP layer shows this argv before execution and sends the same value back;
// keeping it here prevents the preview and the operation from drifting apart.
func (m Manager) RefreshArgv() []string {
	switch m.Kind {
	case Apk:
		return []string{"apk", "update"}
	case Opkg:
		return []string{"opkg", "update"}
	default:
		return nil
	}
}

// Refresh updates only the package catalog. It deliberately does not run upgrade: making packages
// discoverable and replacing installed binaries are separate operator decisions with different
// consequences and must remain separate actions in the panel.
func (m Manager) Refresh(ctx context.Context) (string, error) {
	argv := m.RefreshArgv()
	if len(argv) != 2 {
		return "", fmt.Errorf("pm: no package manager detected")
	}
	return m.run(ctx, argv[0], argv[1])
}
