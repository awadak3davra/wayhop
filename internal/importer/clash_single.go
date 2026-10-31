package importer

import (
	"errors"
	"fmt"
	"strings"

	"wayhop/internal/model"
)

// parseClashSingle is Parse's answer to a whole Clash / mihomo config: its one proxy, or a refusal
// that says where a config with several proxies imports.
func parseClashSingle(raw string) (*model.Endpoint, error) {
	eps, errs := ParseClash(raw)
	switch {
	case len(eps) == 1 && len(errs) == 0:
		return finalize(&eps[0], nil)
	case len(eps) == 0 && len(errs) > 0:
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return nil, fmt.Errorf("a Clash / mihomo config with %d proxies: paste it under Subscription, which lists them to choose from",
		len(eps)+len(errs))
}
