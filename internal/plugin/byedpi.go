package plugin

import (
	"errors"
	"strconv"

	"wayhop/internal/model"
)

// byedpiArgs is ciadpi's argv: a loopback listener on the port the generator gave sing-box's SOCKS
// outbound, then the connection's checked strategy (model.ByeDPIStrategy).
func byedpiArgs(e model.Endpoint, socksPort int) ([]string, error) {
	if socksPort < 1 || socksPort > 65535 {
		return nil, errors.New("no local port assigned")
	}
	strategy, err := model.ByeDPIStrategy(e.Params)
	if err != nil {
		return nil, err
	}
	return append([]string{"-i", "127.0.0.1", "-p", strconv.Itoa(socksPort)}, strategy...), nil
}
