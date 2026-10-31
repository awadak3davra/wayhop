package generator

import "wayhop/internal/model"

// quicMinMinor is the first sing-box minor whose hysteria2 and tuic outbounds carry the QUIC fields
// (option.QUICOptions, docs/configuration/shared/quic.md "Since sing-box 1.14.0").
const quicMinMinor = 14

// quicTuning adds a Hysteria2 or TUIC connection's QUIC tuning (model.QUICTuningOf) to the outbound
// outboundFor built: initial_packet_size and disable_path_mtu_discovery. sing-box 1.12 and 1.13 refuse
// both at decode ("json: unknown field"), which would stop every connection sharing the config, so a
// core that is older, or whose version is unknown, gets the outbound without them: the connection
// still comes up, as it did before the setting, and the Apply review names it on a known older core
// (QUICTuningNeedsNewerCore). A connection without the settings is rendered exactly as before.
func quicTuning(e *model.Endpoint, ob map[string]any, coreVersion string) {
	size, noPMTUD := model.QUICTuningOf(e)
	if (size == 0 && !noPMTUD) || coreMinor(coreVersion) < quicMinMinor {
		return
	}
	if size > 0 {
		ob[model.ParamQUICInitialPacketSize] = size
	}
	if noPMTUD {
		ob[model.ParamQUICDisablePMTUD] = true
	}
}

// QUICSizeReplacedByChrome reports a Hysteria2 connection whose initial packet size is written for the
// core and then does nothing: from 1.14 the client parrots Chrome's QUIC handshake unless
// disable_chrome_parrot is set, and quic-go's parrot replaces the configured size with Chrome's own
// (chromeInitialPacketSize, 1250; 1230 over IPv6). Path MTU discovery is not part of the parrot, so
// only the size is named. An older or unknown core gets no size at all, so it says nothing.
func QUICSizeReplacedByChrome(e *model.Endpoint, coreVersion string) bool {
	if e == nil || e.Protocol != model.ProtoHysteria2 || coreMinor(coreVersion) < quicMinMinor {
		return false
	}
	size, _ := model.QUICTuningOf(e)
	return size > 0 && !boolp(e.Params, "disable_chrome_parrot")
}

// QUICTuningNeedsNewerCore reports a Hysteria2 or TUIC connection whose QUIC tuning the known core
// cannot carry, so the review can say it is applied without it. An unknown version says nothing.
func QUICTuningNeedsNewerCore(e *model.Endpoint, coreVersion string) bool {
	m := coreMinor(coreVersion)
	return model.HasQUICTuning(e) && m >= 0 && m < quicMinMinor
}
