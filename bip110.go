package main

import "strings"

const (
	// BIP-110 uses version bit 4 for miner signaling.
	bip110VersionBit  = uint32(4)
	bip110VersionMask = uint32(1) << bip110VersionBit
)

// applyConfiguredVersionBits applies version policy in precedence order:
// 1) node template version
// 2) policy bip110_enabled (sets bit 4)
// 3) version_bits.toml overrides (final authority, including bit 4)
func applyConfiguredVersionBits(version int32, cfg Config) int32 {
	u := uint32(version)
	if cfg.BIP110Enabled {
		u |= bip110VersionMask
	}
	for bit, enabled := range cfg.VersionBitOverrides {
		if bit > 31 {
			continue
		}
		mask := uint32(1) << bit
		if enabled {
			u |= mask
		} else {
			u &^= mask
		}
	}
	return int32(u)
}

func templateSignalsBIP110(tpl GetBlockTemplateResult) bool {
	version := uint32(tpl.Version)
	return version&bip110VersionMask != 0
}

func bip110Activated(tpl GetBlockTemplateResult) bool {
	for _, rule := range tpl.Rules {
		switch strings.ToLower(strings.TrimSpace(rule)) {
		case "bip110", "bip-110", "bip-0110":
			return true
		}
	}
	return false
}
