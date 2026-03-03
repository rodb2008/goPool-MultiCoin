package main

import (
	"testing"

	"github.com/pelletier/go-toml"
)

func TestDefaultConfigBIP110NotEnabledByDefault(t *testing.T) {
	cfg := defaultConfig()
	if cfg.BIP110Enabled {
		t.Fatalf("expected BIP-110 mode to be disabled by default")
	}
}

func TestBIP110ActivatedRule(t *testing.T) {
	tpl := GetBlockTemplateResult{
		Rules: []string{"segwit", "BIP-110"},
	}
	if !bip110Activated(tpl) {
		t.Fatalf("expected activation detection for BIP-110 rule")
	}
}

func TestApplyConfiguredVersionBits(t *testing.T) {
	base := int32(0x20000000)
	cfg := Config{
		BIP110Enabled: true,
		VersionBitOverrides: map[uint32]bool{
			1: true, // force bit 1 on
		},
	}
	got := applyConfiguredVersionBits(base, cfg)
	if uint32(got)&bip110VersionMask == 0 {
		t.Fatalf("expected BIP-110 bit set by override, got %#x", got)
	}
	if uint32(got)&(uint32(1)<<1) == 0 {
		t.Fatalf("expected bit 1 forced on, got %#x", got)
	}
}

func TestApplyConfiguredVersionBits_OverrideCanDisableBIP110(t *testing.T) {
	base := int32(0x20000000)
	cfg := Config{
		BIP110Enabled: true,
		VersionBitOverrides: map[uint32]bool{
			bip110VersionBit: false,
		},
	}
	got := applyConfiguredVersionBits(base, cfg)
	if uint32(got)&bip110VersionMask != 0 {
		t.Fatalf("expected BIP-110 bit cleared by explicit override, got %#x", got)
	}
}

func TestVersionBitToggleBitAndByteOrder(t *testing.T) {
	base := int32(0x20000000)
	cfg := Config{
		VersionBitOverrides: map[uint32]bool{
			0:  true,  // LSB
			4:  true,  // BIP-110 bit
			31: false, // clear MSB if present
		},
	}

	got := applyConfiguredVersionBits(base, cfg)
	want := int32(0x20000011) // bit 4 + bit 0 set on top of 0x20000000
	if got != want {
		t.Fatalf("unexpected toggled version: got %#x want %#x", got, want)
	}

	// Notify serializes version as big-endian hex; verify exact wire value.
	wireHex := int32ToBEHex(got)
	if wireHex != "20000011" {
		t.Fatalf("unexpected big-endian wire hex: got %q want %q", wireHex, "20000011")
	}

	parsed, err := parseUint32BEHex(wireHex)
	if err != nil {
		t.Fatalf("parseUint32BEHex(%q) error: %v", wireHex, err)
	}
	if parsed != uint32(got) {
		t.Fatalf("roundtrip mismatch: parsed %#x want %#x", parsed, uint32(got))
	}
}

func TestApplyVersionBitsConfigValidation(t *testing.T) {
	cfg := defaultConfig()
	err := applyVersionBitsConfig(&cfg, versionBitsFileConfig{
		Bits: []versionBitOverride{{Bit: 32, Enabled: true}},
	})
	if err == nil {
		t.Fatalf("expected validation error for out-of-range bit")
	}
}

func TestVersionBitsFileParse_MultipleBlocks(t *testing.T) {
	const raw = `
[[bits]]
bit = 5
enabled = true

[[bits]]
bit = 1
enabled = true

[[bits]]
bit = 0
enabled = false
`

	var parsed versionBitsFileConfig
	if err := toml.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("unmarshal version_bits TOML failed: %v", err)
	}
	if len(parsed.Bits) != 3 {
		t.Fatalf("expected 3 bit entries, got %d", len(parsed.Bits))
	}

	cfg := defaultConfig()
	if err := applyVersionBitsConfig(&cfg, parsed); err != nil {
		t.Fatalf("applyVersionBitsConfig failed: %v", err)
	}
	if !cfg.VersionBitOverrides[5] {
		t.Fatalf("expected bit 5 enabled")
	}
	if !cfg.VersionBitOverrides[1] {
		t.Fatalf("expected bit 1 enabled")
	}
	if cfg.VersionBitOverrides[0] {
		t.Fatalf("expected bit 0 disabled")
	}
}
