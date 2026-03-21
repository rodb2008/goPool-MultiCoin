package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// scriptForAddress performs local validation of a Bitcoin address for the given
// network and returns the corresponding scriptPubKey. It supports base58
// (P2PKH/P2SH) and bech32/bech32m segwit destinations.
func scriptForAddress(addr string, params *chaincfg.Params) ([]byte, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" || params == nil {
		return nil, errors.New("empty address")
	}

	// 1. DYNAMIC BECH32 BYPASS (Supports bc1, dgb1, ltc1, etc.)
	// We "sniff" the prefix (HRP) from the address itself.
	if strings.Contains(addr, "1") {
		hrp, data, err := bech32.Decode(addr)
		if err == nil && hrp != "" {
			// Extract witness version and program
			ver := data[0]
			prog, err := bech32.ConvertBits(data[1:], 5, 8, false)
			if err == nil {
				// Manually build the ScriptPubKey: [version] [len] [program]
				script := make([]byte, 0, 2+len(prog))
				if ver == 0 {
					script = append(script, 0x00)
				} else {
					script = append(script, 0x50+ver) // version 1-16 = 0x51-0x60
				}
				script = append(script, byte(len(prog)))
				script = append(script, prog...)
				return script, nil
			}
		}
	}

	// 2. FALLBACK TO STANDARD LOGIC (For Base58 like '1', '3', 'D', 'S')
	// We try the standard library. If it fails for a Bech32 address,
	// we force the detected prefix and try one more time.
	addrDecoded, err := btcutil.DecodeAddress(addr, params)
	if err != nil && strings.Contains(addr, "1") {
		if parts := strings.Split(addr, "1"); len(parts) > 1 {
			lp := *params
			lp.Bech32HRPSegwit = parts[0] // Set HRP to 'dgb', 'bc', etc.
			addrDecoded, err = btcutil.DecodeAddress(addr, &lp)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("decode address: %w", err)
	}

	// 3. Validation: Does the address math match the network?
	// This ensures you can't mine with a BTC address on a DGB pool.
	if !addrDecoded.IsForNet(params) {
		return nil, fmt.Errorf("address %s is not valid for %s", addr, params.Name)
	}

	return txscript.PayToAddrScript(addrDecoded)
}

// scriptToAddress attempts to derive a human-readable Bitcoin address from a
// standard scriptPubKey for the given network (P2PKH, P2SH, and common
// segwit forms). On failure it returns an empty string.
func scriptToAddress(script []byte, params *chaincfg.Params) string {
	if len(script) == 0 || params == nil {
		return ""
	}

	// P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
	// Length check protects all index accesses (0-24)
	if len(script) == 25 &&
		script[0] == 0x76 && script[1] == 0xa9 &&
		script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac {
		hash := script[3:23]
		return base58.CheckEncode(hash, params.PubKeyHashAddrID)
	}

	// P2SH: OP_HASH160 <20> <hash> OP_EQUAL
	// Length check protects all index accesses (0-22)
	if len(script) == 23 &&
		script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
		hash := script[2:22]
		return base58.CheckEncode(hash, params.ScriptHashAddrID)
	}

	// Segwit: OP_n <program>
	if len(script) >= 4 && script[1] >= 0x02 && script[1] <= 0x28 {
		var ver byte
		switch script[0] {
		case 0x00:
			ver = 0
		default:
			if script[0] >= 0x51 && script[0] <= 0x60 {
				ver = script[0] - 0x50
			} else {
				return ""
			}
		}
		progLen := int(script[1])
		if 2+progLen > len(script) {
			return ""
		}
		prog := script[2 : 2+progLen]
		progData, err := bech32.ConvertBits(prog, 8, 5, true)
		if err != nil {
			return ""
		}
		data := append([]byte{ver}, progData...)
		// Determine the correct prefix for the dashboard display
		hrp := params.Bech32HRPSegwit
		if params.Name == "digibyte" {
			hrp = "dgb"
		}

		var addr string
		if ver == 0 {
			addr, err = bech32.Encode(hrp, data)
		} else {
			addr, err = bech32.EncodeM(hrp, data)
		}
		if err != nil {
			return ""
		}
		return addr
	}

	return ""
}
