package main

import (
	"sync"
	"strings"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
)

var (
    // Bitcoin Cash (BCH) Parameters
	BCHParams = (func() chaincfg.Params {
		p := chaincfg.MainNetParams
		p.Name = "bitcoincash"
		return p
	})()
	
	// BTCS / Bitcoin Silver Parameters (assuming BTC-like prefixes)
	BTCSParams = (func() chaincfg.Params {
		p := chaincfg.MainNetParams
		p.Name = "bitcoinsilver"
		// BTCS typically uses BTC prefixes but requires its own name for validation
		return p
	})()
    
	// DigiByte Mainnet Parameters
	DGBParams = (func() chaincfg.Params {
		p := chaincfg.MainNetParams
		p.Name = "digibyte"
		p.PubKeyHashAddrID = 0x1E // Starts with 'D'
		p.ScriptHashAddrID = 0x3F // Starts with '3'
		p.Bech32HRPSegwit = "dgb" // Starts with 'dgb1'
		return p
	})()

    // Bitcoin 2 (BC2) Parameters
	BC2Params = (func() chaincfg.Params {
		p := chaincfg.MainNetParams
		p.Name = "bitcoin2"
		return p
	})()
	
	chainParamsMu sync.RWMutex
	chainParams   *chaincfg.Params = &chaincfg.MainNetParams

)

func init() {
	// Register these so btcutil knows how to decode them
	_ = chaincfg.Register(&DGBParams)
	_ = chaincfg.Register(&BTCSParams)
	_ = chaincfg.Register(&BCHParams)
	_ = chaincfg.Register(&BC2Params)
}


// SetChainParams selects the active Bitcoin network parameters used for local
// address validation. It should be called once during startup, after CLI
// flags / config are resolved. Unknown names default to mainnet.
func SetChainParams(network string) {
	chainParamsMu.Lock()
	defer chainParamsMu.Unlock()

	network = strings.ToLower(network)
	fmt.Printf("DEBUG: Activating Network Parameters for: %s\n", network)

	// Convert to lowercase to handle "BTCS" or "btcs" correctly
	network = strings.ToLower(network)

	switch network {
	case "mainnet", "", "bitcoin", "btc":
		chainParams = &chaincfg.MainNetParams
	case "bch", "bitcoincash":
		chainParams = &BCHParams
	case "btcs", "bitcoinsilver":
		chainParams = &BTCSParams
	case "dgb", "digibyte":
		chainParams = &DGBParams
	case "bc2", "bitcoin2":
		chainParams = &BC2Params
	case "testnet", "testnet3":
		chainParams = &chaincfg.TestNet3Params
	case "regtest", "regressiontest":
		chainParams = &chaincfg.RegressionNetParams
	default:
		// Default to Bitcoin Mainnet so your existing Umbrel users stay happy
		chainParams = &chaincfg.MainNetParams
	}
}

// ChainParams returns the currently selected network parameters. Call
// SetChainParams during startup to ensure this reflects the actual network.
func ChainParams() *chaincfg.Params {
	chainParamsMu.RLock()
	defer chainParamsMu.RUnlock()
	return chainParams
}

