package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
)

var coinGeckoIDs = map[string]string{
	"bitcoin":      "bitcoin",
	"bitcoincash":  "bitcoin-cash",
	"bch":			"bitcoin-cash",
	"bitcoinsilver": "bitcoin-silver",
	"btcs":			"bitcoin-silver",
	"bitcoinii":	"bitcoinii",
	"bc2":			"bitcoinii",
	"digibyte":     "digibyte",
	"dgb":			"digibyte",
}

// priceCacheTTL controls how often we refresh fiat prices from CoinGecko.
const priceCacheTTL = 30 * time.Minute

type PriceService struct {
	mu        sync.Mutex
	lastFetch time.Time
	lastPrice float64
	lastFiat  string
	lastErr   error
	client    *http.Client
}

type PriceServiceSnapshot struct {
	LastFetch time.Time
	LastPrice float64
	LastFiat  string
	LastErr   string
}

func NewPriceService() *PriceService {
	return &PriceService{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// BTCPrice returns the BTC price in the given fiat currency (e.g. "usd"),
// using a small in-process cache backed by api.coingecko.com. On errors it
// returns 0 and the error; callers should treat this as "no price available"
// and avoid failing the UI.
func (p *PriceService) BTCPrice(fiat string) (float64, error) {
	if p == nil {
		return 0, fmt.Errorf("price service not initialized")
	}
	fiat = strings.ToLower(strings.TrimSpace(fiat))
	if fiat == "" {
		fiat = "usd"
	}

	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lastFiat == fiat && !p.lastFetch.IsZero() && now.Sub(p.lastFetch) < priceCacheTTL {
		if p.lastErr != nil {
			return 0, p.lastErr
		}
		if p.lastPrice > 0 {
			return p.lastPrice, nil
		}
	}

	// Get the correct ID for the active network
	coinID := coinGeckoIDs[ChainParams().Name]
	if coinID == "" {
		coinID = "bitcoin" // Fallback
	}

	// Special case for your $0.0121 BTCS dream
	if ChainParams().Name == "bitcoinsilver" {
		p.lastPrice = 0.0121
		p.lastFetch = now
		return 0.0121, nil
	}

	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/price?ids=%s&vs_currencies=%s", coinID, fiat)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		p.lastFetch = now
		p.lastErr = err
		return 0, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		p.lastFetch = now
		p.lastErr = err
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.lastFetch = now
		p.lastErr = fmt.Errorf("price http status %s", resp.Status)
		return 0, p.lastErr
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		p.lastFetch = now
		p.lastErr = err
		return 0, err
	}

	var body map[string]map[string]float64
	if err := sonic.Unmarshal(data, &body); err != nil {
		p.lastFetch = now
		p.lastErr = err
		return 0, err
	}
	coinData, ok := body[coinID]
	if !ok {
		p.lastFetch = now
		p.lastErr = fmt.Errorf("price response missing %s key", coinID)
		return 0, p.lastErr
	}
	price, ok := coinData[fiat]
	if !ok {
		p.lastFetch = now
		p.lastErr = fmt.Errorf("price response missing %s key", fiat)
		return 0, p.lastErr
	}

	p.lastFetch = now
	p.lastPrice = price
	p.lastFiat = fiat
	p.lastErr = nil
	return price, nil
}

// LastUpdate returns the time the price was last fetched from CoinGecko.
// If no successful fetch has occurred yet, it returns the zero time.
func (p *PriceService) LastUpdate() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastFetch
}

func (p *PriceService) Snapshot() PriceServiceSnapshot {
	if p == nil {
		return PriceServiceSnapshot{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	snap := PriceServiceSnapshot{
		LastFetch: p.lastFetch,
		LastPrice: p.lastPrice,
		LastFiat:  p.lastFiat,
	}
	if p.lastErr != nil {
		snap.LastErr = p.lastErr.Error()
	}
	return snap
}
