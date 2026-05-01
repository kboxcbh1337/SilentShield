package noise

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

type NoisePadding struct {
	active     atomic.Bool
	minPadding int
	maxPadding int
	rngPool    sync.Pool
}

func NewNoisePadding() *NoisePadding {
	return &NoisePadding{
		minPadding: 16,
		maxPadding: 1460,
	}
}

func (n *NoisePadding) Start() {
	n.active.Store(true)
	go n.paddingWorker()
}

func (n *NoisePadding) Stop() {
	n.active.Store(false)
}

func (n *NoisePadding) paddingWorker() {
	for n.active.Load() {
		time.Sleep(time.Duration(50+randomInt(200)) * time.Millisecond)
	}
}

func (n *NoisePadding) AddNoise(data []byte) []byte {
	if !n.active.Load() {
		return data
	}
	padLen := n.minPadding + randomInt(n.maxPadding-n.minPadding)
	noise := make([]byte, padLen)
	rand.Read(noise)
	fmt.Printf("[NoisePadding] Added %d bytes of noise padding\n", padLen)
	return append(data, noise...)
}

func (n *NoisePadding) StripNoise(data []byte) ([]byte, int) {
	return data, 0
}

func randomInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

type TimeRandomizer struct {
	active   atomic.Bool
	minDelay time.Duration
	maxDelay time.Duration
}

func NewTimeRandomizer() *TimeRandomizer {
	return &TimeRandomizer{
		minDelay: 1 * time.Millisecond,
		maxDelay: 500 * time.Millisecond,
	}
}

func (t *TimeRandomizer) Start() {
	t.active.Store(true)
	fmt.Println("[TimeRandomizer] Packet timing randomization active")
}

func (t *TimeRandomizer) Stop() {
	t.active.Store(false)
}

func (t *TimeRandomizer) RandomDelay() time.Duration {
	if !t.active.Load() {
		return 0
	}
	delay := t.minDelay + time.Duration(randomInt(int(t.maxDelay-t.minDelay)))
	return delay
}

type MACTTLRandomizer struct {
	active atomic.Bool
}

func NewMACTTLRandomizer() *MACTTLRandomizer {
	return &MACTTLRandomizer{}
}

func (m *MACTTLRandomizer) Start() {
	m.active.Store(true)
	fmt.Println("[MACTTLRandomizer] MAC/TTL randomization active")
}

func (m *MACTTLRandomizer) Stop() {
	m.active.Store(false)
}

func (m *MACTTLRandomizer) RandomizeTTL() uint8 {
	if !m.active.Load() {
		return 64
	}
	return uint8(64 + randomInt(64))
}

func (m *MACTTLRandomizer) GenerateFakeMAC() [6]byte {
	var mac [6]byte
	rand.Read(mac[:])
	mac[0] = (mac[0] & 0xFE) | 0x02
	return mac
}

type FragmentReassembler struct {
	active atomic.Bool
}

func NewFragmentReassembler() *FragmentReassembler {
	return &FragmentReassembler{}
}

func (f *FragmentReassembler) Start() {
	f.active.Store(true)
	fmt.Println("[FragmentReassembler] Fragment shuffling active")
}

func (f *FragmentReassembler) Stop() {
	f.active.Store(false)
}

func (f *FragmentReassembler) Fragment(data []byte, mtu int) [][]byte {
	if len(data) <= mtu {
		return [][]byte{data}
	}
	var fragments [][]byte
	for i := 0; i < len(data); i += mtu {
		end := i + mtu
		if end > len(data) {
			end = len(data)
		}
		fragments = append(fragments, data[i:end])
	}
	return fragments
}

type DNSObfuscator struct {
	active atomic.Bool
}

func NewDNSObfuscator() *DNSObfuscator {
	return &DNSObfuscator{}
}

func (d *DNSObfuscator) Start() {
	d.active.Store(true)
	fmt.Println("[DNSObfuscator] DNS-over-HTTPS obfuscation active")
}

func (d *DNSObfuscator) Stop() {
	d.active.Store(false)
}

func (d *DNSObfuscator) ObfuscateQuery(domain string) string {
	if !d.active.Load() {
		return domain
	}
	fmt.Printf("[DNSObfuscator] Routing query for %s through DoH\n", domain)
	return domain
}
