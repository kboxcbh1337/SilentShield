package protocols

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"
)

type ProtocolHopper struct {
	active    atomic.Bool
	protocols []string
	current   atomic.Uint32
	rng       *rand.Rand
}

func NewProtocolHopper() *ProtocolHopper {
	return &ProtocolHopper{
		protocols: []string{
			"HTTPS/TLS1.3",
			"HTTP/2",
			"HTTP/3 (QUIC)",
			"WebSocket over TLS",
			"gRPC",
			"SSH Tunnel",
			"WireGuard",
		},
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *ProtocolHopper) Start() {
	p.active.Store(true)
	go p.hopWorker()
	fmt.Println("[ProtocolHopper] Dynamic protocol switching active")
}

func (p *ProtocolHopper) Stop() {
	p.active.Store(false)
}

func (p *ProtocolHopper) hopWorker() {
	for p.active.Load() {
		next := p.rng.Intn(len(p.protocols))
		p.current.Store(uint32(next))
		fmt.Printf("[ProtocolHopper] Switched to protocol: %s\n", p.protocols[next])
		time.Sleep(time.Duration(30+p.rng.Intn(120)) * time.Second)
	}
}

func (p *ProtocolHopper) GetCurrentProtocol() string {
	idx := p.current.Load()
	return p.protocols[idx%uint32(len(p.protocols))]
}

func (p *ProtocolHopper) GetNextProtocol() string {
	if !p.active.Load() {
		return "HTTPS/TLS1.3"
	}
	idx := p.rng.Intn(len(p.protocols))
	return p.protocols[idx]
}
