package routing

import (
	"fmt"
	"sync/atomic"
)

type PathDeception struct {
	active     atomic.Bool
	fakePaths  []string
	pathIndex  atomic.Uint32
}

func NewPathDeception() *PathDeception {
	return &PathDeception{
		fakePaths: []string{
			"relay-us-east.silentshield.io",
			"relay-eu-west.silentshield.io",
			"relay-ap-south.silentshield.io",
			"cdn-edge-01.akamai.net",
			"cloudfront.amazonaws.com",
		},
	}
}

func (p *PathDeception) Start() {
	p.active.Store(true)
	fmt.Println("[PathDeception] Multi-path routing with fake relay nodes active")
}

func (p *PathDeception) Stop() {
	p.active.Store(false)
}

func (p *PathDeception) GetNextFakePath() string {
	idx := p.pathIndex.Add(1) % uint32(len(p.fakePaths))
	return p.fakePaths[idx]
}

func (p *PathDeception) GenerateRouteHops(target string) []string {
	if !p.active.Load() {
		return []string{target}
	}
	hops := []string{p.GetNextFakePath(), p.GetNextFakePath(), target}
	fmt.Printf("[PathDeception] Route deception: %v\n", hops)
	return hops
}
