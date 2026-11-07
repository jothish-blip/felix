package cve

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// PublicationCoordinator provides shared cross-component synchronization and generation tracking
// between the persistent SQLite CVE store and the in-memory TemplateRegistry.
// It eliminates visibility windows between database transactions and in-memory template activation.
type PublicationCoordinator struct {
	mu         sync.RWMutex
	generation atomic.Uint64
}

// NewPublicationCoordinator initializes a new coordinator starting at generation 1.
func NewPublicationCoordinator() *PublicationCoordinator {
	c := &PublicationCoordinator{}
	c.generation.Store(1)
	return c
}

// Generation returns the current published generation monotonically.
func (c *PublicationCoordinator) Generation() uint64 {
	return c.generation.Load()
}

// ReadLock acquires a read lock on the publication boundary.
// Readers hold this lock to guarantee that they observe a single consistent generation across both
// the database and template registry.
func (c *PublicationCoordinator) ReadLock() func() {
	c.mu.RLock()
	return func() {
		c.mu.RUnlock()
	}
}

// TryReadLock attempts to acquire a read lock without blocking.
// Returns false if publication is actively committing and publishing.
func (c *PublicationCoordinator) TryReadLock() (func(), bool) {
	if c.mu.TryRLock() {
		return func() { c.mu.RUnlock() }, true
	}
	return nil, false
}

// BeginPublish acquires exclusive access to the publication boundary.
// It returns a completion function that must be called when publication finishes.
// If success is true, the generation is monotonically incremented.
func (c *PublicationCoordinator) BeginPublish() func(success bool) {
	c.mu.Lock()
	return func(success bool) {
		if success {
			c.generation.Add(1)
		}
		c.mu.Unlock()
	}
}

// BindCoordinated establishes a shared PublicationCoordinator between a Store and a TemplateRegistry.
func BindCoordinated(store *Store, reg *TemplateRegistry) *PublicationCoordinator {
	var coord *PublicationCoordinator
	if store != nil {
		coord = store.Coordinator()
	}
	if coord == nil && reg != nil {
		coord = reg.Coordinator()
	}
	if coord == nil {
		coord = NewPublicationCoordinator()
	}

	if store != nil {
		store.SetCoordinator(coord)
	}
	if reg != nil {
		reg.SetCoordinator(coord)
	}
	return coord
}

// VulnerabilityMatch contains a confirmed CVE match from the database along with its corresponding template(s).
type VulnerabilityMatch struct {
	Match     MatchResult
	Templates []*CompiledTemplate
}

// QueryVulnerabilitiesWithTemplates executes an atomic cross-component query across SQLite and TemplateRegistry,
// guaranteeing that callers observe identical database and template generations with zero inconsistency.
func QueryVulnerabilitiesWithTemplates(ctx context.Context, store *Store, reg *TemplateRegistry, cpePrefix string, targetVersion string) ([]VulnerabilityMatch, uint64, error) {
	if store == nil {
		return nil, 0, errors.New("store is nil")
	}

	coord := store.Coordinator()
	if coord == nil && reg != nil {
		coord = reg.Coordinator()
	}

	var unlock func()
	if coord != nil {
		unlock = coord.ReadLock()
		defer unlock()
	}

	matches, _, err := store.QueryByCPE(ctx, cpePrefix, targetVersion)
	if err != nil {
		return nil, 0, err
	}

	var results []VulnerabilityMatch
	for _, m := range matches {
		vm := VulnerabilityMatch{
			Match: m,
		}
		if reg != nil {
			vm.Templates = reg.GetByCVE(m.CVEID)
		}
		results = append(results, vm)
	}

	var gen uint64 = 1
	if coord != nil {
		gen = coord.Generation()
	}

	return results, gen, nil
}
