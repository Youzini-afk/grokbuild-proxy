// Package lb implements multi-credential selection, sticky sessions and cooldown.
//
// It does not perform HTTP or token refresh — only pick / mark success|failure
// and maintain process-local runtime state.
package lb

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

// ErrNoCredential is returned when no enabled, non-cooling credential is available.
var ErrNoCredential = errors.New("lb: no available credential")

type healthStore interface {
	PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error)
}

type healthSnapshot struct {
	version       uint64
	failureCount  int
	cooldownUntil *time.Time
	lastError     string
	lastSuccessAt *time.Time
}

// Selector picks credentials according to strategy, sticky session and cooldown.
type Selector struct {
	strategy     string
	stickyTTL    time.Duration
	cooldownBase time.Duration
	cooldownMax  time.Duration

	mu        sync.Mutex
	persistMu sync.Mutex

	// rrIndex is the flat round-robin cursor (strategy=round_robin).
	rrIndex int
	// priorityRR is per-priority round-robin cursors (strategy=priority_rr).
	priorityRR map[int]int

	sticky map[string]stickyBinding
	states map[string]*runtimeState
	store  healthStore

	poolVersion uint64
	pool        map[string]storage.Credential
	poolOrder   []string
	priorityIDs map[int][]string
	priorities  []int
	modelStates map[string]map[string]*runtimeState
}

// SetHealthStore enables durable failure/cooldown state. It returns s for
// convenient dependency wiring.
func (s *Selector) SetHealthStore(store healthStore) *Selector {
	s.mu.Lock()
	s.store = store
	s.mu.Unlock()
	return s
}

// New builds a Selector from LB configuration.
func New(cfg config.LBConfig) *Selector {
	strategy := cfg.Strategy
	if strategy == "" {
		strategy = "priority_rr"
	}
	base := time.Duration(cfg.Cooldown.BaseSec) * time.Second
	max := time.Duration(cfg.Cooldown.MaxSec) * time.Second
	if base <= 0 {
		base = 300 * time.Second
	}
	if max <= 0 {
		max = 3600 * time.Second
	}
	return &Selector{
		strategy:     strategy,
		stickyTTL:    time.Duration(cfg.StickyTTLSec) * time.Second,
		cooldownBase: base,
		cooldownMax:  max,
		priorityRR:   make(map[int]int),
		sticky:       make(map[string]stickyBinding),
		states:       make(map[string]*runtimeState),
		pool:         make(map[string]storage.Credential),
		priorityIDs:  make(map[int][]string),
		modelStates:  make(map[string]map[string]*runtimeState),
	}
}

// ApplyConfig updates scheduling behavior without discarding health state or
// rebuilding the credential pool.
func (s *Selector) ApplyConfig(cfg config.LBConfig) {
	if s == nil {
		return
	}
	strategy := cfg.Strategy
	if strategy == "" {
		strategy = "priority_rr"
	}
	base := time.Duration(cfg.Cooldown.BaseSec) * time.Second
	max := time.Duration(cfg.Cooldown.MaxSec) * time.Second
	if base <= 0 {
		base = 300 * time.Second
	}
	if max <= 0 {
		max = 3600 * time.Second
	}
	s.mu.Lock()
	s.strategy = strategy
	s.stickyTTL = time.Duration(cfg.StickyTTLSec) * time.Second
	s.cooldownBase = base
	s.cooldownMax = max
	if s.stickyTTL <= 0 {
		s.sticky = make(map[string]stickyBinding)
	}
	s.mu.Unlock()
}

// SyncCredentials rebuilds the immutable scheduling index only when the store
// snapshot version changes. Normal picks are then O(number of skipped peers)
// rather than O(total credentials).
func (s *Selector) SyncCredentials(version uint64, credentials []storage.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version != 0 && version == s.poolVersion {
		return
	}
	pool := make(map[string]storage.Credential, len(credentials))
	order := make([]string, 0, len(credentials))
	groups := make(map[int][]string)
	prioritySet := make(map[int]struct{})
	for _, credential := range credentials {
		pool[credential.ID] = credential
		order = append(order, credential.ID)
		groups[credential.Priority] = append(groups[credential.Priority], credential.ID)
		prioritySet[credential.Priority] = struct{}{}
		s.seedState(credential)
	}
	priorities := make([]int, 0, len(prioritySet))
	for priority := range prioritySet {
		priorities = append(priorities, priority)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(priorities)))
	for id := range s.states {
		if _, ok := pool[id]; !ok {
			delete(s.states, id)
			delete(s.modelStates, id)
		}
	}
	for key, binding := range s.sticky {
		if _, ok := pool[binding.CredID]; !ok {
			delete(s.sticky, key)
		}
	}
	s.poolVersion = version
	s.pool = pool
	s.poolOrder = order
	s.priorityIDs = groups
	s.priorities = priorities
}

// PickCached selects from the prebuilt in-memory index.
func (s *Selector) PickCached(excluded map[string]struct{}, stickyKey, model string, now time.Time) (storage.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stickyKey != "" {
		if id, ok := s.getSticky(stickyKey, now); ok && s.cachedAvailable(id, model, excluded, now) {
			return s.pool[id], nil
		}
	}
	var picked storage.Credential
	var ok bool
	if s.strategy == "round_robin" {
		picked, ok = s.pickCachedRoundRobin(model, excluded, now)
	} else {
		picked, ok = s.pickCachedPriority(model, excluded, now)
	}
	if !ok {
		return storage.Credential{}, ErrNoCredential
	}
	if stickyKey != "" {
		s.bindSticky(stickyKey, picked.ID, now)
	}
	return picked, nil
}

func (s *Selector) pickCachedRoundRobin(model string, excluded map[string]struct{}, now time.Time) (storage.Credential, bool) {
	count := len(s.poolOrder)
	for n := 0; n < count; n++ {
		idx := s.rrIndex % count
		s.rrIndex = (idx + 1) % count
		id := s.poolOrder[idx]
		if s.cachedAvailable(id, model, excluded, now) {
			return s.pool[id], true
		}
	}
	return storage.Credential{}, false
}

func (s *Selector) pickCachedPriority(model string, excluded map[string]struct{}, now time.Time) (storage.Credential, bool) {
	for _, priority := range s.priorities {
		group := s.priorityIDs[priority]
		count := len(group)
		for n := 0; n < count; n++ {
			idx := s.priorityRR[priority] % count
			s.priorityRR[priority] = (idx + 1) % count
			id := group[idx]
			if s.cachedAvailable(id, model, excluded, now) {
				return s.pool[id], true
			}
		}
	}
	return storage.Credential{}, false
}

func (s *Selector) cachedAvailable(id, model string, excluded map[string]struct{}, now time.Time) bool {
	if _, skip := excluded[id]; skip {
		return false
	}
	credential, ok := s.pool[id]
	if !ok || !credential.Enabled || s.inCooldown(credential, now) {
		return false
	}
	if states := s.modelStates[id]; states != nil {
		if state := states[model]; state != nil && state.CooldownUntil.After(now) {
			return false
		}
	}
	return true
}

// Available returns credentials that are enabled and not in cooldown (storage fields only).
func Available(creds []storage.Credential, now time.Time) []storage.Credential {
	out := make([]storage.Credential, 0, len(creds))
	for _, c := range creds {
		if !c.Enabled {
			continue
		}
		if c.CooldownUntil != nil && c.CooldownUntil.After(now) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Pick selects one usable credential.
// When stickyKey is non-empty, a live sticky binding is preferred if still available;
// otherwise a new credential is chosen and re-bound.
func (s *Selector) Pick(creds []storage.Credential, stickyKey string, now time.Time) (storage.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	avail := s.availableLocked(creds, now)
	if len(avail) == 0 {
		return storage.Credential{}, ErrNoCredential
	}

	// Sticky hit.
	if stickyKey != "" {
		if id, ok := s.getSticky(stickyKey, now); ok {
			if c, found := findByID(avail, id); found {
				return c, nil
			}
			// Bound credential no longer available — fall through and rebind.
		}
	}

	picked, err := s.pickByStrategy(avail)
	if err != nil {
		return storage.Credential{}, err
	}
	if stickyKey != "" {
		s.bindSticky(stickyKey, picked.ID, now)
	}
	return picked, nil
}

// MarkSuccess clears failure/cooldown for credID and refreshes sticky binding.
func (s *Selector) MarkSuccess(credID, stickyKey string, now time.Time) {
	if credID == "" {
		return
	}
	s.mu.Lock()
	st := s.ensureState(credID)
	needsPersist := st.FailureCount != 0 ||
		!st.CooldownUntil.IsZero() ||
		st.LastError != ""
	st.FailureCount = 0
	st.CooldownUntil = time.Time{}
	st.LastError = ""

	if stickyKey != "" {
		s.bindSticky(stickyKey, credID, now)
	}
	store := s.store
	var snapshot healthSnapshot
	if needsPersist {
		successAt := now.UTC().Truncate(time.Second)
		st.LastSuccessPersistedAt = successAt
		st.Version++
		snapshot = healthSnapshot{
			version:       st.Version,
			lastSuccessAt: &successAt,
		}
	}
	s.mu.Unlock()
	if store != nil && needsPersist {
		s.persistHealth(store, credID, snapshot)
	}
}

// MarkFailure records a failure and applies cooldown based on status.
// retryAfter is honored for 429 when > 0.
func (s *Selector) MarkFailure(credID string, status int, retryAfter time.Duration, now time.Time) {
	if credID == "" {
		return
	}
	s.mu.Lock()
	st := s.ensureState(credID)
	st.FailureCount++
	d := s.cooldownDuration(status, retryAfter, st.FailureCount-1)
	st.CooldownUntil = now.Add(d)
	if status > 0 {
		st.LastError = fmt.Sprintf("http %d", status)
	} else {
		st.LastError = "network error"
	}

	// Sticky bindings to a cooling credential should not keep routing traffic there.
	if status == 401 || status == 402 || status == 403 || status == 429 {
		s.clearStickyForCred(credID)
	}
	failureCount := st.FailureCount
	cooldownUntil := st.CooldownUntil.UTC().Truncate(time.Second)
	lastError := st.LastError
	st.Version++
	snapshot := healthSnapshot{
		version:       st.Version,
		failureCount:  failureCount,
		cooldownUntil: &cooldownUntil,
		lastError:     lastError,
	}
	store := s.store
	s.mu.Unlock()
	if store != nil {
		s.persistHealth(store, credID, snapshot)
	}
}

// MarkModelFailure cools a credential only for one model. This prevents a
// model entitlement/availability error from disabling otherwise usable models.
func (s *Selector) MarkModelFailure(credID, model string, status int, retryAfter time.Duration, now time.Time) {
	if credID == "" || model == "" {
		s.MarkFailure(credID, status, retryAfter, now)
		return
	}
	s.mu.Lock()
	states := s.modelStates[credID]
	if states == nil {
		states = make(map[string]*runtimeState)
		s.modelStates[credID] = states
	}
	state := states[model]
	if state == nil {
		state = &runtimeState{}
		states[model] = state
	}
	state.FailureCount++
	state.CooldownUntil = now.Add(s.cooldownDuration(status, retryAfter, state.FailureCount-1))
	state.LastError = fmt.Sprintf("http %d", status)
	s.clearStickyForCred(credID)
	s.mu.Unlock()
}

// MarkModelSuccess clears model-local backoff and records global success.
func (s *Selector) MarkModelSuccess(credID, model, stickyKey string, now time.Time) {
	if model != "" {
		s.mu.Lock()
		if states := s.modelStates[credID]; states != nil {
			delete(states, model)
			if len(states) == 0 {
				delete(s.modelStates, credID)
			}
		}
		s.mu.Unlock()
	}
	s.MarkSuccess(credID, stickyKey, now)
}

func (s *Selector) persistHealth(store healthStore, credID string, snapshot healthSnapshot) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.Lock()
	current := s.states[credID]
	stale := current == nil || current.Version != snapshot.version
	s.mu.Unlock()
	if stale {
		return
	}
	_, _ = store.PatchCredential(credID, func(c *storage.Credential) error {
		c.FailureCount = snapshot.failureCount
		c.CooldownUntil = snapshot.cooldownUntil
		c.LastError = snapshot.lastError
		if snapshot.lastSuccessAt != nil {
			c.LastSuccessAt = snapshot.lastSuccessAt
		}
		return nil
	})
}

// availableLocked filters enabled + not cooling, merging memory cooldowns.
// Caller must hold s.mu.
func (s *Selector) availableLocked(creds []storage.Credential, now time.Time) []storage.Credential {
	out := make([]storage.Credential, 0, len(creds))
	for _, c := range creds {
		if !c.Enabled {
			continue
		}
		s.seedState(c)
		if s.inCooldown(c, now) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// seedState restores runtime backoff from persisted health after restart.
// Caller must hold s.mu.
func (s *Selector) seedState(c storage.Credential) {
	if _, exists := s.states[c.ID]; exists {
		return
	}
	st := &runtimeState{FailureCount: c.FailureCount, LastError: c.LastError}
	if c.CooldownUntil != nil {
		st.CooldownUntil = *c.CooldownUntil
	}
	if c.LastSuccessAt != nil {
		st.LastSuccessPersistedAt = *c.LastSuccessAt
	}
	s.states[c.ID] = st
}

// pickByStrategy chooses from a non-empty available list.
// Caller must hold s.mu.
func (s *Selector) pickByStrategy(avail []storage.Credential) (storage.Credential, error) {
	if len(avail) == 0 {
		return storage.Credential{}, ErrNoCredential
	}
	switch s.strategy {
	case "round_robin":
		return s.pickRoundRobin(avail), nil
	case "priority_rr", "":
		return s.pickPriorityRR(avail), nil
	default:
		// Unknown strategy: fall back to priority_rr for safety.
		return s.pickPriorityRR(avail), nil
	}
}

// pickRoundRobin advances a flat RR cursor over avail (order preserved).
// Caller must hold s.mu.
func (s *Selector) pickRoundRobin(avail []storage.Credential) storage.Credential {
	if s.rrIndex < 0 {
		s.rrIndex = 0
	}
	idx := s.rrIndex % len(avail)
	s.rrIndex = (idx + 1) % len(avail)
	// Keep index from growing unbounded when list shrinks.
	if s.rrIndex >= len(avail) {
		s.rrIndex = 0
	}
	return avail[idx]
}

// pickPriorityRR groups by Priority desc and RR within the highest-priority group present.
// Caller must hold s.mu.
func (s *Selector) pickPriorityRR(avail []storage.Credential) storage.Credential {
	// Group by priority.
	groups := make(map[int][]storage.Credential)
	priorities := make([]int, 0)
	for _, c := range avail {
		if _, ok := groups[c.Priority]; !ok {
			priorities = append(priorities, c.Priority)
		}
		groups[c.Priority] = append(groups[c.Priority], c)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(priorities)))

	top := priorities[0]
	group := groups[top]
	idx := s.priorityRR[top]
	if idx < 0 {
		idx = 0
	}
	idx = idx % len(group)
	s.priorityRR[top] = (idx + 1) % len(group)
	return group[idx]
}

func (s *Selector) ensureState(credID string) *runtimeState {
	st, ok := s.states[credID]
	if !ok {
		st = &runtimeState{}
		s.states[credID] = st
	}
	return st
}

func findByID(creds []storage.Credential, id string) (storage.Credential, bool) {
	for _, c := range creds {
		if c.ID == id {
			return c, true
		}
	}
	return storage.Credential{}, false
}
