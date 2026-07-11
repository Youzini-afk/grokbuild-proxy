package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// TokenPersistFunc is called after a successful refresh so callers can
// atomically write the new tokens (including rotated refresh tokens).
// Returning an error does not undo the in-memory token update.
type TokenPersistFunc func(ctx context.Context, next TokenSet) error

// Refresher performs singleflight token refresh per credential/refresh-token key.
type Refresher struct {
	OAuth *OAuthClient
	// Skew is how early tokens are considered expired. Zero uses DefaultRefreshSkew.
	Skew time.Duration
	// Timeout bounds the shared refresh operation. Zero uses DefaultHTTPTimeout.
	Timeout time.Duration
	// Now is optional clock injection for tests.
	Now func() time.Time

	group singleflight.Group

	mu    sync.Mutex
	cache map[string]TokenSet // keyed by flight key
}

// EnsureAccess returns a non-expired access token.
// If current is still valid (respecting skew), it is returned as-is.
// Otherwise a singleflight refresh is performed for the refresh token.
//
// key should uniquely identify the credential (e.g. credential id). When empty,
// the refresh token itself is used as the flight key.
// persist may be nil; when set it is invoked once per successful refresh.
func (r *Refresher) EnsureAccess(ctx context.Context, key string, current TokenSet, persist TokenPersistFunc) (TokenSet, error) {
	if r == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: nil refresher")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := r.now()
	skew := r.skew()
	if strings.TrimSpace(current.AccessToken) != "" && !current.Expired(now, skew) {
		return current, nil
	}
	// Prefer in-process cache after a concurrent refresh (avoid stale RT from caller's snapshot).
	flightKey := strings.TrimSpace(key)
	if flightKey == "" {
		flightKey = strings.TrimSpace(current.RefreshToken)
	}
	if flightKey != "" {
		if cached, ok := r.Cached(flightKey); ok {
			if strings.TrimSpace(cached.AccessToken) != "" && !cached.Expired(now, skew) {
				return cached, nil
			}
			if strings.TrimSpace(cached.RefreshToken) != "" {
				current.RefreshToken = cached.RefreshToken
				if strings.TrimSpace(cached.AccessToken) != "" {
					current.AccessToken = cached.AccessToken
				}
				if !cached.ExpiresAt.IsZero() {
					current.ExpiresAt = cached.ExpiresAt
				}
			}
		}
	}
	if strings.TrimSpace(current.RefreshToken) == "" {
		return TokenSet{}, fmt.Errorf("auth refresh: access expired and no refresh_token")
	}
	return r.ForceRefresh(ctx, key, current, persist)
}

// ForceRefresh always performs a singleflight refresh for the given token set.
func (r *Refresher) ForceRefresh(ctx context.Context, key string, current TokenSet, persist TokenPersistFunc) (TokenSet, error) {
	if r == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: nil refresher")
	}
	if r.OAuth == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: nil oauth client")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refreshToken := strings.TrimSpace(current.RefreshToken)
	if refreshToken == "" {
		return TokenSet{}, fmt.Errorf("auth refresh: refresh_token is required")
	}

	flightKey := strings.TrimSpace(key)
	if flightKey == "" {
		flightKey = refreshToken
	}

	// Deduplicate concurrent refresh for the same credential.
	// Note: singleflight shares the same result; refresh_token rotation is safe
	// because only one network call runs.
	//
	// ForceRefresh must hit the network (401 / admin force). Do not return a
	// still-unexpired cached access token — that may be the exact token that
	// just failed upstream. Only borrow a newer refresh_token from cache so
	// concurrent EnsureAccess rotations are not overwritten with a stale RT.
	resultCh := r.group.DoChan(flightKey, func() (any, error) {
		if cached, ok := r.Cached(flightKey); ok {
			if rt := strings.TrimSpace(cached.RefreshToken); rt != "" {
				refreshToken = rt
			}
		}
		// A shared operation must outlive any one waiter, but it still needs a
		// hard deadline so a stuck token endpoint cannot hold the flight forever.
		opCtx, cancel := context.WithTimeout(context.Background(), r.timeout())
		defer cancel()
		next, err := r.OAuth.Refresh(opCtx, refreshToken)
		if err != nil {
			return nil, err
		}
		// Preserve prior refresh token if server omitted rotation.
		if strings.TrimSpace(next.RefreshToken) == "" {
			next.RefreshToken = refreshToken
		}
		if persist != nil {
			if err := persist(opCtx, *next); err != nil {
				// Still return tokens; persistence failure is reported.
				r.store(flightKey, *next)
				return next, fmt.Errorf("auth refresh: persist: %w", err)
			}
		}
		r.store(flightKey, *next)
		return next, nil
	})
	var v any
	var err error
	select {
	case <-ctx.Done():
		return TokenSet{}, ctx.Err()
	case result := <-resultCh:
		v, err = result.Val, result.Err
	}
	if err != nil {
		// If persist failed but we have tokens, try to surface them.
		if ts, ok := v.(*TokenSet); ok && ts != nil && strings.TrimSpace(ts.AccessToken) != "" {
			return *ts, err
		}
		return TokenSet{}, err
	}
	ts, ok := v.(*TokenSet)
	if !ok || ts == nil {
		return TokenSet{}, fmt.Errorf("auth refresh: invalid singleflight result")
	}
	return *ts, nil
}

// Cached returns the last successful refresh result for key, if any.
func (r *Refresher) Cached(key string) (TokenSet, bool) {
	if r == nil {
		return TokenSet{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		return TokenSet{}, false
	}
	ts, ok := r.cache[key]
	return ts, ok
}

func (r *Refresher) store(key string, ts TokenSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = make(map[string]TokenSet)
	}
	r.cache[key] = ts
}

// PruneCredentials removes cached token material for deleted credentials.
func (r *Refresher) PruneCredentials(keep map[string]struct{}) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.cache {
		if _, ok := keep[key]; !ok {
			delete(r.cache, key)
		}
	}
}

func (r *Refresher) now() time.Time {
	if r != nil && r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Refresher) skew() time.Duration {
	if r != nil && r.Skew > 0 {
		return r.Skew
	}
	return DefaultRefreshSkew
}

func (r *Refresher) timeout() time.Duration {
	if r != nil && r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultHTTPTimeout
}
