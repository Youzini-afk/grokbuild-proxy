package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

// RunRefreshScheduler pre-refreshes only recently used credentials. Cold
// credentials remain demand-driven, avoiding a refresh storm for large pools.
// It blocks until ctx is cancelled and is intended to run in one goroutine.
func (e *Executor) RunRefreshScheduler(ctx context.Context, interval, activeWindow time.Duration, workers int) {
	if e == nil || e.Store == nil || e.Refresher == nil || workers <= 0 || interval <= 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if activeWindow <= 0 {
		activeWindow = 30 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.refreshActiveCredentials(ctx, activeWindow, workers)
		}
	}
}

func (e *Executor) refreshActiveCredentials(ctx context.Context, activeWindow time.Duration, workers int) {
	now := e.now()
	var credentials []storage.Credential
	if snapshots, ok := e.Store.(credentialSnapshotStore); ok {
		_, credentials = snapshots.CredentialSnapshot()
	} else {
		credentials, _ = e.Store.ListCredentials()
	}
	jobs := make(chan string, workers)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for id := range jobs {
				if ctx.Err() != nil {
					return
				}
				_, _, _ = e.EnsureTokenByID(ctx, id)
			}
		}()
	}
	for _, credential := range credentials {
		if !credential.Enabled || credential.RefreshToken == "" || credential.LastUsedAt == nil {
			continue
		}
		if now.Sub(*credential.LastUsedAt) > activeWindow || now.Before(*credential.LastUsedAt) {
			continue
		}
		if !credential.ExpiresAt.IsZero() && credential.ExpiresAt.After(now.Add(5*time.Minute)) {
			continue
		}
		select {
		case jobs <- credential.ID:
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			return
		}
	}
	close(jobs)
	group.Wait()
}
