package lb

import (
	"fmt"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

func BenchmarkPickCached10000(b *testing.B) {
	credentials := make([]storage.Credential, 10_000)
	for i := range credentials {
		credentials[i] = storage.Credential{
			ID: fmt.Sprintf("cred-%05d", i), Enabled: true,
			Priority: 100, AccessToken: "access",
		}
	}
	selector := New(config.LBConfig{Strategy: "priority_rr"})
	selector.SyncCredentials(1, credentials)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := selector.PickCached(nil, "", "grok-4.5", now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPickCachedAdaptive10000(b *testing.B) {
	credentials := make([]storage.Credential, 10_000)
	now := time.Now()
	for i := range credentials {
		credentials[i] = storage.Credential{
			ID: fmt.Sprintf("cred-%05d", i), Enabled: true,
			Priority: 100, AccessToken: "access",
		}
		// Keep a realistic minority in durable quarantine. Normal picks should
		// still advance without rebuilding or sorting the 10k-account pool.
		if i%10 == 0 {
			until := now.Add(time.Hour)
			credentials[i].FailureCount = 3
			credentials[i].LastError = "quota_exhausted:personal-team-blocked:spending-limit"
			credentials[i].CooldownUntil = &until
		}
	}
	selector := New(config.LBConfig{Strategy: "priority_rr"})
	selector.SyncCredentials(1, credentials)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := selector.PickCached(nil, "", "grok-4.5", now); err != nil {
			b.Fatal(err)
		}
	}
}
