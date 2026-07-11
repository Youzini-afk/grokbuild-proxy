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
