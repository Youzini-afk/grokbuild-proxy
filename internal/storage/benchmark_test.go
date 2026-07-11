package storage

import (
	"fmt"
	"testing"
	"time"
)

func TestBulkUpsertTenThousand(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	store := newTestStore(t)
	inputs := scaleCredentialInputs(10_000)
	results, err := store.BulkUpsertCredentials(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(inputs) {
		t.Fatalf("results=%d", len(results))
	}
	_, snapshot := store.CredentialSnapshot()
	if len(snapshot) != len(inputs) {
		t.Fatalf("snapshot=%d", len(snapshot))
	}
}

func BenchmarkBulkUpsert10000(b *testing.B) {
	inputs := scaleCredentialInputs(10_000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store, err := New(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := store.BulkUpsertCredentials(inputs); err != nil {
			b.Fatal(err)
		}
		_ = store.Close()
	}
}

func BenchmarkRecordCredentialCall(b *testing.B) {
	store := &Store{usageByCredential: make(map[string]CredentialUsage)}
	event := CallEvent{CredentialID: "cred-bench", Model: "grok-4.5", Status: 200, Success: true, LatencyMS: 250, CreatedAt: time.Now()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.RecordCredentialCall(event)
	}
}

func scaleCredentialInputs(count int) []CreateCredentialInput {
	inputs := make([]CreateCredentialInput, count)
	for i := range inputs {
		inputs[i] = CreateCredentialInput{
			Name: fmt.Sprintf("account-%05d", i), UserID: fmt.Sprintf("user-%05d", i),
			Email:       fmt.Sprintf("user-%05d@example.com", i),
			AccessToken: fmt.Sprintf("access-%05d", i), RefreshToken: fmt.Sprintf("refresh-%05d", i),
		}
	}
	return inputs
}
