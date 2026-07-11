package admin

import (
	"strings"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type poolSummary struct {
	Total          int        `json:"total"`
	Enabled        int        `json:"enabled"`
	Available      int        `json:"available"`
	Cooling        int        `json:"cooling"`
	Abnormal       int        `json:"abnormal"`
	QuotaLimited   int        `json:"quota_limited"`
	ProbeDue       int        `json:"probe_due"`
	Disabled       int        `json:"disabled"`
	Expired        int        `json:"expired"`
	MissingTokens  int        `json:"missing_tokens"`
	NextRecoveryAt *time.Time `json:"next_recovery_at,omitempty"`
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
}

func summarizePool(creds []storage.Credential, now time.Time, abnormalAfter int) poolSummary {
	if abnormalAfter < 1 {
		abnormalAfter = 4
	}
	summary := poolSummary{Total: len(creds)}
	for _, credential := range creds {
		if !credential.Enabled {
			summary.Disabled++
			continue
		}
		summary.Enabled++
		hasRefresh := strings.TrimSpace(credential.RefreshToken) != ""
		hasTokens := strings.TrimSpace(credential.AccessToken) != "" || hasRefresh
		if !hasTokens {
			summary.MissingTokens++
			continue
		}
		expired := !credential.ExpiresAt.IsZero() && !credential.ExpiresAt.After(now)
		if expired {
			summary.Expired++
		}
		if expired && !hasRefresh {
			continue
		}
		if credential.CooldownUntil != nil && credential.CooldownUntil.After(now) {
			summary.Cooling++
			if summary.NextRecoveryAt == nil || credential.CooldownUntil.Before(*summary.NextRecoveryAt) {
				value := credential.CooldownUntil.UTC()
				summary.NextRecoveryAt = &value
			}
		} else if credential.FailureCount > 0 {
			summary.ProbeDue++
		} else {
			summary.Available++
		}
		failureClass, _, _ := strings.Cut(credential.LastError, ":")
		if failureClass == "auth_invalid" && credential.FailureCount >= abnormalAfter {
			summary.Abnormal++
		}
		if failureClass == "quota_exhausted" && credential.FailureCount > 0 {
			summary.QuotaLimited++
		}
		if credential.LastSuccessAt != nil &&
			(summary.LastSuccessAt == nil || credential.LastSuccessAt.After(*summary.LastSuccessAt)) {
			value := credential.LastSuccessAt.UTC()
			summary.LastSuccessAt = &value
		}
	}
	return summary
}
