package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type importOutcome struct {
	Imported         int              `json:"imported"`
	Created          int              `json:"created"`
	Updated          int              `json:"updated"`
	Failed           int              `json:"failed"`
	Results          []map[string]any `json:"results,omitempty"`
	ResultsTruncated bool             `json:"results_truncated"`
}

func (outcome importOutcome) httpStatus() int {
	if outcome.Failed > 0 {
		return http.StatusMultiStatus
	}
	if outcome.Created > 0 {
		return http.StatusCreated
	}
	return http.StatusOK
}

type ImportJob struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	Total       int            `json:"total"`
	Processed   int            `json:"processed"`
	Outcome     *importOutcome `json:"outcome,omitempty"`
	Error       string         `json:"error,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
}

func (h *Handlers) persistImported(imported []auth.ImportedCredential) (importOutcome, error) {
	inputs := make([]storage.CreateCredentialInput, 0, len(imported))
	for _, credential := range imported {
		name := credential.Email
		if name == "" {
			name = credential.SourceKey
		}
		inputs = append(inputs, storage.CreateCredentialInput{
			Name: name, Email: credential.Email, UserID: credential.UserID, TeamID: credential.TeamID,
			SourceKey: credential.SourceKey, OIDCClientID: credential.OIDCClientID,
			AccessToken: credential.AccessToken, RefreshToken: credential.RefreshToken, ExpiresAt: credential.ExpiresAt,
		})
	}
	outcome := importOutcome{Results: make([]map[string]any, 0, min(len(imported), 100))}
	if bulk, ok := h.Store.(credentialBulkUpserter); ok {
		results, err := bulk.BulkUpsertCredentials(inputs)
		if err != nil {
			return outcome, err
		}
		for i, result := range results {
			status := "updated"
			if result.Err != nil {
				outcome.Failed++
				status = "failed"
			} else if result.Created {
				outcome.Created++
				status = "created"
			} else {
				outcome.Updated++
			}
			if len(outcome.Results) < 100 {
				row := map[string]any{"source_key": imported[i].SourceKey, "status": status}
				if result.Err != nil {
					row["error"] = result.Err.Error()
				} else {
					row["id"] = result.Credential.ID
				}
				outcome.Results = append(outcome.Results, row)
			}
		}
	} else {
		upserter, canUpsert := h.Store.(credentialUpserter)
		for i, input := range inputs {
			var credential storage.Credential
			var created bool
			var err error
			if canUpsert {
				credential, created, err = upserter.UpsertCredential(input)
			} else {
				credential, err = h.Store.CreateCredential(input)
				created = err == nil
			}
			status := "updated"
			if err != nil {
				outcome.Failed++
				status = "failed"
			} else if created {
				outcome.Created++
				status = "created"
			} else {
				outcome.Updated++
			}
			if len(outcome.Results) < 100 {
				row := map[string]any{"source_key": imported[i].SourceKey, "status": status}
				if err != nil {
					row["error"] = err.Error()
				} else {
					row["id"] = credential.ID
				}
				outcome.Results = append(outcome.Results, row)
			}
		}
	}
	outcome.Imported = outcome.Created + outcome.Updated
	outcome.ResultsTruncated = len(imported) > len(outcome.Results)
	return outcome, nil
}

func (h *Handlers) startImportJob(imported []auth.ImportedCredential) ImportJob {
	now := time.Now().UTC()
	job := &ImportJob{ID: newImportJobID(), Status: "queued", Total: len(imported), CreatedAt: now}
	ctx, cancel := context.WithCancel(context.Background())
	h.importMu.Lock()
	if h.importJobs == nil {
		h.importJobs = make(map[string]*ImportJob)
		h.importCancels = make(map[string]context.CancelFunc)
		h.importSem = make(chan struct{}, 1)
	}
	h.importJobs[job.ID] = job
	h.importCancels[job.ID] = cancel
	h.pruneImportJobsLocked(50)
	copyJob := *job
	sem := h.importSem
	h.importMu.Unlock()

	go func() {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			h.finishImportJob(job.ID, nil, ctx.Err())
			return
		}
		started := time.Now().UTC()
		h.importMu.Lock()
		if current := h.importJobs[job.ID]; current != nil {
			current.Status = "running"
			current.StartedAt = &started
		}
		h.importMu.Unlock()
		if ctx.Err() != nil {
			h.finishImportJob(job.ID, nil, ctx.Err())
			return
		}
		outcome, err := h.persistImported(imported)
		h.finishImportJob(job.ID, &outcome, err)
	}()
	return copyJob
}

func (h *Handlers) finishImportJob(id string, outcome *importOutcome, err error) {
	now := time.Now().UTC()
	h.importMu.Lock()
	defer h.importMu.Unlock()
	job := h.importJobs[id]
	if job == nil {
		return
	}
	job.CompletedAt = &now
	delete(h.importCancels, id)
	if err != nil {
		if err == context.Canceled {
			job.Status = "cancelled"
		} else {
			job.Status = "failed"
			job.Error = err.Error()
		}
		return
	}
	job.Status = "completed"
	job.Outcome = outcome
	job.Processed = job.Total
}

func (h *Handlers) GetImportJob(w http.ResponseWriter, r *http.Request, id string) {
	h.importMu.Lock()
	job := h.importJobs[id]
	if job == nil {
		h.importMu.Unlock()
		writeErr(w, http.StatusNotFound, "import job not found")
		return
	}
	copyJob := *job
	h.importMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"job": copyJob})
}

func (h *Handlers) CancelImportJob(w http.ResponseWriter, r *http.Request, id string) {
	h.importMu.Lock()
	cancel := h.importCancels[id]
	job := h.importJobs[id]
	h.importMu.Unlock()
	if job == nil {
		writeErr(w, http.StatusNotFound, "import job not found")
		return
	}
	if cancel != nil {
		cancel()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"cancel_requested": id})
}

func (h *Handlers) pruneImportJobsLocked(keep int) {
	if len(h.importJobs) <= keep {
		return
	}
	completed := make([]*ImportJob, 0)
	for _, job := range h.importJobs {
		if job.CompletedAt != nil {
			completed = append(completed, job)
		}
	}
	sort.Slice(completed, func(i, j int) bool { return completed[i].CreatedAt.Before(completed[j].CreatedAt) })
	for len(h.importJobs) > keep && len(completed) > 0 {
		delete(h.importJobs, completed[0].ID)
		completed = completed[1:]
	}
}

func newImportJobID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "import_" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("import_%d", time.Now().UnixNano())
}

func queryBool(r *http.Request, key string) bool {
	if r == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
