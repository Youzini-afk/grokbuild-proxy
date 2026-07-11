package storage

import (
	"context"
	"database/sql"
	"time"
)

const (
	recentEventsPerCredential = 24
	callEventRetention        = 100_000
)

// CallEvent is a sanitized upstream attempt outcome. It never contains prompts
// or credential material.
type CallEvent struct {
	ID             int64     `json:"id,omitempty"`
	CredentialID   string    `json:"credential_id"`
	CredentialName string    `json:"credential_name,omitempty"`
	Email          string    `json:"email,omitempty"`
	Model          string    `json:"model"`
	Status         int       `json:"status"`
	Success        bool      `json:"success"`
	LatencyMS      int64     `json:"latency_ms"`
	Error          string    `json:"error,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type CredentialUsage struct {
	SuccessCount int64       `json:"success_count"`
	FailureCount int64       `json:"failure_count"`
	TotalCount   int64       `json:"total_count"`
	AverageMS    float64     `json:"average_latency_ms"`
	LastStatus   int         `json:"last_status"`
	LastModel    string      `json:"last_model,omitempty"`
	LastCalledAt *time.Time  `json:"last_called_at,omitempty"`
	Recent       []CallEvent `json:"recent,omitempty"`
	totalLatency int64
}

type UsageBucket struct {
	Time         time.Time `json:"time"`
	SuccessCount int64     `json:"success_count"`
	FailureCount int64     `json:"failure_count"`
	TotalCount   int64     `json:"total_count"`
}

type ModelUsage struct {
	Model        string  `json:"model"`
	SuccessCount int64   `json:"success_count"`
	FailureCount int64   `json:"failure_count"`
	TotalCount   int64   `json:"total_count"`
	AverageMS    float64 `json:"average_latency_ms"`
}

type UsageSummary struct {
	Since          time.Time     `json:"since"`
	SuccessCount   int64         `json:"success_count"`
	FailureCount   int64         `json:"failure_count"`
	TotalCount     int64         `json:"total_count"`
	SuccessRate    float64       `json:"success_rate"`
	AverageMS      float64       `json:"average_latency_ms"`
	ActiveAccounts int           `json:"active_accounts"`
	Buckets        []UsageBucket `json:"buckets"`
	Models         []ModelUsage  `json:"models"`
	Recent         []CallEvent   `json:"recent"`
}

func (s *Store) loadUsageCache() error {
	stats := make(map[string]CredentialUsage)
	rows, err := s.db.Query(`SELECT credential_id,success_count,failure_count,total_latency_ms,last_status,last_model,last_called_at FROM credential_usage_stats`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, model, calledAt string
		var usage CredentialUsage
		if err := rows.Scan(&id, &usage.SuccessCount, &usage.FailureCount, &usage.totalLatency, &usage.LastStatus, &model, &calledAt); err != nil {
			_ = rows.Close()
			return err
		}
		usage.TotalCount = usage.SuccessCount + usage.FailureCount
		if usage.TotalCount > 0 {
			usage.AverageMS = float64(usage.totalLatency) / float64(usage.TotalCount)
		}
		usage.LastModel = model
		usage.LastCalledAt = parseDBTimePointer(calledAt)
		stats[id] = usage
	}
	if err := rows.Close(); err != nil {
		return err
	}

	rows, err = s.db.Query(`SELECT id,credential_id,model,status,success,latency_ms,error,created_at FROM (
		SELECT id,credential_id,model,status,success,latency_ms,error,created_at,
		ROW_NUMBER() OVER(PARTITION BY credential_id ORDER BY created_at DESC,id DESC) AS row_number
		FROM call_events
	) WHERE row_number<=? ORDER BY credential_id,created_at ASC,id ASC`, recentEventsPerCredential)
	if err != nil {
		return err
	}
	for rows.Next() {
		event, err := scanCallEvent(rows)
		if err != nil {
			_ = rows.Close()
			return err
		}
		usage := stats[event.CredentialID]
		usage.Recent = append(usage.Recent, event)
		stats[event.CredentialID] = usage
	}
	if err := rows.Close(); err != nil {
		return err
	}
	s.usageMu.Lock()
	s.usageByCredential = stats
	s.usageMu.Unlock()
	return nil
}

// RecordCredentialCall updates the UI cache immediately and queues one batched
// SQLite write. The caller never waits for disk I/O.
func (s *Store) RecordCredentialCall(event CallEvent) {
	if s == nil || event.CredentialID == "" {
		return
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if event.LatencyMS < 0 {
		event.LatencyMS = 0
	}
	if len(event.Error) > 256 {
		event.Error = event.Error[:256]
	}
	s.usageMu.Lock()
	if s.usageByCredential == nil {
		s.usageByCredential = make(map[string]CredentialUsage)
	}
	usage := s.usageByCredential[event.CredentialID]
	if event.Success {
		usage.SuccessCount++
	} else {
		usage.FailureCount++
	}
	usage.TotalCount++
	usage.totalLatency += event.LatencyMS
	usage.AverageMS = float64(usage.totalLatency) / float64(usage.TotalCount)
	if usage.LastCalledAt == nil || !event.CreatedAt.Before(*usage.LastCalledAt) {
		usage.LastStatus = event.Status
		usage.LastModel = event.Model
		calledAt := event.CreatedAt
		usage.LastCalledAt = &calledAt
	}
	if len(usage.Recent) < recentEventsPerCredential {
		usage.Recent = append(usage.Recent, event)
	} else {
		copy(usage.Recent, usage.Recent[1:])
		usage.Recent[len(usage.Recent)-1] = event
	}
	s.usageByCredential[event.CredentialID] = usage
	s.pendingCallEvents = append(s.pendingCallEvents, event)
	s.usageMu.Unlock()
	s.RecordCredentialUsage(event.CredentialID, event.CreatedAt)
}

func (s *Store) CredentialUsage(id string) CredentialUsage {
	s.usageMu.RLock()
	defer s.usageMu.RUnlock()
	usage := s.usageByCredential[id]
	usage.Recent = append([]CallEvent(nil), usage.Recent...)
	return usage
}

func (s *Store) removeCredentialUsage(id string) {
	s.usageMu.Lock()
	delete(s.usageByCredential, id)
	if len(s.pendingCallEvents) > 0 {
		kept := s.pendingCallEvents[:0]
		for _, event := range s.pendingCallEvents {
			if event.CredentialID != id {
				kept = append(kept, event)
			}
		}
		s.pendingCallEvents = kept
	}
	s.usageMu.Unlock()
	s.runtimeMu.Lock()
	delete(s.pendingUsage, id)
	s.runtimeMu.Unlock()
}

func (s *Store) flushCallEvents() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.usageMu.Lock()
	pending := s.pendingCallEvents
	s.pendingCallEvents = nil
	s.usageMu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	err := s.withLock(func() error {
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck
		for _, event := range pending {
			result, err := tx.Exec(`INSERT INTO call_events(credential_id,model,status,success,latency_ms,error,created_at)
				SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM credentials WHERE id=?)`,
				event.CredentialID, event.Model, event.Status, boolInt(event.Success), event.LatencyMS, event.Error,
				formatDBTime(event.CreatedAt), event.CredentialID)
			if err != nil {
				return err
			}
			inserted, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if inserted == 0 {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO credential_usage_stats(credential_id,success_count,failure_count,total_latency_ms,last_status,last_model,last_called_at)
				VALUES(?,?,?,?,?,?,?) ON CONFLICT(credential_id) DO UPDATE SET
				success_count=success_count+excluded.success_count,
				failure_count=failure_count+excluded.failure_count,
				total_latency_ms=total_latency_ms+excluded.total_latency_ms,
				last_status=CASE WHEN excluded.last_called_at>=last_called_at THEN excluded.last_status ELSE last_status END,
				last_model=CASE WHEN excluded.last_called_at>=last_called_at THEN excluded.last_model ELSE last_model END,
				last_called_at=MAX(last_called_at,excluded.last_called_at)`,
				event.CredentialID, boolInt(event.Success), boolInt(!event.Success), event.LatencyMS,
				event.Status, event.Model, formatDBTime(event.CreatedAt)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DELETE FROM call_events WHERE id < (SELECT id FROM call_events ORDER BY id DESC LIMIT 1 OFFSET ?)`, callEventRetention-1); err != nil {
			return err
		}
		return tx.Commit()
	})
	if err != nil {
		s.usageMu.Lock()
		s.pendingCallEvents = append(pending, s.pendingCallEvents...)
		s.usageMu.Unlock()
	}
	return err
}

// UsageSummary returns persisted aggregates for a time window. Very recent
// events may appear on credential cards before the next one-second flush.
func (s *Store) UsageSummary(since time.Time) (UsageSummary, error) {
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	since = since.UTC().Truncate(time.Second)
	summary := UsageSummary{Since: since, Buckets: []UsageBucket{}, Models: []ModelUsage{}, Recent: []CallEvent{}}
	err := s.withLock(func() error {
		var totalLatency sql.NullFloat64
		if err := s.db.QueryRow(`SELECT COALESCE(SUM(success),0),COALESCE(SUM(CASE WHEN success=0 THEN 1 ELSE 0 END),0),AVG(latency_ms),COUNT(DISTINCT credential_id)
			FROM call_events WHERE created_at>=?`, formatDBTime(since)).Scan(&summary.SuccessCount, &summary.FailureCount, &totalLatency, &summary.ActiveAccounts); err != nil {
			return err
		}
		summary.TotalCount = summary.SuccessCount + summary.FailureCount
		if summary.TotalCount > 0 {
			summary.SuccessRate = float64(summary.SuccessCount) * 100 / float64(summary.TotalCount)
		}
		if totalLatency.Valid {
			summary.AverageMS = totalLatency.Float64
		}

		rows, err := s.db.Query(`SELECT strftime('%Y-%m-%dT%H:00:00Z',created_at),SUM(success),SUM(CASE WHEN success=0 THEN 1 ELSE 0 END),COUNT(*)
			FROM call_events WHERE created_at>=? GROUP BY 1 ORDER BY 1`, formatDBTime(since))
		if err != nil {
			return err
		}
		for rows.Next() {
			var bucket UsageBucket
			var stamp string
			if err := rows.Scan(&stamp, &bucket.SuccessCount, &bucket.FailureCount, &bucket.TotalCount); err != nil {
				_ = rows.Close()
				return err
			}
			bucket.Time = parseDBTime(stamp)
			summary.Buckets = append(summary.Buckets, bucket)
		}
		if err := rows.Close(); err != nil {
			return err
		}

		rows, err = s.db.Query(`SELECT model,SUM(success),SUM(CASE WHEN success=0 THEN 1 ELSE 0 END),COUNT(*),AVG(latency_ms)
			FROM call_events WHERE created_at>=? GROUP BY model ORDER BY COUNT(*) DESC LIMIT 20`, formatDBTime(since))
		if err != nil {
			return err
		}
		for rows.Next() {
			var model ModelUsage
			if err := rows.Scan(&model.Model, &model.SuccessCount, &model.FailureCount, &model.TotalCount, &model.AverageMS); err != nil {
				_ = rows.Close()
				return err
			}
			summary.Models = append(summary.Models, model)
		}
		if err := rows.Close(); err != nil {
			return err
		}

		rows, err = s.db.Query(`SELECT e.id,e.credential_id,c.name,c.email,e.model,e.status,e.success,e.latency_ms,e.error,e.created_at
			FROM call_events e LEFT JOIN credentials c ON c.id=e.credential_id
			WHERE e.created_at>=? ORDER BY e.created_at DESC,e.id DESC LIMIT 50`, formatDBTime(since))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var event CallEvent
			var success int
			var created string
			if err := rows.Scan(&event.ID, &event.CredentialID, &event.CredentialName, &event.Email, &event.Model,
				&event.Status, &success, &event.LatencyMS, &event.Error, &created); err != nil {
				return err
			}
			event.Success = success != 0
			event.CreatedAt = parseDBTime(created)
			summary.Recent = append(summary.Recent, event)
		}
		return rows.Err()
	})
	return summary, err
}

func scanCallEvent(scanner credentialScanner) (CallEvent, error) {
	var event CallEvent
	var success int
	var created string
	err := scanner.Scan(&event.ID, &event.CredentialID, &event.Model, &event.Status, &success, &event.LatencyMS, &event.Error, &created)
	if err != nil {
		return CallEvent{}, err
	}
	event.Success = success != 0
	event.CreatedAt = parseDBTime(created)
	return event, nil
}

func fillHourlyBuckets(summary *UsageSummary, hours int) {
	if summary == nil || hours <= 0 {
		return
	}
	byTime := make(map[string]UsageBucket, len(summary.Buckets))
	for _, bucket := range summary.Buckets {
		byTime[bucket.Time.UTC().Format(time.RFC3339)] = bucket
	}
	end := time.Now().UTC().Truncate(time.Hour)
	filled := make([]UsageBucket, 0, hours)
	for i := hours - 1; i >= 0; i-- {
		stamp := end.Add(-time.Duration(i) * time.Hour)
		bucket := byTime[stamp.Format(time.RFC3339)]
		bucket.Time = stamp
		filled = append(filled, bucket)
	}
	summary.Buckets = filled
}

func (s *Store) UsageSummaryHours(hours int) (UsageSummary, error) {
	if hours < 1 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	summary, err := s.UsageSummary(time.Now().UTC().Add(-time.Duration(hours) * time.Hour))
	if err != nil {
		return summary, err
	}
	fillHourlyBuckets(&summary, hours)
	return summary, nil
}
