package swarm

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"felix/pkg/report"
	_ "modernc.org/sqlite"
)

// WALWriter owns the single-writer database write path for high-concurrency finding ingestion.
// It routes worker findings through a dedicated buffered channel (capacity 5,000) and commits
// findings via periodic batched atomic transactions (every 250ms) under SQLite WAL mode.
type WALWriter struct {
	db           *sql.DB
	ownsDB       bool
	assessmentID string
	executionID  string
	targetID     string

	findingChan chan report.Finding
	batchSize   int
	interval    time.Duration

	seenMu   sync.RWMutex
	seenIDs  map[string]struct{}
	seenKeys map[string]struct{} // fingerprint or composite key deduplication

	metrics SwarmMetrics
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closed  int32
}

// WALWriterConfig configures the single-writer buffered WAL engine.
type WALWriterConfig struct {
	DB              *sql.DB
	DBPath          string
	AssessmentID    string
	ExecutionID     string
	TargetID        string
	ChannelCapacity int
	BatchSize       int
	CommitInterval  time.Duration
}

// NewWALWriter initializes the SQLite WAL engine, applies concurrency pragmas,
// verifies table schemas, and launches the dedicated single-writer background goroutine.
func NewWALWriter(cfg WALWriterConfig) (*WALWriter, error) {
	if cfg.ChannelCapacity <= 0 {
		cfg.ChannelCapacity = 5000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.CommitInterval <= 0 {
		cfg.CommitInterval = 250 * time.Millisecond
	}
	if cfg.AssessmentID == "" {
		cfg.AssessmentID = "ASM-SWARM-DEFAULT"
	}
	if cfg.ExecutionID == "" {
		cfg.ExecutionID = "EXEC-SWARM-DEFAULT"
	}
	if cfg.TargetID == "" {
		cfg.TargetID = "TGT-SWARM-DEFAULT"
	}

	var db *sql.DB
	ownsDB := false

	if cfg.DB != nil {
		db = cfg.DB
	} else if cfg.DBPath != "" {
		// Open SQLite with modernc.org/sqlite
		opened, err := sql.Open("sqlite", cfg.DBPath)
		if err != nil {
			return nil, fmt.Errorf("failed opening SQLite database at %s: %w", cfg.DBPath, err)
		}
		db = opened
		ownsDB = true
	} else {
		return nil, fmt.Errorf("either DB or DBPath must be provided to NewWALWriter")
	}

	// Configure mandatory WAL mode and concurrency pragmas
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			// Memory databases may return specific notices on WAL mode
			if !strings.Contains(pragma, "WAL") || !strings.Contains(err.Error(), "memory") {
				if ownsDB {
					_ = db.Close()
				}
				return nil, fmt.Errorf("failed executing pragma %q: %w", pragma, err)
			}
		}
	}

	// Ensure assessment_findings table exists
	schema := `
	CREATE TABLE IF NOT EXISTS assessment_findings (
		id TEXT PRIMARY KEY,
		assessment_id TEXT NOT NULL,
		execution_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		original_finding_id TEXT NOT NULL,
		title TEXT NOT NULL,
		category TEXT NOT NULL,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		verification_status TEXT NOT NULL,
		target_url TEXT NOT NULL,
		endpoint TEXT NOT NULL,
		method TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		score INTEGER NOT NULL DEFAULT 0,
		evidence_json TEXT NOT NULL,
		verification_json TEXT NOT NULL,
		remediation TEXT,
		created_at TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_findings_assessment_id ON assessment_findings(assessment_id);
	CREATE INDEX IF NOT EXISTS idx_findings_execution_id ON assessment_findings(execution_id);
	CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON assessment_findings(fingerprint);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_asm_fp ON assessment_findings(assessment_id, fingerprint) WHERE fingerprint != '';
	`
	if _, err := db.Exec(schema); err != nil {
		if ownsDB {
			_ = db.Close()
		}
		return nil, fmt.Errorf("failed initializing findings schema: %w", err)
	}

	// Pre-load existing persisted findings for durable idempotency across restarts
	seenIDs := make(map[string]struct{})
	seenKeys := make(map[string]struct{})

	rows, qErr := db.Query("SELECT id, fingerprint FROM assessment_findings WHERE assessment_id = ?", cfg.AssessmentID)
	if qErr == nil {
		defer rows.Close()
		for rows.Next() {
			var rowID, rowFP sql.NullString
			if err := rows.Scan(&rowID, &rowFP); err == nil {
				if rowID.Valid && rowID.String != "" {
					seenIDs[rowID.String] = struct{}{}
				}
				if rowFP.Valid && rowFP.String != "" {
					seenKeys[rowFP.String] = struct{}{}
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	writer := &WALWriter{
		db:           db,
		ownsDB:       ownsDB,
		assessmentID: cfg.AssessmentID,
		executionID:  cfg.ExecutionID,
		targetID:     cfg.TargetID,
		findingChan:  make(chan report.Finding, cfg.ChannelCapacity),
		batchSize:    cfg.BatchSize,
		interval:     cfg.CommitInterval,
		seenIDs:      seenIDs,
		seenKeys:     seenKeys,
		ctx:          ctx,
		cancel:       cancel,
	}

	writer.wg.Add(1)
	go writer.run()

	return writer, nil
}

// Submit enqueues a finding into the single-writer buffered channel.
// Implements in-memory deduplication and explicit channel backpressure handling.
func (w *WALWriter) Submit(f report.Finding) error {
	if atomic.LoadInt32(&w.closed) == 1 {
		return ErrCoordinatorClosed
	}

	// 1. Deduplication Check
	dedupKey := f.Fingerprint
	if dedupKey == "" {
		dedupKey = fmt.Sprintf("%s|%s|%s|%s", f.Target, f.Endpoint, f.Method, f.Category)
	}

	w.seenMu.Lock()
	if f.ID != "" {
		if _, exists := w.seenIDs[f.ID]; exists {
			w.seenMu.Unlock()
			atomic.AddInt64(&w.metrics.DuplicateFindingsDropped, 1)
			return nil // Safely dropped duplicate
		}
	}
	if _, exists := w.seenKeys[dedupKey]; exists {
		w.seenMu.Unlock()
		atomic.AddInt64(&w.metrics.DuplicateFindingsDropped, 1)
		return nil // Safely dropped duplicate
	}

	// Register key as in-flight
	if f.ID != "" {
		w.seenIDs[f.ID] = struct{}{}
	}
	w.seenKeys[dedupKey] = struct{}{}
	w.seenMu.Unlock()

	// 2. Enqueue with Backpressure Management
	select {
	case w.findingChan <- f:
		atomic.AddInt64(&w.metrics.TotalFindingsReceived, 1)
		return nil
	default:
		// Channel is at full capacity: wait with bounded timeout before raising backpressure
		select {
		case w.findingChan <- f:
			atomic.AddInt64(&w.metrics.TotalFindingsReceived, 1)
			return nil
		case <-time.After(100 * time.Millisecond):
			// Evict deduplication reservation since submission failed
			w.seenMu.Lock()
			if f.ID != "" {
				delete(w.seenIDs, f.ID)
			}
			delete(w.seenKeys, dedupKey)
			w.seenMu.Unlock()
			return ErrQueueFull
		case <-w.ctx.Done():
			return ErrCoordinatorClosed
		}
	}
}

// SubmitBatch submits multiple findings atomically with deduplication.
func (w *WALWriter) SubmitBatch(findings []report.Finding) (int, int, error) {
	accepted := 0
	dropped := 0
	for _, f := range findings {
		err := w.Submit(f)
		if err != nil {
			return accepted, dropped, err
		}
		accepted++
	}
	return accepted, dropped, nil
}

// run is the dedicated single-writer background loop committing findings in atomic transactions.
func (w *WALWriter) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	var batch []report.Finding

	for {
		select {
		case f, ok := <-w.findingChan:
			if !ok {
				// Channel closed, flush remaining items
				if len(batch) > 0 {
					w.commitBatch(batch)
				}
				return
			}
			batch = append(batch, f)
			if len(batch) >= w.batchSize {
				w.commitBatch(batch)
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.commitBatch(batch)
				batch = nil
			}

		case <-w.ctx.Done():
			// Context canceled, drain channel
			for {
				select {
				case f, ok := <-w.findingChan:
					if !ok {
						if len(batch) > 0 {
							w.commitBatch(batch)
						}
						return
					}
					batch = append(batch, f)
					if len(batch) >= w.batchSize {
						w.commitBatch(batch)
						batch = nil
					}
				default:
					if len(batch) > 0 {
						w.commitBatch(batch)
					}
					return
				}
			}
		}
	}
}

// commitBatch executes an atomic SQLite transaction to persist a batch of findings.
func (w *WALWriter) commitBatch(batch []report.Finding) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()

	tx, err := w.db.Begin()
	if err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "BUSY") {
			atomic.AddInt64(&w.metrics.SQLiteBusyErrors, 1)
		}
		// In case of error, retry with small backoff
		time.Sleep(10 * time.Millisecond)
		tx, err = w.db.Begin()
		if err != nil {
			return
		}
	}

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_findings (
			id, assessment_id, execution_id, target_id, original_finding_id,
			title, category, severity, confidence, verification_status,
			target_url, endpoint, method, fingerprint, score,
			evidence_json, verification_json, remediation, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title,
			severity = excluded.severity,
			confidence = excluded.confidence,
			score = excluded.score,
			evidence_json = excluded.evidence_json
	`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, f := range batch {
		id := f.ID
		if id == "" {
			if f.Fingerprint != "" {
				id = fmt.Sprintf("FND-%s", f.Fingerprint)
			} else {
				id = fmt.Sprintf("FND-%d", time.Now().UnixNano())
			}
		}

		evidenceBytes, _ := json.Marshal(f.EvidenceDetails)
		verifBytes, _ := json.Marshal(f.Verification)

		createdAt := f.Timestamp
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}

		targetURL := f.Target
		if targetURL == "" {
			targetURL = "http://127.0.0.1"
		}

		_, err := stmt.Exec(
			id,
			w.assessmentID,
			w.executionID,
			w.targetID,
			f.ID,
			f.Title,
			f.Category,
			f.Severity,
			f.Confidence,
			string(f.Verification.Status),
			targetURL,
			f.Endpoint,
			f.Method,
			f.Fingerprint,
			f.Score,
			string(evidenceBytes),
			string(verifBytes),
			f.Remediation,
			createdAt,
		)
		if err != nil {
			if strings.Contains(strings.ToUpper(err.Error()), "BUSY") {
				atomic.AddInt64(&w.metrics.SQLiteBusyErrors, 1)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "BUSY") {
			atomic.AddInt64(&w.metrics.SQLiteBusyErrors, 1)
		}
		_ = tx.Rollback()
		return
	}

	duration := time.Since(start)
	atomic.AddInt64(&w.metrics.BatchesCommitted, 1)
	atomic.AddInt64(&w.metrics.TotalFindingsPersisted, int64(len(batch)))

	// Update throughput metric (findings per second)
	if duration.Seconds() > 0 {
		rate := float64(len(batch)) / duration.Seconds()
		w.metrics.ThroughputFindingsPerSecond = rate
	}
	w.metrics.TotalBatchDurationMs += float64(duration.Microseconds()) / 1000.0
}

// DrainAndClose gracefully drains the buffered finding channel, commits the final batch,
// waits for the background single-writer goroutine to exit, and closes the database if owned.
func (w *WALWriter) DrainAndClose(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&w.closed, 0, 1) {
		return nil
	}

	// Close finding channel so run() can drain all in-flight findings
	close(w.findingChan)

	// Wait for writer to finish flushing to disk
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		w.cancel()
		w.wg.Wait()
	}

	if w.ownsDB && w.db != nil {
		return w.db.Close()
	}
	return nil
}

// GetMetrics returns a snapshot of WALWriter throughput and error counters.
func (w *WALWriter) GetMetrics() SwarmMetrics {
	w.seenMu.RLock()
	defer w.seenMu.RUnlock()
	m := w.metrics
	m.TotalFindingsReceived = atomic.LoadInt64(&w.metrics.TotalFindingsReceived)
	m.TotalFindingsPersisted = atomic.LoadInt64(&w.metrics.TotalFindingsPersisted)
	m.DuplicateFindingsDropped = atomic.LoadInt64(&w.metrics.DuplicateFindingsDropped)
	m.BatchesCommitted = atomic.LoadInt64(&w.metrics.BatchesCommitted)
	m.SQLiteBusyErrors = atomic.LoadInt64(&w.metrics.SQLiteBusyErrors)
	return m
}

// CountPersistedFindings directly counts rows in assessment_findings to verify persistence.
func (w *WALWriter) CountPersistedFindings() (int, error) {
	var count int
	err := w.db.QueryRow("SELECT COUNT(*) FROM assessment_findings").Scan(&count)
	return count, err
}
