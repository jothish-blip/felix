package cve

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store encapsulates the embedded SQLite CVE knowledge base and hybrid SemVer query engine.
type Store struct {
	dbPath      string
	db          *sql.DB
	queryStmt   *sql.Stmt
	mu          sync.RWMutex
	coordinator *PublicationCoordinator
}

// DefaultDBPath returns the canonical location of the FELIX CVE database (~/.felix/cve.db).
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to resolve user home directory: %w", err)
	}
	return filepath.Join(home, ".felix", "cve.db"), nil
}

// NewStore initializes an embedded SQLite database at dbPath, creating parent directories
// and running schema initialization and pragma optimization if necessary.
func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		def, err := DefaultDBPath()
		if err != nil {
			return nil, err
		}
		dbPath = def
	}

	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create cve db directory %s: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database at %s: %w", dbPath, err)
	}

	// Performance, memory, and concurrency tuning pragmas
	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 10000;",
		"PRAGMA synchronous = NORMAL;",
	}
	if dbPath != ":memory:" {
		pragmas = append(pragmas,
			"PRAGMA journal_mode = WAL;",
			"PRAGMA cache_size = -128000;",  // 128MB memory page cache
			"PRAGMA temp_store = MEMORY;",
			"PRAGMA mmap_size = 536870912;", // 512MB memory-mapped I/O
		)
	}

	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			if dbPath != ":memory:" {
				db.Close()
				return nil, fmt.Errorf("failed executing pragma %q: %w", p, err)
			}
		}
	}

	// Execute Schema DDL
	if _, err := db.Exec(SchemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize cve schema: %w", err)
	}

	// Prepare the ultra-fast candidate query statement
	querySQL := `
		SELECT cve_id, source, cpe_prefix, vendor, product,
		       COALESCE(version_start, ''), version_start_including,
		       COALESCE(version_end, ''), version_end_including,
		       COALESCE(exact_version, ''), cvss_score, severity,
		       summary, published_at, updated_at, COALESCE(reference_urls, '')
		FROM cve_index
		WHERE cpe_prefix = ?
	`
	queryStmt, err := db.Prepare(querySQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prepare cve candidate query statement: %w", err)
	}

	return &Store{
		dbPath:      dbPath,
		db:          db,
		queryStmt:   queryStmt,
		coordinator: NewPublicationCoordinator(),
	}, nil
}

// SetCoordinator sets the shared publication coordinator for cross-component atomicity.
func (s *Store) SetCoordinator(c *PublicationCoordinator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coordinator = c
}

// Coordinator returns the assigned publication coordinator without blocking.
func (s *Store) Coordinator() *PublicationCoordinator {
	return s.coordinator
}

// Generation returns the current published generation for the store.
func (s *Store) Generation() uint64 {
	c := s.coordinator
	if c != nil {
		return c.Generation()
	}
	return 1
}

// BindRegistry binds a template registry to this store using a shared publication coordinator.
func (s *Store) BindRegistry(reg *TemplateRegistry) *PublicationCoordinator {
	return BindCoordinated(s, reg)
}

// Close closes prepared statements and releases the database connection.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	if s.queryStmt != nil {
		if err := s.queryStmt.Close(); err != nil {
			firstErr = err
		}
		s.queryStmt = nil
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.db = nil
	}
	return firstErr
}

// DB returns the underlying *sql.DB for advanced transactions or testing.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Optimize executes SQLite wal_checkpoint, ANALYZE and PRAGMA optimize to update query optimizer statistics.
func (s *Store) Optimize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("cve store is closed")
	}
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE); ANALYZE; PRAGMA optimize;")
	return err
}

var candidatePool = sync.Pool{
	New: func() any {
		s := make([]CVERecord, 0, 64)
		return &s
	},
}

// QueryByCPE executes the hybrid two-stage evaluation:
// Stage 1: SQLite indexed retrieval of candidate CVEs matching the canonical CPE prefix (<0.5ms).
// Stage 2: In-memory SemVer evaluation of version constraints using Masterminds/semver (<0.1ms).
// Total target query latency is <1.0ms with zero ASCII collation errors.
func (s *Store) QueryByCPE(ctx context.Context, cpePrefix string, targetVersion string) ([]MatchResult, QueryMetrics, error) {
	coord := s.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || s.queryStmt == nil {
		return nil, QueryMetrics{}, errors.New("cve store is closed")
	}

	cleanPrefix := strings.TrimSpace(strings.ToLower(cpePrefix))

	cPtr := candidatePool.Get().(*[]CVERecord)
	candidates := (*cPtr)[:0]
	defer func() {
		for i := range candidates {
			candidates[i] = CVERecord{}
		}
		if cap(candidates) <= 1024 {
			*cPtr = candidates[:0]
			candidatePool.Put(cPtr)
		}
	}()

	// Stage 1: SQLite indexed candidate retrieval (using high-resolution monotonic timer)
	t0 := MonotonicNowNano()
	rows, err := s.queryStmt.QueryContext(ctx, cleanPrefix)
	if err != nil {
		return nil, QueryMetrics{}, fmt.Errorf("failed executing candidate query for %s: %w", cleanPrefix, err)
	}
	defer rows.Close()

	for rows.Next() {
		var r CVERecord
		var vStartInc, vEndInc int
		if err := rows.Scan(
			&r.CVEID,
			&r.Source,
			&r.CPEPrefix,
			&r.Vendor,
			&r.Product,
			&r.VersionStart,
			&vStartInc,
			&r.VersionEnd,
			&vEndInc,
			&r.ExactVersion,
			&r.CVSSScore,
			&r.Severity,
			&r.Summary,
			&r.PublishedAt,
			&r.UpdatedAt,
			&r.ReferenceURLs,
		); err != nil {
			return nil, QueryMetrics{}, fmt.Errorf("failed scanning candidate row: %w", err)
		}
		r.VersionStartIncluding = (vStartInc != 0)
		r.VersionEndIncluding = (vEndInc != 0)
		candidates = append(candidates, r)
	}
	if err := rows.Err(); err != nil {
		return nil, QueryMetrics{}, fmt.Errorf("row iteration error: %w", err)
	}
	retrievalNanos := MonotonicNowNano() - t0
	if retrievalNanos < 0 {
		retrievalNanos = 0
	}
	retrievalLatency := time.Duration(retrievalNanos)

	// Stage 2: Pure Go in-memory SemVer evaluation
	t2 := MonotonicNowNano()
	results := make([]MatchResult, 0, len(candidates))
	confirmedMatches := 0

	// Parse targetVersion ONCE for all candidates
	targetSem, targetErr := NormalizeSemVer(targetVersion)

	for _, c := range candidates {
		var status MatchStatus
		var constraint, notes string

		if targetErr != nil {
			status = MatchInconclusive
			notes = fmt.Sprintf("Target version %q cannot be parsed as SemVer: %v", targetVersion, targetErr)
		} else {
			status, constraint, notes = EvaluateCandidateSemVer(c, targetSem)
		}

		if status == MatchConfirmed {
			confirmedMatches++
		}
		results = append(results, MatchResult{
			CVEID:           c.CVEID,
			Source:          string(c.Source),
			CPEPrefix:       c.CPEPrefix,
			TargetVersion:   targetVersion,
			MatchStatus:     status,
			CVSSScore:       c.CVSSScore,
			Severity:        c.Severity,
			Summary:         c.Summary,
			Constraint:      constraint,
			EvaluationNotes: notes,
		})
	}
	evalNanos := MonotonicNowNano() - t2
	if evalNanos < 0 {
		evalNanos = 0
	}
	evalLatency := time.Duration(evalNanos)
	totalLatency := retrievalLatency + evalLatency

	metrics := QueryMetrics{
		CPEPrefix:           cleanPrefix,
		TargetVersion:       targetVersion,
		CandidateCount:      len(candidates),
		ConfirmedMatchCount: confirmedMatches,
		RetrievalLatency:    retrievalLatency,
		EvalLatency:         evalLatency,
		TotalLatency:        totalLatency,
		RetrievalLatencyMs:  float64(retrievalLatency.Nanoseconds()) / 1e6,
		EvalLatencyMs:       float64(evalLatency.Nanoseconds()) / 1e6,
		TotalLatencyMs:      float64(totalLatency.Nanoseconds()) / 1e6,
	}

	return results, metrics, nil
}

// InsertBatch inserts a slice of CVERecords into SQLite within optimized transactions.
// It gracefully deduplicates identical records and skips malformed records without corrupting the store.
func (s *Store) InsertBatch(ctx context.Context, records []CVERecord) (IngestStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	startTime := time.Now()
	stats := IngestStats{
		TotalProcessed: len(records),
	}

	if len(records) == 0 {
		return stats, nil
	}

	insertSQL := `
		INSERT OR IGNORE INTO cve_index (
			cve_id, source, cpe_prefix, vendor, product,
			version_start, version_start_including,
			version_end, version_end_including,
			exact_version, cvss_score, severity,
			summary, published_at, updated_at, reference_urls
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	const chunkSize = 5000
	for i := 0; i < len(records); i += chunkSize {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}

		end := i + chunkSize
		if end > len(records) {
			end = len(records)
		}
		chunk := records[i:end]

		if err := func() error {
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("failed beginning transaction: %w", err)
			}
			defer tx.Rollback()

			stmt, err := tx.PrepareContext(ctx, insertSQL)
			if err != nil {
				return fmt.Errorf("failed preparing insert statement: %w", err)
			}
			defer stmt.Close()

			for _, r := range chunk {
				if strings.TrimSpace(r.CVEID) == "" || strings.TrimSpace(r.CPEPrefix) == "" {
					stats.Errors++
					continue
				}

				vStartInc := 0
				if r.VersionStartIncluding {
					vStartInc = 1
				}
				vEndInc := 0
				if r.VersionEndIncluding {
					vEndInc = 1
				}

				cleanPrefix := strings.TrimSpace(strings.ToLower(r.CPEPrefix))
				source := string(r.Source)
				if source == "" {
					source = string(SourceSynthetic)
				}

				res, err := stmt.ExecContext(ctx,
					r.CVEID,
					source,
					cleanPrefix,
					r.Vendor,
					r.Product,
					r.VersionStart,
					vStartInc,
					r.VersionEnd,
					vEndInc,
					r.ExactVersion,
					r.CVSSScore,
					r.Severity,
					r.Summary,
					r.PublishedAt,
					r.UpdatedAt,
					r.ReferenceURLs,
				)
				if err != nil {
					stats.Errors++
					continue
				}
				affected, _ := res.RowsAffected()
				if affected > 0 {
					stats.Inserted++
				} else {
					stats.Skipped++
				}
			}

			return tx.Commit()
		}(); err != nil {
			return stats, err
		}
	}

	stats.Duration = time.Since(startTime)
	if stats.Duration.Seconds() > 0 {
		stats.RecordsPerSec = float64(stats.Inserted) / stats.Duration.Seconds()
	}

	return stats, nil
}

// IngestRecords is a convenience wrapper for InsertBatch.
func (s *Store) IngestRecords(ctx context.Context, records []CVERecord) (IngestStats, error) {
	return s.InsertBatch(ctx, records)
}

// IngestNVDJSON ingests vulnerability entries from an NVD 2.0 JSON document.
func (s *Store) IngestNVDJSON(ctx context.Context, r io.Reader) (IngestStats, error) {
	var payload struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Published   string `json:"published"`
				LastMod     string `json:"lastModified"`
				Description struct {
					DescData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Vulnerable            bool   `json:"vulnerable"`
							Criteria              string `json:"criteria"`
							VersionStartIncluding string `json:"versionStartIncluding"`
							VersionStartExcluding string `json:"versionStartExcluding"`
							VersionEndIncluding   string `json:"versionEndIncluding"`
							VersionEndExcluding   string `json:"versionEndExcluding"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References struct {
					RefData []struct {
						URL string `json:"url"`
					} `json:"reference_data"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return IngestStats{}, fmt.Errorf("failed decoding NVD JSON 2.0 payload: %w", err)
	}

	var records []CVERecord
	for _, vuln := range payload.Vulnerabilities {
		c := vuln.CVE
		summary := ""
		for _, d := range c.Description.DescData {
			if d.Lang == "en" || summary == "" {
				summary = d.Value
			}
		}

		score := 0.0
		severity := "UNKNOWN"
		if len(c.Metrics.CVSSMetricV31) > 0 {
			score = c.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity = c.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		}

		var refs []string
		for _, rf := range c.References.RefData {
			if rf.URL != "" {
				refs = append(refs, rf.URL)
			}
		}
		refStr := strings.Join(refs, ", ")

		for _, config := range c.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CPEMatch {
					if !match.Vulnerable {
						continue
					}
					parts := strings.Split(match.Criteria, ":")
					vendor := ""
					product := ""
					prefix := match.Criteria
					if len(parts) >= 5 {
						vendor = parts[3]
						product = parts[4]
						prefix = strings.Join(parts[:5], ":")
					}

					vStart := match.VersionStartIncluding
					vStartInc := true
					if vStart == "" && match.VersionStartExcluding != "" {
						vStart = match.VersionStartExcluding
						vStartInc = false
					}

					vEnd := match.VersionEndExcluding
					vEndInc := false
					if vEnd == "" && match.VersionEndIncluding != "" {
						vEnd = match.VersionEndIncluding
						vEndInc = true
					}

					records = append(records, CVERecord{
						CVEID:                 c.ID,
						Source:                SourceNVD,
						CPEPrefix:             prefix,
						Vendor:                vendor,
						Product:               product,
						VersionStart:          vStart,
						VersionStartIncluding: vStartInc,
						VersionEnd:            vEnd,
						VersionEndIncluding:   vEndInc,
						CVSSScore:             score,
						Severity:              severity,
						Summary:               summary,
						PublishedAt:           c.Published,
						UpdatedAt:             c.LastMod,
						ReferenceURLs:         refStr,
					})
				}
			}
		}
	}

	return s.InsertBatch(ctx, records)
}

// IngestOSVJSON ingests vulnerability entries from an OSV.dev JSON feed.
func (s *Store) IngestOSVJSON(ctx context.Context, r io.Reader) (IngestStats, error) {
	var payload struct {
		ID        string `json:"id"`
		Summary   string `json:"summary"`
		Details   string `json:"details"`
		Published string `json:"published"`
		Modified  string `json:"modified"`
		Affected  []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
				CPE       string `json:"cpe,omitempty"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
			Versions []string `json:"versions,omitempty"`
		} `json:"affected"`
		DatabaseSpecific struct {
			Severity string  `json:"severity"`
			CVSS     float64 `json:"cvss_score"`
		} `json:"database_specific"`
	}

	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return IngestStats{}, fmt.Errorf("failed decoding OSV JSON payload: %w", err)
	}

	summary := payload.Summary
	if summary == "" {
		summary = payload.Details
	}

	var records []CVERecord
	for _, aff := range payload.Affected {
		cpePrefix := aff.Package.CPE
		vendor := strings.ToLower(aff.Package.Ecosystem)
		product := strings.ToLower(aff.Package.Name)
		if cpePrefix == "" {
			cpePrefix = fmt.Sprintf("cpe:2.3:a:%s:%s", vendor, product)
		}

		for _, rg := range aff.Ranges {
			var intro, fixed string
			for _, ev := range rg.Events {
				if val, ok := ev["introduced"]; ok {
					intro = val
				}
				if val, ok := ev["fixed"]; ok {
					fixed = val
				}
			}
			records = append(records, CVERecord{
				CVEID:                 payload.ID,
				Source:                SourceOSV,
				CPEPrefix:             cpePrefix,
				Vendor:                vendor,
				Product:               product,
				VersionStart:          intro,
				VersionStartIncluding: true,
				VersionEnd:            fixed,
				VersionEndIncluding:   false,
				CVSSScore:             payload.DatabaseSpecific.CVSS,
				Severity:              payload.DatabaseSpecific.Severity,
				Summary:               summary,
				PublishedAt:           payload.Published,
				UpdatedAt:             payload.Modified,
			})
		}

		for _, v := range aff.Versions {
			records = append(records, CVERecord{
				CVEID:        payload.ID,
				Source:       SourceOSV,
				CPEPrefix:    cpePrefix,
				Vendor:       vendor,
				Product:      product,
				ExactVersion: v,
				CVSSScore:    payload.DatabaseSpecific.CVSS,
				Severity:     payload.DatabaseSpecific.Severity,
				Summary:      summary,
				PublishedAt:  payload.Published,
				UpdatedAt:    payload.Modified,
			})
		}
	}

	return s.InsertBatch(ctx, records)
}

// IngestGHSAJSON ingests vulnerability entries from GitHub Advisory Database format.
func (s *Store) IngestGHSAJSON(ctx context.Context, r io.Reader) (IngestStats, error) {
	var payload struct {
		GHSAID    string `json:"ghsa_id"`
		CVEID     string `json:"cve_id"`
		Summary   string `json:"summary"`
		Severity  string `json:"severity"`
		CVSSScore float64 `json:"cvss_score"`
		Package   struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableRange string `json:"vulnerable_version_range"`
		PatchedVersions string `json:"first_patched_version"`
	}

	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return IngestStats{}, fmt.Errorf("failed decoding GHSA payload: %w", err)
	}

	cveID := payload.CVEID
	if cveID == "" {
		cveID = payload.GHSAID
	}

	vendor := strings.ToLower(payload.Package.Ecosystem)
	product := strings.ToLower(payload.Package.Name)
	cpePrefix := fmt.Sprintf("cpe:2.3:a:%s:%s", vendor, product)

	record := CVERecord{
		CVEID:        cveID,
		Source:       SourceGHSA,
		CPEPrefix:    cpePrefix,
		Vendor:       vendor,
		Product:      product,
		CVSSScore:    payload.CVSSScore,
		Severity:     payload.Severity,
		Summary:      payload.Summary,
		ExactVersion: payload.VulnerableRange,
	}

	return s.InsertBatch(ctx, []CVERecord{record})
}

// GetStats inspects the database file and executes diagnostic aggregations.
func (s *Store) GetStats(ctx context.Context) (DatabaseStats, error) {
	coord := s.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return DatabaseStats{}, errors.New("cve store is closed")
	}

	var stats DatabaseStats
	stats.DBPath = s.dbPath
	stats.SchemaVersion = "cve_index_v1"

	if s.dbPath != ":memory:" {
		if fi, err := os.Stat(s.dbPath); err == nil {
			stats.FileSizeBytes = fi.Size()
			stats.FileSizeMB = float64(fi.Size()) / (1024 * 1024)
		}
	}

	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM cve_index").Scan(&stats.TotalRecords); err != nil {
		return stats, fmt.Errorf("failed counting total records: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT cve_id) FROM cve_index").Scan(&stats.UniqueCVEs); err != nil {
		return stats, fmt.Errorf("failed counting unique cves: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT cpe_prefix) FROM cve_index").Scan(&stats.UniqueCPEPrefixes); err != nil {
		return stats, fmt.Errorf("failed counting unique cpe prefixes: %w", err)
	}

	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		stats.IntegrityStatus = fmt.Sprintf("check_failed: %v", err)
	} else {
		stats.IntegrityStatus = integrity
	}

	return stats, nil
}
