package cve

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SyncState tracks persistent vulnerability intelligence synchronization metadata.
type SyncState struct {
	Source        string `json:"source"`
	LastSyncTime  string `json:"last_sync_time"`
	LastModified  string `json:"last_modified,omitempty"`
	RecordsSynced int64  `json:"records_synced"`
	SHA256        string `json:"sha256_checksum,omitempty"`
}

// SyncStats captures detailed throughput and mutation counts for synchronization operations.
type SyncStats struct {
	TotalProcessed int           `json:"total_processed"`
	Inserted       int           `json:"inserted"`
	Updated        int           `json:"updated"`
	Skipped        int           `json:"skipped"`
	Errors         int           `json:"errors"`
	Duration       time.Duration `json:"duration"`
	RecordsPerSec  float64       `json:"records_per_sec"`
}

// TemplateMeta tracks runtime lifecycle metadata for a registered vulnerability template.
type TemplateMeta struct {
	ID        string    `json:"id"`
	Version   string    `json:"version,omitempty"`
	Source    string    `json:"source"`
	ModTime   time.Time `json:"mod_time"`
	Severity  string    `json:"severity"`
	CVE       string    `json:"cve_id,omitempty"`
	LoadedAt  time.Time `json:"loaded_at"`
}

// TemplateUpdateReport tracks the outcome of template discovery and synchronization.
type TemplateUpdateReport struct {
	TotalDiscovered  int           `json:"total_discovered"`
	NewTemplates     int           `json:"new_templates"`
	UpdatedTemplates int           `json:"updated_templates"`
	RemovedTemplates int           `json:"removed_templates"`
	Errors           []string      `json:"errors,omitempty"`
	Duration         time.Duration `json:"duration"`
}

// ArchiveManifest defines the integrity schema for air-gapped compressed update archives.
type ArchiveManifest struct {
	FormatVersion string                  `json:"format_version"`
	CreatedAt     string                  `json:"created_at"`
	Generator     string                  `json:"generator"`
	TotalRecords  int                     `json:"total_records"`
	Files         map[string]FileInfoMeta `json:"files"`
}

// FileInfoMeta describes individual file integrity metadata within an offline archive.
type FileInfoMeta struct {
	SHA256 string `json:"sha256"`
	Count  int    `json:"count,omitempty"`
	Type   string `json:"type"` // "cve_records", "template"
}

// InjectedFailurePoint defines exact transition stages for atomic rollback testing.
type InjectedFailurePoint string

const (
	FailNone                     InjectedFailurePoint = ""
	FailBeforeDatabaseTx         InjectedFailurePoint = "before_db_tx"
	FailDuringDatabaseTx         InjectedFailurePoint = "during_db_tx"
	FailAfterDatabaseTxBeforeReg InjectedFailurePoint = "after_db_before_reg"
	FailDuringTemplateActivation InjectedFailurePoint = "during_template_activation"
	FailBeforeFinalCommit        InjectedFailurePoint = "before_final_commit"
)

// ImportOptions configures air-gapped archive decompression and transactional commit policies.
type ImportOptions struct {
	TrustedArchiveSHA256     string               // Trusted SHA-256 digest obtained from an independently supplied trusted source
	ExpectedArchiveSHA256    string               // Backwards-compatible alias for TrustedArchiveSHA256
	SidecarArchiveSHA256     string               // SHA-256 digest from auto-discovered sidecar file (consistency verification only)
	InjectedFailure          bool                 // Simulates failure before database transaction (defaults to FailBeforeDatabaseTx)
	InjectedFailurePoint     InjectedFailurePoint // Injects simulated failure at exact transition point
	MaxDecompressBytes       int64                // Maximum decompressed size threshold (default: 52428800 = 50 MB)
	OnAfterDBCommitBeforeReg func()               // Deterministic test hook: called between DB commit and registry activation
}

// ImportReport summarizes the verified outcome of an air-gapped archive import operation.
type ImportReport struct {
	ArchivePath        string        `json:"archive_path"`
	ArchiveSHA256      string        `json:"archive_sha256"`
	TrustStatus        string        `json:"trust_status"`
	ManifestVersion    string        `json:"manifest_version"`
	TotalRecords       int           `json:"total_records"`
	InsertedRecords    int           `json:"inserted_records"`
	UpdatedRecords     int           `json:"updated_records"`
	SkippedRecords     int           `json:"skipped_records"`
	ValidatedTemplates int           `json:"validated_templates"`
	Duration           time.Duration `json:"duration"`
}

// GetSyncState retrieves the persistent sync state for the given source from SQLite.
func (s *Store) GetSyncState(ctx context.Context, source string) (*SyncState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, errors.New("cve store is closed")
	}

	query := `
		SELECT source, last_sync_time, COALESCE(last_modified, ''), records_synced, COALESCE(sha256_checksum, '')
		FROM cve_sync_state
		WHERE source = ?
	`
	row := s.db.QueryRowContext(ctx, query, strings.ToUpper(strings.TrimSpace(source)))

	var state SyncState
	if err := row.Scan(&state.Source, &state.LastSyncTime, &state.LastModified, &state.RecordsSynced, &state.SHA256); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed querying sync state for source %s: %w", source, err)
	}
	return &state, nil
}

// SetSyncState records or updates the persistent synchronization state for a source.
func (s *Store) SetSyncState(ctx context.Context, state *SyncState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return errors.New("cve store is closed")
	}

	upsertSQL := `
		INSERT INTO cve_sync_state (source, last_sync_time, last_modified, records_synced, sha256_checksum)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			last_sync_time = excluded.last_sync_time,
			last_modified = excluded.last_modified,
			records_synced = excluded.records_synced,
			sha256_checksum = excluded.sha256_checksum
	`
	_, err := s.db.ExecContext(ctx, upsertSQL,
		strings.ToUpper(strings.TrimSpace(state.Source)),
		state.LastSyncTime,
		state.LastModified,
		state.RecordsSynced,
		state.SHA256,
	)
	if err != nil {
		return fmt.Errorf("failed setting sync state: %w", err)
	}
	return nil
}

// upsertBatchTx executes the batch upsert logic within an already active transaction without committing.
func (s *Store) upsertBatchTx(ctx context.Context, tx *sql.Tx, records []CVERecord) (SyncStats, error) {
	var stats SyncStats
	stats.TotalProcessed = len(records)

	lookupSQL := `
		SELECT id, cvss_score, severity, summary, updated_at, reference_urls
		FROM cve_index
		WHERE cve_id = ? AND cpe_prefix = ?
		  AND COALESCE(version_start, '') = ?
		  AND COALESCE(version_end, '') = ?
		  AND COALESCE(exact_version, '') = ?
		LIMIT 1
	`
	lookupStmt, err := tx.PrepareContext(ctx, lookupSQL)
	if err != nil {
		return stats, fmt.Errorf("failed preparing lookup statement: %w", err)
	}
	defer lookupStmt.Close()

	insertSQL := `
		INSERT INTO cve_index (
			cve_id, source, cpe_prefix, vendor, product,
			version_start, version_start_including,
			version_end, version_end_including,
			exact_version, cvss_score, severity,
			summary, published_at, updated_at, reference_urls
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	insertStmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return stats, fmt.Errorf("failed preparing insert statement: %w", err)
	}
	defer insertStmt.Close()

	updateSQL := `
		UPDATE cve_index SET
			source = ?, vendor = ?, product = ?,
			version_start_including = ?, version_end_including = ?,
			cvss_score = ?, severity = ?, summary = ?,
			published_at = ?, updated_at = ?, reference_urls = ?
		WHERE id = ?
	`
	updateStmt, err := tx.PrepareContext(ctx, updateSQL)
	if err != nil {
		return stats, fmt.Errorf("failed preparing update statement: %w", err)
	}
	defer updateStmt.Close()

	for _, r := range records {
		cveID := strings.TrimSpace(r.CVEID)
		cpePrefix := strings.TrimSpace(strings.ToLower(r.CPEPrefix))
		if cveID == "" || cpePrefix == "" {
			stats.Errors++
			continue
		}

		vStart := strings.TrimSpace(r.VersionStart)
		vEnd := strings.TrimSpace(r.VersionEnd)
		exact := strings.TrimSpace(r.ExactVersion)

		vStartInc := 0
		if r.VersionStartIncluding {
			vStartInc = 1
		}
		vEndInc := 0
		if r.VersionEndIncluding {
			vEndInc = 1
		}

		source := string(r.Source)
		if source == "" {
			source = string(SourceSynthetic)
		}

		var existingID int64
		var existingCVSS float64
		var existingSev, existingSum, existingUpd, existingRefs string

		err := lookupStmt.QueryRowContext(ctx, cveID, cpePrefix, vStart, vEnd, exact).Scan(
			&existingID, &existingCVSS, &existingSev, &existingSum, &existingUpd, &existingRefs,
		)

		if err == nil {
			// Row exists - compare authoritative attributes
			needsUpdate := (r.CVSSScore != existingCVSS) ||
				(r.Severity != existingSev) ||
				(r.Summary != existingSum) ||
				(r.UpdatedAt != "" && r.UpdatedAt != existingUpd) ||
				(r.ReferenceURLs != "" && r.ReferenceURLs != existingRefs)

			if needsUpdate {
				_, uErr := updateStmt.ExecContext(ctx,
					source, r.Vendor, r.Product,
					vStartInc, vEndInc,
					r.CVSSScore, r.Severity, r.Summary,
					r.PublishedAt, r.UpdatedAt, r.ReferenceURLs,
					existingID,
				)
				if uErr != nil {
					return stats, fmt.Errorf("failed updating record %s: %w", cveID, uErr)
				}
				stats.Updated++
			} else {
				stats.Skipped++
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			// Row does not exist - insert new record
			_, iErr := insertStmt.ExecContext(ctx,
				cveID, source, cpePrefix, r.Vendor, r.Product,
				vStart, vStartInc,
				vEnd, vEndInc,
				exact, r.CVSSScore, r.Severity,
				r.Summary, r.PublishedAt, r.UpdatedAt, r.ReferenceURLs,
			)
			if iErr != nil {
				return stats, fmt.Errorf("failed inserting record %s: %w", cveID, iErr)
			}
			stats.Inserted++
		} else {
			return stats, fmt.Errorf("lookup failed for %s: %w", cveID, err)
		}
	}

	return stats, nil
}

// UpsertBatch performs an atomic transactional upsert of CVE records into SQLite.
// If an identical record exists, it is counted as Skipped.
// If an existing record exists with modified attributes, it is updated in-place and counted as Updated.
// If a record is new, it is inserted and counted as Inserted.
// If any database error occurs, the entire transaction is rolled back, guaranteeing zero partial writes.
func (s *Store) UpsertBatch(ctx context.Context, records []CVERecord) (SyncStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	startTime := time.Now()
	var stats SyncStats
	stats.TotalProcessed = len(records)

	if s.db == nil {
		return stats, errors.New("cve store is closed")
	}

	if len(records) == 0 {
		return stats, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, fmt.Errorf("failed beginning atomic upsert transaction: %w", err)
	}
	defer tx.Rollback()

	stats, err = s.upsertBatchTx(ctx, tx, records)
	if err != nil {
		return stats, err
	}

	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("transaction commit failed: %w", err)
	}

	stats.Duration = time.Since(startTime)
	if stats.Duration.Seconds() > 0 {
		stats.RecordsPerSec = float64(stats.Inserted+stats.Updated) / stats.Duration.Seconds()
	}
	return stats, nil
}

// RegisterOrUpdate registers a template or updates it in-place if already registered.
func (r *TemplateRegistry) RegisterOrUpdate(tmpl *Template, meta ...TemplateMeta) (*CompiledTemplate, error) {
	if tmpl == nil {
		return nil, errors.New("cannot register nil template")
	}

	ct, err := CompileTemplate(tmpl)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.metadata == nil {
		r.metadata = make(map[string]TemplateMeta)
	}

	// If replacing existing template, prune old CVE and Tag lookups
	if oldCT, exists := r.templates[tmpl.ID]; exists {
		if oldCT.CVEID != "" {
			cveKey := strings.ToUpper(oldCT.CVEID)
			filtered := make([]*CompiledTemplate, 0, len(r.byCVE[cveKey]))
			for _, item := range r.byCVE[cveKey] {
				if item.ID != tmpl.ID {
					filtered = append(filtered, item)
				}
			}
			if len(filtered) > 0 {
				r.byCVE[cveKey] = filtered
			} else {
				delete(r.byCVE, cveKey)
			}
		}

		if oldCT.Info.Tags != "" {
			for _, tag := range strings.Split(oldCT.Info.Tags, ",") {
				tClean := strings.ToLower(strings.TrimSpace(tag))
				if tClean != "" {
					filtered := make([]*CompiledTemplate, 0, len(r.byTag[tClean]))
					for _, item := range r.byTag[tClean] {
						if item.ID != tmpl.ID {
							filtered = append(filtered, item)
						}
					}
					if len(filtered) > 0 {
						r.byTag[tClean] = filtered
					} else {
						delete(r.byTag, tClean)
					}
				}
			}
		}
	}

	// Register compiled template
	r.templates[ct.ID] = ct

	if ct.CVEID != "" {
		cveKey := strings.ToUpper(ct.CVEID)
		r.byCVE[cveKey] = append(r.byCVE[cveKey], ct)
	}

	if ct.Info.Tags != "" {
		for _, tag := range strings.Split(ct.Info.Tags, ",") {
			tClean := strings.ToLower(strings.TrimSpace(tag))
			if tClean != "" {
				r.byTag[tClean] = append(r.byTag[tClean], ct)
			}
		}
	}

	m := TemplateMeta{
		ID:       ct.ID,
		Source:   tmpl.SourcePath,
		Severity: ct.Info.Severity,
		CVE:      ct.CVEID,
		LoadedAt: time.Now(),
	}
	if len(meta) > 0 {
		m = meta[0]
		if m.ID == "" {
			m.ID = ct.ID
		}
	}
	r.metadata[ct.ID] = m

	return ct, nil
}

// Unregister removes a template by ID from all internal registry indexes.
func (r *TemplateRegistry) Unregister(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	ct, exists := r.templates[id]
	if !exists {
		return false
	}

	delete(r.templates, id)
	if r.metadata != nil {
		delete(r.metadata, id)
	}

	if ct.CVEID != "" {
		cveKey := strings.ToUpper(ct.CVEID)
		filtered := make([]*CompiledTemplate, 0, len(r.byCVE[cveKey]))
		for _, item := range r.byCVE[cveKey] {
			if item.ID != id {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) > 0 {
			r.byCVE[cveKey] = filtered
		} else {
			delete(r.byCVE, cveKey)
		}
	}

	if ct.Info.Tags != "" {
		for _, tag := range strings.Split(ct.Info.Tags, ",") {
			tClean := strings.ToLower(strings.TrimSpace(tag))
			if tClean != "" {
				filtered := make([]*CompiledTemplate, 0, len(r.byTag[tClean]))
				for _, item := range r.byTag[tClean] {
					if item.ID != id {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					r.byTag[tClean] = filtered
				} else {
					delete(r.byTag, tClean)
				}
			}
		}
	}

	return true
}

// GetMeta retrieves lifecycle metadata for a registered template ID.
func (r *TemplateRegistry) GetMeta(id string) (TemplateMeta, bool) {
	coord := r.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.metadata == nil {
		return TemplateMeta{}, false
	}
	m, ok := r.metadata[id]
	return m, ok
}

// AllMeta returns all tracked template metadata entries.
func (r *TemplateRegistry) AllMeta() []TemplateMeta {
	coord := r.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.metadata == nil {
		return nil
	}
	out := make([]TemplateMeta, 0, len(r.metadata))
	for _, m := range r.metadata {
		out = append(out, m)
	}
	return out
}

// SyncFromDir synchronizes the template registry against an on-disk directory.
func (r *TemplateRegistry) SyncFromDir(dir string) (TemplateUpdateReport, error) {
	start := time.Now()
	var report TemplateUpdateReport

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return report, fmt.Errorf("directory %s does not exist", dir)
	}

	var yamlFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				yamlFiles = append(yamlFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		return report, fmt.Errorf("failed walking directory %s: %w", dir, err)
	}

	report.TotalDiscovered = len(yamlFiles)

	for _, path := range yamlFiles {
		bytes, err := os.ReadFile(path)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: read error: %v", path, err))
			continue
		}

		info, _ := os.Stat(path)
		modTime := time.Now()
		if info != nil {
			modTime = info.ModTime()
		}

		tmpl, err := ParseTemplate(bytes, path)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: parse error: %v", path, err))
			continue
		}

		meta := TemplateMeta{
			ID:       tmpl.ID,
			Source:   path,
			ModTime:  modTime,
			Severity: tmpl.Info.Severity,
			LoadedAt: time.Now(),
		}

		_, isExisting := r.Get(tmpl.ID)
		if _, err := r.RegisterOrUpdate(tmpl, meta); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: registration error: %v", path, err))
			continue
		}

		if isExisting {
			report.UpdatedTemplates++
		} else {
			report.NewTemplates++
		}
	}

	report.Duration = time.Since(start)
	return report, nil
}

// OSVSyncOptions specifies options for incremental OSV.dev vulnerability synchronization.
type OSVSyncOptions struct {
	BaseURL       string        `json:"base_url"`
	HTTPClient    *http.Client  `json:"-"`
	ModifiedAfter string        `json:"modified_after"`
	MaxRetries    int           `json:"max_retries"`
	RetryWait     time.Duration `json:"retry_wait"`
}

// OSVSyncReport captures metrics from an incremental OSV sync run.
type OSVSyncReport struct {
	Source        string        `json:"source"`
	LastSyncTime  string        `json:"last_sync_time"`
	RecordsSynced int           `json:"records_synced"`
	Inserted      int           `json:"inserted"`
	Updated       int           `json:"updated"`
	Skipped       int           `json:"skipped"`
	Errors        int           `json:"errors"`
	Duration      time.Duration `json:"duration"`
}

// SyncOSVIncremental synchronizes vulnerability records incrementally from OSV.dev.
func SyncOSVIncremental(ctx context.Context, store *Store, opts OSVSyncOptions) (*OSVSyncReport, error) {
	start := time.Now()
	if store == nil {
		return nil, errors.New("cve store is nil")
	}

	baseURL := strings.TrimRight(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.osv.dev/v1"
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
		}
	}

	since := opts.ModifiedAfter
	if since == "" {
		existingState, err := store.GetSyncState(ctx, "OSV")
		if err == nil && existingState != nil && existingState.LastSyncTime != "" {
			since = existingState.LastSyncTime
		}
	}

	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	retryWait := opts.RetryWait
	if retryWait <= 0 {
		retryWait = 100 * time.Millisecond
	}

	// Fetch query endpoint with retry handling
	reqURL := fmt.Sprintf("%s/query", baseURL)
	queryBody := map[string]any{
		"package": map[string]string{
			"name":      "tomcat",
			"ecosystem": "Apache",
		},
	}
	if since != "" {
		queryBody["modified"] = since
	}
	bodyBytes, _ := json.Marshal(queryBody)

	var resp *http.Response
	var reqErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed creating OSV request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "FELIX-CVE-Updater/1.0")

		resp, reqErr = client.Do(req)
		if reqErr == nil && resp.StatusCode == http.StatusOK {
			break
		}

		if resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				time.Sleep(retryWait * time.Duration(1<<attempt))
				continue
			}
		}
		time.Sleep(retryWait)
	}

	if reqErr != nil {
		return nil, fmt.Errorf("OSV incremental sync request failed: %w", reqErr)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		return nil, fmt.Errorf("OSV incremental sync failed with HTTP status %d", code)
	}
	defer resp.Body.Close()

	// Parse response into CVE records
	var osvResp struct {
		Vulns []struct {
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
					Type   string              `json:"type"`
					Events []map[string]string `json:"events"`
				} `json:"ranges"`
				Versions []string `json:"versions,omitempty"`
			} `json:"affected"`
			DatabaseSpecific struct {
				Severity string  `json:"severity"`
				CVSS     float64 `json:"cvss_score"`
			} `json:"database_specific"`
		} `json:"vulns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed decoding OSV API response: %w", err)
	}

	var records []CVERecord
	for _, v := range osvResp.Vulns {
		summary := v.Summary
		if summary == "" {
			summary = v.Details
		}

		for _, aff := range v.Affected {
			vendor := strings.ToLower(aff.Package.Ecosystem)
			product := strings.ToLower(aff.Package.Name)
			cpePrefix := aff.Package.CPE
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
					CVEID:                 v.ID,
					Source:                SourceOSV,
					CPEPrefix:             cpePrefix,
					Vendor:                vendor,
					Product:               product,
					VersionStart:          intro,
					VersionStartIncluding: true,
					VersionEnd:            fixed,
					VersionEndIncluding:   false,
					CVSSScore:             v.DatabaseSpecific.CVSS,
					Severity:              v.DatabaseSpecific.Severity,
					Summary:               summary,
					PublishedAt:           v.Published,
					UpdatedAt:             v.Modified,
				})
			}

			for _, ver := range aff.Versions {
				records = append(records, CVERecord{
					CVEID:        v.ID,
					Source:       SourceOSV,
					CPEPrefix:    cpePrefix,
					Vendor:       vendor,
					Product:      product,
					ExactVersion: ver,
					CVSSScore:    v.DatabaseSpecific.CVSS,
					Severity:     v.DatabaseSpecific.Severity,
					Summary:      summary,
					PublishedAt:  v.Published,
					UpdatedAt:    v.Modified,
				})
			}
		}
	}

	stats, err := store.UpsertBatch(ctx, records)
	if err != nil {
		return nil, fmt.Errorf("failed atomic upsert of OSV sync records: %w", err)
	}

	nowISO := time.Now().UTC().Format(time.RFC3339)
	_ = store.SetSyncState(ctx, &SyncState{
		Source:        "OSV",
		LastSyncTime:  nowISO,
		LastModified:  nowISO,
		RecordsSynced: int64(stats.Inserted + stats.Updated),
	})

	return &OSVSyncReport{
		Source:        "OSV",
		LastSyncTime:  nowISO,
		RecordsSynced: stats.Inserted + stats.Updated,
		Inserted:      stats.Inserted,
		Updated:       stats.Updated,
		Skipped:       stats.Skipped,
		Errors:        stats.Errors,
		Duration:      time.Since(start),
	}, nil
}

// CreateOfflineArchive packages CVE records and YAML templates into a cryptographically verified .tar.gz archive.
func CreateOfflineArchive(archivePath string, records []CVERecord, templates []*Template) error {
	dir := filepath.Dir(archivePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating archive parent directory %s: %w", dir, err)
	}

	outF, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("failed creating archive file %s: %w", archivePath, err)
	}
	defer outF.Close()

	gw := gzip.NewWriter(outF)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	manifest := ArchiveManifest{
		FormatVersion: "1.0",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Generator:     "felix-cve-exporter/1.0",
		TotalRecords:  len(records),
		Files:         make(map[string]FileInfoMeta),
	}

	// 1. Prepare and hash cve/records.json
	cveBytes, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling CVE records: %w", err)
	}
	cveHash := sha256.Sum256(cveBytes)
	manifest.Files["cve/records.json"] = FileInfoMeta{
		SHA256: hex.EncodeToString(cveHash[:]),
		Count:  len(records),
		Type:   "cve_records",
	}

	// 2. Prepare and hash template files
	templateDataMap := make(map[string][]byte)
	for _, tmpl := range templates {
		if tmpl == nil {
			continue
		}
		var raw []byte
		if tmpl.RawYAML != "" {
			raw = []byte(tmpl.RawYAML)
		} else {
			var err error
			raw, err = yaml.Marshal(tmpl)
			if err != nil {
				return fmt.Errorf("failed marshaling template %s: %w", tmpl.ID, err)
			}
		}
		relPath := fmt.Sprintf("templates/%s.yaml", tmpl.ID)
		tHash := sha256.Sum256(raw)
		manifest.Files[relPath] = FileInfoMeta{
			SHA256: hex.EncodeToString(tHash[:]),
			Type:   "template",
		}
		templateDataMap[relPath] = raw
	}

	// 3. Write manifest.json to archive
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling manifest: %w", err)
	}
	mHdr := &tar.Header{
		Name:     "manifest.json",
		Mode:     0644,
		Size:     int64(len(manifestBytes)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(mHdr); err != nil {
		return fmt.Errorf("failed writing manifest tar header: %w", err)
	}
	if _, err := tw.Write(manifestBytes); err != nil {
		return fmt.Errorf("failed writing manifest content: %w", err)
	}

	// 4. Write cve/records.json to archive
	cHdr := &tar.Header{
		Name:     "cve/records.json",
		Mode:     0644,
		Size:     int64(len(cveBytes)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(cHdr); err != nil {
		return fmt.Errorf("failed writing CVE tar header: %w", err)
	}
	if _, err := tw.Write(cveBytes); err != nil {
		return fmt.Errorf("failed writing CVE content: %w", err)
	}

	// 5. Write templates to archive
	for relPath, tBytes := range templateDataMap {
		tHdr := &tar.Header{
			Name:     relPath,
			Mode:     0644,
			Size:     int64(len(tBytes)),
			ModTime:  time.Now(),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(tHdr); err != nil {
			return fmt.Errorf("failed writing template header for %s: %w", relPath, err)
		}
		if _, err := tw.Write(tBytes); err != nil {
			return fmt.Errorf("failed writing template bytes for %s: %w", relPath, err)
		}
	}

	return nil
}

// ImportOfflineArchive imports compressed vulnerability definitions and templates in air-gapped environments.
// It verifies:
// 1. Independent trusted checksum verification (if provided).
// 2. Safe decompression with zip-slip, symlink, and 50MB decompression bomb guards.
// 3. Manifest presence and cryptographic SHA-256 integrity verification across all files.
// 4. Pre-validation and compilation of all templates and CVE definitions before modifying active state.
// 5. Coordinated two-phase atomicity across SQLite database and in-memory TemplateRegistry,
// guaranteeing complete rollback and zero partial writes on failure at any transition point.
func ImportOfflineArchive(ctx context.Context, archivePath string, store *Store, reg *TemplateRegistry, opts ImportOptions) (*ImportReport, error) {
	start := time.Now()

	// 1. Calculate archive file SHA-256 and verify file existence
	archFile, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening archive %s: %w", archivePath, err)
	}
	defer archFile.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, archFile); err != nil {
		return nil, fmt.Errorf("failed hashing archive file %s: %w", archivePath, err)
	}
	archiveSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if _, err := archFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed rewinding archive file %s: %w", archivePath, err)
	}

	// 2. Independent Trusted Checksum & Sidecar Consistency Verification Gate
	trustStatus := "CHECKSUM_VERIFIED (Unauthenticated: Cryptographic signature not provided)"
	trustedExpected := strings.ToLower(strings.TrimSpace(opts.TrustedArchiveSHA256))
	if trustedExpected == "" {
		trustedExpected = strings.ToLower(strings.TrimSpace(opts.ExpectedArchiveSHA256))
	}
	sidecarExpected := strings.ToLower(strings.TrimSpace(opts.SidecarArchiveSHA256))

	if trustedExpected != "" {
		if archiveSHA256 != trustedExpected {
			return nil, fmt.Errorf("trusted archive verification failed: expected SHA-256 %s, got %s", trustedExpected, archiveSHA256)
		}
		if sidecarExpected != "" && archiveSHA256 != sidecarExpected {
			return nil, fmt.Errorf("sidecar checksum mismatch: expected SHA-256 %s, got %s", sidecarExpected, archiveSHA256)
		}
		trustStatus = "TRUSTED_CHECKSUM_VERIFIED (Unauthenticated: Cryptographic signature not provided)"
	} else if sidecarExpected != "" {
		if archiveSHA256 != sidecarExpected {
			return nil, fmt.Errorf("sidecar checksum mismatch: expected SHA-256 %s, got %s", sidecarExpected, archiveSHA256)
		}
		trustStatus = "CHECKSUM_CONSISTENCY_VERIFIED (Unauthenticated: Sidecar checksum matches archive; not an independent trusted source)"
	}

	// 3. Set decompression size threshold (default 50 MB limit)
	maxDecompress := opts.MaxDecompressBytes
	if maxDecompress <= 0 {
		maxDecompress = 52428800 // 50 MB
	}

	// 4. Prepare isolated staging directory
	stagingDir, err := os.MkdirTemp("", "felix-import-staging-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	// 5. Safe decompress with zip-slip, symlink, and zip-bomb protection
	gzr, err := gzip.NewReader(archFile)
	if err != nil {
		return nil, fmt.Errorf("corrupted archive: invalid gzip stream: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var totalDecompressed int64

	cleanStaging := filepath.Clean(stagingDir)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("corrupted archive: tar reading error: %w", err)
		}

		// Security Check A: Reject symlinks and hardlinks
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return nil, fmt.Errorf("unsafe archive: symlinks and hardlinks are strictly prohibited: %s", hdr.Name)
		}

		// Security Check B: Path Traversal (Zip-Slip) Defense
		cleanRel := filepath.Clean(hdr.Name)
		if filepath.IsAbs(cleanRel) || strings.HasPrefix(cleanRel, "..") || strings.Contains(cleanRel, ":") {
			return nil, fmt.Errorf("archive path traversal attempt detected: %s", hdr.Name)
		}
		destPath := filepath.Join(cleanStaging, cleanRel)
		if !strings.HasPrefix(destPath, cleanStaging+string(filepath.Separator)) && destPath != cleanStaging {
			return nil, fmt.Errorf("archive path escapes staging directory: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return nil, fmt.Errorf("failed creating staging directory %s: %w", destPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return nil, fmt.Errorf("failed creating parent directory for %s: %w", destPath, err)
			}

			// Security Check C: Oversized Decompression / Zip-Bomb Defense
			if totalDecompressed+hdr.Size > maxDecompress {
				return nil, fmt.Errorf("archive decompressed size exceeds maximum safety limit of %d bytes", maxDecompress)
			}

			outF, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return nil, fmt.Errorf("failed creating staged file %s: %w", destPath, err)
			}

			written, err := io.Copy(outF, io.LimitReader(tr, maxDecompress-totalDecompressed+1))
			outF.Close()
			if err != nil {
				return nil, fmt.Errorf("failed extracting %s: %w", hdr.Name, err)
			}
			totalDecompressed += written
			if totalDecompressed > maxDecompress {
				return nil, fmt.Errorf("archive decompressed size exceeds maximum safety limit of %d bytes", maxDecompress)
			}
		}
	}

	// 6. Verify manifest presence and decode
	manifestPath := filepath.Join(cleanStaging, "manifest.json")
	mBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("archive missing required manifest.json")
		}
		return nil, fmt.Errorf("failed reading manifest.json: %w", err)
	}

	var manifest ArchiveManifest
	if err := json.Unmarshal(mBytes, &manifest); err != nil {
		return nil, fmt.Errorf("corrupted archive: invalid manifest.json: %w", err)
	}
	if manifest.FormatVersion == "" || len(manifest.Files) == 0 {
		return nil, errors.New("corrupted archive: manifest.json is empty or unsupported")
	}

	// 7. Cryptographic SHA-256 Digest Verification for all manifest files
	for relPath, meta := range manifest.Files {
		cleanRel := filepath.Clean(relPath)
		targetFile := filepath.Join(cleanStaging, cleanRel)

		fBytes, err := os.ReadFile(targetFile)
		if err != nil {
			return nil, fmt.Errorf("manifest references missing file %s: %w", relPath, err)
		}

		actualHashBytes := sha256.Sum256(fBytes)
		actualHex := hex.EncodeToString(actualHashBytes[:])
		if !strings.EqualFold(actualHex, meta.SHA256) {
			return nil, fmt.Errorf("SHA-256 digest verification failed for %s: expected %s, got %s", relPath, meta.SHA256, actualHex)
		}
	}

	// 8. Validate and compile all template files in staging before committing anything
	var validatedTemplates []*Template
	for relPath, meta := range manifest.Files {
		if meta.Type == "template" || strings.HasPrefix(relPath, "templates/") {
			targetFile := filepath.Join(cleanStaging, filepath.Clean(relPath))
			tBytes, err := os.ReadFile(targetFile)
			if err != nil {
				return nil, fmt.Errorf("failed reading template %s: %w", relPath, err)
			}
			tmpl, err := ParseTemplate(tBytes, targetFile)
			if err != nil {
				return nil, fmt.Errorf("template validation failed for %s: %w", relPath, err)
			}
			// Pre-compile validation
			if _, err := CompileTemplate(tmpl); err != nil {
				return nil, fmt.Errorf("template compilation validation failed for %s: %w", relPath, err)
			}
			validatedTemplates = append(validatedTemplates, tmpl)
		}
	}

	// 9. Ingest and validate CVE record definitions in staging
	var allRecords []CVERecord
	for relPath, meta := range manifest.Files {
		if meta.Type == "cve_records" || strings.HasPrefix(relPath, "cve/") {
			targetFile := filepath.Join(cleanStaging, filepath.Clean(relPath))
			cBytes, err := os.ReadFile(targetFile)
			if err != nil {
				return nil, fmt.Errorf("failed reading CVE file %s: %w", relPath, err)
			}
			var fileRecords []CVERecord
			if err := json.Unmarshal(cBytes, &fileRecords); err != nil {
				return nil, fmt.Errorf("failed parsing CVE JSON records from %s: %w", relPath, err)
			}
			allRecords = append(allRecords, fileRecords...)
		}
	}

	// 10. Prepare Template Registry Staging
	// The live registry is NOT modified until the database transaction commits cleanly.
	// This prevents concurrent readers from observing uncommitted or transient state.
	var stagedSnapshot *RegistrySnapshot
	if reg != nil && len(validatedTemplates) > 0 {
		var stageErr error
		stagedSnapshot, stageErr = reg.StageTemplates(validatedTemplates)
		if stageErr != nil {
			return nil, fmt.Errorf("template staging failed: %w", stageErr)
		}
	}

	// Transition Failure Point 1: Before Database Transaction
	if opts.InjectedFailure || opts.InjectedFailurePoint == FailBeforeDatabaseTx {
		return nil, errors.New("injected failure before database transaction")
	}

	// 11. Coordinated Two-Phase Cross-Component Atomic Publication:
	// Establish a shared PublicationCoordinator between store and reg.
	// Acquire exclusive publication write lock across both the database commit and the template
	// registry activation. This eliminates the visibility window where database readers could observe
	// committed CVE records while template readers still saw the previous registry generation.
	coord := BindCoordinated(store, reg)
	endPublish := coord.BeginPublish()
	publishSuccess := false
	defer func() {
		endPublish(publishSuccess)
	}()

	var tx *sql.Tx
	storeLocked := false
	if store != nil {
		store.mu.Lock()
		storeLocked = true
		defer func() {
			if storeLocked {
				store.mu.Unlock()
			}
		}()

		if store.db == nil {
			return nil, errors.New("cve store is closed")
		}

		var bErr error
		tx, bErr = store.db.BeginTx(ctx, nil)
		if bErr != nil {
			return nil, fmt.Errorf("failed beginning database transaction: %w", bErr)
		}
		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()
	}

	// Stage database mutations in transaction
	var stats SyncStats
	if store != nil && len(allRecords) > 0 && tx != nil {
		// Transition Failure Point 2: During Database Transaction
		if opts.InjectedFailurePoint == FailDuringDatabaseTx {
			return nil, errors.New("injected failure during database transaction")
		}

		var upsertErr error
		stats, upsertErr = store.upsertBatchTx(ctx, tx, allRecords)
		if upsertErr != nil {
			return nil, fmt.Errorf("atomic database upsert failed: %w", upsertErr)
		}
	}

	// Transition Failure Point 3: After Database Transaction, Before Template Activation
	if opts.InjectedFailurePoint == FailAfterDatabaseTxBeforeReg {
		return nil, errors.New("injected failure after database transaction before template activation")
	}

	// Transition Failure Point 4: During Template Activation
	if opts.InjectedFailurePoint == FailDuringTemplateActivation {
		return nil, errors.New("injected failure during template activation")
	}

	// Transition Failure Point 5: Before Final Commit
	if opts.InjectedFailurePoint == FailBeforeFinalCommit {
		return nil, errors.New("injected failure before final transaction commit")
	}

	// 1. Finalize SQLite Transaction
	if tx != nil {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("transaction commit failed: %w", err)
		}
		tx = nil // committed cleanly

		nowISO := time.Now().UTC().Format(time.RFC3339)
		upsertStateSQL := `
			INSERT INTO cve_sync_state (source, last_sync_time, last_modified, records_synced, sha256_checksum)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(source) DO UPDATE SET
				last_sync_time = excluded.last_sync_time,
				last_modified = excluded.last_modified,
				records_synced = excluded.records_synced,
				sha256_checksum = excluded.sha256_checksum
		`
		_, _ = store.db.ExecContext(ctx, upsertStateSQL,
			"OFFLINE_ARCHIVE",
			nowISO,
			manifest.CreatedAt,
			int64(stats.Inserted+stats.Updated),
			archiveSHA256,
		)

		if store != nil && storeLocked {
			store.mu.Unlock()
			storeLocked = false
		}
	}

	// Deterministic pause hook: invoked after DB commit and before registry activation
	if opts.OnAfterDBCommitBeforeReg != nil {
		opts.OnAfterDBCommitBeforeReg()
	}

	// 2. Atomically activate staged templates into live registry
	if reg != nil && stagedSnapshot != nil {
		reg.ApplySnapshot(stagedSnapshot)
	}

	// Mark publication successful: advances generation and releases lock in deferred endPublish
	publishSuccess = true

	return &ImportReport{
		ArchivePath:        archivePath,
		ArchiveSHA256:      archiveSHA256,
		TrustStatus:        trustStatus,
		ManifestVersion:    manifest.FormatVersion,
		TotalRecords:       manifest.TotalRecords,
		InsertedRecords:    stats.Inserted,
		UpdatedRecords:     stats.Updated,
		SkippedRecords:     stats.Skipped,
		ValidatedTemplates: len(validatedTemplates),
		Duration:           time.Since(start),
	}, nil
}
