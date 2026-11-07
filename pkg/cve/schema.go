package cve

import (
	"time"
)

// IngestionSource identifies the authoritative origin of vulnerability records.
type IngestionSource string

const (
	SourceNVD       IngestionSource = "NVD"
	SourceOSV       IngestionSource = "OSV"
	SourceGHSA      IngestionSource = "GHSA"
	SourceSynthetic IngestionSource = "SYNTHETIC"
)

// MatchStatus represents the deterministic outcome of a version evaluation against a CVE.
type MatchStatus string

const (
	MatchConfirmed    MatchStatus = "CONFIRMED_VULNERABLE"
	MatchNotAffected  MatchStatus = "NOT_AFFECTED"
	MatchInconclusive MatchStatus = "INCONCLUSIVE"
)

// CVERecord represents a normalized vulnerability entry indexed in SQLite.
type CVERecord struct {
	ID                    int64           `json:"id,omitempty"`
	CVEID                 string          `json:"cve_id"`
	Source                IngestionSource `json:"source"`
	CPEPrefix             string          `json:"cpe_prefix"` // e.g. "cpe:2.3:a:apache:tomcat"
	Vendor                string          `json:"vendor"`
	Product               string          `json:"product"`
	VersionStart          string          `json:"version_start,omitempty"`
	VersionStartIncluding bool            `json:"version_start_including"`
	VersionEnd            string          `json:"version_end,omitempty"`
	VersionEndIncluding   bool            `json:"version_end_including"`
	ExactVersion          string          `json:"exact_version,omitempty"`
	CVSSScore             float64         `json:"cvss_score"`
	Severity              string          `json:"severity"`
	Summary               string          `json:"summary"`
	PublishedAt           string          `json:"published_at,omitempty"`
	UpdatedAt             string          `json:"updated_at,omitempty"`
	ReferenceURLs         string          `json:"reference_urls,omitempty"`
}

// MatchResult represents the detailed output of querying a CVE against a component finding.
type MatchResult struct {
	CVEID           string      `json:"cve_id"`
	Source          string      `json:"source"`
	CPEPrefix       string      `json:"cpe_prefix"`
	TargetVersion   string      `json:"target_version"`
	MatchStatus     MatchStatus `json:"match_status"`
	CVSSScore       float64     `json:"cvss_score"`
	Severity        string      `json:"severity"`
	Summary         string      `json:"summary"`
	Constraint      string      `json:"constraint,omitempty"`
	EvaluationNotes string      `json:"evaluation_notes,omitempty"`
}

// QueryMetrics tracks high-resolution performance timings of the hybrid query.
type QueryMetrics struct {
	CPEPrefix           string        `json:"cpe_prefix"`
	TargetVersion       string        `json:"target_version"`
	CandidateCount      int           `json:"candidate_count"`
	ConfirmedMatchCount int           `json:"confirmed_match_count"`
	RetrievalLatency    time.Duration `json:"retrieval_latency"`
	EvalLatency         time.Duration `json:"eval_latency"`
	TotalLatency        time.Duration `json:"total_latency"`
	RetrievalLatencyMs  float64       `json:"retrieval_latency_ms"`
	EvalLatencyMs       float64       `json:"eval_latency_ms"`
	TotalLatencyMs      float64       `json:"total_latency_ms"`
}

// IngestStats captures throughput and count statistics for database ingestion.
type IngestStats struct {
	TotalProcessed int           `json:"total_processed"`
	Inserted       int           `json:"inserted"`
	Skipped        int           `json:"skipped"`
	Errors         int           `json:"errors"`
	Duration       time.Duration `json:"duration"`
	RecordsPerSec  float64       `json:"records_per_sec"`
}

// DatabaseStats reports structural and storage metrics of the SQLite CVE index.
type DatabaseStats struct {
	DBPath            string  `json:"db_path"`
	FileSizeBytes     int64   `json:"file_size_bytes"`
	FileSizeMB        float64 `json:"file_size_mb"`
	TotalRecords      int64   `json:"total_records"`
	UniqueCVEs        int64   `json:"unique_cves"`
	UniqueCPEPrefixes int64   `json:"unique_cpe_prefixes"`
	IntegrityStatus   string  `json:"integrity_status"`
	SchemaVersion     string  `json:"schema_version"`
}

// SchemaDDL defines the SQLite tables, uniqueness constraints, and high-speed B-Tree indexes.
const SchemaDDL = `
CREATE TABLE IF NOT EXISTS cve_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL,
    cpe_prefix TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version_start TEXT,
    version_start_including INTEGER DEFAULT 1,
    version_end TEXT,
    version_end_including INTEGER DEFAULT 0,
    exact_version TEXT,
    cvss_score REAL DEFAULT 0.0,
    severity TEXT,
    summary TEXT,
    published_at TEXT,
    updated_at TEXT,
    reference_urls TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_dedup ON cve_index (
    cve_id,
    cpe_prefix,
    COALESCE(version_start, ''),
    COALESCE(version_end, ''),
    COALESCE(exact_version, '')
);

CREATE INDEX IF NOT EXISTS idx_cve_cpe_prefix ON cve_index(cpe_prefix);
CREATE INDEX IF NOT EXISTS idx_cve_cve_id ON cve_index(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_vendor_product ON cve_index(vendor, product);

CREATE TABLE IF NOT EXISTS cve_sync_state (
    source TEXT PRIMARY KEY,
    last_sync_time TEXT NOT NULL,
    last_modified TEXT,
    records_synced INTEGER DEFAULT 0,
    sha256_checksum TEXT
);
`
