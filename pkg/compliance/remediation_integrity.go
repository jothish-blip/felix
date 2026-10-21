package compliance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ComputeRemediationCanonicalDigest generates a deterministic SHA-256 digest of a RemediationRecord's core fields.
func ComputeRemediationCanonicalDigest(rec *RemediationRecord) string {
	if rec == nil {
		return ""
	}

	compAtStr := ""
	if rec.CompletedAt != nil {
		compAtStr = rec.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	reopAtStr := ""
	if rec.ReopenedAt != nil {
		reopAtStr = rec.ReopenedAt.UTC().Format(time.RFC3339Nano)
	}

	canonicalMap := map[string]any{
		"id":                  strings.TrimSpace(rec.ID),
		"finding_id":          strings.TrimSpace(rec.FindingID),
		"finding_source":      strings.TrimSpace(rec.FindingSource),
		"finding_category":    strings.TrimSpace(rec.FindingCategory),
		"assessment_id":       strings.TrimSpace(rec.AssessmentID),
		"catalog_id":          strings.TrimSpace(rec.CatalogID),
		"control_id":          strings.TrimSpace(rec.ControlID),
		"evaluation_id":       strings.TrimSpace(rec.EvaluationID),
		"severity":            strings.ToUpper(strings.TrimSpace(rec.Severity)),
		"severity_source":     strings.TrimSpace(rec.SeveritySource),
		"policy_id":           strings.TrimSpace(rec.PolicyID),
		"policy_version":      strings.TrimSpace(rec.PolicyVersion),
		"policy_rule_matched": strings.TrimSpace(rec.PolicyRuleMatched),
		"assigned_at":         rec.AssignedAt.UTC().Format(time.RFC3339Nano),
		"sla_start_time":      rec.SLAStartTime.UTC().Format(time.RFC3339Nano),
		"deadline":            rec.Deadline.UTC().Format(time.RFC3339Nano),
		"time_basis":          strings.TrimSpace(rec.TimeBasis),
		"status":              string(rec.Status),
		"completed_at":        compAtStr,
		"reopen_count":        rec.ReopenCount,
		"reopened_at":         reopAtStr,
	}

	b, _ := json.Marshal(canonicalMap)
	hash := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(hash[:]))
}

// ComputeRemediationHistoryChainDigest generates a deterministic SHA-256 digest over the ordered history events.
func ComputeRemediationHistoryChainDigest(events []RemediationHistoryEvent) string {
	if len(events) == 0 {
		h := sha256.Sum256([]byte("empty-history-chain"))
		return fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:]))
	}

	sorted := make([]RemediationHistoryEvent, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Timestamp.Equal(sorted[j].Timestamp) {
			ordI := historyEventOrder(sorted[i].EventType)
			ordJ := historyEventOrder(sorted[j].EventType)
			if ordI != ordJ {
				return ordI < ordJ
			}
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	h := sha256.New()
	for _, e := range sorted {
		evtMap := map[string]any{
			"id":             e.ID,
			"remediation_id": e.RemediationID,
			"event_type":     string(e.EventType),
			"from_status":    string(e.FromStatus),
			"to_status":      string(e.ToStatus),
			"actor":          e.Actor,
			"reason":         e.Reason,
			"details_json":   e.DetailsJSON,
			"timestamp":      e.Timestamp.UTC().Format(time.RFC3339Nano),
		}
		b, _ := json.Marshal(evtMap)
		evtHash := sha256.Sum256(b)
		h.Write(evtHash[:])
	}

	chainHash := h.Sum(nil)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(chainHash))
}

// SaveRemediationRecordWithKey atomically persists a RemediationRecord, its history event, and updates its integrity metadata.
func (s *SQLiteComplianceStore) SaveRemediationRecordWithKey(rec *RemediationRecord, event *RemediationHistoryEvent, keyProvider KeyProvider) error {
	if rec == nil {
		return errors.New("remediation record cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed beginning transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	rec.IntegrityVersion = CurrentRemediationIntegrityFormatVersion

	var riskJSON sql.NullString
	if rec.RiskAcceptance != nil {
		b, err := json.Marshal(rec.RiskAcceptance)
		if err == nil {
			riskJSON = sql.NullString{String: string(b), Valid: true}
		}
	}

	evRefsJSON, _ := json.Marshal(rec.EvidenceReferences)

	upsertSQL := `
	INSERT INTO compliance_remediation_records (
		id, finding_id, finding_source, finding_title, finding_category,
		assessment_id, catalog_id, control_id, evaluation_id, severity,
		severity_source, policy_id, policy_version, policy_rule_matched,
		assigned_at, sla_start_time, deadline, time_basis, status,
		completed_at, risk_acceptance_json, reopen_count, reopened_at,
		evidence_references_json, integrity_version, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		severity = excluded.severity,
		severity_source = excluded.severity_source,
		policy_id = excluded.policy_id,
		policy_version = excluded.policy_version,
		policy_rule_matched = excluded.policy_rule_matched,
		deadline = excluded.deadline,
		status = excluded.status,
		completed_at = excluded.completed_at,
		risk_acceptance_json = excluded.risk_acceptance_json,
		reopen_count = excluded.reopen_count,
		reopened_at = excluded.reopened_at,
		evidence_references_json = excluded.evidence_references_json,
		integrity_version = excluded.integrity_version,
		updated_at = excluded.updated_at;
	`

	_, err = tx.Exec(upsertSQL,
		rec.ID, rec.FindingID, rec.FindingSource, rec.FindingTitle, rec.FindingCategory,
		rec.AssessmentID, rec.CatalogID, rec.ControlID, rec.EvaluationID, rec.Severity,
		rec.SeveritySource, rec.PolicyID, rec.PolicyVersion, rec.PolicyRuleMatched,
		rec.AssignedAt, rec.SLAStartTime, rec.Deadline, rec.TimeBasis, string(rec.Status),
		rec.CompletedAt, riskJSON, rec.ReopenCount, rec.ReopenedAt,
		string(evRefsJSON), rec.IntegrityVersion, rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed saving remediation record %s: %w", rec.ID, err)
	}

	if event != nil {
		if event.ID == "" {
			event.ID = GenerateRemediationEventID(rec.ID)
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = now
		}
		eventSQL := `
		INSERT INTO compliance_remediation_history (
			id, remediation_id, event_type, from_status, to_status, actor, reason, details_json, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
		`
		_, err = tx.Exec(eventSQL,
			event.ID, rec.ID, string(event.EventType), string(event.FromStatus), string(event.ToStatus),
			event.Actor, event.Reason, event.DetailsJSON, event.Timestamp,
		)
		if err != nil {
			return fmt.Errorf("failed saving remediation history event: %w", err)
		}
	}

	// Fetch all events for this remediation record inside tx to compute chain digest
	rows, err := tx.Query(`
		SELECT id, remediation_id, event_type, from_status, to_status, actor, reason, details_json, timestamp
		FROM compliance_remediation_history
		WHERE remediation_id = ?
		ORDER BY timestamp ASC, id ASC;
	`, rec.ID)
	if err != nil {
		return fmt.Errorf("failed querying history for integrity: %w", err)
	}

	var allEvents []RemediationHistoryEvent
	for rows.Next() {
		var (
			e                      RemediationHistoryEvent
			eType, fromSt, toSt    string
			actor, reason, detJSON sql.NullString
		)
		if err := rows.Scan(&e.ID, &e.RemediationID, &eType, &fromSt, &toSt, &actor, &reason, &detJSON, &e.Timestamp); err == nil {
			e.EventType = RemediationHistoryEventType(eType)
			e.FromStatus = RemediationLifecycleStatus(fromSt)
			e.ToStatus = RemediationLifecycleStatus(toSt)
			e.Actor = actor.String
			e.Reason = reason.String
			e.DetailsJSON = detJSON.String
			allEvents = append(allEvents, e)
		}
	}
	rows.Close()

	recDigest := ComputeRemediationCanonicalDigest(rec)
	histDigest := ComputeRemediationHistoryChainDigest(allEvents)

	algo := AlgorithmNone
	keyID := ""
	signatureTag := ""

	if keyProvider != nil {
		key, keyErr := keyProvider.GetSigningKey(context.Background())
		if keyErr == nil && key != nil && len(key.Material) > 0 {
			algo = AlgorithmHMACSHA256
			keyID = key.ID
			mac := hmac.New(sha256.New, key.Material)
			mac.Write([]byte(recDigest + ":" + histDigest))
			signatureTag = hex.EncodeToString(mac.Sum(nil))
		}
	}

	integritySQL := `
	INSERT INTO compliance_remediation_integrity_records (
		remediation_id, format_version, canonical_digest, authenticity_algorithm,
		key_id, signature_tag, event_count, history_chain_digest, protected_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(remediation_id) DO UPDATE SET
		format_version = excluded.format_version,
		canonical_digest = excluded.canonical_digest,
		authenticity_algorithm = excluded.authenticity_algorithm,
		key_id = excluded.key_id,
		signature_tag = excluded.signature_tag,
		event_count = excluded.event_count,
		history_chain_digest = excluded.history_chain_digest,
		protected_at = excluded.protected_at;
	`

	_, err = tx.Exec(integritySQL,
		rec.ID, CurrentRemediationIntegrityFormatVersion, recDigest, algo,
		keyID, signatureTag, len(allEvents), histDigest, now,
	)
	if err != nil {
		return fmt.Errorf("failed saving remediation integrity record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed committing remediation transaction: %w", err)
	}

	return nil
}

// VerifyRemediationIntegrity independently checks the content integrity and authenticity of a remediation record and its history.
func (s *SQLiteComplianceStore) VerifyRemediationIntegrity(remediationID string, keyProvider KeyProvider) (*RemediationIntegrityVerificationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	result := &RemediationIntegrityVerificationResult{
		RemediationID: remediationID,
		VerifiedAt:    now,
	}

	// 1. Fetch remediation record
	rec, err := s.GetRemediationRecord(remediationID)
	if err != nil {
		result.Status = StatusOperationalFailure
		result.Violations = append(result.Violations, fmt.Sprintf("failed reading remediation record: %v", err))
		return result, nil
	}
	if rec == nil {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations, "remediation record does not exist in store")
		return result, nil
	}

	// 2. Fetch integrity record
	intRow := s.db.QueryRow(`
		SELECT remediation_id, format_version, canonical_digest, authenticity_algorithm,
		       key_id, signature_tag, event_count, history_chain_digest, protected_at
		FROM compliance_remediation_integrity_records
		WHERE remediation_id = ?;
	`, remediationID)

	var (
		irID, fmtVer, canDigest, algo, histDigest string
		keyID, sigTag                             sql.NullString
		evtCount                                  int
		protAt                                    time.Time
	)

	err = intRow.Scan(&irID, &fmtVer, &canDigest, &algo, &keyID, &sigTag, &evtCount, &histDigest, &protAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if rec.IntegrityVersion != "" {
				// Record has integrity marker but integrity row was deleted -> tampering!
				result.Status = StatusIntegrityMismatch
				result.Violations = append(result.Violations, "integrity metadata row is missing for integrity-protected remediation (unauthorized deletion detected)")
				return result, nil
			}
			result.Status = StatusUnverifiedLegacy
			return result, nil
		}
		result.Status = StatusOperationalFailure
		result.Violations = append(result.Violations, fmt.Sprintf("database error reading integrity record: %v", err))
		return result, nil
	}

	result.RecordedDigest = canDigest
	result.RecordedHistoryDigest = histDigest
	result.Algorithm = algo
	result.KeyID = keyID.String

	// 3. Query all history events for this remediation
	events, err := s.GetRemediationHistory(remediationID)
	if err != nil {
		result.Status = StatusOperationalFailure
		result.Violations = append(result.Violations, fmt.Sprintf("failed retrieving history: %v", err))
		return result, nil
	}

	result.EventCount = len(events)
	if len(events) != evtCount {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations, fmt.Sprintf("event count mismatch: recorded %d, found %d (history row deletion or insertion detected)", evtCount, len(events)))
		return result, nil
	}

	// 4. Verify history chain digest
	computedHistDigest := ComputeRemediationHistoryChainDigest(events)
	result.ComputedHistoryDigest = computedHistDigest
	if computedHistDigest != histDigest {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations, "history chain digest mismatch: tamper detected in history events (timestamps, ordering, or event types)")
		return result, nil
	}
	result.HistoryChainMatch = true

	// 5. Verify record canonical digest
	computedRecDigest := ComputeRemediationCanonicalDigest(rec)
	result.ComputedDigest = computedRecDigest
	if computedRecDigest != canDigest {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations, "canonical digest mismatch: tamper detected in remediation record fields (start time, completion time, deadline, or status)")
		return result, nil
	}
	result.CanonicalDigestMatch = true

	// 6. Verify cryptographic authenticity if HMAC signed
	if algo == AlgorithmHMACSHA256 {
		if keyProvider == nil {
			result.Status = StatusIntegrityOnly
			return result, nil
		}

		key, keyErr := keyProvider.GetVerificationKey(context.Background(), keyID.String)
		if keyErr != nil || key == nil || len(key.Material) == 0 {
			result.Status = StatusUnknownKey
			result.Violations = append(result.Violations, fmt.Sprintf("verification key not found: %v", keyErr))
			return result, nil
		}

		mac := hmac.New(sha256.New, key.Material)
		mac.Write([]byte(canDigest + ":" + histDigest))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		if subtle.ConstantTimeCompare([]byte(sigTag.String), []byte(expectedSig)) != 1 {
			result.Status = StatusIntegrityMismatch
			result.Violations = append(result.Violations, "cryptographic HMAC signature mismatch: unauthorized modification detected")
			return result, nil
		}
		result.AuthenticityMatch = true
		result.Status = StatusVerified
	} else {
		result.Status = StatusIntegrityOnly
	}

	return result, nil
}

// GetRemediationIntegrityRecord returns the stored integrity record for a remediation ID.
func (s *SQLiteComplianceStore) GetRemediationIntegrityRecord(remediationID string) (*RemediationIntegrityRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	intRow := s.db.QueryRow(`
		SELECT remediation_id, format_version, canonical_digest, authenticity_algorithm,
		       key_id, signature_tag, event_count, history_chain_digest, protected_at, verified_at
		FROM compliance_remediation_integrity_records
		WHERE remediation_id = ?;
	`, remediationID)

	var (
		ir            RemediationIntegrityRecord
		keyID, sigTag sql.NullString
		verAt         sql.NullTime
	)

	err := intRow.Scan(
		&ir.RemediationID, &ir.FormatVersion, &ir.CanonicalDigest, &ir.AuthenticityAlgorithm,
		&keyID, &sigTag, &ir.EventCount, &ir.HistoryChainDigest, &ir.ProtectedAt, &verAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	ir.KeyID = keyID.String
	ir.SignatureTag = sigTag.String
	if verAt.Valid {
		ir.VerifiedAt = &verAt.Time
	}

	return &ir, nil
}
