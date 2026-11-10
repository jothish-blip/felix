package commercial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

var alertIDCounter atomic.Int64

// AlertDeliveryResult captures structured output of an alert transmission attempt.
type AlertDeliveryResult struct {
	FindingFingerprint string    `json:"finding_fingerprint"`
	FindingTitle       string    `json:"finding_title"`
	Severity           string    `json:"severity"`
	Provider           string    `json:"provider"`
	TargetURL          string    `json:"target_url"`
	Delivered          bool      `json:"delivered"`
	StatusCode         int       `json:"status_code"`
	ReceiptID          string    `json:"receipt_id,omitempty"`
	ErrorMessage       string    `json:"error_message,omitempty"`
	Timestamp          time.Time `json:"timestamp"`
}

// SmartAlertOptions provides configurable parameters for SmartAlertNotifier initialization.
type SmartAlertOptions struct {
	AllowLoopback   bool
	AllowPrivateIPs bool
	Resolver        crawler.Resolver
	KeyRegistry     assessment.TrustedKeyRegistry
	Timeout         time.Duration
}

// SmartAlertNotifier delivers notifications strictly gated to newly verified findings.
type SmartAlertNotifier struct {
	store          *CPaaSStore
	httpClient     *http.Client
	keyRegistry    assessment.TrustedKeyRegistry
	maxRetries     int
	initialBackoff time.Duration
	timeProvider   func() time.Time
}

// NewSmartAlertNotifierWithOptions constructs a smart alert notifier with full security and networking options.
func NewSmartAlertNotifierWithOptions(store *CPaaSStore, opts SmartAlertOptions) *SmartAlertNotifier {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout:         timeout,
		AllowLoopback:   opts.AllowLoopback,
		AllowPrivateIPs: opts.AllowPrivateIPs,
		Resolver:        opts.Resolver,
	})

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			// Enforce HTTP/HTTPS only
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q blocked", scheme)
			}
			host := req.URL.Hostname()
			if host == "169.254.169.254" || strings.EqualFold(host, "fd00:ec2::254") {
				return fmt.Errorf("redirect to cloud metadata service blocked: %s", host)
			}
			return nil
		},
	}

	return &SmartAlertNotifier{
		store:          store,
		httpClient:     client,
		keyRegistry:    opts.KeyRegistry,
		maxRetries:     3,
		initialBackoff: 50 * time.Millisecond,
		timeProvider:   time.Now,
	}
}

// NewSmartAlertNotifier constructs a validated smart alert notifier.
func NewSmartAlertNotifier(store *CPaaSStore, allowLoopback, allowPrivateIPs bool) *SmartAlertNotifier {
	return NewSmartAlertNotifierWithOptions(store, SmartAlertOptions{
		AllowLoopback:   allowLoopback,
		AllowPrivateIPs: allowPrivateIPs,
	})
}

// SetKeyRegistry sets the trusted key registry for cryptographic verification of defect proof.
func (n *SmartAlertNotifier) SetKeyRegistry(reg assessment.TrustedKeyRegistry) {
	n.keyRegistry = reg
}

// Close closes idle HTTP connections and cleans up background resources.
func (n *SmartAlertNotifier) Close() {
	if n.httpClient != nil {
		if tr, ok := n.httpClient.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

// SetHTTPClient allows injecting an instrumented HTTP client for unit tests.
func (n *SmartAlertNotifier) SetHTTPClient(client *http.Client) {
	n.httpClient = client
}

// verifyFindingProof verifies that a finding has independently trusted cryptographic proof of being a VERIFIED_DEFECT.
// Unauthenticated caller-supplied strings or booleans are strictly rejected.
func (n *SmartAlertNotifier) verifyFindingProof(finding FindingSnapshot, currentSnapshot *AttackSurfaceSnapshot) error {
	// 1. Strict status check: must be exact "VERIFIED_DEFECT"
	if finding.Status != "VERIFIED_DEFECT" {
		return fmt.Errorf("finding status %q is not eligible for alert dispatch (must be exact VERIFIED_DEFECT)", finding.Status)
	}

	// 2. Fail-closed: Must have an independent trusted key registry configured
	if n.keyRegistry == nil {
		return errors.New("fail-closed: no trusted key registry configured; cannot verify defect authenticity")
	}

	// 3. Must have either a SignedEvidenceRecord or an AttestationLetter
	if finding.SignedEvidence == nil && finding.AttestationLetter == nil {
		return errors.New("caller-supplied VERIFIED_DEFECT status rejected: missing independent cryptographic attestation or signed evidence")
	}

	// Check 3A: SignedEvidenceRecord
	if finding.SignedEvidence != nil {
		rec := finding.SignedEvidence
		if rec.Payload.EvidenceID == "" {
			return errors.New("signed evidence missing evidence_id")
		}
		if rec.Signature.KeyID == "" || rec.Signature.SignatureHex == "" {
			return errors.New("signed evidence missing signature or key_id")
		}

		// Recompute canonical digest
		recomputedDigest, err := assessment.ComputeCanonicalEvidenceDigest(rec.Payload)
		if err != nil {
			return fmt.Errorf("failed computing canonical evidence digest: %w", err)
		}
		if recomputedDigest != rec.CanonicalDigest {
			return fmt.Errorf("canonical digest mismatch (tampering detected): expected %s, got %s", rec.CanonicalDigest, recomputedDigest)
		}

		// Check expiration
		now := n.timeProvider().UTC()
		if !rec.Payload.ExpiresAt.IsZero() && now.After(rec.Payload.ExpiresAt) {
			return fmt.Errorf("signed evidence expired at %s", rec.Payload.ExpiresAt.Format(time.RFC3339))
		}

		// Verify finding correspondence
		matchedFinding := rec.Payload.FindingID == finding.Fingerprint ||
			rec.Payload.FindingID == finding.ID ||
			rec.Payload.OriginalFindingRef == finding.Fingerprint ||
			rec.Payload.OriginalFindingRef == finding.ID
		if !matchedFinding {
			return fmt.Errorf("signed evidence finding reference %q does not match finding fingerprint %q", rec.Payload.FindingID, finding.Fingerprint)
		}

		// Verify target correspondence if specified
		if rec.Payload.TargetURL != "" && finding.TargetURL != "" {
			if !strings.EqualFold(rec.Payload.TargetURL, finding.TargetURL) && !strings.Contains(finding.TargetURL, rec.Payload.TargetURL) && !strings.Contains(rec.Payload.TargetURL, finding.TargetURL) {
				return fmt.Errorf("signed evidence target_url %q does not match finding target_url %q", rec.Payload.TargetURL, finding.TargetURL)
			}
		}

		// Lookup trusted key in registry
		trustedKey, ok := n.keyRegistry.LookupKey(rec.Signature.KeyID)
		if !ok {
			return fmt.Errorf("evidence signing key %q is not present in trusted key registry", rec.Signature.KeyID)
		}
		if len(trustedKey.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted key %q has invalid Ed25519 public key length", rec.Signature.KeyID)
		}

		// Verify Ed25519 digital signature
		sigBytes, err := hex.DecodeString(rec.Signature.SignatureHex)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			return errors.New("evidence signature is invalid hex or does not match Ed25519 signature size")
		}
		expectedEnvelope := fmt.Sprintf("FELIX_EVIDENCE_V1:%s:%s", rec.CanonicalDigest, rec.Signature.KeyID)
		if !ed25519.Verify(trustedKey.PublicKey, []byte(expectedEnvelope), sigBytes) {
			return errors.New("cryptographic Ed25519 signature verification failed: signature invalid for trusted public key")
		}

		return nil
	}

	// Check 3B: AttestationLetter
	if finding.AttestationLetter != nil {
		letter := *finding.AttestationLetter
		res, err := assessment.VerifyAttestationLetterAdvanced(letter, assessment.VerificationOptions{
			Registry: n.keyRegistry,
		})
		if err != nil {
			return fmt.Errorf("attestation letter verification failed: %w", err)
		}
		if !res.Valid || !res.KeyTrusted || !res.SignatureVerified || !res.DigestMatched {
			return fmt.Errorf("attestation letter invalid: %s", res.FailureReason)
		}

		// Verify that this finding is explicitly documented in the attestation's SignificantExposures
		foundInSnapshot := false
		for _, exp := range letter.Snapshot.SignificantExposures {
			if exp.FindingID == finding.ID || exp.FindingID == finding.Fingerprint || exp.Title == finding.Title {
				if exp.Status == "VERIFIED_DEFECT" || exp.VerificationStatus == "VERIFIED" {
					// Verify finding has not been tampered with or modified after attestation
					if exp.Title != finding.Title {
						return fmt.Errorf("finding title %q does not match attestation title %q (post-attestation modification detected)", finding.Title, exp.Title)
					}
					if exp.TargetEndpoint != "" && finding.TargetURL != "" && !strings.Contains(finding.TargetURL, exp.TargetEndpoint) && !strings.Contains(exp.TargetEndpoint, finding.TargetURL) {
						return fmt.Errorf("finding target %q does not match attestation endpoint %q", finding.TargetURL, exp.TargetEndpoint)
					}
					foundInSnapshot = true
					break
				}
			}
		}

		if !foundInSnapshot {
			return fmt.Errorf("finding %q (%s) is not documented as a confirmed VERIFIED_DEFECT in the cryptographic attestation letter", finding.Title, finding.Fingerprint)
		}

		return nil
	}

	return errors.New("unknown verification error")
}

// DispatchAlerts evaluates a drift report and dispatches notifications strictly for newly verified VERIFIED_DEFECT findings.
func (n *SmartAlertNotifier) DispatchAlerts(
	ctx context.Context,
	schedule *ScheduleConfig,
	driftReport *DriftReport,
	currentSnapshot *AttackSurfaceSnapshot,
) ([]AlertDeliveryResult, error) {
	if schedule == nil || driftReport == nil || currentSnapshot == nil {
		return nil, nil
	}

	if len(schedule.NotificationTargets) == 0 {
		return nil, nil
	}

	// 1. Identify newly verified VERIFIED_DEFECT findings
	var verifiedFindings []FindingSnapshot
	for _, evt := range driftReport.DriftEvents {
		// Cross-assessment transition semantics:
		// Only NEW_FINDING or FINDING_STATUS_CHANGE transitioning to VERIFIED_DEFECT qualify!
		if evt.Type == DriftTypeNewFinding {
			if evt.AfterState != "VERIFIED_DEFECT" {
				continue
			}
		} else if evt.Type == DriftTypeFindingStatusChange {
			// Must transition to VERIFIED_DEFECT from a non-verified state
			if evt.BeforeState == "VERIFIED_DEFECT" || evt.AfterState != "VERIFIED_DEFECT" {
				continue
			}
		} else {
			continue
		}

		f, exists := currentSnapshot.Findings[evt.EvidenceReference]
		if !exists {
			continue
		}

		// STRICT GATE: Must be exact VERIFIED_DEFECT!
		if f.Status != "VERIFIED_DEFECT" {
			continue
		}

		// CRYPTOGRAPHIC PROOF VERIFICATION:
		// Never trust caller-supplied status without independently verified attestation or signed evidence!
		if err := n.verifyFindingProof(f, currentSnapshot); err != nil {
			// Fail-closed: unverified finding produces zero alerts
			continue
		}

		verifiedFindings = append(verifiedFindings, f)
	}

	// If zero newly verified findings, dispatch ZERO notifications (strict gate)
	if len(verifiedFindings) == 0 {
		return nil, nil
	}

	var results []AlertDeliveryResult

	// 2. Transmit to each configured notification target with idempotency deduplication
	for _, target := range schedule.NotificationTargets {
		if !target.Enabled {
			continue
		}

		for _, finding := range verifiedFindings {
			// Idempotency check: prevent duplicate alerts for the same finding verification
			if n.store != nil {
				delivered, err := n.store.IsAlertDelivered(ctx, finding.Fingerprint, target.Provider, schedule.ID)
				if err == nil && delivered {
					continue // Already alerted
				}
			}

			res := n.sendWithRetry(ctx, schedule, target, finding)
			results = append(results, res)

			if res.Delivered && n.store != nil {
				alertID := fmt.Sprintf("alt_%s_%s_%s_%d_%d", schedule.ID, finding.Fingerprint, target.Provider, n.timeProvider().UnixNano(), alertIDCounter.Add(1))
				_ = n.store.RecordAlertDelivery(
					ctx,
					alertID,
					finding.Fingerprint,
					currentSnapshot.AssessmentID,
					schedule.ID,
					target.Provider,
					res.StatusCode,
					res.ReceiptID,
				)
			}
		}
	}

	return results, nil
}

func (n *SmartAlertNotifier) sendWithRetry(
	ctx context.Context,
	schedule *ScheduleConfig,
	target NotificationTarget,
	finding FindingSnapshot,
) AlertDeliveryResult {
	now := n.timeProvider().UTC()
	result := AlertDeliveryResult{
		FindingFingerprint: finding.Fingerprint,
		FindingTitle:       finding.Title,
		Severity:           finding.Severity,
		Provider:           target.Provider,
		TargetURL:          secrets.RedactText(target.EndpointURL),
		Timestamp:          now,
	}

	payload, err := n.buildPayload(schedule, target, finding)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("payload serialization error: %v", err)
		return result
	}

	destURL := target.EndpointURL
	if target.Provider == "pagerduty" && destURL == "" {
		destURL = "https://events.pagerduty.com/v2/enqueue"
	}

	// Validate destination URL format
	parsed, err := url.Parse(destURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		result.ErrorMessage = fmt.Sprintf("invalid webhook destination URL %q", secrets.RedactText(destURL))
		return result
	}

	backoff := n.initialBackoff
	for attempt := 0; attempt < n.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", destURL, bytes.NewReader(payload))
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("failed creating request: %v", err)
			return result
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "FELIX-CPaaS/3.0 (Security-Notifier)")

		if target.Token != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", target.Token))
		}

		resp, err := n.httpClient.Do(req)
		if err != nil {
			result.ErrorMessage = secrets.RedactText(err.Error())
			select {
			case <-ctx.Done():
				return result
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}

		_ = resp.Body.Close()
		result.StatusCode = resp.StatusCode

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Delivered = true
			result.ReceiptID = fmt.Sprintf("rcpt_%s_%s_%d", target.Provider, finding.Fingerprint, now.Unix())
			result.ErrorMessage = ""
			return result
		}

		// Permanent 4xx client errors (except 429) should not retry
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			result.ErrorMessage = fmt.Sprintf("endpoint rejected alert with HTTP %d", resp.StatusCode)
			return result
		}

		result.ErrorMessage = fmt.Sprintf("transient HTTP error %d", resp.StatusCode)
		select {
		case <-ctx.Done():
			return result
		case <-time.After(backoff):
			backoff *= 2
		}
	}

	return result
}

func (n *SmartAlertNotifier) buildPayload(
	schedule *ScheduleConfig,
	target NotificationTarget,
	finding FindingSnapshot,
) ([]byte, error) {
	switch strings.ToLower(target.Provider) {
	case "slack":
		return json.Marshal(formatSlackBlockKit(schedule, finding))
	case "teams":
		return json.Marshal(formatTeamsMessageCard(schedule, finding))
	case "pagerduty":
		routingKey := target.RoutingKey
		if routingKey == "" {
			routingKey = target.Token
		}
		return json.Marshal(formatPagerDutyEvent(schedule, finding, routingKey))
	default:
		// Generic webhook
		return json.Marshal(map[string]interface{}{
			"event":               "FELIX_VERIFIED_DEFECT_ALERT",
			"schedule_id":         schedule.ID,
			"schedule_name":       schedule.Name,
			"finding_id":          finding.ID,
			"finding_fingerprint": finding.Fingerprint,
			"title":               finding.Title,
			"severity":            finding.Severity,
			"category":            finding.Category,
			"target_url":          secrets.RedactText(finding.TargetURL),
			"status":              finding.Status,
			"timestamp":           time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// formatSlackBlockKit formats an alert according to the Slack Block Kit schema.
func formatSlackBlockKit(schedule *ScheduleConfig, finding FindingSnapshot) map[string]interface{} {
	cleanTitle := sanitizeAlertText(finding.Title)
	cleanURL := secrets.RedactText(finding.TargetURL)

	return map[string]interface{}{
		"text": fmt.Sprintf("🚨 FELIX CPaaS Security Alert: VERIFIED_DEFECT on %s", cleanURL),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type":  "plain_text",
					"text":  "🚨 FELIX Continuous Pentest: VERIFIED DEFECT",
					"emoji": true,
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Vulnerability:* %s\n*Target URL:* `%s`\n*Severity:* *%s* | *Status:* *%s*",
						cleanTitle, cleanURL, finding.Severity, finding.Status),
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Category:*\n%s", finding.Category)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Schedule:*\n%s", schedule.Name)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Fingerprint:*\n`%s`", finding.Fingerprint[:min(len(finding.Fingerprint), 16)])},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Discovered:*\n%s", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))},
				},
			},
			{
				"type": "context",
				"elements": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": "🛡️ *FELIX CPaaS Continuous Security Engine* — Automated Monthly Pentesting",
					},
				},
			},
		},
	}
}

// formatTeamsMessageCard formats an alert according to the Microsoft Teams MessageCard schema.
func formatTeamsMessageCard(schedule *ScheduleConfig, finding FindingSnapshot) map[string]interface{} {
	cleanTitle := sanitizeAlertText(finding.Title)
	cleanURL := secrets.RedactText(finding.TargetURL)

	themeColor := "D83B01" // Red for Critical/High
	if finding.Severity == "MEDIUM" {
		themeColor = "EA4300"
	}

	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": themeColor,
		"summary":    fmt.Sprintf("FELIX VERIFIED DEFECT: %s", cleanTitle),
		"title":      "🚨 FELIX CPaaS Alert: Verified Vulnerability Detected",
		"sections": []map[string]interface{}{
			{
				"activityTitle":    cleanTitle,
				"activitySubtitle": fmt.Sprintf("Target: %s", cleanURL),
				"facts": []map[string]string{
					{"name": "Severity", "value": finding.Severity},
					{"name": "Status", "value": finding.Status},
					{"name": "Category", "value": finding.Category},
					{"name": "Schedule", "value": schedule.Name},
					{"name": "Fingerprint", "value": finding.Fingerprint[:min(len(finding.Fingerprint), 16)]},
				},
				"markdown": true,
			},
		},
	}
}

// formatPagerDutyEvent formats an alert according to the PagerDuty Events API v2 schema.
func formatPagerDutyEvent(schedule *ScheduleConfig, finding FindingSnapshot, routingKey string) map[string]interface{} {
	sev := "critical"
	switch strings.ToUpper(finding.Severity) {
	case "CRITICAL":
		sev = "critical"
	case "HIGH":
		sev = "error"
	case "MEDIUM":
		sev = "warning"
	default:
		sev = "info"
	}

	return map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("felix_%s_%s", schedule.ID, finding.Fingerprint),
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("FELIX VERIFIED DEFECT: %s on %s", sanitizeAlertText(finding.Title), secrets.RedactText(finding.TargetURL)),
			"severity":  sev,
			"source":    "felix-cpaas",
			"component": finding.Category,
			"custom_details": map[string]interface{}{
				"finding_id":          finding.ID,
				"finding_fingerprint": finding.Fingerprint,
				"target_url":          secrets.RedactText(finding.TargetURL),
				"status":              finding.Status,
				"schedule_id":         schedule.ID,
				"schedule_name":       schedule.Name,
			},
		},
	}
}

func sanitizeAlertText(input string) string {
	r := strings.NewReplacer(
		"@", "",
		"<", "",
		">", "",
		"\r", " ",
		"\n", " ",
	)
	return strings.TrimSpace(r.Replace(input))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
