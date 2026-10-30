package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"felix/pkg/secrets"
)

// StorageSurface defines browser-managed client storage surfaces.
type StorageSurface string

const (
	SurfaceLocalStorage   StorageSurface = "localStorage"
	SurfaceSessionStorage StorageSurface = "sessionStorage"
	SurfaceIndexedDB      StorageSurface = "IndexedDB"
	SurfaceCookie         StorageSurface = "Cookie"
)

// StorageExposureType characterizes findings by evidence confidence and risk tier.
type StorageExposureType string

const (
	// ExposureDiscoveredStorage represents benign, ordinary application state (e.g. preferences).
	ExposureDiscoveredStorage StorageExposureType = "STORAGE_DISCOVERED"

	// ExposureSensitiveCandidate represents a heuristic match (e.g. key name matches pattern or ambiguous UUID),
	// requiring contextual evaluation before being considered a credential.
	ExposureSensitiveCandidate StorageExposureType = "SENSITIVE_LOOKING_VALUE"

	// ExposurePotentiallyExposed represents a candidate credential or high-entropy token pattern
	// stored in client-accessible storage (localStorage, sessionStorage, IndexedDB) accessible to DOM scripts.
	ExposurePotentiallyExposed StorageExposureType = "POTENTIALLY_EXPOSED_CREDENTIAL"

	// ExposureConfirmedMisconfig represents a proven security attribute violation
	// (e.g. sensitive session cookie missing HttpOnly or Secure flag).
	ExposureConfirmedMisconfig StorageExposureType = "CONFIRMED_MISCONFIGURATION"

	// ExposureInconclusive represents an uninspected, blocked, or error-terminated storage surface.
	ExposureInconclusive StorageExposureType = "INCONCLUSIVE_OBSERVATION"
)

// StorageItem models an observed storage record with strict raw-secret omission.
type StorageItem struct {
	Surface        StorageSurface `json:"surface"`
	Origin         string         `json:"origin"`
	DatabaseName   string         `json:"database_name,omitempty"`
	StoreName      string         `json:"store_name,omitempty"`
	Key            string         `json:"key"`
	ValueLength    int            `json:"value_length"`
	Preview        string         `json:"preview"` // Masked preview only (no raw secrets)
	Fingerprint    string         `json:"fingerprint"`
	IsSensitive    bool           `json:"is_sensitive"`
	DetectedType   string         `json:"detected_type,omitempty"`
	AccessibleToJS bool           `json:"accessible_to_js"`
}

// CookieMetadata records browser-reported cookie attributes and JavaScript accessibility.
type CookieMetadata struct {
	Name            string  `json:"name"`
	Domain          string  `json:"domain"`
	Path            string  `json:"path"`
	Expires         float64 `json:"expires"`
	Size            int     `json:"size"`
	Secure          bool    `json:"secure"`
	HTTPOnly        bool    `json:"http_only"`
	SameSite        string  `json:"same_site"`
	AccessibleToJS  bool    `json:"accessible_to_js"`
	ValueLength     int     `json:"value_length"`
	RedactedPreview string  `json:"redacted_preview"`
	IsSensitive     bool    `json:"is_sensitive"`
	DetectedType    string  `json:"detected_type,omitempty"`
}

// StorageExposureFinding models an actionable exposure finding with minimal redacted evidence.
type StorageExposureFinding struct {
	Surface       StorageSurface      `json:"surface"`
	Origin        string              `json:"origin"`
	KeyName       string              `json:"key_name"`
	ExposureType  StorageExposureType `json:"exposure_type"`
	Severity      string              `json:"severity"`
	Confidence    string              `json:"confidence"`
	Rationale     string              `json:"rationale"`
	SecurityAttrs map[string]any      `json:"security_attributes,omitempty"`
	Evidence      string              `json:"evidence"` // Strictly masked evidence
	Fingerprint   string              `json:"fingerprint"`
	Remediation   string              `json:"remediation,omitempty"`
	Limitations   string              `json:"limitations,omitempty"`
}

// StorageAuditConfig bounds storage exploration to prevent hangs or resource exhaustion.
type StorageAuditConfig struct {
	MaxItemsPerStore    int
	MaxRecordsIndexedDB int
	MaxBytesPerStore    int
	MaxValueLengthBytes int
	InspectionTimeout   time.Duration
	DetectSecrets       bool
}

// DefaultStorageAuditConfig returns production hardened defaults for authorized storage auditing.
func DefaultStorageAuditConfig() StorageAuditConfig {
	return StorageAuditConfig{
		MaxItemsPerStore:    100,
		MaxRecordsIndexedDB: 50,
		MaxBytesPerStore:    65536, // 64 KB per object store
		MaxValueLengthBytes: 4096,
		InspectionTimeout:   10 * time.Second,
		DetectSecrets:       true,
	}
}

// StorageAuditReport consolidates findings across all audited client-side surfaces.
type StorageAuditReport struct {
	Origin               string                    `json:"origin"`
	DurationMS           float64                   `json:"duration_ms"`
	SurfacesInspected    []StorageSurface          `json:"surfaces_inspected"`
	TotalItemsDiscovered int                       `json:"total_items_discovered"`
	TotalFindings        int                       `json:"total_findings"`
	Findings             []*StorageExposureFinding `json:"findings"`
	DiscoveredItems      []*StorageItem            `json:"discovered_items"`
	Cookies              []*CookieMetadata         `json:"cookies"`
	Limitations          []string                  `json:"limitations"`
}

// StorageAuditor inspects client-side storage for sensitive data exposure.
type StorageAuditor struct {
	inst     *Instance
	cfg      StorageAuditConfig
	detector *secrets.Detector
	mu       sync.RWMutex
}

// NewStorageAuditor creates and initializes a client storage auditor bound to a browser instance.
func NewStorageAuditor(inst *Instance, cfg StorageAuditConfig) (*StorageAuditor, error) {
	if inst == nil || inst.Ctx == nil {
		return nil, fmt.Errorf("invalid browser instance: context is nil")
	}

	if cfg.MaxItemsPerStore <= 0 {
		cfg.MaxItemsPerStore = 100
	}
	if cfg.MaxRecordsIndexedDB <= 0 {
		cfg.MaxRecordsIndexedDB = 50
	}
	if cfg.MaxBytesPerStore <= 0 {
		cfg.MaxBytesPerStore = 65536
	}
	if cfg.MaxValueLengthBytes <= 0 {
		cfg.MaxValueLengthBytes = 4096
	}
	if cfg.InspectionTimeout <= 0 {
		cfg.InspectionTimeout = 10 * time.Second
	}

	return &StorageAuditor{
		inst:     inst,
		cfg:      cfg,
		detector: secrets.NewDetector(),
	}, nil
}

// Audit inspects all supported client-side storage surfaces on the active page context.
func (sa *StorageAuditor) Audit(parentCtx context.Context) (*StorageAuditReport, error) {
	startTime := time.Now()

	auditCtx, cancel := context.WithTimeout(parentCtx, sa.cfg.InspectionTimeout)
	defer cancel()

	// 1. Resolve current origin and URL
	var currentURL string
	var currentOrigin string
	urlScript := `(function() { return { url: window.location.href, origin: window.location.origin }; })()`

	type urlInfo struct {
		URL    string `json:"url"`
		Origin string `json:"origin"`
	}
	tTrue := true
	evalRes, err := chromedp.Call(sa.inst.Ctx, runtime.Evaluate, runtime.EvaluateParams{
		Expression:    urlScript,
		ReturnByValue: &tTrue,
	})
	if err == nil && evalRes.Result != nil && len(evalRes.Result.Value) > 0 {
		var u urlInfo
		if err := json.Unmarshal(evalRes.Result.Value, &u); err == nil {
			currentURL = u.URL
			currentOrigin = u.Origin
		}
	}
	if currentURL == "" {
		currentURL = "about:blank"
		currentOrigin = "about:blank"
	}

	report := &StorageAuditReport{
		Origin:            currentOrigin,
		SurfacesInspected: make([]StorageSurface, 0),
		Findings:          make([]*StorageExposureFinding, 0),
		DiscoveredItems:   make([]*StorageItem, 0),
		Cookies:           make([]*CookieMetadata, 0),
		Limitations: []string{
			"Cache Storage and OPFS (Origin Private File System) are not enumerated in Phase 1.5 scope",
			"WebSQL is deprecated and unsupported in modern Chromium",
			"Third-party iframe isolated storage partitions require context-specific frame targeting",
		},
	}

	seenFindings := make(map[string]struct{})

	// 2. Inspect localStorage
	localItems, localFindings, localErr := sa.inspectWebStorage(auditCtx, "localStorage", SurfaceLocalStorage, currentOrigin)
	if localErr != nil {
		report.Findings = append(report.Findings, &StorageExposureFinding{
			Surface:      SurfaceLocalStorage,
			Origin:       currentOrigin,
			ExposureType: ExposureInconclusive,
			Severity:     "INFO",
			Confidence:   "LOW",
			Rationale:    fmt.Sprintf("Failed to inspect localStorage: %v", localErr),
			Limitations:  "localStorage access restricted or threw SecurityError",
		})
	} else {
		report.SurfacesInspected = append(report.SurfacesInspected, SurfaceLocalStorage)
		report.DiscoveredItems = append(report.DiscoveredItems, localItems...)
		for _, f := range localFindings {
			if _, exists := seenFindings[f.Fingerprint]; !exists {
				seenFindings[f.Fingerprint] = struct{}{}
				report.Findings = append(report.Findings, f)
			}
		}
	}

	// 3. Inspect sessionStorage
	sessItems, sessFindings, sessErr := sa.inspectWebStorage(auditCtx, "sessionStorage", SurfaceSessionStorage, currentOrigin)
	if sessErr != nil {
		report.Findings = append(report.Findings, &StorageExposureFinding{
			Surface:      SurfaceSessionStorage,
			Origin:       currentOrigin,
			ExposureType: ExposureInconclusive,
			Severity:     "INFO",
			Confidence:   "LOW",
			Rationale:    fmt.Sprintf("Failed to inspect sessionStorage: %v", sessErr),
			Limitations:  "sessionStorage access restricted or threw SecurityError",
		})
	} else {
		report.SurfacesInspected = append(report.SurfacesInspected, SurfaceSessionStorage)
		report.DiscoveredItems = append(report.DiscoveredItems, sessItems...)
		for _, f := range sessFindings {
			if _, exists := seenFindings[f.Fingerprint]; !exists {
				seenFindings[f.Fingerprint] = struct{}{}
				report.Findings = append(report.Findings, f)
			}
		}
	}

	// 4. Inspect IndexedDB
	idbItems, idbFindings, idbErr := sa.inspectIndexedDB(auditCtx, currentOrigin)
	if idbErr != nil {
		report.Findings = append(report.Findings, &StorageExposureFinding{
			Surface:      SurfaceIndexedDB,
			Origin:       currentOrigin,
			ExposureType: ExposureInconclusive,
			Severity:     "INFO",
			Confidence:   "LOW",
			Rationale:    fmt.Sprintf("IndexedDB inspection encountered error or unsupported API: %v", idbErr),
			Limitations:  "IndexedDB access restricted, unsupported, blocked, or timed out",
		})
		report.Limitations = append(report.Limitations, fmt.Sprintf("IndexedDB unavailable: %v", idbErr))
	} else {
		report.SurfacesInspected = append(report.SurfacesInspected, SurfaceIndexedDB)
		report.DiscoveredItems = append(report.DiscoveredItems, idbItems...)
		for _, f := range idbFindings {
			if _, exists := seenFindings[f.Fingerprint]; !exists {
				seenFindings[f.Fingerprint] = struct{}{}
				report.Findings = append(report.Findings, f)
			}
		}
	}

	// 5. Inspect Cookies via CDP
	cookies, cookieFindings, cookieErr := sa.inspectCookies(auditCtx, currentURL, currentOrigin)
	if cookieErr != nil {
		report.Findings = append(report.Findings, &StorageExposureFinding{
			Surface:      SurfaceCookie,
			Origin:       currentOrigin,
			ExposureType: ExposureInconclusive,
			Severity:     "INFO",
			Confidence:   "LOW",
			Rationale:    fmt.Sprintf("Failed to query cookies via CDP: %v", cookieErr),
		})
	} else {
		report.SurfacesInspected = append(report.SurfacesInspected, SurfaceCookie)
		report.Cookies = append(report.Cookies, cookies...)
		for _, f := range cookieFindings {
			if _, exists := seenFindings[f.Fingerprint]; !exists {
				seenFindings[f.Fingerprint] = struct{}{}
				report.Findings = append(report.Findings, f)
			}
		}
	}

	report.TotalItemsDiscovered = len(report.DiscoveredItems) + len(report.Cookies)
	report.TotalFindings = len(report.Findings)
	report.DurationMS = float64(time.Since(startTime).Milliseconds())

	return report, nil
}

type webStoragePayload struct {
	Error string `json:"error"`
	Items []struct {
		Key string `json:"key"`
		Val string `json:"val"`
		Len int    `json:"len"`
	} `json:"items"`
}

func (sa *StorageAuditor) inspectWebStorage(ctx context.Context, jsProp string, surface StorageSurface, origin string) ([]*StorageItem, []*StorageExposureFinding, error) {
	script := fmt.Sprintf(`(function(storageProp, maxItems, maxLen) {
		try {
			const store = window[storageProp];
			if (!store) return JSON.stringify({ error: 'storage_unavailable', items: [] });
			const results = [];
			const count = Math.min(store.length, maxItems);
			for (let i = 0; i < count; i++) {
				const key = store.key(i);
				if (key === null) continue;
				let val = '';
				try {
					val = store.getItem(key) || '';
				} catch(e) {}
				const valLen = val.length;
				const truncated = val.length > maxLen ? val.substring(0, maxLen) : val;
				results.push({
					key: key,
					val: truncated,
					len: valLen
				});
			}
			return JSON.stringify({ error: '', items: results });
		} catch(e) {
			return JSON.stringify({ error: e.message || 'access_denied', items: [] });
		}
	})('%s', %d, %d)`, jsProp, sa.cfg.MaxItemsPerStore, sa.cfg.MaxValueLengthBytes)

	resJSON, err := chromedp.Run(sa.inst.Ctx, chromedp.Evaluate[string](script))
	if err != nil {
		return nil, nil, fmt.Errorf("failed executing %s extraction script: %w", jsProp, err)
	}

	var payload webStoragePayload
	if err := json.Unmarshal([]byte(resJSON), &payload); err != nil {
		return nil, nil, fmt.Errorf("failed parsing %s extraction payload: %w", jsProp, err)
	}

	if payload.Error != "" {
		return nil, nil, fmt.Errorf("browser returned error for %s: %s", jsProp, payload.Error)
	}

	var items []*StorageItem
	var findings []*StorageExposureFinding

	for _, raw := range payload.Items {
		item, finding := sa.analyzeStorageEntry(surface, origin, "", "", raw.Key, raw.Val, raw.Len, true)
		items = append(items, item)
		if finding != nil {
			findings = append(findings, finding)
		}
	}

	return items, findings, nil
}

type idbStoreRecord struct {
	Index int    `json:"index"`
	Val   string `json:"val"`
	Len   int    `json:"len"`
}

type idbStorePayload struct {
	Name    string           `json:"name"`
	Records []idbStoreRecord `json:"records"`
}

type idbDatabasePayload struct {
	Name    string            `json:"name"`
	Version int               `json:"version"`
	Error   string            `json:"error,omitempty"`
	Stores  []idbStorePayload `json:"stores"`
}

type idbResultPayload struct {
	Error     string               `json:"error"`
	Databases []idbDatabasePayload `json:"databases"`
}

func (sa *StorageAuditor) inspectIndexedDB(ctx context.Context, origin string) ([]*StorageItem, []*StorageExposureFinding, error) {
	// Bounded streaming collection using openCursor to enforce record counts,
	// byte limits, and timeouts actively during collection, not only post-retrieval.
	script := fmt.Sprintf(`(async function(maxDBs, maxStores, maxRecords, maxLen, maxBytesPerStore) {
		if (!window.indexedDB || typeof window.indexedDB.databases !== 'function') {
			return JSON.stringify({ error: 'indexeddb_databases_unsupported', databases: [] });
		}
		try {
			const timeoutPromise = new Promise((_, reject) =>
				setTimeout(() => reject(new Error('indexeddb_timeout')), 4000)
			);
			const inspectPromise = (async () => {
				const dbList = await window.indexedDB.databases();
				const results = [];
				const dbsToScan = (dbList || []).slice(0, maxDBs);
				for (const dbInfo of dbsToScan) {
					if (!dbInfo || !dbInfo.name) continue;
					const dbRes = { name: dbInfo.name, version: dbInfo.version || 1, stores: [] };
					try {
						const db = await new Promise((resolve, reject) => {
							const req = indexedDB.open(dbInfo.name);
							req.onsuccess = () => resolve(req.result);
							req.onerror = () => reject(req.error || new Error('open_failed'));
							req.onblocked = () => reject(new Error('open_blocked'));
						});
						const storeNames = Array.from(db.objectStoreNames || []).slice(0, maxStores);
						for (const sName of storeNames) {
							try {
								const storeRes = { name: sName, records: [] };
								const records = await new Promise((resolve, reject) => {
									try {
										const tx = db.transaction(sName, 'readonly');
										tx.onerror = () => reject(tx.error || new Error('tx_failed'));
										tx.onabort = () => reject(new Error('tx_aborted'));
										const store = tx.objectStore(sName);
										const req = store.openCursor();
										const items = [];
										let totalBytes = 0;
										const storeStart = Date.now();
										req.onsuccess = (e) => {
											const cursor = e.target.result;
											if (!cursor) {
												resolve(items);
												return;
											}
											let serialized = '';
											try {
												serialized = typeof cursor.value === 'string' ? cursor.value : JSON.stringify(cursor.value);
											} catch(_) {
												serialized = String(cursor.value || '');
											}
											const recLen = serialized.length;
											const truncated = recLen > maxLen ? serialized.substring(0, maxLen) : serialized;
											totalBytes += recLen;
											items.push({
												index: items.length,
												val: truncated,
												len: recLen
											});
											// Bounded actively during collection
											if (items.length >= maxRecords || totalBytes >= maxBytesPerStore || (Date.now() - storeStart) > 2000) {
												resolve(items);
												return;
											}
											try {
												cursor.continue();
											} catch(_) {
												resolve(items);
											}
										};
										req.onerror = () => reject(req.error || new Error('cursor_failed'));
									} catch(err) {
										reject(err);
									}
								});
								storeRes.records = records;
								dbRes.stores.push(storeRes);
							} catch(e) {}
						}
						db.close();
					} catch(e) {
						dbRes.error = e.message || 'db_access_failed';
					}
					results.push(dbRes);
				}
				return { error: '', databases: results };
			})();
			const res = await Promise.race([inspectPromise, timeoutPromise]);
			return JSON.stringify(res);
		} catch(e) {
			return JSON.stringify({ error: e.message || 'indexeddb_enumeration_failed', databases: [] });
		}
	})(10, 10, %d, %d, %d)`, sa.cfg.MaxRecordsIndexedDB, sa.cfg.MaxValueLengthBytes, sa.cfg.MaxBytesPerStore)

	tTrue := true
	evalRes, err := chromedp.Call(sa.inst.Ctx, runtime.Evaluate, runtime.EvaluateParams{
		Expression:    script,
		AwaitPromise:  &tTrue,
		ReturnByValue: &tTrue,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed executing IndexedDB evaluation: %w", err)
	}

	if evalRes.ExceptionDetails != nil {
		return nil, nil, fmt.Errorf("IndexedDB evaluation exception: %s", evalRes.ExceptionDetails.Text)
	}

	var resJSON string
	if evalRes.Result != nil && len(evalRes.Result.Value) > 0 {
		_ = json.Unmarshal(evalRes.Result.Value, &resJSON)
	}

	var payload idbResultPayload
	if err := json.Unmarshal([]byte(resJSON), &payload); err != nil {
		return nil, nil, fmt.Errorf("failed parsing IndexedDB payload: %w", err)
	}

	if payload.Error != "" {
		return nil, nil, fmt.Errorf("IndexedDB extraction error: %s", payload.Error)
	}

	var items []*StorageItem
	var findings []*StorageExposureFinding

	for _, db := range payload.Databases {
		for _, store := range db.Stores {
			for _, rec := range store.Records {
				keyName := fmt.Sprintf("%s/%s[%d]", db.Name, store.Name, rec.Index)
				item, finding := sa.analyzeStorageEntry(SurfaceIndexedDB, origin, db.Name, store.Name, keyName, rec.Val, rec.Len, true)
				items = append(items, item)
				if finding != nil {
					findings = append(findings, finding)
				}
			}
		}
	}

	return items, findings, nil
}

func (sa *StorageAuditor) inspectCookies(ctx context.Context, targetURL, origin string) ([]*CookieMetadata, []*StorageExposureFinding, error) {
	params := network.GetCookiesParams{}
	if targetURL != "" && targetURL != "about:blank" {
		params.URLs = []string{targetURL}
	}
	cookiesRes, err := chromedp.Call(sa.inst.Ctx, network.GetCookies, params)
	if err != nil {
		return nil, nil, fmt.Errorf("CDP network.GetCookies failed: %w", err)
	}
	if len(cookiesRes.Cookies) == 0 && len(params.URLs) > 0 {
		cookiesRes, _ = chromedp.Call(sa.inst.Ctx, network.GetCookies, network.GetCookiesParams{})
	}

	var cookies []*CookieMetadata
	var findings []*StorageExposureFinding

	for _, c := range cookiesRes.Cookies {
		if c == nil {
			continue
		}

		rawVal := c.Value
		valLen := len(rawVal)
		redactedPreview := secrets.RedactSecret(rawVal)
		fingerprint := secrets.GenerateFingerprint("cookie", c.Name+":"+rawVal)

		isSensitive, detectedType := sa.detectSensitiveValue(c.Name, rawVal)
		accessibleToJS := !c.HTTPOnly

		meta := &CookieMetadata{
			Name:            c.Name,
			Domain:          c.Domain,
			Path:            c.Path,
			Expires:         c.Expires,
			Size:            int(c.Size),
			Secure:          c.Secure,
			HTTPOnly:        c.HTTPOnly,
			SameSite:        string(c.SameSite),
			AccessibleToJS:  accessibleToJS,
			ValueLength:     valLen,
			RedactedPreview: redactedPreview,
			IsSensitive:     isSensitive,
			DetectedType:    detectedType,
		}
		cookies = append(cookies, meta)

		// Audit security attribute misconfigurations strictly when cookie is sensitive
		if isSensitive {
			if !c.HTTPOnly {
				// Observed attribute: Sensitive authentication or session cookie exposed to JavaScript
				findings = append(findings, &StorageExposureFinding{
					Surface:      SurfaceCookie,
					Origin:       origin,
					KeyName:      c.Name,
					ExposureType: ExposureConfirmedMisconfig,
					Severity:     "MEDIUM", // Justified risk: attribute violation, not standalone critical exploit
					Confidence:   "CONFIRMED",
					Rationale:    fmt.Sprintf("Observed attribute: Cookie %q lacks the HttpOnly attribute, making its value accessible to client-side JavaScript via document.cookie (AccessibleToJS: true). While not directly exploitable without a client-side injection vulnerability (such as XSS), this misconfiguration permits token exfiltration if script execution occurs.", c.Name),
					SecurityAttrs: map[string]any{
						"http_only":        c.HTTPOnly,
						"secure":           c.Secure,
						"same_site":        string(c.SameSite),
						"accessible_to_js": accessibleToJS,
						"domain":           c.Domain,
						"path":             c.Path,
					},
					Evidence:    fmt.Sprintf("Cookie name=%q, HttpOnly=false, RedactedVal=%s", c.Name, redactedPreview),
					Fingerprint: fingerprint,
					Remediation: "Set the HttpOnly directive on sensitive session and authentication cookies to prevent access via document.cookie.",
				})
			} else if !c.Secure && strings.HasPrefix(strings.ToLower(targetURL), "https://") {
				// Sensitive cookie transmitted without Secure flag over HTTPS
				findings = append(findings, &StorageExposureFinding{
					Surface:      SurfaceCookie,
					Origin:       origin,
					KeyName:      c.Name,
					ExposureType: ExposureConfirmedMisconfig,
					Severity:     "MEDIUM",
					Confidence:   "CONFIRMED",
					Rationale:    fmt.Sprintf("Observed attribute: Sensitive cookie %q is missing the Secure attribute on an HTTPS origin, permitting transmission over unencrypted channels.", c.Name),
					SecurityAttrs: map[string]any{
						"http_only": c.HTTPOnly,
						"secure":    c.Secure,
						"same_site": string(c.SameSite),
						"domain":    c.Domain,
						"path":      c.Path,
					},
					Evidence:    fmt.Sprintf("Cookie name=%q, Secure=false, RedactedVal=%s", c.Name, redactedPreview),
					Fingerprint: fingerprint,
					Remediation: "Add the Secure directive to sensitive cookies to enforce transmission exclusively over TLS.",
				})
			}
		}
	}

	return cookies, findings, nil
}

func (sa *StorageAuditor) analyzeStorageEntry(surface StorageSurface, origin, dbName, storeName, key, val string, valLen int, accessibleToJS bool) (*StorageItem, *StorageExposureFinding) {
	redactedPreview := secrets.RedactSecret(val)
	fingerprint := secrets.GenerateFingerprint(secrets.SecretType(surface), key+":"+val)

	isSensitive, detectedType := sa.detectSensitiveValue(key, val)

	item := &StorageItem{
		Surface:        surface,
		Origin:         origin,
		DatabaseName:   dbName,
		StoreName:      storeName,
		Key:            key,
		ValueLength:    valLen,
		Preview:        redactedPreview,
		Fingerprint:    fingerprint,
		IsSensitive:    isSensitive,
		DetectedType:   detectedType,
		AccessibleToJS: accessibleToJS,
	}

	if !isSensitive {
		// Benign item (e.g. theme, language, display preferences, ordinary UUIDs) -> No finding created (zero false positives)
		return item, nil
	}

	// Classify sensitivity with evidence-backed semantics
	var exposureType StorageExposureType
	var sev string
	var conf string
	var rationale string

	switch detectedType {
	case "JWT", "api_token", "aws_key":
		if isTestOrMockContext(key) {
			exposureType = ExposureSensitiveCandidate
			sev = "LOW"
			conf = "LOW"
			rationale = fmt.Sprintf("Pattern resembles a credential (%s), but storage context (%q) indicates a synthetic, test, or mock candidate value.", detectedType, key)
		} else {
			exposureType = ExposurePotentiallyExposed
			sev = "HIGH"
			conf = "MEDIUM" // Context discovers client persistence; backend validity is not asserted
			rationale = fmt.Sprintf("Candidate credential pattern (%s) identified in client-accessible %s (exposed to any DOM script or XSS). Note: Backend validity is not asserted.", detectedType, surface)
		}

	case "candidate_session_uuid":
		exposureType = ExposureSensitiveCandidate
		sev = "LOW"
		conf = "LOW"
		rationale = fmt.Sprintf("Storage key %q contains an opaque UUID in %s. Without server-side session validation, this is evaluated as a candidate session identifier rather than an exposed credential.", key, surface)

	case "session_token":
		exposureType = ExposurePotentiallyExposed
		sev = "MEDIUM"
		conf = "MEDIUM"
		rationale = fmt.Sprintf("Candidate session or authorization token identified in client-accessible %s (accessible to client scripts).", surface)

	case "candidate_key":
		exposureType = ExposureSensitiveCandidate
		sev = "LOW"
		conf = "LOW"
		rationale = fmt.Sprintf("Storage key %q matches sensitive naming convention in %s, but lacks verified credential format", key, surface)

	default:
		exposureType = ExposureDiscoveredStorage
		sev = "INFO"
		conf = "LOW"
		rationale = fmt.Sprintf("Storage entry in %s contains sensitive keywords", surface)
	}

	finding := &StorageExposureFinding{
		Surface:      surface,
		Origin:       origin,
		KeyName:      key,
		ExposureType: exposureType,
		Severity:     sev,
		Confidence:   conf,
		Rationale:    rationale,
		SecurityAttrs: map[string]any{
			"accessible_to_js": accessibleToJS,
			"value_length":     valLen,
		},
		Evidence:    fmt.Sprintf("Key=%q, Type=%s, Redacted=%s", key, detectedType, redactedPreview),
		Fingerprint: fingerprint,
		Remediation: "Avoid persisting sensitive credentials, session tokens, or private keys in client-accessible browser storage.",
	}

	return item, finding
}

var sensitiveKeyTokens = map[string]struct{}{
	"token":         {},
	"tokens":        {},
	"auth":          {},
	"jwt":           {},
	"secret":        {},
	"password":      {},
	"passwd":        {},
	"api_key":       {},
	"apikey":        {},
	"session":       {},
	"sessionid":     {},
	"session_id":    {},
	"access_token":  {},
	"refresh_token": {},
	"bearer":        {},
	"credential":    {},
	"credentials":   {},
	"private_key":   {},
}

var benignKeyTokens = map[string]struct{}{
	"request_id":     {},
	"req_id":         {},
	"trace_id":       {},
	"correlation_id": {},
	"client_uuid":    {},
	"device_id":      {},
	"device_uuid":    {},
	"anon_id":        {},
	"visitor_id":     {},
	"cart_id":        {},
	"item_id":        {},
	"transaction_id": {},
	"build_hash":     {},
	"asset_hash":     {},
	"cache_buster":   {},
	"checksum":       {},
	"version_hash":   {},
	"etag":           {},
}

var uuidRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isTestOrMockContext(key string) bool {
	lower := strings.ToLower(key)
	return strings.HasPrefix(lower, "mock_") ||
		strings.HasPrefix(lower, "test_") ||
		strings.HasPrefix(lower, "sample_") ||
		strings.HasPrefix(lower, "dummy_") ||
		strings.HasPrefix(lower, "example_") ||
		strings.Contains(lower, "placeholder")
}

func isSensitiveKeyName(key string) bool {
	norm := strings.ToLower(key)
	norm = strings.ReplaceAll(norm, "-", "_")
	norm = strings.ReplaceAll(norm, ".", "_")
	parts := strings.Split(norm, "_")
	for _, p := range parts {
		if _, ok := sensitiveKeyTokens[p]; ok {
			return true
		}
	}
	return false
}

func isExplicitBenignKeyName(key string) bool {
	norm := strings.ToLower(key)
	if _, ok := benignKeyTokens[norm]; ok {
		return true
	}
	norm = strings.ReplaceAll(norm, "-", "_")
	if _, ok := benignKeyTokens[norm]; ok {
		return true
	}
	return false
}

func (sa *StorageAuditor) detectSensitiveValue(key, val string) (bool, string) {
	trimmedVal := strings.TrimSpace(val)
	if len(trimmedVal) == 0 {
		return false, ""
	}

	// 1. Explicit benign identifier check (negative control protection for request IDs, device UUIDs, cache hashes)
	if isExplicitBenignKeyName(key) {
		return false, ""
	}

	// 2. UUID analysis
	if uuidRegex.MatchString(trimmedVal) {
		lowerKey := strings.ToLower(key)
		// If key strongly suggests a session ID, classify as candidate session UUID
		if strings.Contains(lowerKey, "session") || strings.Contains(lowerKey, "sid") {
			return true, "candidate_session_uuid"
		}
		// Generic or non-session UUID is an ordinary identifier, NOT a credential
		return false, ""
	}

	// 3. Check for standard 3-part JWT format: eyJ... . eyJ... . ...
	jwtParts := strings.Split(trimmedVal, ".")
	if len(jwtParts) == 3 && strings.HasPrefix(jwtParts[0], "eyJ") && strings.HasPrefix(jwtParts[1], "eyJ") {
		return true, "JWT"
	}

	// 4. Known API key / token prefixes
	knownPrefixes := []string{"sk-proj-", "sk-live-", "sk-test-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA", "AIzaSy"}
	for _, p := range knownPrefixes {
		if strings.Contains(trimmedVal, p) {
			if strings.Contains(trimmedVal, "AKIA") {
				return true, "aws_key"
			}
			return true, "api_token"
		}
	}

	// 5. Scan with FELIX secret detector
	if sa.detector != nil && len(trimmedVal) >= 16 {
		findings := sa.detector.ScanContent("browser_storage", []byte(trimmedVal))
		if len(findings) > 0 {
			return true, string(findings[0].Type)
		}
	}

	// 6. Heuristic: Key name is strongly sensitive and value has entropy/length
	lowerKey := strings.ToLower(key)
	if isSensitiveKeyName(key) || strings.Contains(lowerKey, "session") || strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "auth") || strings.Contains(lowerKey, "credential") {
		if len(trimmedVal) >= 16 && !strings.Contains(trimmedVal, " ") {
			return true, "session_token"
		}
		return true, "candidate_key"
	}

	return false, ""
}
