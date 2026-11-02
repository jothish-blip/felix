package cloudsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// -------------------------------------------------------------------------
// Storage Classification & Constants (Technical Roadmap Phase 5.2)
// -------------------------------------------------------------------------

// StorageClassification represents the verified posture of a cloud storage resource.
type StorageClassification string

const (
	StorageNotReachable            StorageClassification = "NOT_REACHABLE"
	StorageResourceNotFound        StorageClassification = "RESOURCE_NOT_FOUND"
	StorageAccessDenied            StorageClassification = "ACCESS_DENIED"
	StoragePublicObjectRead        StorageClassification = "PUBLIC_OBJECT_READ"
	StoragePublicContainerList     StorageClassification = "PUBLIC_CONTAINER_LIST"
	StoragePublicBucketList        StorageClassification = "PUBLIC_BUCKET_LIST"
	StoragePublicConfigExposed     StorageClassification = "PUBLIC_CONFIGURATION_EXPOSED"
	StorageAnonymousWriteIndicator StorageClassification = "ANONYMOUS_WRITE_INDICATOR"
	StorageAuthenticationRequired  StorageClassification = "AUTHENTICATION_REQUIRED"
	StorageInconclusive            StorageClassification = "INCONCLUSIVE"
)

// StorageResourceType identifies the specific cloud storage element.
type StorageResourceType string

const (
	StorageResourceBucket    StorageResourceType = "BUCKET"
	StorageResourceContainer StorageResourceType = "CONTAINER"
	StorageResourceObject    StorageResourceType = "OBJECT"
	StorageResourceBlob      StorageResourceType = "BLOB"
	StorageResourcePolicy    StorageResourceType = "POLICY"
)

const (
	DefaultStorageMaxResponseSize int64         = 1024 * 1024 // 1 MB limit
	DefaultStorageAuditTimeout    time.Duration = 10 * time.Second
	DefaultStorageUserAgent                     = "Felix-CloudSec-StorageAuditor/3.0"
)

// -------------------------------------------------------------------------
// URL Matching Expressions
// -------------------------------------------------------------------------

var (
	// AWS S3 patterns:
	// Virtual-hosted: bucket.s3.amazonaws.com, bucket.s3.us-east-1.amazonaws.com, bucket.s3-us-west-2.amazonaws.com
	reS3VirtualHost = regexp.MustCompile(`^([a-z0-9.\-]+)\.s3(?:[.\-]([a-z0-9\-]+))?\.amazonaws\.com$`)
	// Path-style: s3.amazonaws.com/bucket or s3.us-east-1.amazonaws.com/bucket
	reS3PathStyle = regexp.MustCompile(`^s3(?:[.\-]([a-z0-9\-]+))?\.amazonaws\.com$`)

	// GCS patterns:
	// bucket.storage.googleapis.com
	reGCSVirtualHost = regexp.MustCompile(`^([a-z0-9.\-_]+)\.storage\.googleapis\.com$`)
	// storage.googleapis.com/bucket or www.googleapis.com/storage/v1/b/bucket
	reGCSPathStyle = regexp.MustCompile(`^(?:www\.)?(?:storage\.googleapis\.com|googleapis\.com)$`)

	// Azure Blob pattern:
	// account.blob.core.windows.net
	reAzureBlob = regexp.MustCompile(`^([a-z0-9]+)\.blob\.core\.windows\.net$`)
)

// -------------------------------------------------------------------------
// Storage Target & Result Types
// -------------------------------------------------------------------------

// StorageTarget defines a parsed, normalized cloud storage resource to be audited.
type StorageTarget struct {
	Provider      Provider            `json:"provider"`
	ResourceType  StorageResourceType `json:"resource_type"`
	Account       string              `json:"account,omitempty"`       // Azure storage account or AWS account/region
	BucketName    string              `json:"bucket_name"`            // Bucket or container name
	ObjectKey     string              `json:"object_key,omitempty"`    // Optional specific object or blob key
	RawURL        string              `json:"raw_url"`                // Normalized evaluation URL
	Region        string              `json:"region,omitempty"`
	IsLoopback    bool                `json:"is_loopback"`
	CustomHeaders map[string]string   `json:"custom_headers,omitempty"`
}

// StorageAuditResult captures the complete, evidence-supported outcome of an audit.
type StorageAuditResult struct {
	ID                string                `json:"id"`
	Provider          Provider              `json:"provider"`
	ResourceType      StorageResourceType   `json:"resource_type"`
	ResourceID        string                `json:"resource_id"` // Bucket or container name
	TargetURL         string                `json:"target_url"`  // Redacted canonical URL
	Classification    StorageClassification `json:"classification"`
	HTTPStatus        int                   `json:"http_status"`
	CanList           bool                  `json:"can_list"`
	CanReadObject     bool                  `json:"can_read_object"`
	HasWriteIndicator bool                  `json:"has_write_indicator"`
	HasPublicPolicy   bool                  `json:"has_public_policy"`
	PublicAccessType  string                `json:"public_access_type,omitempty"` // "AllUsers", "allUsers", "container", "blob", etc.
	ObjectCount       int                   `json:"object_count,omitempty"`       // Count of objects listed (no content stored)
	ObjectSampleKey   string                `json:"object_sample_key,omitempty"`  // Sample key name only
	ObjectSHA256      string                `json:"object_sha256,omitempty"`      // SHA-256 of read object (no raw data)
	SafeHeaders       map[string]string     `json:"safe_headers,omitempty"`       // Non-sensitive server/request headers
	EvidenceSummary   string                `json:"evidence_summary"`
	Severity          string                `json:"severity"`
	Confidence        string                `json:"confidence"`
	Remediation       string                `json:"remediation,omitempty"`
	AuditDuration     time.Duration         `json:"audit_duration"`
	AuditTimestamp    time.Time             `json:"audit_timestamp"`
	Finding           *report.Finding       `json:"finding,omitempty"`
}

// StorageAuditorOptions configures the safe storage audit engine.
type StorageAuditorOptions struct {
	Client          *http.Client
	Transport       http.RoundTripper
	AllowLoopback   bool
	AllowPrivateIPs bool
	MaxResponseSize int64
	Timeout         time.Duration
	UserAgent       string
	ScopeCheck      func(urlStr string) bool
}

// StorageAuditor manages read-only verification of cloud storage misconfigurations.
type StorageAuditor struct {
	options StorageAuditorOptions
	client  *http.Client
}

// NewStorageAuditor constructs an authorized, network-bounded StorageAuditor.
func NewStorageAuditor(opts StorageAuditorOptions) *StorageAuditor {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultStorageAuditTimeout
	}
	if opts.MaxResponseSize <= 0 {
		opts.MaxResponseSize = DefaultStorageMaxResponseSize
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultStorageUserAgent
	}

	client := opts.Client
	if client == nil {
		transport := opts.Transport
		if transport == nil {
			safeOpts := crawler.SafeTransportOptions{
				Timeout:         opts.Timeout,
				AllowLoopback:   opts.AllowLoopback,
				AllowPrivateIPs: opts.AllowPrivateIPs,
			}
			transport = crawler.NewSafeTransport(safeOpts)
		}

		client = &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("storage audit: maximum redirect limit (5) exceeded")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("storage audit: redirect to unsupported scheme %q blocked", req.URL.Scheme)
				}
				if opts.ScopeCheck != nil && !opts.ScopeCheck(req.URL.String()) {
					return fmt.Errorf("storage audit: redirect to %s blocked by scope policy", req.URL.String())
				}
				if !opts.AllowLoopback && isLoopbackHost(req.URL.Hostname()) {
					return fmt.Errorf("storage audit: redirect to loopback address %s prohibited", req.URL.Hostname())
				}
				if isProhibitedMetadataHost(req.URL.Hostname()) {
					return fmt.Errorf("storage audit: redirect to cloud metadata service %s blocked by security policy", req.URL.Hostname())
				}
				return nil
			},
		}
	}

	return &StorageAuditor{
		options: opts,
		client:  client,
	}
}

// -------------------------------------------------------------------------
// URL Parsing & Normalization
// -------------------------------------------------------------------------

// ParseStorageURL inspects and normalizes rawURL into a structured StorageTarget.
func ParseStorageURL(rawURL string) (*StorageTarget, error) {
	cleanURL := strings.TrimSpace(rawURL)
	if cleanURL == "" {
		return nil, errors.New("empty storage URL")
	}

	// Default to https if scheme is missing
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "https://" + cleanURL
	}

	u, err := url.Parse(cleanURL)
	if err != nil {
		return nil, fmt.Errorf("invalid storage URL: %w", err)
	}

	// Redact embedded user credentials immediately
	if u.User != nil {
		u.User = nil
	}

	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.Path, "/")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) == 1 && pathSegments[0] == "" {
		pathSegments = nil
	}

	isLoopback := isLoopbackHost(host)

	// 1. AWS S3 Recognition
	// A. Virtual-hosted style: <bucket>.s3[.<region>].amazonaws.com
	if matches := reS3VirtualHost.FindStringSubmatch(host); len(matches) > 1 {
		bucket := matches[1]
		region := ""
		if len(matches) > 2 {
			region = matches[2]
		}
		key := strings.Join(pathSegments, "/")
		return &StorageTarget{
			Provider:     ProviderAWS,
			ResourceType: StorageResourceBucket,
			BucketName:   bucket,
			ObjectKey:    key,
			Region:       region,
			RawURL:       u.String(),
			IsLoopback:   isLoopback,
		}, nil
	}

	// B. Path style: s3[.<region>].amazonaws.com/<bucket>[/<key>]
	if matches := reS3PathStyle.FindStringSubmatch(host); len(matches) > 0 {
		region := ""
		if len(matches) > 1 {
			region = matches[1]
		}
		if len(pathSegments) == 0 {
			return nil, errors.New("S3 path-style URL missing bucket name in path")
		}
		bucket := pathSegments[0]
		key := strings.Join(pathSegments[1:], "/")
		return &StorageTarget{
			Provider:     ProviderAWS,
			ResourceType: StorageResourceBucket,
			BucketName:   bucket,
			ObjectKey:    key,
			Region:       region,
			RawURL:       u.String(),
			IsLoopback:   isLoopback,
		}, nil
	}

	// 2. Google Cloud Storage Recognition
	// A. Virtual-hosted style: <bucket>.storage.googleapis.com
	if matches := reGCSVirtualHost.FindStringSubmatch(host); len(matches) > 1 {
		bucket := matches[1]
		key := strings.Join(pathSegments, "/")
		return &StorageTarget{
			Provider:     ProviderGCP,
			ResourceType: StorageResourceBucket,
			BucketName:   bucket,
			ObjectKey:    key,
			RawURL:       u.String(),
			IsLoopback:   isLoopback,
		}, nil
	}

	// B. Path style: storage.googleapis.com/<bucket>[/<key>] or www.googleapis.com/storage/v1/b/<bucket>
	if reGCSPathStyle.MatchString(host) {
		if strings.HasPrefix(path, "storage/v1/b/") {
			parts := strings.Split(strings.TrimPrefix(path, "storage/v1/b/"), "/")
			bucket := parts[0]
			key := ""
			if len(parts) > 2 && parts[1] == "o" {
				key = strings.Join(parts[2:], "/")
			}
			return &StorageTarget{
				Provider:     ProviderGCP,
				ResourceType: StorageResourceBucket,
				BucketName:   bucket,
				ObjectKey:    key,
				RawURL:       u.String(),
				IsLoopback:   isLoopback,
			}, nil
		}
		if len(pathSegments) > 0 {
			bucket := pathSegments[0]
			key := strings.Join(pathSegments[1:], "/")
			return &StorageTarget{
				Provider:     ProviderGCP,
				ResourceType: StorageResourceBucket,
				BucketName:   bucket,
				ObjectKey:    key,
				RawURL:       u.String(),
				IsLoopback:   isLoopback,
			}, nil
		}
	}

	// 3. Azure Blob Storage Recognition
	// <account>.blob.core.windows.net/<container>[/<blob>]
	if matches := reAzureBlob.FindStringSubmatch(host); len(matches) > 1 {
		account := matches[1]
		if len(pathSegments) == 0 {
			return nil, errors.New("Azure Blob URL missing container name in path")
		}
		container := pathSegments[0]
		blob := strings.Join(pathSegments[1:], "/")
		return &StorageTarget{
			Provider:     ProviderAzure,
			ResourceType: StorageResourceContainer,
			Account:      account,
			BucketName:   container,
			ObjectKey:    blob,
			RawURL:       u.String(),
			IsLoopback:   isLoopback,
		}, nil
	}

	// 4. Local Loopback / Synthetic Fixture Recognition
	if isLoopback {
		// Detect provider hints in query, header, or path
		qProvider := strings.ToUpper(u.Query().Get("provider"))
		if qProvider == string(ProviderAWS) || strings.HasPrefix(path, "s3-") || strings.Contains(path, "/s3/") {
			bucket := "synthetic-s3"
			key := ""
			if len(pathSegments) > 0 {
				bucket = pathSegments[0]
				key = strings.Join(pathSegments[1:], "/")
			}
			return &StorageTarget{
				Provider:     ProviderAWS,
				ResourceType: StorageResourceBucket,
				BucketName:   bucket,
				ObjectKey:    key,
				RawURL:       u.String(),
				IsLoopback:   true,
			}, nil
		}
		if qProvider == string(ProviderGCP) || strings.HasPrefix(path, "gcs-") || strings.Contains(path, "/gcs/") || strings.Contains(path, "storage/v1/b/") {
			bucket := "synthetic-gcs"
			key := ""
			if len(pathSegments) > 0 {
				bucket = pathSegments[0]
				key = strings.Join(pathSegments[1:], "/")
			}
			return &StorageTarget{
				Provider:     ProviderGCP,
				ResourceType: StorageResourceBucket,
				BucketName:   bucket,
				ObjectKey:    key,
				RawURL:       u.String(),
				IsLoopback:   true,
			}, nil
		}
		if qProvider == string(ProviderAzure) || strings.HasPrefix(path, "azure-") || strings.Contains(path, "/azure/") || u.Query().Has("restype") {
			container := "synthetic-azure"
			blob := ""
			if len(pathSegments) > 0 {
				container = pathSegments[0]
				blob = strings.Join(pathSegments[1:], "/")
			}
			return &StorageTarget{
				Provider:     ProviderAzure,
				ResourceType: StorageResourceContainer,
				Account:      "syntheticaccount",
				BucketName:   container,
				ObjectKey:    blob,
				RawURL:       u.String(),
				IsLoopback:   true,
			}, nil
		}

		// Generic loopback fallback
		bucket := "synthetic-storage"
		if len(pathSegments) > 0 {
			bucket = pathSegments[0]
		}
		return &StorageTarget{
			Provider:     ProviderAWS, // Default to AWS mock handling
			ResourceType: StorageResourceBucket,
			BucketName:   bucket,
			RawURL:       u.String(),
			IsLoopback:   true,
		}, nil
	}

	return nil, fmt.Errorf("unrecognized cloud storage endpoint hostname %q", host)
}

// -------------------------------------------------------------------------
// Core Storage Auditor Methods
// -------------------------------------------------------------------------

// Audit evaluates a StorageTarget against cloud storage security misconfigurations.
func (a *StorageAuditor) Audit(ctx context.Context, target StorageTarget) (*StorageAuditResult, error) {
	// Scope check
	if a.options.ScopeCheck != nil && !a.options.ScopeCheck(target.RawURL) {
		return nil, fmt.Errorf("target URL %s rejected: outside declared authorized scope", target.RawURL)
	}

	// Loopback gate
	if target.IsLoopback && !a.options.AllowLoopback {
		return nil, fmt.Errorf("target %s rejected: loopback targets prohibited without explicit authorization", target.RawURL)
	}

	switch target.Provider {
	case ProviderAWS:
		return a.AuditS3(ctx, target)
	case ProviderGCP:
		return a.AuditGCS(ctx, target)
	case ProviderAzure:
		return a.AuditAzure(ctx, target)
	default:
		return nil, fmt.Errorf("unsupported cloud storage provider %q", target.Provider)
	}
}

// AuditURL parses rawURL and conducts an authorized, read-only misconfiguration audit.
func (a *StorageAuditor) AuditURL(ctx context.Context, rawURL string, testObjectKey string) (*StorageAuditResult, error) {
	target, err := ParseStorageURL(rawURL)
	if err != nil {
		return nil, err
	}
	if testObjectKey != "" && target.ObjectKey == "" {
		target.ObjectKey = testObjectKey
	}
	return a.Audit(ctx, *target)
}

// -------------------------------------------------------------------------
// Provider Audits: AWS S3
// -------------------------------------------------------------------------

// AuditS3 performs safe verification of public listing, public read, ACLs, and policy write indicators on AWS S3.
func (a *StorageAuditor) AuditS3(ctx context.Context, target StorageTarget) (*StorageAuditResult, error) {
	start := time.Now()
	res := &StorageAuditResult{
		ID:             uuid.New().String(),
		Provider:       ProviderAWS,
		ResourceType:   StorageResourceBucket,
		ResourceID:     target.BucketName,
		TargetURL:      sanitizeURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := buildS3BaseURL(target)

	// Step 1: Probe Bucket Root (Public Listing check)
	reqRoot, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating S3 root request: %w", err)
	}
	reqRoot.Header.Set("User-Agent", a.options.UserAgent)

	respRoot, err := a.client.Do(reqRoot)
	if err != nil {
		res.Classification = StorageNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to S3 endpoint failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respRoot.Body.Close()

	res.HTTPStatus = respRoot.StatusCode
	extractSafeHeaders(respRoot.Header, res.SafeHeaders)

	bodyRoot, _ := readLimitedBody(respRoot.Body, a.options.MaxResponseSize)

	// Evaluate Root Response
	switch respRoot.StatusCode {
	case http.StatusOK:
		// Check for S3 ListBucketResult XML
		if isS3ListingXML(bodyRoot) {
			res.CanList = true
			res.Classification = StoragePublicBucketList
			res.ObjectCount, res.ObjectSampleKey = parseS3ListKeys(bodyRoot)
			res.EvidenceSummary = fmt.Sprintf("Public bucket listing verified on AWS S3 bucket %q (%d object keys exposed)", target.BucketName, res.ObjectCount)
			res.Severity = "HIGH"
			res.Confidence = "CONFIRMED"
			res.Remediation = "Apply S3 Block Public Access to prevent anonymous ListBucket operations."
		} else if isHTMLResponse(respRoot.Header, bodyRoot) {
			// False-positive defense: Generic HTML 200 is not an S3 bucket
			res.Classification = StorageInconclusive
			res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML webpage; not an active AWS S3 storage API"
			res.Severity = "INFO"
			res.Confidence = "LOW"
		} else {
			res.Classification = StorageInconclusive
			res.EvidenceSummary = "Endpoint returned HTTP 200 without recognized S3 XML schema"
			res.Severity = "INFO"
			res.Confidence = "LOW"
		}

	case http.StatusForbidden:
		res.Classification = StorageAccessDenied
		res.EvidenceSummary = fmt.Sprintf("AWS S3 bucket %q exists but anonymous access is denied (403 Forbidden)", target.BucketName)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"

	case http.StatusNotFound:
		if isS3NotFoundXML(bodyRoot) {
			res.Classification = StorageResourceNotFound
			res.EvidenceSummary = fmt.Sprintf("AWS S3 bucket %q does not exist (404 NoSuchBucket)", target.BucketName)
			res.Severity = "INFO"
			res.Confidence = "CONFIRMED"
		} else {
			res.Classification = StorageResourceNotFound
			res.EvidenceSummary = fmt.Sprintf("Resource not found at %s", baseURL)
			res.Severity = "INFO"
			res.Confidence = "CONFIRMED"
		}

	default:
		res.Classification = StorageInconclusive
		res.EvidenceSummary = fmt.Sprintf("Unexpected HTTP status %d received from S3 endpoint", respRoot.StatusCode)
		res.Severity = "INFO"
		res.Confidence = "LOW"
	}

	// Step 2: Probe Object Read if object key specified or found in listing
	objKey := target.ObjectKey
	if objKey == "" && res.ObjectSampleKey != "" {
		objKey = res.ObjectSampleKey
	}

	if objKey != "" && res.Classification != StorageResourceNotFound {
		objURL := buildS3ObjectURL(baseURL, objKey)
		reqObj, errObj := http.NewRequestWithContext(ctx, http.MethodGet, objURL, nil)
		if errObj == nil {
			reqObj.Header.Set("User-Agent", a.options.UserAgent)
			respObj, errDo := a.client.Do(reqObj)
			if errDo == nil {
				defer respObj.Body.Close()
				if respObj.StatusCode == http.StatusOK {
					objBody, _ := readLimitedBody(respObj.Body, a.options.MaxResponseSize)
					if !isHTMLResponse(respObj.Header, objBody) && len(objBody) > 0 {
						res.CanReadObject = true
						h := sha256.Sum256(objBody)
						res.ObjectSHA256 = hex.EncodeToString(h[:])
						if res.Classification != StoragePublicBucketList {
							res.Classification = StoragePublicObjectRead
							res.EvidenceSummary = fmt.Sprintf("Public object read verified for key %q in AWS S3 bucket %q", objKey, target.BucketName)
							res.Severity = "MEDIUM"
							res.Confidence = "CONFIRMED"
							res.Remediation = "Remove public Read permissions from bucket objects or enable S3 Block Public Access."
						}
					}
				}
			}
		}
	}

	// Step 3: Probe Public ACL / Policy Write Indicators (Safe GET queries only)
	if res.Classification != StorageResourceNotFound && res.Classification != StorageNotReachable {
		a.auditS3PolicyAndACL(ctx, baseURL, target.BucketName, res)
	}

	res.AuditDuration = time.Since(start)
	res.Finding = res.ToFinding(target.RawURL)
	return res, nil
}

// auditS3PolicyAndACL checks for anonymous public ACL grants or public bucket policy write permissions.
func (a *StorageAuditor) auditS3PolicyAndACL(ctx context.Context, baseURL string, bucketName string, res *StorageAuditResult) {
	// A. Check ?acl
	aclURL := strings.TrimRight(baseURL, "/") + "/?acl"
	reqACL, err := http.NewRequestWithContext(ctx, http.MethodGet, aclURL, nil)
	if err == nil {
		reqACL.Header.Set("User-Agent", a.options.UserAgent)
		if respACL, errACL := a.client.Do(reqACL); errACL == nil {
			defer respACL.Body.Close()
			if respACL.StatusCode == http.StatusOK {
				bodyACL, _ := readLimitedBody(respACL.Body, a.options.MaxResponseSize)
				strACL := string(bodyACL)
				if strings.Contains(strACL, "AllUsers") || strings.Contains(strACL, "AuthenticatedUsers") {
					res.HasPublicPolicy = true
					if strings.Contains(strACL, "<Permission>WRITE</Permission>") || strings.Contains(strACL, "<Permission>FULL_CONTROL</Permission>") {
						res.HasWriteIndicator = true
						res.Classification = StorageAnonymousWriteIndicator
						res.PublicAccessType = "AllUsers:WRITE"
						res.EvidenceSummary = fmt.Sprintf("Anonymous WRITE permission detected in ACL of S3 bucket %q", bucketName)
						res.Severity = "CRITICAL"
						res.Confidence = "HIGH"
						res.Remediation = "Remove WRITE grants to AllUsers/AuthenticatedUsers from S3 bucket ACL immediately."
						return
					}
					if res.Classification != StoragePublicBucketList && res.Classification != StoragePublicObjectRead {
						res.Classification = StoragePublicConfigExposed
						res.PublicAccessType = "AllUsers:READ"
						res.EvidenceSummary = fmt.Sprintf("Public READ ACL detected on S3 bucket %q", bucketName)
						res.Severity = "LOW"
						res.Confidence = "HIGH"
					}
				}
			}
		}
	}

	// B. Check ?policy
	policyURL := strings.TrimRight(baseURL, "/") + "/?policy"
	reqPol, errPol := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if errPol == nil {
		reqPol.Header.Set("User-Agent", a.options.UserAgent)
		if respPol, errDo := a.client.Do(reqPol); errDo == nil {
			defer respPol.Body.Close()
			if respPol.StatusCode == http.StatusOK {
				bodyPol, _ := readLimitedBody(respPol.Body, a.options.MaxResponseSize)
				var polDoc struct {
					Statement []struct {
						Effect    string `json:"Effect"`
						Principal any    `json:"Principal"`
						Action    any    `json:"Action"`
					} `json:"Statement"`
				}
				if json.Unmarshal(bodyPol, &polDoc) == nil {
					for _, stmt := range polDoc.Statement {
						if strings.EqualFold(stmt.Effect, "Allow") && isWildcardPrincipal(stmt.Principal) {
							res.HasPublicPolicy = true
							if containsWriteActions(stmt.Action) {
								res.HasWriteIndicator = true
								res.Classification = StorageAnonymousWriteIndicator
								res.PublicAccessType = "Policy:PublicWrite"
								res.EvidenceSummary = fmt.Sprintf("Public write policy indicator confirmed on S3 bucket %q", bucketName)
								res.Severity = "CRITICAL"
								res.Confidence = "HIGH"
								res.Remediation = "Revoke public PutObject/DeleteObject actions from S3 bucket policy."
								return
							}
							if res.Classification != StoragePublicBucketList && res.Classification != StoragePublicObjectRead {
								res.Classification = StoragePublicConfigExposed
								res.PublicAccessType = "Policy:PublicRead"
								res.EvidenceSummary = fmt.Sprintf("Publicly accessible bucket policy discovered on S3 bucket %q", bucketName)
								res.Severity = "LOW"
								res.Confidence = "HIGH"
							}
						}
					}
				}
			}
		}
	}
}

// -------------------------------------------------------------------------
// Provider Audits: Google Cloud Storage (GCS)
// -------------------------------------------------------------------------

// AuditGCS verifies public listing, public object read, allUsers IAM policies, and write indicators on GCS.
func (a *StorageAuditor) AuditGCS(ctx context.Context, target StorageTarget) (*StorageAuditResult, error) {
	start := time.Now()
	res := &StorageAuditResult{
		ID:             uuid.New().String(),
		Provider:       ProviderGCP,
		ResourceType:   StorageResourceBucket,
		ResourceID:     target.BucketName,
		TargetURL:      sanitizeURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := buildGCSBaseURL(target)

	// Step 1: Probe Bucket Listing
	reqRoot, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating GCS request: %w", err)
	}
	reqRoot.Header.Set("User-Agent", a.options.UserAgent)

	respRoot, err := a.client.Do(reqRoot)
	if err != nil {
		res.Classification = StorageNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to GCS endpoint failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respRoot.Body.Close()

	res.HTTPStatus = respRoot.StatusCode
	extractSafeHeaders(respRoot.Header, res.SafeHeaders)

	bodyRoot, _ := readLimitedBody(respRoot.Body, a.options.MaxResponseSize)

	switch respRoot.StatusCode {
	case http.StatusOK:
		if isGCSListing(bodyRoot) {
			res.CanList = true
			res.Classification = StoragePublicBucketList
			res.ObjectCount, res.ObjectSampleKey = parseGCSListKeys(bodyRoot)
			res.EvidenceSummary = fmt.Sprintf("Public object listing verified on Google Cloud Storage bucket %q (%d objects listed)", target.BucketName, res.ObjectCount)
			res.Severity = "HIGH"
			res.Confidence = "CONFIRMED"
			res.Remediation = "Enable public access prevention on GCS bucket and audit IAM bindings."
		} else if isHTMLResponse(respRoot.Header, bodyRoot) {
			res.Classification = StorageInconclusive
			res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML web response; not a valid GCS API"
			res.Severity = "INFO"
			res.Confidence = "LOW"
		} else {
			res.Classification = StorageInconclusive
			res.EvidenceSummary = "Endpoint returned HTTP 200 without recognized GCS object schema"
			res.Severity = "INFO"
			res.Confidence = "LOW"
		}

	case http.StatusForbidden:
		res.Classification = StorageAccessDenied
		res.EvidenceSummary = fmt.Sprintf("Google Cloud Storage bucket %q exists but access is denied (403 Forbidden)", target.BucketName)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"

	case http.StatusNotFound:
		res.Classification = StorageResourceNotFound
		res.EvidenceSummary = fmt.Sprintf("Google Cloud Storage bucket %q does not exist (404 Not Found)", target.BucketName)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"

	case http.StatusUnauthorized:
		res.Classification = StorageAuthenticationRequired
		res.EvidenceSummary = fmt.Sprintf("Authentication required for GCS bucket %q (401 Unauthorized)", target.BucketName)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"

	default:
		res.Classification = StorageInconclusive
		res.EvidenceSummary = fmt.Sprintf("Unexpected HTTP status %d received from GCS endpoint", respRoot.StatusCode)
		res.Severity = "INFO"
		res.Confidence = "LOW"
	}

	// Step 2: Probe Object Read if object key specified or found in listing
	objKey := target.ObjectKey
	if objKey == "" && res.ObjectSampleKey != "" {
		objKey = res.ObjectSampleKey
	}

	if objKey != "" && res.Classification != StorageResourceNotFound {
		objURL := buildGCSObjectURL(baseURL, objKey)
		reqObj, errObj := http.NewRequestWithContext(ctx, http.MethodGet, objURL, nil)
		if errObj == nil {
			reqObj.Header.Set("User-Agent", a.options.UserAgent)
			respObj, errDo := a.client.Do(reqObj)
			if errDo == nil {
				defer respObj.Body.Close()
				if respObj.StatusCode == http.StatusOK {
					objBody, _ := readLimitedBody(respObj.Body, a.options.MaxResponseSize)
					if !isHTMLResponse(respObj.Header, objBody) && len(objBody) > 0 {
						res.CanReadObject = true
						h := sha256.Sum256(objBody)
						res.ObjectSHA256 = hex.EncodeToString(h[:])
						if res.Classification != StoragePublicBucketList {
							res.Classification = StoragePublicObjectRead
							res.EvidenceSummary = fmt.Sprintf("Public object read verified for key %q in GCS bucket %q", objKey, target.BucketName)
							res.Severity = "MEDIUM"
							res.Confidence = "CONFIRMED"
							res.Remediation = "Remove allUsers/allAuthenticatedUsers from GCS object ACLs or enable uniform bucket-level access."
						}
					}
				}
			}
		}
	}

	// Step 3: Probe Public IAM Policy (Safe read-only check)
	if res.Classification != StorageResourceNotFound && res.Classification != StorageNotReachable {
		a.auditGCSIAMPolicy(ctx, baseURL, target.BucketName, res)
	}

	res.AuditDuration = time.Since(start)
	res.Finding = res.ToFinding(target.RawURL)
	return res, nil
}

// auditGCSIAMPolicy checks for allUsers or allAuthenticatedUsers in GCS IAM bindings.
func (a *StorageAuditor) auditGCSIAMPolicy(ctx context.Context, baseURL string, bucketName string, res *StorageAuditResult) {
	iamURL := strings.TrimRight(baseURL, "/") + "/?iam"
	reqIAM, err := http.NewRequestWithContext(ctx, http.MethodGet, iamURL, nil)
	if err == nil {
		reqIAM.Header.Set("User-Agent", a.options.UserAgent)
		if respIAM, errDo := a.client.Do(reqIAM); errDo == nil {
			defer respIAM.Body.Close()
			if respIAM.StatusCode == http.StatusOK {
				bodyIAM, _ := readLimitedBody(respIAM.Body, a.options.MaxResponseSize)
				var doc struct {
					Bindings []struct {
						Role    string   `json:"role"`
						Members []string `json:"members"`
					} `json:"bindings"`
				}
				if json.Unmarshal(bodyIAM, &doc) == nil {
					for _, b := range doc.Bindings {
						for _, m := range b.Members {
							if m == "allUsers" || m == "allAuthenticatedUsers" {
								res.HasPublicPolicy = true
								res.PublicAccessType = m
								roleLower := strings.ToLower(b.Role)
								if strings.Contains(roleLower, "admin") || strings.Contains(roleLower, "writer") || strings.Contains(roleLower, "creator") {
									res.HasWriteIndicator = true
									res.Classification = StorageAnonymousWriteIndicator
									res.EvidenceSummary = fmt.Sprintf("Public write IAM binding %q granted to %s on GCS bucket %q", b.Role, m, bucketName)
									res.Severity = "CRITICAL"
									res.Confidence = "HIGH"
									res.Remediation = "Remove write/admin roles from allUsers/allAuthenticatedUsers on GCS bucket."
									return
								}
								if res.Classification != StoragePublicBucketList && res.Classification != StoragePublicObjectRead {
									res.Classification = StoragePublicConfigExposed
									res.EvidenceSummary = fmt.Sprintf("Public read IAM binding %q granted to %s on GCS bucket %q", b.Role, m, bucketName)
									res.Severity = "LOW"
									res.Confidence = "HIGH"
								}
							}
						}
					}
				}
			}
		}
	}
}

// -------------------------------------------------------------------------
// Provider Audits: Azure Blob Storage
// -------------------------------------------------------------------------

// AuditAzure verifies anonymous container listing, blob reads, and public-access configuration on Azure.
func (a *StorageAuditor) AuditAzure(ctx context.Context, target StorageTarget) (*StorageAuditResult, error) {
	start := time.Now()
	res := &StorageAuditResult{
		ID:             uuid.New().String(),
		Provider:       ProviderAzure,
		ResourceType:   StorageResourceContainer,
		ResourceID:     target.BucketName,
		TargetURL:      sanitizeURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	containerURL := buildAzureContainerURL(target)

	// Step 1: Probe Container Listing (?restype=container&comp=list)
	listURL := strings.TrimRight(containerURL, "/") + "?restype=container&comp=list"
	reqList, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating Azure list request: %w", err)
	}
	reqList.Header.Set("User-Agent", a.options.UserAgent)
	reqList.Header.Set("x-ms-version", "2021-08-06")

	respList, err := a.client.Do(reqList)
	if err != nil {
		res.Classification = StorageNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to Azure Blob endpoint failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respList.Body.Close()

	res.HTTPStatus = respList.StatusCode
	extractSafeHeaders(respList.Header, res.SafeHeaders)

	bodyList, _ := readLimitedBody(respList.Body, a.options.MaxResponseSize)

	switch respList.StatusCode {
	case http.StatusOK:
		if isAzureListingXML(bodyList) {
			res.CanList = true
			res.Classification = StoragePublicContainerList
			res.ObjectCount, res.ObjectSampleKey = parseAzureListBlobs(bodyList)
			res.EvidenceSummary = fmt.Sprintf("Public container listing verified on Azure Blob container %q (%d blobs listed)", target.BucketName, res.ObjectCount)
			res.Severity = "HIGH"
			res.Confidence = "CONFIRMED"
			res.Remediation = "Set container public access level to Private (no anonymous access) in Azure Storage Account."
		} else if isHTMLResponse(respList.Header, bodyList) {
			res.Classification = StorageInconclusive
			res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML web response; not a valid Azure Blob API"
			res.Severity = "INFO"
			res.Confidence = "LOW"
		} else {
			res.Classification = StorageInconclusive
			res.EvidenceSummary = "Endpoint returned HTTP 200 without recognized Azure Blob XML schema"
			res.Severity = "INFO"
			res.Confidence = "LOW"
		}

	case http.StatusForbidden:
		res.Classification = StorageAccessDenied
		res.EvidenceSummary = fmt.Sprintf("Azure Blob container %q exists but anonymous listing is rejected (403 AuthorizationFailure)", target.BucketName)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"

	case http.StatusNotFound:
		res.Classification = StorageResourceNotFound
		res.EvidenceSummary = fmt.Sprintf("Azure Blob container %q does not exist (404 ContainerNotFound)", target.BucketName)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"

	default:
		res.Classification = StorageInconclusive
		res.EvidenceSummary = fmt.Sprintf("Unexpected HTTP status %d received from Azure Blob endpoint", respList.StatusCode)
		res.Severity = "INFO"
		res.Confidence = "LOW"
	}

	// Step 2: Probe Container Public-Access Configuration Header (?restype=container)
	reqConfig, errConfig := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(containerURL, "/")+"?restype=container", nil)
	if errConfig == nil {
		reqConfig.Header.Set("User-Agent", a.options.UserAgent)
		reqConfig.Header.Set("x-ms-version", "2021-08-06")
		if respConfig, errDo := a.client.Do(reqConfig); errDo == nil {
			defer respConfig.Body.Close()
			extractSafeHeaders(respConfig.Header, res.SafeHeaders)
			pubAccess := strings.ToLower(respConfig.Header.Get("x-ms-blob-public-access"))
			if pubAccess == "container" || pubAccess == "blob" {
				res.HasPublicPolicy = true
				res.PublicAccessType = pubAccess
				if res.Classification != StoragePublicContainerList {
					res.Classification = StoragePublicConfigExposed
					res.EvidenceSummary = fmt.Sprintf("Azure container %q public access level configured to %q", target.BucketName, pubAccess)
					res.Severity = "LOW"
					res.Confidence = "HIGH"
					res.Remediation = "Disable public blob access on storage account or set container level to private."
				}
			}
		}
	}

	// Step 3: Probe Blob Read if blob key specified or found in container listing
	blobKey := target.ObjectKey
	if blobKey == "" && res.ObjectSampleKey != "" {
		blobKey = res.ObjectSampleKey
	}

	if blobKey != "" && res.Classification != StorageResourceNotFound {
		blobURL := strings.TrimRight(containerURL, "/") + "/" + strings.TrimLeft(blobKey, "/")
		reqBlob, errBlob := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
		if errBlob == nil {
			reqBlob.Header.Set("User-Agent", a.options.UserAgent)
			reqBlob.Header.Set("x-ms-version", "2021-08-06")
			if respBlob, errDo := a.client.Do(reqBlob); errDo == nil {
				defer respBlob.Body.Close()
				if respBlob.StatusCode == http.StatusOK {
					blobBody, _ := readLimitedBody(respBlob.Body, a.options.MaxResponseSize)
					if !isHTMLResponse(respBlob.Header, blobBody) && len(blobBody) > 0 {
						res.CanReadObject = true
						h := sha256.Sum256(blobBody)
						res.ObjectSHA256 = hex.EncodeToString(h[:])
						if res.Classification != StoragePublicContainerList {
							res.Classification = StoragePublicObjectRead
							res.EvidenceSummary = fmt.Sprintf("Anonymous blob read verified for blob %q in Azure container %q", blobKey, target.BucketName)
							res.Severity = "MEDIUM"
							res.Confidence = "CONFIRMED"
							res.Remediation = "Set Azure container access level to private."
						}
					}
				}
			}
		}
	}

	res.AuditDuration = time.Since(start)
	res.Finding = res.ToFinding(target.RawURL)
	return res, nil
}

// -------------------------------------------------------------------------
// Batch Concurrency & Worker Pool
// -------------------------------------------------------------------------

// AuditBatch executes bounded concurrent audits across multiple storage targets.
func (a *StorageAuditor) AuditBatch(ctx context.Context, targets []StorageTarget, maxConcurrency int) ([]StorageAuditResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}

	results := make([]StorageAuditResult, len(targets))
	errCh := make(chan error, len(targets))
	targetCh := make(chan int, len(targets))

	var wg sync.WaitGroup
	workers := maxConcurrency
	if workers > len(targets) {
		workers = len(targets)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range targetCh {
				select {
				case <-ctx.Done():
					return
				default:
					res, err := a.Audit(ctx, targets[idx])
					if err != nil {
						errCh <- fmt.Errorf("audit target %s: %w", targets[idx].RawURL, err)
						continue
					}
					if res != nil {
						results[idx] = *res
					}
				}
			}
		}()
	}

	for i := range targets {
		targetCh <- i
	}
	close(targetCh)

	wg.Wait()
	close(errCh)

	// Collect any fatal errors
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}

	return results, firstErr
}

// -------------------------------------------------------------------------
// Finding Integration
// -------------------------------------------------------------------------

// ToFinding converts a StorageAuditResult into a standardized FELIX report.Finding.
func (r *StorageAuditResult) ToFinding(targetURL string) *report.Finding {
	if r.Classification == StorageNotReachable || r.Classification == StorageResourceNotFound || r.Classification == StorageAccessDenied || r.Classification == StorageInconclusive {
		return nil
	}

	findingID := computeDeterministicFindingID(string(r.Provider), r.ResourceID, string(r.Classification))
	title := fmt.Sprintf("[%s] %s Misconfiguration: %s", r.Provider, r.ResourceType, r.Classification)
	switch r.Classification {
	case StoragePublicBucketList, StoragePublicContainerList:
		title = fmt.Sprintf("[%s] Public %s Listing Discovered (%s)", r.Provider, r.ResourceType, r.ResourceID)
	case StoragePublicObjectRead:
		title = fmt.Sprintf("[%s] Anonymous %s Read Exposure Verified (%s)", r.Provider, r.ResourceType, r.ResourceID)
	case StorageAnonymousWriteIndicator:
		title = fmt.Sprintf("[%s] Critical Anonymous Write Exposure Indicator (%s)", r.Provider, r.ResourceID)
	case StoragePublicConfigExposed:
		title = fmt.Sprintf("[%s] Public Configuration Exposed (%s)", r.Provider, r.ResourceID)
	}

	details := map[string]string{
		"provider":            string(r.Provider),
		"resource_type":       string(r.ResourceType),
		"resource_id":         r.ResourceID,
		"classification":      string(r.Classification),
		"can_list":            fmt.Sprintf("%t", r.CanList),
		"can_read_object":     fmt.Sprintf("%t", r.CanReadObject),
		"has_write_indicator": fmt.Sprintf("%t", r.HasWriteIndicator),
		"has_public_policy":   fmt.Sprintf("%t", r.HasPublicPolicy),
		"public_access_type":  r.PublicAccessType,
		"object_count":        fmt.Sprintf("%d", r.ObjectCount),
		"object_sample_key":   r.ObjectSampleKey,
		"object_sha256":       r.ObjectSHA256,
		"http_status":         fmt.Sprintf("%d", r.HTTPStatus),
		"audit_duration_ms":   fmt.Sprintf("%.2f", float64(r.AuditDuration.Nanoseconds())/1e6),
	}

	sanitizedTarget := sanitizeURL(targetURL)

	f := &report.Finding{
		ID:          findingID,
		Title:       title,
		Description: r.EvidenceSummary,
		Severity:    r.Severity,
		Confidence:  r.Confidence,
		Category:    "CloudSec / Public Cloud Storage Exposure",
		Remediation: r.Remediation,
		Timestamp:   r.AuditTimestamp,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedTarget,
		Method:      "STORAGE_AUDIT",
		Evidence:    r.EvidenceSummary,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     r.EvidenceSummary,
			Location:        sanitizedTarget,
			DetectionMethod: "CLOUD_STORAGE_AUDITOR",
			Details:         details,
		},
	}
	return f
}

// -------------------------------------------------------------------------
// Helper & Validation Functions
// -------------------------------------------------------------------------

func readLimitedBody(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultStorageMaxResponseSize
	}
	return io.ReadAll(io.LimitReader(r, limit))
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

func extractSafeHeaders(src http.Header, dst map[string]string) {
	for k, v := range src {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "x-amz-") || strings.HasPrefix(lower, "x-goog-") || strings.HasPrefix(lower, "x-ms-") || lower == "server" || lower == "content-type" || lower == "etag" {
			dst[k] = strings.Join(v, ", ")
		}
	}
}

func isHTMLResponse(headers http.Header, body []byte) bool {
	ct := strings.ToLower(headers.Get("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return true
	}
	preview := strings.ToLower(string(body[:minInt(len(body), 512)]))
	return strings.Contains(preview, "<!doctype html") || strings.Contains(preview, "<html") || strings.Contains(preview, "<head>")
}

func isS3ListingXML(body []byte) bool {
	str := string(body)
	return strings.Contains(str, "<ListBucketResult") && (strings.Contains(str, "http://s3.amazonaws.com/doc/2006-03-01/") || strings.Contains(str, "<Contents>") || strings.Contains(str, "<Name>"))
}

func isS3NotFoundXML(body []byte) bool {
	str := string(body)
	return strings.Contains(str, "<Code>NoSuchBucket</Code>") || strings.Contains(str, "<Code>NoSuchKey</Code>")
}

func isGCSListing(body []byte) bool {
	str := string(body)
	if strings.Contains(str, "<ListBucketResult") {
		return true
	}
	var doc struct {
		Kind  string `json:"kind"`
		Items any    `json:"items"`
	}
	if json.Unmarshal(body, &doc) == nil {
		return doc.Kind == "storage#objects" || doc.Items != nil
	}
	return false
}

func isAzureListingXML(body []byte) bool {
	str := string(body)
	return strings.Contains(str, "<EnumerationResults") && strings.Contains(str, "<Blobs>")
}

func parseS3ListKeys(body []byte) (int, string) {
	type ContentItem struct {
		Key string `xml:"Key"`
	}
	type ListResult struct {
		Contents []ContentItem `xml:"Contents"`
	}
	var doc ListResult
	_ = xml.Unmarshal(body, &doc)
	sample := ""
	if len(doc.Contents) > 0 {
		sample = doc.Contents[0].Key
	}
	return len(doc.Contents), sample
}

func parseGCSListKeys(body []byte) (int, string) {
	// XML check
	type ContentItem struct {
		Key string `xml:"Key"`
	}
	type ListResult struct {
		Contents []ContentItem `xml:"Contents"`
	}
	var xmlDoc ListResult
	if xml.Unmarshal(body, &xmlDoc) == nil && len(xmlDoc.Contents) > 0 {
		return len(xmlDoc.Contents), xmlDoc.Contents[0].Key
	}

	// JSON check
	var jsonDoc struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &jsonDoc) == nil && len(jsonDoc.Items) > 0 {
		return len(jsonDoc.Items), jsonDoc.Items[0].Name
	}
	return 0, ""
}

func parseAzureListBlobs(body []byte) (int, string) {
	type BlobItem struct {
		Name string `xml:"Name"`
	}
	type ResultDoc struct {
		Blobs struct {
			Blob []BlobItem `xml:"Blob"`
		} `xml:"Blobs"`
	}
	var doc ResultDoc
	_ = xml.Unmarshal(body, &doc)
	sample := ""
	if len(doc.Blobs.Blob) > 0 {
		sample = doc.Blobs.Blob[0].Name
	}
	return len(doc.Blobs.Blob), sample
}

func isWildcardPrincipal(p any) bool {
	if s, ok := p.(string); ok {
		return s == "*"
	}
	if m, ok := p.(map[string]any); ok {
		if awsP, exists := m["AWS"]; exists {
			if s, ok := awsP.(string); ok && s == "*" {
				return true
			}
			if list, ok := awsP.([]any); ok {
				for _, item := range list {
					if s, ok := item.(string); ok && s == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func containsWriteActions(a any) bool {
	writeActions := []string{"s3:putobject", "s3:deleteobject", "s3:putobjectacl", "s3:*"}
	checkStr := func(act string) bool {
		lower := strings.ToLower(act)
		for _, w := range writeActions {
			if lower == w {
				return true
			}
		}
		return false
	}

	if s, ok := a.(string); ok {
		return checkStr(s)
	}
	if list, ok := a.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok && checkStr(s) {
				return true
			}
		}
	}
	return false
}

func buildS3BaseURL(t StorageTarget) string {
	u, err := url.Parse(t.RawURL)
	if err != nil {
		return t.RawURL
	}
	if t.IsLoopback {
		// Preserve loopback host/path
		return fmt.Sprintf("http://%s/%s/", u.Host, t.BucketName)
	}
	if t.Region != "" {
		return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", t.BucketName, t.Region)
	}
	return fmt.Sprintf("https://%s.s3.amazonaws.com/", t.BucketName)
}

func buildS3ObjectURL(baseURL, key string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(key, "/")
}

func buildGCSBaseURL(t StorageTarget) string {
	u, err := url.Parse(t.RawURL)
	if err != nil {
		return t.RawURL
	}
	if t.IsLoopback {
		return fmt.Sprintf("http://%s/%s/", u.Host, t.BucketName)
	}
	return fmt.Sprintf("https://storage.googleapis.com/%s/", t.BucketName)
}

func buildGCSObjectURL(baseURL, key string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(key, "/")
}

func buildAzureContainerURL(t StorageTarget) string {
	u, err := url.Parse(t.RawURL)
	if err != nil {
		return t.RawURL
	}
	if t.IsLoopback {
		return fmt.Sprintf("http://%s/%s", u.Host, t.BucketName)
	}
	return fmt.Sprintf("https://%s.blob.core.windows.net/%s", t.Account, t.BucketName)
}

func computeDeterministicFindingID(provider, resource, classification string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", provider, resource, classification)))
	return hex.EncodeToString(h[:16])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
