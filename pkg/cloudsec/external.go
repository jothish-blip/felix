package cloudsec

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// ExternalEvaluator assesses external cloud exposures and endpoint characteristics.
type ExternalEvaluator struct {
	config Config
}

// NewExternalEvaluator initializes an external cloud evaluator.
func NewExternalEvaluator(cfg Config) *ExternalEvaluator {
	return &ExternalEvaluator{config: cfg}
}

// Assess evaluates external targets for cloud provider attribution and exposure indicators.
func (ee *ExternalEvaluator) Assess(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, map[string]ServiceCoverage) {
	coverage := make(map[string]ServiceCoverage)
	var results []Result
	var findings []report.Finding

	// Initialize supported external service coverage buckets
	extServices := []struct {
		provider Provider
		service  string
	}{
		{ProviderAWS, "s3_external"},
		{ProviderAWS, "cloudfront_external"},
		{ProviderAWS, "apigateway_external"},
		{ProviderAWS, "lambda_external"},
		{ProviderAzure, "blob_external"},
		{ProviderAzure, "appservice_external"},
		{ProviderAzure, "frontdoor_external"},
		{ProviderGCP, "storage_external"},
		{ProviderGCP, "cloudrun_external"},
	}

	for _, es := range extServices {
		key := fmt.Sprintf("%s:%s", es.provider, es.service)
		coverage[key] = ServiceCoverage{
			Provider: es.provider,
			Service:  es.service,
			Status:   CoverageAssessed,
		}
	}

	for _, target := range actx.ExternalTargets {
		// Strict scope validation
		if actx.IsExcluded != nil && actx.IsExcluded(target.URL) {
			continue
		}
		if actx.IsAllowed != nil && !actx.IsAllowed(target.URL) {
			continue
		}

		u, err := url.Parse(target.URL)
		if err != nil {
			continue
		}

		host := strings.ToLower(u.Hostname())

		// 1. AWS External Checks
		ee.evalAWSS3(ctx, actx, client, target, u, host, &results, &findings, coverage)
		ee.evalAWSCloudFront(ctx, actx, client, target, u, host, &results, &findings, coverage)
		ee.evalAWSAPIGateway(ctx, actx, client, target, u, host, &results, &findings, coverage)
		ee.evalAWSLambdaURL(ctx, actx, client, target, u, host, &results, &findings, coverage)

		// 2. Azure External Checks
		ee.evalAzureBlob(ctx, actx, client, target, u, host, &results, &findings, coverage)
		ee.evalAzureAppService(ctx, actx, client, target, u, host, &results, &findings, coverage)
		ee.evalAzureFrontDoor(ctx, actx, client, target, u, host, &results, &findings, coverage)

		// 3. GCP External Checks
		ee.evalGCPStorage(ctx, actx, client, target, u, host, &results, &findings, coverage)
		ee.evalGCPCloudRun(ctx, actx, client, target, u, host, &results, &findings, coverage)
	}

	return results, findings, coverage
}

// -------------------------------------------------------------------------
// AWS External Probes
// -------------------------------------------------------------------------

func (ee *ExternalEvaluator) evalAWSS3(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AWS:s3_external"
	cov := coverage[key]

	isS3Host := strings.Contains(host, ".s3.") || strings.Contains(host, ".s3-") ||
		strings.HasSuffix(host, ".s3.amazonaws.com") || host == "s3.amazonaws.com"
	hasS3Header := false
	if serverHdr, ok := target.Headers["server"]; ok && strings.Contains(strings.ToLower(serverHdr), "amazons3") {
		hasS3Header = true
	}
	if _, ok := target.Headers["x-amz-request-id"]; ok {
		hasS3Header = true
	}

	if !isS3Host && !hasS3Header {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeExternal,
		Service:      "s3_external",
		CheckID:      "EXT-AWS-S3-ANON",
		CheckName:    "External S3 Storage Endpoint & Anonymous Exposure Check",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	// Safe bounded probe to check for anonymous bucket read exposure
	req, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	req.Header.Set("User-Agent", ee.config.UserAgent)
	resp, err := client.Do(req)

	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Target %s matches AWS S3 endpoint pattern; probe failed with network error: %v", target.URL, err)
		cov.Inconclusive++
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(body)

		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "<ListBucketResult") || strings.Contains(bodyStr, "<ListAllMyBucketsResult")) {
			// VERIFIED: Bucket is publicly readable without credentials
			r.VerificationState = StateVerified
			r.Severity = report.SeverityHigh
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Target %s exposes anonymous object listing (<ListBucketResult> returned on unauthenticated GET). Account-level configuration was not inspected.", target.URL)
			r.EvidenceDetails = map[string]string{
				"endpoint": target.URL,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"defect":   "ANONYMOUS_S3_BUCKET_LISTING",
			}
			fnd := createCloudFinding(actx, r, "Publicly Accessible AWS S3 Bucket Listing",
				r.EvidenceSummary, report.SeverityHigh, 85)
			r.Finding = fnd
			*findings = append(*findings, *fnd)
			cov.Verified++
		} else {
			// OBSERVED: S3 hosted, but anonymous listing is not exposed
			r.VerificationState = StateObserved
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Target %s is identified as AWS S3 storage infrastructure (HTTP %d). Anonymous listing was not permitted; account-level bucket policy not inspected.", target.URL, resp.StatusCode)
			cov.Observations++
		}
	}

	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

func (ee *ExternalEvaluator) evalAWSCloudFront(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AWS:cloudfront_external"
	cov := coverage[key]

	isCFHost := strings.HasSuffix(host, ".cloudfront.net")
	viaHdr := target.Headers["via"]
	serverHdr := target.Headers["server"]
	isCFHeader := strings.Contains(strings.ToLower(viaHdr), "cloudfront") ||
		strings.Contains(strings.ToLower(serverHdr), "cloudfront") ||
		strings.Contains(strings.ToLower(target.Headers["x-cache"]), "cloudfront")

	if !isCFHost && !isCFHeader {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeExternal,
		Service:      "cloudfront_external",
		CheckID:      "EXT-AWS-CLOUDFRONT-OBS",
		CheckName:    "External CloudFront Distribution Observation",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	r.VerificationState = StateObserved
	r.Severity = report.SeverityInfo
	r.Confidence = report.ConfidenceHigh
	r.EvidenceSummary = fmt.Sprintf("Target %s is delivered via AWS CloudFront CDN distribution. Private distribution configuration and Origin Access Controls were not inspected.", target.URL)
	cov.Observations++
	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

func (ee *ExternalEvaluator) evalAWSAPIGateway(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AWS:apigateway_external"
	cov := coverage[key]

	if !strings.Contains(host, ".execute-api.") || !strings.HasSuffix(host, ".amazonaws.com") {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeExternal,
		Service:      "apigateway_external",
		CheckID:      "EXT-AWS-APIGW-OBS",
		CheckName:    "External AWS API Gateway Endpoint Observation",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	r.VerificationState = StateObserved
	r.Severity = report.SeverityInfo
	r.Confidence = report.ConfidenceHigh
	r.EvidenceSummary = fmt.Sprintf("Target endpoint %s is hosted on AWS API Gateway. Authorizer, WAF, and resource policy configurations were not inspected.", target.URL)
	cov.Observations++
	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

func (ee *ExternalEvaluator) evalAWSLambdaURL(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AWS:lambda_external"
	cov := coverage[key]

	if !strings.Contains(host, ".lambda-url.") || !strings.HasSuffix(host, ".on.aws") {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeExternal,
		Service:      "lambda_external",
		CheckID:      "EXT-AWS-LAMBDA-URL",
		CheckName:    "External AWS Lambda Function URL Observation",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	r.VerificationState = StateObserved
	r.Severity = report.SeverityInfo
	r.Confidence = report.ConfidenceHigh
	r.EvidenceSummary = fmt.Sprintf("Target %s is an AWS Lambda Function URL endpoint. Function execution context and internal IAM configuration were not inspected.", target.URL)
	cov.Observations++
	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

// -------------------------------------------------------------------------
// Azure External Probes
// -------------------------------------------------------------------------

func (ee *ExternalEvaluator) evalAzureBlob(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AZURE:blob_external"
	cov := coverage[key]

	isBlobHost := strings.HasSuffix(host, ".blob.core.windows.net")
	hasAzureHeader := false
	if _, ok := target.Headers["x-ms-request-id"]; ok {
		hasAzureHeader = true
	}
	if serverHdr, ok := target.Headers["server"]; ok && strings.Contains(strings.ToLower(serverHdr), "windows-azure-blob") {
		hasAzureHeader = true
	}

	if !isBlobHost && !hasAzureHeader {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeExternal,
		Service:      "blob_external",
		CheckID:      "EXT-AZURE-BLOB-ANON",
		CheckName:    "External Azure Blob Storage Endpoint Check",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	req.Header.Set("User-Agent", ee.config.UserAgent)
	resp, err := client.Do(req)

	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Target %s matches Azure Blob Storage endpoint; probe failed with network error: %v", target.URL, err)
		cov.Inconclusive++
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(body)

		if resp.StatusCode == 200 && strings.Contains(bodyStr, "<EnumerationResults") {
			r.VerificationState = StateVerified
			r.Severity = report.SeverityHigh
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Target %s exposes anonymous container enumeration (<EnumerationResults> returned on unauthenticated GET). Storage account configuration was not inspected.", target.URL)
			r.EvidenceDetails = map[string]string{
				"endpoint": target.URL,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"defect":   "ANONYMOUS_BLOB_CONTAINER_ENUMERATION",
			}
			fnd := createCloudFinding(actx, r, "Publicly Accessible Azure Blob Container Listing",
				r.EvidenceSummary, report.SeverityHigh, 85)
			r.Finding = fnd
			*findings = append(*findings, *fnd)
			cov.Verified++
		} else {
			r.VerificationState = StateObserved
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Target %s is identified as Microsoft Azure Blob Storage (HTTP %d). Anonymous container listing was rejected; storage account settings not inspected.", target.URL, resp.StatusCode)
			cov.Observations++
		}
	}

	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

func (ee *ExternalEvaluator) evalAzureAppService(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AZURE:appservice_external"
	cov := coverage[key]

	if !strings.HasSuffix(host, ".azurewebsites.net") {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeExternal,
		Service:      "appservice_external",
		CheckID:      "EXT-AZURE-APPSERVICE-OBS",
		CheckName:    "External Azure App Service Observation",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	r.VerificationState = StateObserved
	r.Severity = report.SeverityInfo
	r.Confidence = report.ConfidenceHigh
	r.EvidenceSummary = fmt.Sprintf("Target endpoint %s is hosted on Microsoft Azure App Service. Private App Service plan, Key Vault references, and VNet integration were not inspected.", target.URL)
	cov.Observations++
	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

func (ee *ExternalEvaluator) evalAzureFrontDoor(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "AZURE:frontdoor_external"
	cov := coverage[key]

	isFDHost := strings.HasSuffix(host, ".azurefd.net")
	_, hasFDHeader := target.Headers["x-azure-ref"]

	if !isFDHost && !hasFDHeader {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeExternal,
		Service:      "frontdoor_external",
		CheckID:      "EXT-AZURE-FRONTDOOR-OBS",
		CheckName:    "External Azure Front Door Endpoint Observation",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	r.VerificationState = StateObserved
	r.Severity = report.SeverityInfo
	r.Confidence = report.ConfidenceHigh
	r.EvidenceSummary = fmt.Sprintf("Target %s is routed via Azure Front Door / CDN. Backend origin configuration and WAF policies were not inspected.", target.URL)
	cov.Observations++
	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

// -------------------------------------------------------------------------
// GCP External Probes
// -------------------------------------------------------------------------

func (ee *ExternalEvaluator) evalGCPStorage(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "GCP:storage_external"
	cov := coverage[key]

	isGCSHost := strings.HasSuffix(host, ".storage.googleapis.com") || host == "storage.googleapis.com"
	hasGCSHeader := false
	if _, ok := target.Headers["x-goog-generation"]; ok {
		hasGCSHeader = true
	}
	if serverHdr, ok := target.Headers["server"]; ok && strings.Contains(strings.ToLower(serverHdr), "gcs") {
		hasGCSHeader = true
	}

	if !isGCSHost && !hasGCSHeader {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderGCP,
		Mode:         ModeExternal,
		Service:      "storage_external",
		CheckID:      "EXT-GCP-GCS-ANON",
		CheckName:    "External Google Cloud Storage Endpoint Check",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	req.Header.Set("User-Agent", ee.config.UserAgent)
	resp, err := client.Do(req)

	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Target %s matches Google Cloud Storage endpoint; probe failed with network error: %v", target.URL, err)
		cov.Inconclusive++
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(body)

		if resp.StatusCode == 200 && strings.Contains(bodyStr, "<ListBucketResult") {
			r.VerificationState = StateVerified
			r.Severity = report.SeverityHigh
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Target %s exposes anonymous GCS object listing (<ListBucketResult> returned on unauthenticated GET). Project IAM bindings were not inspected.", target.URL)
			r.EvidenceDetails = map[string]string{
				"endpoint": target.URL,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"defect":   "ANONYMOUS_GCS_BUCKET_LISTING",
			}
			fnd := createCloudFinding(actx, r, "Publicly Accessible Google Cloud Storage Bucket Listing",
				r.EvidenceSummary, report.SeverityHigh, 85)
			r.Finding = fnd
			*findings = append(*findings, *fnd)
			cov.Verified++
		} else {
			r.VerificationState = StateObserved
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Target %s is identified as Google Cloud Storage (HTTP %d). Anonymous listing was rejected; project bucket policies not inspected.", target.URL, resp.StatusCode)
			cov.Observations++
		}
	}

	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

func (ee *ExternalEvaluator) evalGCPCloudRun(ctx context.Context, actx *AssessmentContext, client *http.Client, target ExternalTarget, u *url.URL, host string, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	key := "GCP:cloudrun_external"
	cov := coverage[key]

	if !strings.HasSuffix(host, ".run.app") {
		return
	}

	cov.ResourcesFound++
	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderGCP,
		Mode:         ModeExternal,
		Service:      "cloudrun_external",
		CheckID:      "EXT-GCP-CLOUDRUN-OBS",
		CheckName:    "External Google Cloud Run Endpoint Observation",
		ResourceID:   target.URL,
		CreatedAt:    time.Now().UTC(),
	}

	r.VerificationState = StateObserved
	r.Severity = report.SeverityInfo
	r.Confidence = report.ConfidenceHigh
	r.EvidenceSummary = fmt.Sprintf("Target endpoint %s is hosted on Google Cloud Run. Service IAM policy, VPC egress, and internal environment configuration were not inspected.", target.URL)
	cov.Observations++
	cov.ChecksRun++
	coverage[key] = cov
	*results = append(*results, r)
}

// -------------------------------------------------------------------------
// Helper: createCloudFinding
// -------------------------------------------------------------------------

func createCloudFinding(
	actx *AssessmentContext,
	r Result,
	title string,
	evidence string,
	severity string,
	score int,
) *report.Finding {
	sanitizedEndpoint := SanitizeURL(r.ResourceID)
	fpData := fmt.Sprintf("%s|%s|%s|%s", r.Provider, r.Service, r.CheckID, sanitizedEndpoint)
	hash := sha256.Sum256([]byte(fpData))
	fingerprint := fmt.Sprintf("cloudsec-%x", hash[:8])

	conf := r.Confidence
	if conf == "" {
		conf = report.ConfidenceHigh
	}

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    fmt.Sprintf("CLOUD_SECURITY / %s", r.Provider),
		Severity:    severity,
		Confidence:  conf,
		Target:      sanitizedEndpoint,
		Endpoint:    sanitizedEndpoint,
		Method:      "CLOUD_CHECK",
		Description: fmt.Sprintf("[%s / %s] %s", r.Provider, r.CheckID, r.CheckName),
		Evidence:    RedactText(evidence),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     RedactText(evidence),
			Location:        sanitizedEndpoint,
			DetectionMethod: "CLOUD_SECURITY_ENGINE",
			Details: map[string]string{
				"provider": string(r.Provider),
				"service":  r.Service,
				"mode":     string(r.Mode),
				"check_id": r.CheckID,
			},
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationStatus(r.VerificationState),
			Result:    string(r.VerificationState),
			Rationale: RedactText(evidence),
		},
		Source:      "cloud_security_engine",
		Fingerprint: fingerprint,
		Score:       score,
	}
}
