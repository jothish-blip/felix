package cloudsec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"felix/pkg/report"
)

// 1. Test External Mode: S3 Anonymous Bucket Read Probe
func TestCloudSec_External_S3(t *testing.T) {
	// Vulnerable S3 Bucket: Returns public object listing
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("x-amz-request-id", "REQ-12345")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>my-public-bucket</Name></ListBucketResult>`)
	}))
	defer vulnServer.Close()

	// Safe S3 Bucket: Rejects unauthenticated listing with 403 Access Denied
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("x-amz-request-id", "REQ-67890")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>`)
	}))
	defer safeServer.Close()

	engine := NewEngine(DefaultConfig())

	// Positive Control: Anonymous Listing Exposed -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-ext-s3-vuln",
		Mode:         ModeExternal,
		Provider:     ProviderAWS,
		ExternalTargets: []ExternalTarget{
			{
				URL:      vulnServer.URL + "/assets",
				Hostname: "my-public-bucket.s3.amazonaws.com",
				Headers:  map[string]string{"server": "AmazonS3", "x-amz-request-id": "REQ-12345"},
			},
		},
	}
	resultsVuln, findingsVuln, summaryVuln, err := engine.Assess(context.Background(), actxVuln)
	if err != nil {
		t.Fatalf("unexpected assessment error: %v", err)
	}
	if summaryVuln.VerifiedCount != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified anonymous S3 exposure, got %d (findings: %d)", summaryVuln.VerifiedCount, len(findingsVuln))
	}
	if resultsVuln[0].VerificationState != StateVerified {
		t.Errorf("expected StateVerified, got %s", resultsVuln[0].VerificationState)
	}

	// Negative Control: 403 Forbidden -> OBSERVED (not marked vulnerable)
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-ext-s3-safe",
		Mode:         ModeExternal,
		Provider:     ProviderAWS,
		ExternalTargets: []ExternalTarget{
			{
				URL:      safeServer.URL + "/assets",
				Hostname: "secure-bucket.s3.amazonaws.com",
				Headers:  map[string]string{"server": "AmazonS3", "x-amz-request-id": "REQ-67890"},
			},
		},
	}
	resultsSafe, findingsSafe, summarySafe, err := engine.Assess(context.Background(), actxSafe)
	if err != nil {
		t.Fatalf("unexpected assessment error: %v", err)
	}
	if summarySafe.VerifiedCount != 0 || len(findingsSafe) != 0 {
		t.Fatalf("expected 0 verified findings on secure S3 bucket, got %d", summarySafe.VerifiedCount)
	}
	if resultsSafe[0].VerificationState != StateObserved {
		t.Errorf("expected StateObserved, got %s", resultsSafe[0].VerificationState)
	}
}

// 2. Test External Mode: Azure Blob Anonymous Container Listing
func TestCloudSec_External_AzureBlob(t *testing.T) {
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.Header().Set("x-ms-request-id", "MS-REQ-111")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ContainerName="public-media"></EnumerationResults>`)
	}))
	defer vulnServer.Close()

	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer safeServer.Close()

	engine := NewEngine(DefaultConfig())

	// Positive Control
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-ext-blob-vuln",
		Mode:         ModeExternal,
		Provider:     ProviderAzure,
		ExternalTargets: []ExternalTarget{
			{
				URL:      vulnServer.URL + "/public-media",
				Hostname: "coredata.blob.core.windows.net",
				Headers:  map[string]string{"server": "Windows-Azure-Blob/1.0", "x-ms-request-id": "MS-REQ-111"},
			},
		},
	}
	_, findingsVuln, summaryVuln, _ := engine.Assess(context.Background(), actxVuln)
	if summaryVuln.VerifiedCount != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified Azure Blob finding, got %d", summaryVuln.VerifiedCount)
	}

	// Negative Control
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-ext-blob-safe",
		Mode:         ModeExternal,
		Provider:     ProviderAzure,
		ExternalTargets: []ExternalTarget{
			{
				URL:      safeServer.URL + "/private-media",
				Hostname: "privatedata.blob.core.windows.net",
				Headers:  map[string]string{"server": "Windows-Azure-Blob/1.0"},
			},
		},
	}
	resultsSafe, findingsSafe, _, _ := engine.Assess(context.Background(), actxSafe)
	if len(findingsSafe) != 0 || resultsSafe[0].VerificationState != StateObserved {
		t.Fatalf("expected safe Azure Blob to be OBSERVED, got %s", resultsSafe[0].VerificationState)
	}
}

// 3. Test External Mode: GCP Cloud Storage Anonymous Listing
func TestCloudSec_External_GCPStorage(t *testing.T) {
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GCS")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>gcs-open-bucket</Name></ListBucketResult>`)
	}))
	defer vulnServer.Close()

	engine := NewEngine(DefaultConfig())

	actx := &AssessmentContext{
		AssessmentID: "asm-ext-gcs-vuln",
		Mode:         ModeExternal,
		Provider:     ProviderGCP,
		ExternalTargets: []ExternalTarget{
			{
				URL:      vulnServer.URL,
				Hostname: "storage.googleapis.com",
				Headers:  map[string]string{"server": "GCS", "x-goog-generation": "12345"},
			},
		},
	}
	_, findings, summary, _ := engine.Assess(context.Background(), actx)
	if summary.VerifiedCount != 1 || len(findings) != 1 {
		t.Fatalf("expected 1 verified GCS finding, got %d", summary.VerifiedCount)
	}
}

// 4. Test External Mode: Scope Enforcement & Exclusion
func TestCloudSec_External_ScopeAndExclusions(t *testing.T) {
	reqCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewEngine(DefaultConfig())

	// Target is excluded
	actx := &AssessmentContext{
		AssessmentID: "asm-ext-excluded",
		Mode:         ModeExternal,
		Provider:     ProviderAWS,
		ExternalTargets: []ExternalTarget{
			{URL: server.URL, Hostname: "test.s3.amazonaws.com"},
		},
		IsExcluded: func(u string) bool { return true },
	}

	results, _, _, _ := engine.Assess(context.Background(), actx)
	if len(results) != 0 || reqCount != 0 {
		t.Fatalf("expected 0 checks run for excluded target, got results=%d, reqs=%d", len(results), reqCount)
	}
}

// 5. Test Credentialed Identity & Scope Validation (AWS, Azure, GCP)
func TestCloudSec_IdentityAndScopeValidation(t *testing.T) {
	iv := NewIdentityValidator(nil)

	// AWS: Correct scope match
	awsCreds := Credentials{
		Provider:           ProviderAWS,
		AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	awsScope := DeclaredScope{
		Provider:        ProviderAWS,
		TargetAccountID: "123456789012",
	}
	identAWS, err := iv.VerifyIdentity(context.Background(), awsCreds, awsScope)
	if err != nil || !identAWS.IsScopeMatched {
		t.Fatalf("expected AWS identity match, got err=%v, matched=%t", err, identAWS.IsScopeMatched)
	}

	// AWS: Mismatched account scope -> Fails closed
	badAWSScope := DeclaredScope{
		Provider:        ProviderAWS,
		TargetAccountID: "999999999999", // Different account
	}
	identAWSMismatch, err := iv.VerifyIdentity(context.Background(), awsCreds, badAWSScope)
	if err == nil {
		t.Fatalf("expected error on mismatched account scope, got nil (ident: %v)", identAWSMismatch)
	}

	// Azure: Correct subscription match
	azureCreds := Credentials{
		Provider:            ProviderAzure,
		AzureTenantID:       "tenant-111",
		AzureClientID:       "client-222",
		AzureClientSecret:   "secret-333",
		AzureSubscriptionID: "00000000-0000-0000-0000-111111111111",
	}
	azureScope := DeclaredScope{
		Provider:           ProviderAzure,
		TargetSubscription: "00000000-0000-0000-0000-111111111111",
	}
	identAzure, err := iv.VerifyIdentity(context.Background(), azureCreds, azureScope)
	if err != nil || !identAzure.IsScopeMatched {
		t.Fatalf("expected Azure identity match, got err=%v", err)
	}

	// GCP: Correct project match
	gcpCreds := Credentials{
		Provider:       ProviderGCP,
		GCPProjectID:   "my-prod-project",
		GCPClientEmail: "sa@my-prod-project.iam.gserviceaccount.com",
	}
	gcpScope := DeclaredScope{
		Provider:        ProviderGCP,
		TargetProjectID: "my-prod-project",
	}
	identGCP, err := iv.VerifyIdentity(context.Background(), gcpCreds, gcpScope)
	if err != nil || !identGCP.IsScopeMatched {
		t.Fatalf("expected GCP identity match, got err=%v", err)
	}

	// Missing credentials -> Fails closed
	emptyCreds := Credentials{Provider: ProviderAWS}
	_, err = iv.VerifyIdentity(context.Background(), emptyCreds, awsScope)
	if err == nil {
		t.Fatalf("expected error for missing credentials, got nil")
	}
}

// 6. Test AWS Credentialed Adapter: All 8 Services
func TestCloudSec_AWS_CredentialedServices(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive Synthetic Fixture: Should detect flaws across S3, IAM, EC2, APIGW, Lambda, Cognito, RDS, CloudFront
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-aws-cred-vuln",
		Mode:             ModeCredentialed,
		Provider:         ProviderAWS,
		SyntheticFixture: true,
		Credentials: Credentials{
			Provider:           ProviderAWS,
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Scope: DeclaredScope{
			Provider:        ProviderAWS,
			TargetAccountID: "123456789012",
		},
	}

	resultsVuln, findingsVuln, summaryVuln, err := engine.Assess(context.Background(), actxVuln)
	if err != nil {
		t.Fatalf("AWS credentialed assessment error: %v", err)
	}

	if len(resultsVuln) != 8 {
		t.Errorf("expected 8 AWS service results, got %d", len(resultsVuln))
	}
	if summaryVuln.VerifiedCount != 3 || summaryVuln.CandidateCount != 5 || len(findingsVuln) != 8 {
		t.Fatalf("expected 3 verified and 5 candidate findings across AWS services, got verified=%d, candidates=%d, findings=%d",
			summaryVuln.VerifiedCount, summaryVuln.CandidateCount, len(findingsVuln))
	}

	// Verify specific critical finding titles
	foundIAM := false
	foundS3 := false
	foundEC2 := false
	for _, f := range findingsVuln {
		if strings.Contains(f.Title, "IAM Policy") {
			foundIAM = true
		}
		if strings.Contains(f.Title, "S3 Bucket") {
			foundS3 = true
		}
		if strings.Contains(f.Title, "SSH Port") {
			foundEC2 = true
		}
	}
	if !foundIAM || !foundS3 || !foundEC2 {
		t.Errorf("missing expected AWS findings: iam=%t, s3=%t, ec2=%t", foundIAM, foundS3, foundEC2)
	}

	// Negative Control: Fully secure infrastructure -> 0 verified findings
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-aws-cred-safe",
		Mode:             ModeCredentialed,
		Provider:         ProviderAWS,
		SyntheticFixture: false,
		Credentials: Credentials{
			Provider:           ProviderAWS,
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Scope: DeclaredScope{
			Provider:        ProviderAWS,
			TargetAccountID: "123456789012",
		},
	}
	resultsSafe, findingsSafe, summarySafe, err := engine.Assess(context.Background(), actxSafe)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summarySafe.VerifiedCount != 0 || len(findingsSafe) != 0 {
		t.Fatalf("expected 0 verified findings on secure AWS account, got %d", summarySafe.VerifiedCount)
	}
	if summarySafe.InconclusiveCount != 8 {
		t.Errorf("expected 8 Inconclusive checks in offline mode, got %d", summarySafe.InconclusiveCount)
	}
	for _, r := range resultsSafe {
		if r.VerificationState != StateInconclusive {
			t.Errorf("check %s expected StateInconclusive, got %s", r.CheckID, r.VerificationState)
		}
	}
}

// 7. Test Azure Credentialed Adapter: All 5 Services
func TestCloudSec_Azure_CredentialedServices(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive Control
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-azure-cred-vuln",
		Mode:             ModeCredentialed,
		Provider:         ProviderAzure,
		SyntheticFixture: true,
		Credentials: Credentials{
			Provider:            ProviderAzure,
			AzureTenantID:       "tenant-111",
			AzureClientID:       "client-222",
			AzureClientSecret:   "secret-333",
			AzureSubscriptionID: "00000000-0000-0000-0000-111111111111",
		},
		Scope: DeclaredScope{
			Provider:           ProviderAzure,
			TargetSubscription: "00000000-0000-0000-0000-111111111111",
		},
	}

	resultsVuln, findingsVuln, summaryVuln, err := engine.Assess(context.Background(), actxVuln)
	if err != nil {
		t.Fatalf("Azure credentialed assessment error: %v", err)
	}
	if len(resultsVuln) != 5 || summaryVuln.VerifiedCount != 1 || summaryVuln.CandidateCount != 3 || summaryVuln.ObservedCount != 1 || len(findingsVuln) != 4 {
		t.Fatalf("expected 5 results (1 verified, 3 candidates, 1 observed) and 4 findings for Azure, got results=%d, verified=%d, candidates=%d, observed=%d, findings=%d",
			len(resultsVuln), summaryVuln.VerifiedCount, summaryVuln.CandidateCount, summaryVuln.ObservedCount, len(findingsVuln))
	}

	// Negative Control
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-azure-cred-safe",
		Mode:             ModeCredentialed,
		Provider:         ProviderAzure,
		SyntheticFixture: false,
		Credentials: Credentials{
			Provider:            ProviderAzure,
			AzureTenantID:       "tenant-111",
			AzureClientID:       "client-222",
			AzureClientSecret:   "secret-333",
			AzureSubscriptionID: "00000000-0000-0000-0000-111111111111",
		},
		Scope: DeclaredScope{
			Provider:           ProviderAzure,
			TargetSubscription: "00000000-0000-0000-0000-111111111111",
		},
	}
	resultsSafe, findingsSafe, summarySafe, _ := engine.Assess(context.Background(), actxSafe)
	if summarySafe.VerifiedCount != 0 || len(findingsSafe) != 0 {
		t.Fatalf("expected 0 verified findings on safe Azure subscription, got %d", summarySafe.VerifiedCount)
	}
	if summarySafe.InconclusiveCount != 5 {
		t.Errorf("expected 5 Inconclusive checks in offline mode, got %d", summarySafe.InconclusiveCount)
	}
	for _, r := range resultsSafe {
		if r.VerificationState != StateInconclusive {
			t.Errorf("check %s expected StateInconclusive, got %s", r.CheckID, r.VerificationState)
		}
	}
}

// 8. Test GCP Credentialed Adapter: All 5 Services
func TestCloudSec_GCP_CredentialedServices(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive Control
	actxVuln := &AssessmentContext{
		AssessmentID:     "asm-gcp-cred-vuln",
		Mode:             ModeCredentialed,
		Provider:         ProviderGCP,
		SyntheticFixture: true,
		Credentials: Credentials{
			Provider:       ProviderGCP,
			GCPProjectID:   "my-prod-project",
			GCPClientEmail: "sa@my-prod-project.iam.gserviceaccount.com",
		},
		Scope: DeclaredScope{
			Provider:        ProviderGCP,
			TargetProjectID: "my-prod-project",
		},
	}

	resultsVuln, findingsVuln, summaryVuln, err := engine.Assess(context.Background(), actxVuln)
	if err != nil {
		t.Fatalf("GCP credentialed assessment error: %v", err)
	}
	if len(resultsVuln) != 5 || summaryVuln.VerifiedCount != 3 || summaryVuln.CandidateCount != 1 || summaryVuln.ObservedCount != 1 || len(findingsVuln) != 4 {
		t.Fatalf("expected 5 results (3 verified, 1 candidate, 1 observed) and 4 findings for GCP, got results=%d, verified=%d, candidates=%d, observed=%d, findings=%d",
			len(resultsVuln), summaryVuln.VerifiedCount, summaryVuln.CandidateCount, summaryVuln.ObservedCount, len(findingsVuln))
	}

	// Negative Control: Offline mode -> 5 Inconclusive checks
	actxSafe := &AssessmentContext{
		AssessmentID:     "asm-gcp-cred-safe",
		Mode:             ModeCredentialed,
		Provider:         ProviderGCP,
		SyntheticFixture: false,
		Credentials: Credentials{
			Provider:       ProviderGCP,
			GCPProjectID:   "my-prod-project",
			GCPClientEmail: "sa@my-prod-project.iam.gserviceaccount.com",
		},
		Scope: DeclaredScope{
			Provider:        ProviderGCP,
			TargetProjectID: "my-prod-project",
		},
	}
	resultsSafe, findingsSafe, summarySafe, _ := engine.Assess(context.Background(), actxSafe)
	if summarySafe.VerifiedCount != 0 || len(findingsSafe) != 0 {
		t.Fatalf("expected 0 verified findings on safe GCP project, got %d", summarySafe.VerifiedCount)
	}
	if summarySafe.InconclusiveCount != 5 {
		t.Errorf("expected 5 Inconclusive checks in offline mode, got %d", summarySafe.InconclusiveCount)
	}
	for _, r := range resultsSafe {
		if r.VerificationState != StateInconclusive {
			t.Errorf("check %s expected StateInconclusive, got %s", r.CheckID, r.VerificationState)
		}
	}
}

// 9. Test Secret Protection, Redaction, and Zero Persistence
func TestCloudSec_SecretSafetyAndRedaction(t *testing.T) {
	rawSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	rawKey := "AKIAIOSFODNN7EXAMPLE"
	rawJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	privKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m5g...\n-----END RSA PRIVATE KEY-----"

	textWithSecrets := fmt.Sprintf("Error connecting with key %s, secret %s, jwt=%s, priv=%s", rawKey, rawSecret, rawJWT, privKey)
	redacted := RedactText(textWithSecrets)

	if strings.Contains(redacted, rawKey) {
		t.Errorf("raw AWS key leaked in redacted text!")
	}
	if strings.Contains(redacted, rawJWT) {
		t.Errorf("raw JWT leaked in redacted text!")
	}
	if strings.Contains(redacted, privKey) {
		t.Errorf("raw private key leaked in redacted text!")
	}

	// RedactedCopy proof
	creds := Credentials{
		Provider:           ProviderAWS,
		AWSAccessKeyID:     rawKey,
		AWSSecretAccessKey: rawSecret,
	}
	safeCopy := creds.RedactedCopy()
	if safeCopy.AWSSecretAccessKey != "[REDACTED]" {
		t.Errorf("RedactedCopy failed to scrub secret access key!")
	}

	// URL Sanitization
	targetWithSecretURL := "https://api.cloud.target.com/v1/resource?token=secretToken123&key=mykey456"
	sanitized := SanitizeURL(targetWithSecretURL)
	if strings.Contains(sanitized, "secretToken123") || strings.Contains(sanitized, "mykey456") {
		t.Errorf("SanitizeURL failed to scrub URL query secrets: %s", sanitized)
	}
}

// 10. Test Dry-Run Planning: Zero Request Dispatch
func TestCloudSec_DryRunPlanning(t *testing.T) {
	reqCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewEngine(DefaultConfig())

	// Dry run in external mode
	actxExt := &AssessmentContext{
		AssessmentID: "asm-dryrun-ext",
		Mode:         ModeExternal,
		Provider:     ProviderAWS,
		ExternalTargets: []ExternalTarget{
			{URL: server.URL, Hostname: "assets.s3.amazonaws.com"},
		},
	}
	planExt, err := engine.Plan(context.Background(), actxExt)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if planExt.ReadyChecks != 7 {
		t.Errorf("expected 7 planned external checks, got %d", planExt.ReadyChecks)
	}
	if reqCount != 0 {
		t.Fatalf("dry run dispatched HTTP requests! reqCount=%d", reqCount)
	}

	// Dry run in credentialed mode
	actxCred := &AssessmentContext{
		AssessmentID: "asm-dryrun-cred",
		Mode:         ModeCredentialed,
		Provider:     ProviderAWS,
		Credentials: Credentials{
			Provider:           ProviderAWS,
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Scope: DeclaredScope{
			Provider:        ProviderAWS,
			TargetAccountID: "123456789012",
		},
	}
	planCred, err := engine.Plan(context.Background(), actxCred)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if planCred.ReadyChecks != 8 {
		t.Errorf("expected 8 ready checks for AWS, got %d", planCred.ReadyChecks)
	}
}

// 11. Regression Test: External S3 Probe Enforces Zero Data Exposure (max-keys=0 & bounded read)
func TestCloudSec_External_S3_ZeroDataExposure(t *testing.T) {
	var capturedQuery string
	s3PayloadWithSensitiveData := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>confidential-acme-records</Name>
  <Prefix></Prefix>
  <Marker></Marker>
  <MaxKeys>0</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>confidential_customer_data_2026.csv</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <ETag>&quot;1234567890abcdef&quot;</ETag>
    <Size>987654321</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>production_database_passwords.sql</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <ETag>&quot;fedcba0987654321&quot;</ETag>
    <Size>12345</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("x-amz-request-id", "REQ-SAFE-S3-999")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, s3PayloadWithSensitiveData)
	}))
	defer server.Close()

	engine := NewEngine(DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-s3-safety-audit",
		Mode:         ModeExternal,
		Provider:     ProviderAWS,
		ExternalTargets: []ExternalTarget{
			{
				URL:      server.URL + "/confidential-acme-records",
				Hostname: "confidential-acme-records.s3.amazonaws.com",
				Headers:  map[string]string{"server": "AmazonS3"},
			},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected assessment error: %v", err)
	}

	// 1. Verify Felix client explicitly sent max-keys=0 to prevent AWS S3 from returning object listings
	if !strings.Contains(capturedQuery, "max-keys=0") {
		t.Fatalf("expected probe to enforce 'max-keys=0', but sent: %s", capturedQuery)
	}

	// 2. Verify finding was registered as verified public listing
	if summary.VerifiedCount != 1 || len(findings) != 1 {
		t.Fatalf("expected 1 verified finding, got verified=%d, findings=%d", summary.VerifiedCount, len(findings))
	}

	// 3. Verify ZERO customer object keys or sensitive strings are present in findings or results
	forbiddenStrings := []string{
		"confidential_customer_data_2026.csv",
		"production_database_passwords.sql",
		"987654321",
	}

	for _, f := range findings {
		for _, forbidden := range forbiddenStrings {
			if strings.Contains(f.Title, forbidden) ||
				strings.Contains(f.Description, forbidden) ||
				strings.Contains(f.Evidence, forbidden) {
				t.Fatalf("SAFETY VIOLATION: finding leaked sensitive customer object data: %s", forbidden)
			}
		}
	}

	for _, r := range results {
		for _, forbidden := range forbiddenStrings {
			if strings.Contains(r.EvidenceSummary, forbidden) {
				t.Fatalf("SAFETY VIOLATION: result EvidenceSummary leaked sensitive customer object data: %s", forbidden)
			}
			for k, v := range r.EvidenceDetails {
				if strings.Contains(k, forbidden) || strings.Contains(v, forbidden) {
					t.Fatalf("SAFETY VIOLATION: result EvidenceDetails leaked sensitive customer object data: %s", forbidden)
				}
			}
		}
		if r.EvidenceDetails["safety"] != "SAFE_PROBE_ZERO_OBJECT_KEYS_RETRIEVED" {
			t.Errorf("expected safety annotation SAFE_PROBE_ZERO_OBJECT_KEYS_RETRIEVED, got %s", r.EvidenceDetails["safety"])
		}
	}
}

// 12. Regression Test: External Azure Blob Probe Enforces Zero Data Exposure (HEAD/bounded GET)
func TestCloudSec_External_AzureBlob_ZeroDataExposure(t *testing.T) {
	var capturedQueries []string

	azureXMLWithSensitiveBlobs := `<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ContainerName="hr-confidential">
  <Blobs>
    <Blob>
      <Name>executive_salaries_q4.xlsx</Name>
      <Properties>
        <Content-Length>5000000</Content-Length>
      </Properties>
    </Blob>
    <Blob>
      <Name>ssn_tax_filings.pdf</Name>
      <Properties>
        <Content-Length>2000000</Content-Length>
      </Properties>
    </Blob>
  </Blobs>
</EnumerationResults>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQueries = append(capturedQueries, r.URL.RawQuery)
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")

		if r.Method == "HEAD" {
			// HEAD does not return container header, so it falls back to GET
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, azureXMLWithSensitiveBlobs)
			return
		}
	}))
	defer server.Close()

	engine := NewEngine(DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-azure-safety-audit",
		Mode:         ModeExternal,
		Provider:     ProviderAzure,
		ExternalTargets: []ExternalTarget{
			{
				URL:      server.URL + "/hr-confidential",
				Hostname: "hrcorporate.blob.core.windows.net",
				Headers:  map[string]string{"server": "Windows-Azure-Blob/1.0"},
			},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected assessment error: %v", err)
	}

	// 1. Verify GET query parameters contain safe bounds
	foundSafeParams := false
	for _, q := range capturedQueries {
		if strings.Contains(q, "restype=container") && strings.Contains(q, "comp=list") && strings.Contains(q, "maxresults=1") {
			foundSafeParams = true
		}
	}
	if !foundSafeParams {
		t.Fatalf("expected Azure probe to send safe params restype=container&comp=list&maxresults=1, got queries: %v", capturedQueries)
	}

	// 2. Verify finding generated
	if summary.VerifiedCount != 1 || len(findings) != 1 {
		t.Fatalf("expected 1 verified finding, got verified=%d, findings=%d", summary.VerifiedCount, len(findings))
	}

	// 3. Verify zero sensitive blob names leaked into findings or results
	forbiddenStrings := []string{
		"executive_salaries_q4.xlsx",
		"ssn_tax_filings.pdf",
		"5000000",
	}

	for _, f := range findings {
		for _, forbidden := range forbiddenStrings {
			if strings.Contains(f.Title, forbidden) ||
				strings.Contains(f.Description, forbidden) ||
				strings.Contains(f.Evidence, forbidden) {
				t.Fatalf("SAFETY VIOLATION: finding leaked sensitive blob name: %s", forbidden)
			}
		}
	}

	for _, r := range results {
		for _, forbidden := range forbiddenStrings {
			if strings.Contains(r.EvidenceSummary, forbidden) {
				t.Fatalf("SAFETY VIOLATION: result leaked sensitive blob name: %s", forbidden)
			}
			for k, v := range r.EvidenceDetails {
				if strings.Contains(k, forbidden) || strings.Contains(v, forbidden) {
					t.Fatalf("SAFETY VIOLATION: result EvidenceDetails leaked sensitive blob name: %s", forbidden)
				}
			}
		}
	}
}

// 13. Regression Test: External Storage 403/404 Classified As OBSERVED (Never Public Access)
func TestCloudSec_External_BucketExistenceNotPublic(t *testing.T) {
	// S3 returning 403 Forbidden
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>`)
	}))
	defer s3Server.Close()

	// Azure Blob returning 403 Forbidden
	azureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>AuthenticationFailed</Code></Error>`)
	}))
	defer azureServer.Close()

	// GCP Storage returning 403 Forbidden
	gcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GCS")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>`)
	}))
	defer gcpServer.Close()

	engine := NewEngine(DefaultConfig())

	targets := []struct {
		name     string
		provider Provider
		url      string
		host     string
		headers  map[string]string
	}{
		{"AWS S3 403", ProviderAWS, s3Server.URL + "/bucket", "bucket.s3.amazonaws.com", map[string]string{"server": "AmazonS3"}},
		{"Azure Blob 403", ProviderAzure, azureServer.URL + "/cont", "acc.blob.core.windows.net", map[string]string{"server": "Windows-Azure-Blob/1.0"}},
		{"GCP Storage 403", ProviderGCP, gcpServer.URL, "storage.googleapis.com", map[string]string{"server": "GCS"}},
	}

	for _, tt := range targets {
		t.Run(tt.name, func(t *testing.T) {
			actx := &AssessmentContext{
				AssessmentID: "asm-test-existence-" + string(tt.provider),
				Mode:         ModeExternal,
				Provider:     tt.provider,
				ExternalTargets: []ExternalTarget{
					{
						URL:      tt.url,
						Hostname: tt.host,
						Headers:  tt.headers,
					},
				},
			}

			results, findings, summary, err := engine.Assess(context.Background(), actx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Must NOT be classified as verified public access
			if summary.VerifiedCount != 0 || len(findings) != 0 {
				t.Fatalf("HTTP 403 must NEVER produce verified vulnerability findings; got verified=%d, findings=%d",
					summary.VerifiedCount, len(findings))
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].VerificationState != StateObserved {
				t.Fatalf("HTTP 403 bucket existence must be classified as StateObserved, got %s", results[0].VerificationState)
			}
			if results[0].Severity != report.SeverityInfo {
				t.Fatalf("HTTP 403 bucket existence must have SeverityInfo, got %s", results[0].Severity)
			}
		})
	}
}

// 14. Regression Test: Credentialed Assessment in Offline/Unpermitted Mode Yields INCONCLUSIVE
func TestCloudSec_Credentialed_MissingPermissionsInconclusive(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	providers := []struct {
		name     string
		provider Provider
		creds    Credentials
		scope    DeclaredScope
		expected int
	}{
		{
			name:     "AWS Offline",
			provider: ProviderAWS,
			creds: Credentials{
				Provider:           ProviderAWS,
				AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			scope:    DeclaredScope{Provider: ProviderAWS, TargetAccountID: "123456789012"},
			expected: 8,
		},
		{
			name:     "Azure Offline",
			provider: ProviderAzure,
			creds: Credentials{
				Provider:            ProviderAzure,
				AzureTenantID:       "tenant-111",
				AzureClientID:       "client-222",
				AzureClientSecret:   "secret-333",
				AzureSubscriptionID: "00000000-0000-0000-0000-111111111111",
			},
			scope:    DeclaredScope{Provider: ProviderAzure, TargetSubscription: "00000000-0000-0000-0000-111111111111"},
			expected: 5,
		},
		{
			name:     "GCP Offline",
			provider: ProviderGCP,
			creds: Credentials{
				Provider:       ProviderGCP,
				GCPProjectID:   "my-prod-project",
				GCPClientEmail: "sa@my-prod-project.iam.gserviceaccount.com",
			},
			scope:    DeclaredScope{Provider: ProviderGCP, TargetProjectID: "my-prod-project"},
			expected: 5,
		},
	}

	for _, prov := range providers {
		t.Run(prov.name, func(t *testing.T) {
			actx := &AssessmentContext{
				AssessmentID:     "asm-offline-" + string(prov.provider),
				Mode:             ModeCredentialed,
				Provider:         prov.provider,
				SyntheticFixture: false, // Live API unreached / offline mode
				Credentials:      prov.creds,
				Scope:            prov.scope,
			}

			results, findings, summary, err := engine.Assess(context.Background(), actx)
			if err != nil {
				t.Fatalf("unexpected assessment error: %v", err)
			}

			if len(findings) != 0 {
				t.Fatalf("offline assessment must produce 0 findings, got %d", len(findings))
			}
			if summary.VerifiedCount != 0 {
				t.Fatalf("offline assessment must produce 0 verified, got %d", summary.VerifiedCount)
			}
			if summary.NotVulnerableCount != 0 {
				t.Fatalf("offline assessment must NEVER claim StateNotVulnerable without live API contact; got %d", summary.NotVulnerableCount)
			}
			if summary.InconclusiveCount != prov.expected {
				t.Fatalf("expected %d inconclusive checks, got %d", prov.expected, summary.InconclusiveCount)
			}

			for _, r := range results {
				if r.VerificationState != StateInconclusive {
					t.Errorf("check %s must be StateInconclusive, got %s", r.CheckID, r.VerificationState)
				}
			}
		})
	}
}

// 15. Regression Test: Scope Filtering Sets CoverageSkippedScope for Excluded Services
func TestCloudSec_ScopeFilter_SkippedServices(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	actx := &AssessmentContext{
		AssessmentID:     "asm-scope-filter",
		Mode:             ModeCredentialed,
		Provider:         ProviderAWS,
		SyntheticFixture: true,
		Credentials: Credentials{
			Provider:           ProviderAWS,
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Scope: DeclaredScope{
			Provider:        ProviderAWS,
			TargetAccountID: "123456789012",
			Services:        []string{"s3"}, // Only s3 requested; all other 7 services excluded
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected assessment error: %v", err)
	}

	// Only 1 check from s3 should be executed
	if len(results) != 1 {
		t.Fatalf("expected 1 result from s3, got %d", len(results))
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from s3, got %d", len(findings))
	}

	// Verify coverage map: s3 is ASSESSED; all others are SKIPPED_SCOPE
	covS3 := summary.ServiceCoverageMap["s3"]
	if covS3.Status != CoverageAssessed || covS3.ChecksRun != 1 {
		t.Fatalf("expected s3 to be ASSESSED with 1 check, got status=%s, checks=%d", covS3.Status, covS3.ChecksRun)
	}

	skippedServices := []string{"iam", "ec2", "apigateway", "lambda", "cognito", "rds", "cloudfront"}
	for _, svc := range skippedServices {
		cov := summary.ServiceCoverageMap[svc]
		if cov.Status != CoverageSkippedScope {
			t.Errorf("expected %s to have CoverageSkippedScope, got %s", svc, cov.Status)
		}
		if cov.ChecksRun != 0 {
			t.Errorf("expected 0 checks run for out-of-scope %s, got %d", svc, cov.ChecksRun)
		}
	}
}

// 16. Regression Test: Synthetic Fixtures Are Explicitly Labeled in Findings and Summaries
func TestCloudSec_SyntheticFixture_ExplicitLabeling(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Fixture ON
	actxFixture := &AssessmentContext{
		AssessmentID:     "asm-fixture-labeling",
		Mode:             ModeCredentialed,
		Provider:         ProviderAWS,
		SyntheticFixture: true,
		Credentials: Credentials{
			Provider:           ProviderAWS,
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Scope: DeclaredScope{
			Provider:        ProviderAWS,
			TargetAccountID: "123456789012",
			Services:        []string{"s3"},
		},
	}

	_, findingsFixture, summaryFixture, err := engine.Assess(context.Background(), actxFixture)
	if err != nil {
		t.Fatalf("assessment error: %v", err)
	}
	if !summaryFixture.SyntheticFixture {
		t.Fatalf("expected summary.SyntheticFixture to be true")
	}
	if len(findingsFixture) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findingsFixture))
	}
	if findingsFixture[0].EvidenceDetails.Details["synthetic_fixture"] != "true" {
		t.Fatalf("expected finding detail 'synthetic_fixture' to be 'true'")
	}
	if findingsFixture[0].EvidenceDetails.Details["evaluation_environment"] != "SYNTHETIC_FIXTURE_SIMULATION" {
		t.Fatalf("expected evaluation_environment to be 'SYNTHETIC_FIXTURE_SIMULATION'")
	}

	// Fixture OFF
	actxLiveOffline := &AssessmentContext{
		AssessmentID:     "asm-live-offline",
		Mode:             ModeCredentialed,
		Provider:         ProviderAWS,
		SyntheticFixture: false,
		Credentials: Credentials{
			Provider:           ProviderAWS,
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Scope: DeclaredScope{
			Provider:        ProviderAWS,
			TargetAccountID: "123456789012",
			Services:        []string{"s3"},
		},
	}

	_, findingsLive, summaryLive, err := engine.Assess(context.Background(), actxLiveOffline)
	if err != nil {
		t.Fatalf("assessment error: %v", err)
	}
	if summaryLive.SyntheticFixture {
		t.Fatalf("expected summaryLive.SyntheticFixture to be false")
	}
	if len(findingsLive) != 0 {
		t.Fatalf("expected 0 findings in offline mode, got %d", len(findingsLive))
	}
}

// 17. Regression Test: External Storage Probes Adhere to Minimum Necessary Evidence
func TestCloudSec_External_StorageProbes_MinimumEvidenceIntegrity(t *testing.T) {
	// S3 Server
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>public-bucket</Name></ListBucketResult>`)
	}))
	defer s3Server.Close()

	// Azure Server
	azureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.Header().Set("x-ms-blob-public-access", "container")
		w.WriteHeader(http.StatusOK)
	}))
	defer azureServer.Close()

	// GCS Server
	gcsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GCS")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>public-gcs-bucket</Name></ListBucketResult>`)
	}))
	defer gcsServer.Close()

	engine := NewEngine(DefaultConfig())

	tests := []struct {
		name          string
		provider      Provider
		url           string
		hostname      string
		headers       map[string]string
		expectedTitle string
	}{
		{
			name:          "AWS S3 Listing Title & Evidence Claim",
			provider:      ProviderAWS,
			url:           s3Server.URL + "/public-bucket",
			hostname:      "public-bucket.s3.amazonaws.com",
			headers:       map[string]string{"server": "AmazonS3"},
			expectedTitle: "Publicly Accessible AWS S3 Bucket Listing",
		},
		{
			name:          "Azure Blob Listing Title & Evidence Claim",
			provider:      ProviderAzure,
			url:           azureServer.URL + "/public-cont",
			hostname:      "myaccount.blob.core.windows.net",
			headers:       map[string]string{"server": "Windows-Azure-Blob/1.0"},
			expectedTitle: "Publicly Accessible Azure Blob Container Listing",
		},
		{
			name:          "GCS Listing Title & Evidence Claim",
			provider:      ProviderGCP,
			url:           gcsServer.URL,
			hostname:      "storage.googleapis.com",
			headers:       map[string]string{"server": "GCS"},
			expectedTitle: "Publicly Accessible Google Cloud Storage Bucket Listing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actx := &AssessmentContext{
				AssessmentID: "asm-evidence-integrity-" + string(tt.provider),
				Mode:         ModeExternal,
				Provider:     tt.provider,
				ExternalTargets: []ExternalTarget{
					{
						URL:      tt.url,
						Hostname: tt.hostname,
						Headers:  tt.headers,
					},
				},
			}

			results, findings, _, err := engine.Assess(context.Background(), actx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}

			finding := findings[0]
			if finding.Title != tt.expectedTitle {
				t.Fatalf("expected title %q, got %q", tt.expectedTitle, finding.Title)
			}

			// Proves only listing access: title must contain "Listing"
			if !strings.Contains(finding.Title, "Listing") {
				t.Errorf("finding title must describe listing permission only: %s", finding.Title)
			}

			// Proves findings do NOT claim object download
			if strings.Contains(strings.ToLower(finding.Description), "object downloaded") ||
				strings.Contains(strings.ToLower(finding.Evidence), "object downloaded") {
				t.Errorf("finding must NOT claim object contents were downloaded")
			}

			// Proves finding explicitly acknowledges account/project policies were not inspected
			if !strings.Contains(finding.Evidence, "not inspected") {
				t.Errorf("finding must acknowledge account/project policy was not inspected: %s", finding.Evidence)
			}

			// Proves results have safety annotation
			res := results[0]
			if res.EvidenceDetails["safety"] == "" {
				t.Errorf("result must contain explicit safety probe annotation")
			}
		})
	}
}
