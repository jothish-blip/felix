package cloudsec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if summaryVuln.VerifiedCount != 8 || len(findingsVuln) != 8 {
		t.Fatalf("expected 8 verified findings across AWS services, got verified=%d, findings=%d", summaryVuln.VerifiedCount, len(findingsVuln))
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
	if summarySafe.NotVulnerableCount != 8 {
		t.Errorf("expected 8 NotVulnerable checks, got %d", summarySafe.NotVulnerableCount)
	}
	for _, r := range resultsSafe {
		if r.VerificationState != StateNotVulnerable {
			t.Errorf("check %s expected StateNotVulnerable, got %s", r.CheckID, r.VerificationState)
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
	if len(resultsVuln) != 5 || summaryVuln.VerifiedCount != 5 || len(findingsVuln) != 5 {
		t.Fatalf("expected 5 verified Azure findings, got results=%d, verified=%d, findings=%d",
			len(resultsVuln), summaryVuln.VerifiedCount, len(findingsVuln))
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
	_, findingsSafe, summarySafe, _ := engine.Assess(context.Background(), actxSafe)
	if summarySafe.VerifiedCount != 0 || len(findingsSafe) != 0 {
		t.Fatalf("expected 0 verified findings on safe Azure subscription, got %d", summarySafe.VerifiedCount)
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
	if len(resultsVuln) != 5 || summaryVuln.VerifiedCount != 5 || len(findingsVuln) != 5 {
		t.Fatalf("expected 5 verified GCP findings, got results=%d, verified=%d, findings=%d",
			len(resultsVuln), summaryVuln.VerifiedCount, len(findingsVuln))
	}

	// Negative Control
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
	_, findingsSafe, summarySafe, _ := engine.Assess(context.Background(), actxSafe)
	if summarySafe.VerifiedCount != 0 || len(findingsSafe) != 0 {
		t.Fatalf("expected 0 verified findings on safe GCP project, got %d", summarySafe.VerifiedCount)
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
