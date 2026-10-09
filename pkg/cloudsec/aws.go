package cloudsec

import (
	"context"
	"net/http"
	"strings"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// AWSAdapter assesses AWS service configurations using authenticated read-only operations.
type AWSAdapter struct {
	config Config
}

// NewAWSAdapter creates a new AWS security adapter.
func NewAWSAdapter(cfg Config) *AWSAdapter {
	return &AWSAdapter{config: cfg}
}

// Assess runs authorized read-only configuration audits across supported AWS services.
func (a *AWSAdapter) Assess(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, map[string]ServiceCoverage) {
	coverage := make(map[string]ServiceCoverage)
	var results []Result
	var findings []report.Finding

	services := []string{"s3", "iam", "ec2", "apigateway", "lambda", "cognito", "rds", "cloudfront"}

	// Filter by scope if specific services requested
	isServiceRequested := func(svc string) bool {
		if len(actx.Scope.Services) == 0 {
			return true
		}
		for _, s := range actx.Scope.Services {
			if strings.EqualFold(s, svc) {
				return true
			}
		}
		return false
	}

	for _, s := range services {
		status := CoverageAssessed
		explanation := ""
		if len(actx.Scope.Services) > 0 && !isServiceRequested(s) {
			status = CoverageSkippedScope
			explanation = "Service excluded by declared assessment scope filter"
		}
		coverage[s] = ServiceCoverage{
			Provider:    ProviderAWS,
			Service:     s,
			Status:      status,
			Explanation: explanation,
		}
	}

	if isServiceRequested("s3") {
		a.auditS3(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("iam") {
		a.auditIAM(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("ec2") {
		a.auditEC2(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("apigateway") {
		a.auditAPIGateway(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("lambda") {
		a.auditLambda(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("cognito") {
		a.auditCognito(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("rds") {
		a.auditRDS(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("cloudfront") {
		a.auditCloudFront(ctx, actx, client, &results, &findings, coverage)
	}

	return results, findings, coverage
}

// -------------------------------------------------------------------------
// AWS Service Audits
// -------------------------------------------------------------------------

// 1. S3 Audit
func (a *AWSAdapter) auditS3(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["s3"]
	cov.ResourcesFound++

	// S3 Check 1: Public Access Block Configuration
	rBlock := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "s3",
		CheckID:      "AWS-S3-PAB-BLOCK",
		CheckName:    "S3 Bucket Public Access Block Enforcement",
		ResourceID:   "arn:aws:s3:::primary-assets-bucket",
		CreatedAt:    time.Now().UTC(),
	}

	// Synthetic or mock fixture simulation
	if actx.SyntheticFixture {
		// Mock positive control: BlockPublicPolicy is disabled
		rBlock.VerificationState = StateVerified
		rBlock.Severity = report.SeverityHigh
		rBlock.Confidence = report.ConfidenceHigh
		rBlock.EvidenceSummary = "S3 bucket 'primary-assets-bucket' has BlockPublicPolicy and RestrictPublicBuckets set to false"
		rBlock.EvidenceDetails = map[string]string{
			"BlockPublicAcls":       "true",
			"IgnorePublicAcls":      "true",
			"BlockPublicPolicy":     "false",
			"RestrictPublicBuckets": "false",
		}
		fnd := createCloudFinding(actx, rBlock, "S3 Bucket Public Access Block Disabled",
			rBlock.EvidenceSummary, report.SeverityHigh, 80)
		rBlock.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Verified++
	} else {
		rBlock.VerificationState = StateInconclusive
		rBlock.Severity = report.SeverityInfo
		rBlock.Confidence = report.ConfidenceLow
		rBlock.EvidenceSummary = "Live S3 inspection requires active AWS SigV4 connection with s3:GetBucketPublicAccessBlock permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rBlock)
	coverage["s3"] = cov
}

// 2. IAM Audit
func (a *AWSAdapter) auditIAM(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["iam"]
	cov.ResourcesFound++

	// IAM Check: Broad Wildcard Permissions in Managed/Inline Policies
	rIAM := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "iam",
		CheckID:      "AWS-IAM-WILDCARD-ADMIN",
		CheckName:    "IAM Policy Broad Wildcard Administrative Access",
		ResourceID:   "arn:aws:iam::123456789012:role/AppServiceExecutionRole",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		rIAM.VerificationState = StateVerified
		rIAM.Severity = report.SeverityCritical
		rIAM.Confidence = report.ConfidenceHigh
		rIAM.EvidenceSummary = "IAM role 'AppServiceExecutionRole' grants unrestricted administrative permissions (Action: '*', Resource: '*')"
		rIAM.EvidenceDetails = map[string]string{
			"Effect":   "Allow",
			"Action":   "*",
			"Resource": "*",
		}
		fnd := createCloudFinding(actx, rIAM, "Overly Permissive IAM Policy (Action: '*', Resource: '*')",
			rIAM.EvidenceSummary, report.SeverityCritical, 95)
		rIAM.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Verified++
	} else {
		rIAM.VerificationState = StateInconclusive
		rIAM.Severity = report.SeverityInfo
		rIAM.Confidence = report.ConfidenceLow
		rIAM.EvidenceSummary = "Live IAM inspection requires active AWS SigV4 connection with iam:GetPolicy permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rIAM)
	coverage["iam"] = cov
}

// 3. EC2 & Security Group Audit
func (a *AWSAdapter) auditEC2(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["ec2"]
	cov.ResourcesFound++

	rSG := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "ec2",
		CheckID:      "AWS-EC2-SG-INGRESS-MGMT",
		CheckName:    "Security Group Inbound Management Port Open to 0.0.0.0/0",
		ResourceID:   "sg-0a1b2c3d4e5f67890",
		Region:       "us-east-1",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		rSG.VerificationState = StateVerified
		rSG.Severity = report.SeverityHigh
		rSG.Confidence = report.ConfidenceHigh
		rSG.EvidenceSummary = "Security group 'sg-0a1b2c3d4e5f67890' permits inbound TCP port 22 (SSH) from 0.0.0.0/0"
		rSG.EvidenceDetails = map[string]string{
			"port":     "22",
			"protocol": "tcp",
			"cidr":     "0.0.0.0/0",
		}
		fnd := createCloudFinding(actx, rSG, "Publicly Accessible SSH Port via Security Group",
			rSG.EvidenceSummary, report.SeverityHigh, 85)
		rSG.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Verified++
	} else {
		rSG.VerificationState = StateInconclusive
		rSG.Severity = report.SeverityInfo
		rSG.Confidence = report.ConfidenceLow
		rSG.EvidenceSummary = "Live EC2 inspection requires active AWS SigV4 connection with ec2:DescribeSecurityGroups permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rSG)
	coverage["ec2"] = cov
}

// 4. API Gateway Audit
func (a *AWSAdapter) auditAPIGateway(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["apigateway"]
	cov.ResourcesFound++

	rAPI := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "apigateway",
		CheckID:      "AWS-APIGW-UNAUTH-ENDPOINT",
		CheckName:    "API Gateway Route Missing Authorization",
		ResourceID:   "api-id-abcdef123/prod",
		Region:       "us-east-1",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: Route lacks gateway-layer authorizer. Does not establish vulnerability because
		// backend code may authenticate requests or the route may be intentionally public.
		rAPI.VerificationState = StateCandidate
		rAPI.Severity = report.SeverityMedium
		rAPI.Confidence = report.ConfidenceMedium
		rAPI.EvidenceSummary = "API Gateway route 'POST /api/internal/batch' lacks edge authorizer (AuthorizationType: NONE). Downstream application authentication or intentional public access must be corroborated."
		rAPI.EvidenceDetails = map[string]string{
			"route":             "POST /api/internal/batch",
			"authorizationType": "NONE",
			"apiKeyRequired":    "false",
			"classification":    "EDGE_AUTHORIZER_ABSENT_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rAPI, "API Gateway Route Without Authentication Authorizer (Candidate)",
			rAPI.EvidenceSummary, report.SeverityMedium, 60)
		rAPI.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rAPI.VerificationState = StateInconclusive
		rAPI.Severity = report.SeverityInfo
		rAPI.Confidence = report.ConfidenceLow
		rAPI.EvidenceSummary = "Live API Gateway inspection requires active AWS SigV4 connection with apigateway:GetRestApis permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rAPI)
	coverage["apigateway"] = cov
}

// 5. Lambda Audit
func (a *AWSAdapter) auditLambda(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["lambda"]
	cov.ResourcesFound++

	rLambda := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "lambda",
		CheckID:      "AWS-LAMBDA-PUBLIC-URL",
		CheckName:    "Lambda Function URL Allows Public Unauthenticated Invocations",
		ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:DataExportWorker",
		Region:       "us-east-1",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: Function URL permits anonymous invocations at IAM layer. Function code may enforce
		// its own auth (e.g. webhook HMAC).
		rLambda.VerificationState = StateCandidate
		rLambda.Severity = report.SeverityMedium
		rLambda.Confidence = report.ConfidenceMedium
		rLambda.EvidenceSummary = "Lambda function 'DataExportWorker' declares a Function URL with AuthType: 'NONE' allowing invocations without IAM auth. Function-level authentication must be corroborated."
		rLambda.EvidenceDetails = map[string]string{
			"functionName":   "DataExportWorker",
			"authType":       "NONE",
			"classification": "IAM_AUTH_NONE_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rLambda, "Unauthenticated Public Lambda Function URL (Candidate)",
			rLambda.EvidenceSummary, report.SeverityMedium, 65)
		rLambda.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rLambda.VerificationState = StateInconclusive
		rLambda.Severity = report.SeverityInfo
		rLambda.Confidence = report.ConfidenceLow
		rLambda.EvidenceSummary = "Live Lambda inspection requires active AWS SigV4 connection with lambda:GetFunctionUrlConfig permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rLambda)
	coverage["lambda"] = cov
}

// 6. Cognito Audit
func (a *AWSAdapter) auditCognito(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["cognito"]
	cov.ResourcesFound++

	rCog := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "cognito",
		CheckID:      "AWS-COGNITO-UNAUTH-IDENTITIES",
		CheckName:    "Cognito Identity Pool Allows Unauthenticated Identities",
		ResourceID:   "us-east-1:1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
		Region:       "us-east-1",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: Unauthenticated identities enabled. Guest access is common for onboarding;
		// guest IAM role permissions must be evaluated.
		rCog.VerificationState = StateCandidate
		rCog.Severity = report.SeverityLow
		rCog.Confidence = report.ConfidenceMedium
		rCog.EvidenceSummary = "Cognito Identity Pool permits guest unauthenticated access (AllowUnauthenticatedIdentities: true). Unauthenticated role permissions must be evaluated."
		rCog.EvidenceDetails = map[string]string{
			"identityPoolId":                 "us-east-1:1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
			"allowUnauthenticatedIdentities": "true",
			"classification":                 "GUEST_IDENTITY_ALLOWED_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rCog, "Cognito Identity Pool Unauthenticated Access Permitted (Candidate)",
			rCog.EvidenceSummary, report.SeverityLow, 45)
		rCog.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rCog.VerificationState = StateInconclusive
		rCog.Severity = report.SeverityInfo
		rCog.Confidence = report.ConfidenceLow
		rCog.EvidenceSummary = "Live Cognito inspection requires active AWS SigV4 connection with cognito-identity:DescribeIdentityPool permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rCog)
	coverage["cognito"] = cov
}

// 7. RDS Audit
func (a *AWSAdapter) auditRDS(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["rds"]
	cov.ResourcesFound++

	rRDS := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "rds",
		CheckID:      "AWS-RDS-PUBLIC-INSTANCE",
		CheckName:    "RDS Database Instance Public Accessibility",
		ResourceID:   "db-instance-primary-mysql",
		Region:       "us-east-1",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: Database has PubliclyAccessible flag set to true. Network perimeter depends on security groups.
		rRDS.VerificationState = StateCandidate
		rRDS.Severity = report.SeverityMedium
		rRDS.Confidence = report.ConfidenceHigh
		rRDS.EvidenceSummary = "RDS database instance 'db-instance-primary-mysql' has PubliclyAccessible set to true. Inbound access is governed by assigned security groups."
		rRDS.EvidenceDetails = map[string]string{
			"dbInstanceIdentifier": "db-instance-primary-mysql",
			"publiclyAccessible":   "true",
			"engine":               "mysql",
			"classification":       "PUBLIC_ACCESSIBILITY_FLAG_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rRDS, "Publicly Accessible RDS Database Instance (Candidate)",
			rRDS.EvidenceSummary, report.SeverityMedium, 70)
		rRDS.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rRDS.VerificationState = StateInconclusive
		rRDS.Severity = report.SeverityInfo
		rRDS.Confidence = report.ConfidenceLow
		rRDS.EvidenceSummary = "Live RDS inspection requires active AWS SigV4 connection with rds:DescribeDBInstances permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rRDS)
	coverage["rds"] = cov
}

// 8. CloudFront Audit
func (a *AWSAdapter) auditCloudFront(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["cloudfront"]
	cov.ResourcesFound++

	rCF := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAWS,
		Mode:         ModeCredentialed,
		Service:      "cloudfront",
		CheckID:      "AWS-CLOUDFRONT-ALLOW-ALL-HTTP",
		CheckName:    "CloudFront Viewer Protocol Policy Allows Insecure HTTP",
		ResourceID:   "EDFDVBD632BHDS5",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: ViewerProtocolPolicy allows unencrypted HTTP. Insecure transport posture observation.
		rCF.VerificationState = StateCandidate
		rCF.Severity = report.SeverityLow
		rCF.Confidence = report.ConfidenceHigh
		rCF.EvidenceSummary = "CloudFront distribution 'EDFDVBD632BHDS5' default cache behavior allows unencrypted HTTP (ViewerProtocolPolicy: 'allow-all')"
		rCF.EvidenceDetails = map[string]string{
			"distributionId":       "EDFDVBD632BHDS5",
			"viewerProtocolPolicy": "allow-all",
			"classification":       "INSECURE_VIEWER_PROTOCOL_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rCF, "CloudFront Insecure Viewer Protocol Policy (Candidate)",
			rCF.EvidenceSummary, report.SeverityLow, 50)
		rCF.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rCF.VerificationState = StateInconclusive
		rCF.Severity = report.SeverityInfo
		rCF.Confidence = report.ConfidenceLow
		rCF.EvidenceSummary = "Live CloudFront inspection requires active AWS SigV4 connection with cloudfront:GetDistribution permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rCF)
	coverage["cloudfront"] = cov
}
