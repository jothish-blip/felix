package cloudsec

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"felix/pkg/report"
)

// Engine orchestrates external and credentialed cloud security assessments.
type Engine struct {
	config Config
}

// NewEngine creates a new Cloud Security Engine.
func NewEngine(cfg Config) *Engine {
	return &Engine{config: cfg}
}

// scopedClient creates an HTTP client strictly bound to assessment scope and redirect enforcement.
func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	return &http.Client{
		Timeout: e.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			destURL := req.URL.String()
			if actx.IsExcluded != nil && actx.IsExcluded(destURL) {
				return fmt.Errorf("redirect blocked: %s is excluded from assessment scope", destURL)
			}
			if actx.IsAllowed != nil && !actx.IsAllowed(destURL) {
				return fmt.Errorf("redirect blocked: %s is out of authorized scope", destURL)
			}
			return nil
		},
	}
}

// Plan prepares a pre-assessment execution plan without dispatching state-changing requests.
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*PlanResult, error) {
	plan := &PlanResult{
		AssessmentID: actx.AssessmentID,
		Mode:         actx.Mode,
		Provider:     actx.Provider,
		GeneratedAt:  time.Now().UTC(),
	}

	if actx.Mode == ModeExternal {
		plan.TargetScope = fmt.Sprintf("%d approved external targets", len(actx.ExternalTargets))
		plan.PlannedChecks = []PlannedCheck{
			{ID: "EXT-AWS-S3", Provider: ProviderAWS, Service: "s3_external", Name: "S3 Storage Endpoint & Anonymous Read", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
			{ID: "EXT-AWS-CF", Provider: ProviderAWS, Service: "cloudfront_external", Name: "CloudFront Distribution Detection", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
			{ID: "EXT-AWS-APIGW", Provider: ProviderAWS, Service: "apigateway_external", Name: "API Gateway Endpoint Observation", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
			{ID: "EXT-AZURE-BLOB", Provider: ProviderAzure, Service: "blob_external", Name: "Azure Blob Anonymous Read Check", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
			{ID: "EXT-AZURE-APP", Provider: ProviderAzure, Service: "appservice_external", Name: "Azure App Service Endpoint Check", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
			{ID: "EXT-GCP-GCS", Provider: ProviderGCP, Service: "storage_external", Name: "Google Cloud Storage Anonymous Check", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
			{ID: "EXT-GCP-RUN", Provider: ProviderGCP, Service: "cloudrun_external", Name: "Cloud Run Public Endpoint Observation", Mode: ModeExternal, ReadOnly: true, Status: "READY"},
		}
		plan.ReadyChecks = len(plan.PlannedChecks)
		return plan, nil
	}

	// Credentialed mode
	iv := NewIdentityValidator(nil)
	ident, err := iv.VerifyIdentity(ctx, actx.Credentials, actx.Scope)
	if err != nil {
		plan.BlockedChecks = 1
		plan.PlannedChecks = append(plan.PlannedChecks, PlannedCheck{
			ID:       "PLAN-IDENTITY-AUTH",
			Provider: actx.Provider,
			Name:     "Caller Identity & Scope Verification",
			Mode:     ModeCredentialed,
			Status:   "BLOCKED",
			Reason:   err.Error(),
		})
		return plan, nil
	}

	plan.VerifiedPrincipal = ident.PrincipalARN
	if plan.VerifiedPrincipal == "" {
		plan.VerifiedPrincipal = ident.ServiceAccount
	}
	if plan.VerifiedPrincipal == "" {
		plan.VerifiedPrincipal = ident.TenantID
	}
	plan.IdentitySource = ident.IdentitySource

	switch actx.Provider {
	case ProviderAWS:
		plan.TargetScope = fmt.Sprintf("AWS Account: %s", ident.AccountID)
		plan.PlannedChecks = []PlannedCheck{
			{ID: "AWS-S3-PAB-BLOCK", Provider: ProviderAWS, Service: "s3", Name: "S3 Public Access Block Enforcement", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "s3:GetPublicAccessBlock", Status: "READY"},
			{ID: "AWS-IAM-WILDCARD-ADMIN", Provider: ProviderAWS, Service: "iam", Name: "IAM Broad Wildcard Administration", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "iam:GetPolicy", Status: "READY"},
			{ID: "AWS-EC2-SG-INGRESS-MGMT", Provider: ProviderAWS, Service: "ec2", Name: "Security Group Management Port Ingress", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "ec2:DescribeSecurityGroups", Status: "READY"},
			{ID: "AWS-APIGW-UNAUTH-ENDPOINT", Provider: ProviderAWS, Service: "apigateway", Name: "API Gateway Route Authorizer Check", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "apigateway:GetRestApis", Status: "READY"},
			{ID: "AWS-LAMBDA-PUBLIC-URL", Provider: ProviderAWS, Service: "lambda", Name: "Lambda Function URL AuthType Check", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "lambda:GetFunctionUrlConfig", Status: "READY"},
			{ID: "AWS-COGNITO-UNAUTH-IDENTITIES", Provider: ProviderAWS, Service: "cognito", Name: "Cognito Identity Pool Unauthenticated Access", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "cognito-identity:DescribeIdentityPool", Status: "READY"},
			{ID: "AWS-RDS-PUBLIC-INSTANCE", Provider: ProviderAWS, Service: "rds", Name: "RDS Public Accessibility Check", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "rds:DescribeDBInstances", Status: "READY"},
			{ID: "AWS-CLOUDFRONT-ALLOW-ALL-HTTP", Provider: ProviderAWS, Service: "cloudfront", Name: "CloudFront Viewer Protocol Policy", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "cloudfront:GetDistribution", Status: "READY"},
		}
	case ProviderAzure:
		plan.TargetScope = fmt.Sprintf("Azure Subscription: %s", ident.SubscriptionID)
		plan.PlannedChecks = []PlannedCheck{
			{ID: "AZURE-STORAGE-BLOB-ANON", Provider: ProviderAzure, Service: "blob", Name: "Storage Account Public Blob Access", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "Microsoft.Storage/storageAccounts/read", Status: "READY"},
			{ID: "AZURE-APPSERVICE-HTTP", Provider: ProviderAzure, Service: "appservice", Name: "App Service Insecure HTTP Traffic", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "Microsoft.Web/sites/read", Status: "READY"},
			{ID: "AZURE-FUNC-ANON", Provider: ProviderAzure, Service: "functions", Name: "Function Anonymous HTTP Trigger", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "Microsoft.Web/sites/functions/read", Status: "READY"},
			{ID: "AZURE-KEYVAULT-PUBLIC", Provider: ProviderAzure, Service: "keyvault", Name: "Key Vault Public Network Access", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "Microsoft.KeyVault/vaults/read", Status: "READY"},
			{ID: "AZURE-IAM-OWNER", Provider: ProviderAzure, Service: "identity", Name: "Subscription-Level Owner Role Assignment", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "Microsoft.Authorization/roleAssignments/read", Status: "READY"},
		}
	case ProviderGCP:
		plan.TargetScope = fmt.Sprintf("GCP Project: %s", ident.ProjectID)
		plan.PlannedChecks = []PlannedCheck{
			{ID: "GCP-GCS-PUBLIC-IAM", Provider: ProviderGCP, Service: "storage", Name: "Cloud Storage Bucket allUsers Binding", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "storage.buckets.getIamPolicy", Status: "READY"},
			{ID: "GCP-CLOUDRUN-PUBLIC", Provider: ProviderGCP, Service: "cloudrun", Name: "Cloud Run allUsers Invoker Binding", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "run.services.getIamPolicy", Status: "READY"},
			{ID: "GCP-COMPUTE-FW-MGMT", Provider: ProviderGCP, Service: "compute", Name: "VPC Inbound Management Port 0.0.0.0/0", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "compute.firewalls.list", Status: "READY"},
			{ID: "GCP-IAM-PRIMITIVE-OWNER", Provider: ProviderGCP, Service: "iam", Name: "Project-Level Primitive Owner Role", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "resourcemanager.projects.getIamPolicy", Status: "READY"},
			{ID: "GCP-CLOUDSQL-PUBLIC-NET", Provider: ProviderGCP, Service: "cloudsql", Name: "Cloud SQL 0.0.0.0/0 Authorized Network", Mode: ModeCredentialed, ReadOnly: true, RequiredAPI: "sqladmin.instances.get", Status: "READY"},
		}
	}

	plan.ReadyChecks = len(plan.PlannedChecks)
	return plan, nil
}

// Assess executes the cloud assessment according to the selected mode and authorized scope.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, []report.Finding, *Summary, error) {
	client := e.scopedClient(actx)

	var allResults []Result
	var allFindings []report.Finding
	coverageMap := make(map[string]ServiceCoverage)

	var targetScope string
	var verifiedPrincipal string

	if actx.Mode == ModeExternal {
		targetScope = fmt.Sprintf("%d external targets", len(actx.ExternalTargets))
		eval := NewExternalEvaluator(e.config)
		res, fnd, cov := eval.Assess(ctx, actx, client)
		allResults = append(allResults, res...)
		allFindings = append(allFindings, fnd...)
		for k, v := range cov {
			coverageMap[k] = v
		}
	} else {
		// Credentialed mode: verify identity and enforce scope
		iv := NewIdentityValidator(client)
		ident, err := iv.VerifyIdentity(ctx, actx.Credentials, actx.Scope)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("credentialed identity verification failed: %w", err)
		}
		if !ident.IsScopeMatched {
			return nil, nil, nil, fmt.Errorf("scope enforcement failure: %s", ident.ScopeMismatchMsg)
		}

		verifiedPrincipal = ident.PrincipalARN
		if verifiedPrincipal == "" {
			verifiedPrincipal = ident.ServiceAccount
		}
		if verifiedPrincipal == "" {
			verifiedPrincipal = ident.TenantID
		}

		switch actx.Provider {
		case ProviderAWS:
			targetScope = fmt.Sprintf("AWS Account: %s", ident.AccountID)
			adapter := NewAWSAdapter(e.config)
			res, fnd, cov := adapter.Assess(ctx, actx, client)
			allResults = append(allResults, res...)
			allFindings = append(allFindings, fnd...)
			for k, v := range cov {
				coverageMap[k] = v
			}
		case ProviderAzure:
			targetScope = fmt.Sprintf("Azure Subscription: %s", ident.SubscriptionID)
			adapter := NewAzureAdapter(e.config)
			res, fnd, cov := adapter.Assess(ctx, actx, client)
			allResults = append(allResults, res...)
			allFindings = append(allFindings, fnd...)
			for k, v := range cov {
				coverageMap[k] = v
			}
		case ProviderGCP:
			targetScope = fmt.Sprintf("GCP Project: %s", ident.ProjectID)
			adapter := NewGCPAdapter(e.config)
			res, fnd, cov := adapter.Assess(ctx, actx, client)
			allResults = append(allResults, res...)
			allFindings = append(allFindings, fnd...)
			for k, v := range cov {
				coverageMap[k] = v
			}
		default:
			return nil, nil, nil, fmt.Errorf("unsupported provider: %s", actx.Provider)
		}
	}

	summary := e.compileSummary(actx.Mode, actx.Provider, targetScope, verifiedPrincipal, allResults, coverageMap, actx.SyntheticFixture)
	return allResults, allFindings, summary, nil
}

func (e *Engine) compileSummary(
	mode AssessmentMode,
	provider Provider,
	targetScope string,
	verifiedPrincipal string,
	results []Result,
	coverage map[string]ServiceCoverage,
	syntheticFixture bool,
) *Summary {
	sum := &Summary{
		Mode:               mode,
		Provider:           provider,
		TargetScope:        targetScope,
		VerifiedPrincipal:  verifiedPrincipal,
		SyntheticFixture:   syntheticFixture,
		TotalChecks:        len(results),
		ServicesAssessed:   len(coverage),
		ServiceCoverageMap: coverage,
	}

	for _, r := range results {
		switch r.VerificationState {
		case StateVerified:
			sum.VerifiedCount++
		case StateCandidate:
			sum.CandidateCount++
		case StateObserved:
			sum.ObservedCount++
		case StateInconclusive:
			sum.InconclusiveCount++
		case StateNotVulnerable:
			sum.NotVulnerableCount++
		}
	}

	return sum
}
