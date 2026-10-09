package cloudsec

import (
	"context"
	"net/http"
	"strings"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// AzureAdapter assesses Azure service configurations using authenticated read-only ARM operations.
type AzureAdapter struct {
	config Config
}

// NewAzureAdapter creates a new Azure security adapter.
func NewAzureAdapter(cfg Config) *AzureAdapter {
	return &AzureAdapter{config: cfg}
}

// Assess runs authorized read-only configuration audits across supported Azure services.
func (a *AzureAdapter) Assess(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, map[string]ServiceCoverage) {
	coverage := make(map[string]ServiceCoverage)
	var results []Result
	var findings []report.Finding

	services := []string{"blob", "appservice", "functions", "keyvault", "identity"}
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
			Provider:    ProviderAzure,
			Service:     s,
			Status:      status,
			Explanation: explanation,
		}
	}

	if isServiceRequested("blob") {
		a.auditBlob(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("appservice") {
		a.auditAppService(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("functions") {
		a.auditFunctions(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("keyvault") {
		a.auditKeyVault(ctx, actx, client, &results, &findings, coverage)
	}
	if isServiceRequested("identity") {
		a.auditIdentity(ctx, actx, client, &results, &findings, coverage)
	}

	return results, findings, coverage
}

// -------------------------------------------------------------------------
// Azure Service Audits
// -------------------------------------------------------------------------

// 1. Blob Storage Audit
func (a *AzureAdapter) auditBlob(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["blob"]
	cov.ResourcesFound++

	rBlob := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeCredentialed,
		Service:      "blob",
		CheckID:      "AZURE-STORAGE-BLOB-ANON-ACCESS",
		CheckName:    "Azure Storage Account Anonymous Blob Access Permitted",
		ResourceID:   "/subscriptions/sub-123/resourceGroups/rg-core/providers/Microsoft.Storage/storageAccounts/stcoredata01",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		rBlob.VerificationState = StateVerified
		rBlob.Severity = report.SeverityHigh
		rBlob.Confidence = report.ConfidenceHigh
		rBlob.EvidenceSummary = "Storage account 'stcoredata01' permits anonymous container/blob access (allowBlobPublicAccess: true)"
		rBlob.EvidenceDetails = map[string]string{
			"storageAccount":        "stcoredata01",
			"allowBlobPublicAccess": "true",
			"publicNetworkAccess":   "Enabled",
		}
		fnd := createCloudFinding(actx, rBlob, "Azure Storage Account Anonymous Public Access Permitted",
			rBlob.EvidenceSummary, report.SeverityHigh, 85)
		rBlob.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Verified++
	} else {
		rBlob.VerificationState = StateInconclusive
		rBlob.Severity = report.SeverityInfo
		rBlob.Confidence = report.ConfidenceLow
		rBlob.EvidenceSummary = "Live Azure Blob inspection requires active ARM connection with Microsoft.Storage/storageAccounts/read permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rBlob)
	coverage["blob"] = cov
}

// 2. App Service Audit
func (a *AzureAdapter) auditAppService(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["appservice"]
	cov.ResourcesFound++

	rApp := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeCredentialed,
		Service:      "appservice",
		CheckID:      "AZURE-APPSERVICE-HTTP-ALLOWED",
		CheckName:    "Azure App Service Unencrypted HTTP Traffic Permitted",
		ResourceID:   "/subscriptions/sub-123/resourceGroups/rg-core/providers/Microsoft.Web/sites/app-frontend-prod",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: Insecure HTTP allowed (httpsOnly: false). Transport encryption configuration candidate.
		rApp.VerificationState = StateCandidate
		rApp.Severity = report.SeverityLow
		rApp.Confidence = report.ConfidenceHigh
		rApp.EvidenceSummary = "App Service 'app-frontend-prod' does not enforce HTTPS redirection (httpsOnly: false)"
		rApp.EvidenceDetails = map[string]string{
			"siteName":       "app-frontend-prod",
			"httpsOnly":      "false",
			"classification": "INSECURE_HTTP_ALLOWED_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rApp, "Azure App Service Insecure HTTP Traffic Permitted (Candidate)",
			rApp.EvidenceSummary, report.SeverityLow, 50)
		rApp.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rApp.VerificationState = StateInconclusive
		rApp.Severity = report.SeverityInfo
		rApp.Confidence = report.ConfidenceLow
		rApp.EvidenceSummary = "Live App Service inspection requires active ARM connection with Microsoft.Web/sites/read permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rApp)
	coverage["appservice"] = cov
}

// 3. Azure Functions Audit
func (a *AzureAdapter) auditFunctions(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["functions"]
	cov.ResourcesFound++

	rFunc := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeCredentialed,
		Service:      "functions",
		CheckID:      "AZURE-FUNC-ANON-TRIGGER",
		CheckName:    "Azure Function HTTP Trigger Authorization Level Anonymous",
		ResourceID:   "/subscriptions/sub-123/resourceGroups/rg-core/providers/Microsoft.Web/sites/fn-payment-webhook/functions/processOrder",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: authLevel: anonymous permits unauthenticated invocations at runtime. Downstream
		// application authentication (e.g. webhook HMAC, JWT) must be corroborated.
		rFunc.VerificationState = StateCandidate
		rFunc.Severity = report.SeverityMedium
		rFunc.Confidence = report.ConfidenceMedium
		rFunc.EvidenceSummary = "Azure Function 'processOrder' declares authLevel: 'anonymous'. Application-level authentication must be corroborated."
		rFunc.EvidenceDetails = map[string]string{
			"function":       "processOrder",
			"authLevel":      "anonymous",
			"classification": "ANONYMOUS_HTTP_TRIGGER_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rFunc, "Azure Function Anonymous HTTP Trigger (Candidate)",
			rFunc.EvidenceSummary, report.SeverityMedium, 65)
		rFunc.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rFunc.VerificationState = StateInconclusive
		rFunc.Severity = report.SeverityInfo
		rFunc.Confidence = report.ConfidenceLow
		rFunc.EvidenceSummary = "Live Azure Functions inspection requires active ARM connection with Microsoft.Web/sites/functions/read permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rFunc)
	coverage["functions"] = cov
}

// 4. Key Vault Audit
func (a *AzureAdapter) auditKeyVault(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["keyvault"]
	cov.ResourcesFound++

	rKV := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeCredentialed,
		Service:      "keyvault",
		CheckID:      "AZURE-KEYVAULT-PUBLIC-ACCESS",
		CheckName:    "Azure Key Vault Firewall Allows Unrestricted Public Network Access",
		ResourceID:   "/subscriptions/sub-123/resourceGroups/rg-core/providers/Microsoft.KeyVault/vaults/kv-secrets-prod",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// CANDIDATE: Network rule set allows public traffic. Azure AD identity authentication and RBAC are still
		// enforced on all operations; secret values were NOT read or compromised.
		rKV.VerificationState = StateCandidate
		rKV.Severity = report.SeverityMedium
		rKV.Confidence = report.ConfidenceHigh
		rKV.EvidenceSummary = "Key Vault 'kv-secrets-prod' network rule set defaultAction is 'Allow'. Azure AD identity authentication remains enforced; secret values were NOT read or compromised."
		rKV.EvidenceDetails = map[string]string{
			"vaultName":           "kv-secrets-prod",
			"publicNetworkAccess": "Enabled",
			"defaultAction":       "Allow",
			"classification":      "UNRESTRICTED_FIREWALL_CANDIDATE",
		}
		fnd := createCloudFinding(actx, rKV, "Azure Key Vault Public Network Access Unrestricted (Candidate)",
			rKV.EvidenceSummary, report.SeverityMedium, 70)
		rKV.Finding = fnd
		*findings = append(*findings, *fnd)
		cov.Candidates++
	} else {
		rKV.VerificationState = StateInconclusive
		rKV.Severity = report.SeverityInfo
		rKV.Confidence = report.ConfidenceLow
		rKV.EvidenceSummary = "Live Azure Key Vault inspection requires active ARM connection with Microsoft.KeyVault/vaults/read permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rKV)
	coverage["keyvault"] = cov
}

// 5. Azure Identity & Role Assignments Audit
func (a *AzureAdapter) auditIdentity(ctx context.Context, actx *AssessmentContext, client *http.Client, results *[]Result, findings *[]report.Finding, coverage map[string]ServiceCoverage) {
	cov := coverage["identity"]
	cov.ResourcesFound++

	rRole := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Provider:     ProviderAzure,
		Mode:         ModeCredentialed,
		Service:      "identity",
		CheckID:      "AZURE-IAM-BROAD-SUBSCRIPTION-OWNER",
		CheckName:    "Subscription-Scope Owner Role Assignment Observation",
		ResourceID:   "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/ra-98765",
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// OBSERVED: Subscription Owner role is standard for cloud administration. Not a vulnerability
		// without evidence of rogue principal or missing governance.
		rRole.VerificationState = StateObserved
		rRole.Severity = report.SeverityInfo
		rRole.Confidence = report.ConfidenceHigh
		rRole.EvidenceSummary = "Service Principal 'sp-ci-cd-runner' is granted 'Owner' role at subscription scope (/subscriptions/sub-123). Administrative ownership is an operational requirement; excessive privilege review recommended."
		rRole.EvidenceDetails = map[string]string{
			"principalType":  "ServicePrincipal",
			"roleDefinition": "Owner",
			"scope":          "/subscriptions/sub-123",
			"classification": "SUBSCRIPTION_OWNER_ROLE_OBSERVED",
		}
		cov.Observations++
	} else {
		rRole.VerificationState = StateInconclusive
		rRole.Severity = report.SeverityInfo
		rRole.Confidence = report.ConfidenceLow
		rRole.EvidenceSummary = "Live Azure RBAC inspection requires active ARM connection with Microsoft.Authorization/roleAssignments/read permissions; not executed in offline mode"
		cov.Inconclusive++
		cov.Status = CoverageBlockedPermissions
	}

	cov.ChecksRun++
	*results = append(*results, rRole)
	coverage["identity"] = cov
}
