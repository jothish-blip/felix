package auth

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"felix/pkg/crawler"
	"felix/pkg/discovery"
	"felix/pkg/report"
)

// Engine orchestrates authentication surface discovery, classification, evidence, and safe verification.
type Engine struct {
	classifier *Classifier
	protected  *ProtectedEndpointClassifier
}

// NewEngine creates an authentication intelligence engine instance.
func NewEngine() *Engine {
	return &Engine{
		classifier: NewClassifier(),
		protected:  NewProtectedEndpointClassifier(),
	}
}

// AnalyzeAuthentication processes target discovery artifacts, responses, and scripts to build the AuthInventory.
func (e *Engine) AnalyzeAuthentication(
	inv *discovery.Inventory,
	crawledAssets []crawler.Asset,
	respHeader http.Header,
	targetURL string,
	asmID, execID, targetID string,
) (AuthInventory, []report.Finding) {
	var authInv AuthInventory
	var findings []report.Finding
	seenSurfaces := make(map[string]struct{})

	addSurface := func(s AuthSurface) {
		if _, exists := seenSurfaces[s.CanonicalID]; !exists {
			seenSurfaces[s.CanonicalID] = struct{}{}
			authInv.Surfaces = append(authInv.Surfaces, s)
		}
	}

	// 1. Passive Cookie Analysis
	cookies := ParseAndAnalyzeCookies(respHeader, targetURL, asmID, execID, targetID)
	authInv.Cookies = append(authInv.Cookies, cookies...)

	for _, c := range cookies {
		if c.IsSession && c.HasSecurityIssue {
			for _, defect := range c.SecurityDefects {
				severity := report.SeverityLow
				score := 20
				if strings.Contains(defect, "Secure") {
					score = 25
				}

				fp := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:cookie:%s:%s", targetURL, c.Name, defect))))
				findings = append(findings, report.Finding{
					ID:          uuid.New().String(),
					Title:       fmt.Sprintf("Session Cookie Security Defect: %s (%s)", c.Name, defect),
					Category:    "Authentication / Session Security",
					Severity:    severity,
					Confidence:  report.ConfidenceHigh,
					Target:      targetURL,
					Endpoint:    c.Path,
					Method:      "GET",
					Description: fmt.Sprintf("Session cookie '%s' observed with security defect: %s.", c.Name, defect),
					Evidence:    fmt.Sprintf("Cookie name: %s | Secure: %t | HttpOnly: %t | SameSite: %s", c.Name, c.IsSecure, c.IsHTTPOnly, c.SameSite),
					EvidenceDetails: report.EvidenceDetails{
						Observation:     defect,
						Location:        fmt.Sprintf("Set-Cookie Header on %s", targetURL),
						HTTPMethod:      "GET",
						DetectionMethod: "PASSIVE_COOKIE_INSPECTION",
					},
					Verification: report.VerificationRecord{
						Status:    report.VerificationVerified,
						Result:    "Verified cookie attributes on authorized response",
						Rationale: "Observed directly in Set-Cookie header without secret disclosure",
					},
					Remediation: "", // Explicitly deferred in Stage 3 per specification
					Source:      "auth",
					Fingerprint: fp,
					Score:       score,
				})
			}
		}
	}

	// 2. Token Analysis across Crawled Assets
	for _, asset := range crawledAssets {
		text := string(asset.Content)
		tokens := ExtractAndAnalyzeTokens(text, asset.URL, asmID, execID, targetID)
		authInv.Tokens = append(authInv.Tokens, tokens...)

		for _, t := range tokens {
			if t.TokenType == "PKCE" && t.Algorithm == "PLAIN" {
				fp := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:pkce:plain", asset.URL))))
				findings = append(findings, report.Finding{
					ID:          uuid.New().String(),
					Title:       "Insecure PKCE Implementation (plain code_challenge_method)",
					Category:    "Authentication / OAuth PKCE",
					Severity:    report.SeverityMedium,
					Confidence:  report.ConfidenceHigh,
					Target:      targetURL,
					Endpoint:    asset.URL,
					Method:      "GET",
					Description: "Client authentication flow was observed declaring code_challenge_method='plain'. RFC 7636 requires 'S256' for secure authorization code interception defense.",
					Evidence:    t.EvidenceSummary,
					EvidenceDetails: report.EvidenceDetails{
						Observation:     "PKCE plain method observed",
						Location:        asset.URL,
						DetectionMethod: "STATIC_SCRIPT_TOKEN_ANALYSIS",
					},
					Verification: report.VerificationRecord{
						Status:    report.VerificationVerified,
						Result:    "Verified plain PKCE configuration in script bundle",
						Rationale: "Directly detected in client OAuth parameter setup",
					},
					Remediation: "",
					Source:      "auth",
					Fingerprint: fp,
					Score:       45,
				})
			}

			if t.TokenType == "JWT" && strings.EqualFold(t.Algorithm, "none") {
				fp := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:jwt:none", asset.URL))))
				findings = append(findings, report.Finding{
					ID:          uuid.New().String(),
					Title:       "Insecure JWT Algorithm ('none') in Client Asset",
					Category:    "Authentication / Token Security",
					Severity:    report.SeverityHigh,
					Confidence:  report.ConfidenceHigh,
					Target:      targetURL,
					Endpoint:    asset.URL,
					Method:      "GET",
					Description: "A JWT structure with algorithm 'none' was observed in client assets. Unsigned tokens allow arbitrary claim tampering if accepted by backend verification.",
					Evidence:    t.EvidenceSummary,
					EvidenceDetails: report.EvidenceDetails{
						Observation:     "JWT header specifies alg=none",
						Location:        asset.URL,
						DetectionMethod: "STATIC_JWT_HEADER_ANALYSIS",
					},
					Verification: report.VerificationRecord{
						Status:    report.VerificationVerified,
						Result:    "Verified alg=none in decoded JWT header",
						Rationale: "Base64 header inspection revealed unsigned token declaration",
					},
					Remediation: "",
					Source:      "auth",
					Fingerprint: fp,
					Score:       70,
				})
			}
		}

		// 3. Client Auth SDK Signatures
		sdkSurfaces := e.classifier.ClassifyScriptSDK(text, asset.URL, asmID, execID, targetID, "")
		for _, s := range sdkSurfaces {
			addSurface(s)
		}
	}

	// 4. Form Classification from Discovery Inventory
	if inv != nil {
		for _, a := range inv.Assets {
			if a.Type == discovery.AssetTypeForm {
				action, _ := a.Metadata["action"].(string)
				purpose, _ := a.Metadata["purpose"].(string)
				method, _ := a.Metadata["method"].(string)

				cat := CategoryUnknown
				sub := SubtypePassword
				switch purpose {
				case "LOGIN":
					cat = CategoryLogin
				case "REGISTRATION":
					cat = CategoryRegistration
				case "PASSWORD_RESET":
					cat = CategoryPasswordReset
				}

				if cat != CategoryUnknown {
					addSurface(AuthSurface{
						ID:                 uuid.New().String(),
						AssessmentID:       asmID,
						ExecutionID:        execID,
						TargetID:           targetID,
						CanonicalID:        fmt.Sprintf("FORM:%s:%s", cat, action),
						Category:           cat,
						Subtype:            sub,
						Identifier:         action,
						AppID:              a.ParentID,
						DiscoveryMethod:    "HTML_FORM",
						Confidence:         ConfidenceHigh,
						VerificationStatus: VerificationDiscovered,
						AuthState:          AuthStateAnonymousObserved,
						InScope:            true,
						Explanation:        fmt.Sprintf("HTML form for %s posting to %s", cat, action),
						Evidence: map[string]any{
							"action":  action,
							"method":  method,
							"purpose": purpose,
						},
						Metadata:  a.Metadata,
						CreatedAt: time.Now().UTC(),
						UpdatedAt: time.Now().UTC(),
					})
				}
			}
		}

		// 5. Endpoint & Parameter Correlation
		// Group parameters by endpoint to enable parameter-based auth classification
		endpointParams := make(map[string][]string)
		for _, a := range inv.Assets {
			if a.Type == discovery.AssetTypeParameter {
				epPath, _ := a.Metadata["endpoint_path"].(string)
				paramName, _ := a.Metadata["name"].(string)
				if epPath != "" && paramName != "" {
					endpointParams[epPath] = append(endpointParams[epPath], paramName)
				}
			}
		}

		for _, a := range inv.Assets {
			if a.Type == discovery.AssetTypeEndpoint {
				path, _ := a.Metadata["path"].(string)
				method, _ := a.Metadata["method"].(string)
				if path == "" {
					continue
				}

				// Check Route Naming
				cat, sub, isAuth, explanation := e.classifier.ClassifyRoute(path)

				// If not classified by route, check associated parameters
				if !isAuth {
					if pList, ok := endpointParams[path]; ok && len(pList) > 0 {
						cat, sub, isAuth, explanation = e.classifier.ClassifyFromParameters(path, pList)
					}
				}

				if isAuth {
					addSurface(AuthSurface{
						ID:                 uuid.New().String(),
						AssessmentID:       asmID,
						ExecutionID:        execID,
						TargetID:           targetID,
						CanonicalID:        fmt.Sprintf("ENDPOINT:%s:%s", cat, path),
						Category:           cat,
						Subtype:            sub,
						Identifier:         path,
						EndpointID:         a.ID,
						AppID:              a.ParentID,
						DiscoveryMethod:    "ROUTE_AND_PARAMETER_CORRELATION",
						Confidence:         ConfidenceHigh,
						VerificationStatus: VerificationDiscovered,
						AuthState:          AuthStateIndicatorPresent,
						InScope:            true,
						Explanation:        explanation,
						Evidence: map[string]any{
							"endpoint_path": path,
							"method":        method,
							"parameters":    endpointParams[path],
						},
						Metadata:  a.Metadata,
						CreatedAt: time.Now().UTC(),
						UpdatedAt: time.Now().UTC(),
					})
				}

				// 6. Protected Endpoint Evaluation
				authChallenge := respHeader.Get("WWW-Authenticate")
				locationHeader := respHeader.Get("Location")
				statusCode := 200 // Default observed status
				if codeVal, ok := a.Evidence["status_code"].(int); ok && codeVal > 0 {
					statusCode = codeVal
				}

				var associatedSurfaces []string
				if isAuth {
					associatedSurfaces = append(associatedSurfaces, fmt.Sprintf("%s (%s)", path, cat))
				}

				protInfo := e.protected.EvaluateEndpointProtection(path, method, statusCode, authChallenge, locationHeader, associatedSurfaces)
				authInv.ProtectedEndpoints = append(authInv.ProtectedEndpoints, protInfo)
			}
		}
	}

	return authInv, findings
}

// GenerateSummary calculates aggregate metrics from an AuthInventory.
func (e *Engine) GenerateSummary(inv AuthInventory) AuthSummary {
	summary := AuthSummary{
		TotalSurfaces:      len(inv.Surfaces),
		SurfacesByCategory: make(map[string]int),
		TotalCookies:       len(inv.Cookies),
		TotalTokens:        len(inv.Tokens),
		ProtectedEndpoints: len(inv.ProtectedEndpoints),
	}

	for _, s := range inv.Surfaces {
		summary.SurfacesByCategory[string(s.Category)]++
	}

	for _, c := range inv.Cookies {
		if c.IsSession {
			summary.SessionCookies++
		}
		if c.HasSecurityIssue {
			summary.InsecureCookies++
		}
	}

	return summary
}
