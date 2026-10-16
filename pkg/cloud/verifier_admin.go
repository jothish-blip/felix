package cloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VerifyMongoExpressAccess evaluates Mongo Express web console reachability, Basic Auth challenges, and bounded status checks.
func VerifyMongoExpressAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechMongoExpress,
		Family:              FamilyDatabaseAdmin,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	cleanURL := strings.TrimRight(targetURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	// 1. Unauthenticated root request
	req, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/", nil)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	bodyStr := string(resp.Body)
	isMongoExp := strings.Contains(bodyStr, "Mongo Express") ||
		strings.Contains(bodyStr, "mongo-express") ||
		strings.Contains(resp.Header.Get("X-Powered-By"), "Express")

	if resp.StatusCode == http.StatusUnauthorized {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = "Mongo Express returned HTTP 401 Basic Authentication challenge"
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = fmt.Sprintf("Mongo Express web console reachable (HTTP 200, recognized=%v)", isMongoExp)
		record.Limitations = "Console reachability verified; does not confirm underlying MongoDB read/write permissions"
		if isMongoExp && strings.Contains(bodyStr, "Database") {
			// Unprotected console exposed without credentials
			record.Status = StatusUnauthenticatedAccess
			record.FindingSuitable = true
			record.Evidence = "Mongo Express console accessible without authentication"
		}
	}

	// 2. Authenticated check if credential profile provided
	if cred != nil && (cred.Username != "" || cred.Secret != "") {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true

		authReq, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/", nil)
		if err == nil {
			authReq.SetBasicAuth(cred.Username, cred.Secret)
			authResp, err := client.Do(ctx, authReq)
			if err == nil {
				if authResp.StatusCode == http.StatusOK {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "Mongo Express console authenticated successfully with provided credentials"
				} else {
					record.Status = StatusAuthChallenged
					record.Decision = DecisionDenied
					record.Evidence = fmt.Sprintf("Mongo Express credentials rejected (HTTP %d)", authResp.StatusCode)
				}
			}
		}
	}

	// 3. Bounded check on test resource (e.g. status endpoint or explicit path)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		record.Operation = OpBoundedRead
		record.ResourceScope = resConfig.ResourceID

		testPath := strings.TrimLeft(resConfig.ResourceID, "/")
		subReqURL := fmt.Sprintf("%s/%s", cleanURL, testPath)
		subReq, err := http.NewRequestWithContext(ctx, "GET", subReqURL, nil)
		if err == nil {
			if record.AuthContext == AuthContextAuthenticated && cred != nil {
				subReq.SetBasicAuth(cred.Username, cred.Secret)
			}
			subResp, err := client.Do(ctx, subReq)
			if err == nil {
				if subResp.StatusCode == http.StatusOK {
					record.Status = StatusReadAllowed
					record.Decision = DecisionAllowed
					record.Evidence = fmt.Sprintf("Read access to Mongo Express resource %q succeeded (HTTP 200)", resConfig.ResourceID)
					if record.AuthContext == AuthContextUnauthenticated {
						record.FindingSuitable = true
					}
				} else if subResp.StatusCode == http.StatusUnauthorized || subResp.StatusCode == http.StatusForbidden {
					record.Status = StatusReadDenied
					record.Decision = DecisionDenied
					record.Evidence = fmt.Sprintf("Access to Mongo Express resource %q denied (HTTP %d)", resConfig.ResourceID, subResp.StatusCode)
				}
			}
		}
	}

	return record
}
