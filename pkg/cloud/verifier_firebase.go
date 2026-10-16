package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyFirebaseRTDBAccess evaluates Firebase Realtime Database reachability, security rules, and bounded test path reads.
func VerifyFirebaseRTDBAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechFirebaseRTDB,
		Family:              FamilyFirebase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	cleanURL := strings.TrimRight(targetURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "https://" + cleanURL
	}

	// Default test path: never root /.json; use a dedicated synthetic test path if none specified
	testPath := "felix_test_path"
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testPath = strings.Trim(resConfig.ResourceID, "/")
	}
	record.ResourceScope = testPath
	record.Operation = OpBoundedRead

	// 1. Unauthenticated Bounded Read against test path (.json)
	probeURL := fmt.Sprintf("%s/%s.json?shallow=true&limitToFirst=1", cleanURL, url.PathEscape(testPath))
	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
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
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || strings.Contains(bodyStr, "Permission denied") {
		record.Status = StatusReadDenied
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("Firebase RTDB rules denied unauthenticated read on %q (HTTP %d)", testPath, resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusReadAllowed
		record.Decision = DecisionAllowed
		record.FindingSuitable = true
		record.Evidence = fmt.Sprintf("Firebase RTDB allowed unauthenticated public read on test path %q (HTTP 200)", testPath)
	}

	// 2. Credential verification if provided
	if cred != nil && cred.Secret != "" {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true

		authProbeURL := fmt.Sprintf("%s/%s.json?shallow=true&limitToFirst=1", cleanURL, url.PathEscape(testPath))
		authReq, err := http.NewRequestWithContext(ctx, "GET", authProbeURL, nil)
		if err == nil {
			authReq.Header.Set("Authorization", "Bearer "+cred.Secret)
			authResp, err := client.Do(ctx, authReq)
			if err != nil {
				classifyClientError(&record, err)
			} else {
				if authResp.StatusCode == http.StatusOK {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = fmt.Sprintf("Authenticated read on Firebase RTDB path %q succeeded with provided token", testPath)
				} else {
					record.Status = StatusAuthChallenged
					record.Decision = DecisionDenied
					record.Evidence = fmt.Sprintf("Provided Firebase RTDB authentication token rejected (HTTP %d)", authResp.StatusCode)
				}
			}
		}
	}

	return record
}

// VerifyFirestoreAccess evaluates Cloud Firestore reachability, rule enforcement, and bounded test document reads.
func VerifyFirestoreAccess(
	ctx context.Context,
	client *Client,
	projectID string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	target := projectID
	if !strings.HasPrefix(target, "http") {
		target = fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)", projectID)
	}

	record := AccessVerificationRecord{
		Target:              target,
		Technology:          TechFirestore,
		Family:              FamilyFirebase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	// 1. Root database metadata probe
	rootURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)", projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", rootURL, nil)
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("Firestore root metadata request denied (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "Firestore database metadata reachable (HTTP 200)"
		record.Limitations = "Database metadata visibility does not confirm document-level read permission"
	}

	// 2. Bounded document read if explicit test document is configured
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testDocPath := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testDocPath

		docURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", projectID, testDocPath)
		docReq, err := http.NewRequestWithContext(ctx, "GET", docURL, nil)
		if err == nil {
			if cred != nil && cred.Secret != "" {
				record.AuthContext = AuthContextAuthenticated
				record.CredentialUsed = true
				docReq.Header.Set("Authorization", "Bearer "+cred.Secret)
			}

			docResp, err := client.Do(ctx, docReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			if docResp.StatusCode == http.StatusOK {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Bounded read on Firestore document %q succeeded (HTTP 200)", testDocPath)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else if docResp.StatusCode == http.StatusUnauthorized || docResp.StatusCode == http.StatusForbidden {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Read on Firestore document %q denied by security rules (HTTP %d)", testDocPath, docResp.StatusCode)
			}
		}
	}

	return record
}
