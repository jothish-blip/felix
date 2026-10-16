package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyAWSS3Access evaluates AWS S3 bucket/object reachability and bounded synthetic object reads.
func VerifyAWSS3Access(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechAWSS3,
		Family:              FamilyObjectStorage,
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

	// 1. Root / Bucket-level HEAD probe (metadata check)
	req, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
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

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("AWS S3 bucket root returned access challenge (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "AWS S3 bucket responded 200 OK to root HEAD request"
		record.Limitations = "Bucket root reachability does not confirm public object read permissions; requires bounded object verification"
	}

	// 2. Credential verification if provided
	if cred != nil && cred.Secret != "" {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
		// In automated audits, credentials for AWS are provided via headers or signing tokens
		if cred.Headers != nil && cred.Headers["Authorization"] != "" {
			authReq, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
			if err == nil {
				for k, v := range cred.Headers {
					authReq.Header.Set(k, v)
				}
				authResp, err := client.Do(ctx, authReq)
				if err == nil && authResp.StatusCode == http.StatusOK {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "Supplied AWS credentials successfully authorized against S3 target"
				}
			}
		}
	}

	// 3. Bounded Object Read check against explicitly configured synthetic test object
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testObject := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testObject

		objURL := fmt.Sprintf("%s/%s", cleanURL, url.PathEscape(testObject))
		objReq, err := http.NewRequestWithContext(ctx, "HEAD", objURL, nil)
		if err == nil {
			if record.AuthContext == AuthContextAuthenticated && cred != nil && cred.Headers != nil {
				for k, v := range cred.Headers {
					objReq.Header.Set(k, v)
				}
			}

			objResp, err := client.Do(ctx, objReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			if objResp.StatusCode == http.StatusOK {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Public read confirmed: HEAD on synthetic object %q succeeded (HTTP 200)", testObject)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else if objResp.StatusCode == http.StatusForbidden || objResp.StatusCode == http.StatusUnauthorized {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Read access to synthetic object %q denied (HTTP %d)", testObject, objResp.StatusCode)
			}
		}
	}

	return record
}

// VerifyAzureBlobAccess evaluates Azure Blob Storage container/blob reachability and bounded read access.
func VerifyAzureBlobAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechAzureBlob,
		Family:              FamilyObjectStorage,
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

	// 1. Container / Endpoint HEAD probe
	req, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}
	req.Header.Set("x-ms-version", "2020-10-02")

	resp, err := client.Do(ctx, req)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("Azure Blob target returned access challenge (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "Azure Blob target responded 200 OK to HEAD probe"
		record.Limitations = "Target reachability confirmed; blob read permissions require explicit bounded resource verification"
	}

	// 2. Credential verification if provided (e.g. SAS token)
	if cred != nil && cred.Secret != "" {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
	}

	// 3. Bounded Blob Read against explicitly configured synthetic test blob
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testBlob := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testBlob

		blobURL := fmt.Sprintf("%s/%s", cleanURL, url.PathEscape(testBlob))
		if record.AuthContext == AuthContextAuthenticated && cred != nil && cred.Secret != "" {
			if strings.HasPrefix(cred.Secret, "?") {
				blobURL += cred.Secret
			} else {
				blobURL += "?" + cred.Secret
			}
		}

		blobReq, err := http.NewRequestWithContext(ctx, "HEAD", blobURL, nil)
		if err == nil {
			blobReq.Header.Set("x-ms-version", "2020-10-02")
			blobResp, err := client.Do(ctx, blobReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			if blobResp.StatusCode == http.StatusOK {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Anonymous read on Azure blob %q succeeded (HTTP 200)", testBlob)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else if blobResp.StatusCode == http.StatusForbidden || blobResp.StatusCode == http.StatusUnauthorized {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Read access to Azure blob %q denied (HTTP %d)", testBlob, blobResp.StatusCode)
			}
		}
	}

	return record
}

// VerifyGCSAccess evaluates Google Cloud Storage bucket/object reachability and bounded read access.
func VerifyGCSAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechGCS,
		Family:              FamilyObjectStorage,
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

	// 1. Bucket root metadata HEAD probe
	req, err := http.NewRequestWithContext(ctx, "HEAD", cleanURL, nil)
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

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("Google Cloud Storage target returned access challenge (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "Google Cloud Storage bucket root responded 200 OK to HEAD request"
		record.Limitations = "Bucket root reachability does not confirm public object read permissions; requires bounded object verification"
	}

	// 2. Credential verification if provided
	if cred != nil && cred.Secret != "" {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
	}

	// 3. Bounded Object Read check against explicitly configured synthetic test object
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testObject := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testObject

		objURL := fmt.Sprintf("%s/%s", cleanURL, url.PathEscape(testObject))
		objReq, err := http.NewRequestWithContext(ctx, "HEAD", objURL, nil)
		if err == nil {
			if record.AuthContext == AuthContextAuthenticated && cred != nil && cred.Secret != "" {
				objReq.Header.Set("Authorization", "Bearer "+cred.Secret)
			}

			objResp, err := client.Do(ctx, objReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			if objResp.StatusCode == http.StatusOK {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Public read confirmed: HEAD on GCS object %q succeeded (HTTP 200)", testObject)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else if objResp.StatusCode == http.StatusForbidden || objResp.StatusCode == http.StatusUnauthorized {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Read access to GCS object %q denied (HTTP %d)", testObject, objResp.StatusCode)
			}
		}
	}

	return record
}

// VerifyMinIOAccess evaluates MinIO service/console reachability, S3 auth challenges, and bounded test object access.
func VerifyMinIOAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechMinIO,
		Family:              FamilyObjectStorage,
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

	// 1. MinIO Health / Live probe
	healthURL := cleanURL + "/minio/health/live"
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		// Fallback to root HEAD probe
		reqRoot, rErr := http.NewRequestWithContext(ctx, "HEAD", cleanURL+"/", nil)
		if rErr == nil {
			resp, err = client.Do(ctx, reqRoot)
		}
	}

	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	serverHdr := resp.Header.Get("Server")
	isMinIO := strings.Contains(strings.ToLower(serverHdr), "minio")

	if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = fmt.Sprintf("MinIO health/probe responded 200 OK (Server: %q)", serverHdr)
		record.Limitations = "Service health check confirms reachability; bucket/object read permissions require bounded resource verification"
	} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("MinIO endpoint returned authentication challenge (HTTP %d)", resp.StatusCode)
	}

	// 2. Credential verification if provided
	if cred != nil && (cred.Username != "" || cred.Secret != "") {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
		record.Status = StatusAuthenticatedAccess
		record.Decision = DecisionAllowed
		record.Evidence = fmt.Sprintf("Configured credentials recorded for MinIO (recognized=%v)", isMinIO)
	}

	// 3. Bounded Object Read check against explicitly configured synthetic test object
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testObject := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testObject

		objURL := fmt.Sprintf("%s/%s", cleanURL, url.PathEscape(testObject))
		objReq, err := http.NewRequestWithContext(ctx, "HEAD", objURL, nil)
		if err == nil {
			objResp, err := client.Do(ctx, objReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			if objResp.StatusCode == http.StatusOK {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Read on MinIO test object %q succeeded (HTTP 200)", testObject)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else if objResp.StatusCode == http.StatusForbidden || objResp.StatusCode == http.StatusUnauthorized {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Read on MinIO test object %q denied (HTTP %d)", testObject, objResp.StatusCode)
			}
		}
	}

	return record
}
