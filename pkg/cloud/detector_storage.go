package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	azureBlobRegex = regexp.MustCompile(`https://([a-zA-Z0-9_\-]+)\.blob\.core\.windows\.net(?:/[a-zA-Z0-9_\.\-]*)?`)
	minioURLRegex  = regexp.MustCompile(`https?://[a-zA-Z0-9_\.\-]+:9000(?:/[a-zA-Z0-9_\.\-]*)?`)
)

// ExtractStorageTargets inspects content for object storage references across S3, Azure, GCS, and MinIO.
func ExtractStorageTargets(source string, content []byte) []DiscoveredService {
	var results []DiscoveredService
	text := string(content)
	now := time.Now().UTC()

	// 1. AWS S3
	for _, match := range s3HostRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".s3.amazonaws.com"
		results = append(results, DiscoveredService{
			Technology:      TechAWSS3,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            match[1] + ".s3.amazonaws.com",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered AWS S3 bucket URL in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"bucket": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}
	for _, match := range s3PathRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://s3.amazonaws.com/" + match[1]
		results = append(results, DiscoveredService{
			Technology:      TechAWSS3,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            "s3.amazonaws.com",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered AWS S3 path URL in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"bucket": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}

	// 2. Azure Blob Storage
	for _, match := range azureBlobRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".blob.core.windows.net"
		results = append(results, DiscoveredService{
			Technology:      TechAzureBlob,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            match[1] + ".blob.core.windows.net",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Azure Blob Storage account in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"account": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}

	// 3. Google Cloud Storage
	for _, match := range gcsHostRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://storage.googleapis.com/" + match[1]
		results = append(results, DiscoveredService{
			Technology:      TechGCS,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            "storage.googleapis.com",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Google Cloud Storage bucket URL in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"bucket": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}
	for _, match := range gcsSubRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".storage.googleapis.com"
		results = append(results, DiscoveredService{
			Technology:      TechGCS,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            match[1] + ".storage.googleapis.com",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Google Cloud Storage subdomain URL in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"bucket": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}

	// 4. MinIO candidate port :9000
	for _, match := range minioURLRegex.FindAllString(text, -1) {
		results = append(results, DiscoveredService{
			Technology:      TechMinIO,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Endpoint:        match,
			Protocol:        "http",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered MinIO candidate port 9000 reference in %s: %s", source, match),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	return results
}

// ProbeAWSS3 executes safe HTTP verification against an AWS S3 bucket without enumerating objects.
func ProbeAWSS3(ctx context.Context, client *Client, bucketURL string) DiscoveredService {
	parsed, err := url.Parse(bucketURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechAWSS3,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     bucketURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	probeURL := strings.TrimRight(bucketURL, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, "HEAD", probeURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechAWSS3,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     bucketURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		// Fallback to bounded non-enumerating GET if HEAD is rejected by transport
		reqGET, errGET := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if errGET != nil {
			return DiscoveredService{
				Technology:      TechAWSS3,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeInconclusive,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
		resp, err = client.Do(ctx, reqGET)
		if err != nil {
			return DiscoveredService{
				Technology:      TechAWSS3,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeInconclusive,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
	}

	serverHdr := resp.Header.Get("Server")
	amzReqID := resp.Header.Get("x-amz-request-id")
	bodyStr := string(resp.Body)

	isS3 := strings.Contains(serverHdr, "AmazonS3") || amzReqID != "" || strings.Contains(bodyStr, "AmazonS3")

	if isS3 {
		metadata := map[string]any{
			"server": serverHdr,
		}
		if amzReqID != "" {
			metadata["amz_request_id"] = amzReqID
		}

		// 1. Unauthenticated root response
		if resp.StatusCode == http.StatusOK {
			return DiscoveredService{
				Technology:      TechAWSS3,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				Protocol:        parsed.Scheme,
				DetectionMethod: "HTTP_PROBE",
				AuthRequired:    false,
				PublicAccess:    false, // Discovery probe does not establish public data access; Phase 2.2 verifies permissions
				Evidence:        fmt.Sprintf("AWS S3 endpoint confirmed via response headers (HTTP 200, Server: %s)", serverHdr),
				Metadata:        metadata,
				Limitations:     "Root responded 200 OK; object read and write boundaries deferred to Phase 2.2",
				InScope:         true,
				DiscoveredAt:    time.Now().UTC(),
			}
		}

		// 2. Protected Bucket (HTTP 403 or 401 with S3 headers)
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			return DiscoveredService{
				Technology:      TechAWSS3,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				Protocol:        parsed.Scheme,
				DetectionMethod: "HTTP_PROBE",
				AuthRequired:    true,
				PublicAccess:    false,
				Evidence:        fmt.Sprintf("AWS S3 bucket confirmed: access restricted (HTTP %d, Server: %s, x-amz-request-id: %s)", resp.StatusCode, serverHdr, amzReqID),
				Metadata:        metadata,
				InScope:         true,
				DiscoveredAt:    time.Now().UTC(),
			}
		}

		// 3. Bucket does not exist (HTTP 404)
		if resp.StatusCode == http.StatusNotFound && (strings.Contains(bodyStr, "NoSuchBucket") || amzReqID != "") {
			return DiscoveredService{
				Technology:      TechAWSS3,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeNotDetected,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Evidence:        "AWS S3 bucket does not exist (HTTP 404 NoSuchBucket)",
				DiscoveredAt:    time.Now().UTC(),
			}
		}

		return DiscoveredService{
			Technology:      TechAWSS3,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        bucketURL,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    false,
			PublicAccess:    false,
			Evidence:        fmt.Sprintf("AWS S3 service headers observed (HTTP %d, Server: %s)", resp.StatusCode, serverHdr),
			Metadata:        metadata,
			InScope:         true,
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	return DiscoveredService{
		Technology:      TechAWSS3,
		Family:          FamilyObjectStorage,
		Outcome:         OutcomeNotDetected,
		Endpoint:        bucketURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("HTTP status %d returned without AWS S3 signatures", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}

// ProbeAzureBlob executes safe HTTP verification against an Azure Blob Storage container without enumeration.
func ProbeAzureBlob(ctx context.Context, client *Client, containerURL string) DiscoveredService {
	parsed, err := url.Parse(containerURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechAzureBlob,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     containerURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	probeURL := strings.TrimRight(containerURL, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, "HEAD", probeURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechAzureBlob,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     containerURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		reqGET, errGET := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if errGET != nil {
			return DiscoveredService{
				Technology:      TechAzureBlob,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeInconclusive,
				Endpoint:        containerURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
		resp, err = client.Do(ctx, reqGET)
		if err != nil {
			return DiscoveredService{
				Technology:      TechAzureBlob,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeInconclusive,
				Endpoint:        containerURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
	}

	serverHdr := resp.Header.Get("Server")
	msReqID := resp.Header.Get("x-ms-request-id")
	bodyStr := string(resp.Body)

	isAzure := strings.Contains(serverHdr, "Windows-Azure-Blob") || msReqID != ""

	if isAzure {
		metadata := map[string]any{
			"server": serverHdr,
		}
		if msReqID != "" {
			metadata["ms_request_id"] = msReqID
		}

		authRequired := resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized || strings.Contains(bodyStr, "AuthenticationFailed")

		return DiscoveredService{
			Technology:      TechAzureBlob,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        containerURL,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    authRequired,
			PublicAccess:    false, // Non-enumerating probe; access verification deferred to Phase 2.2
			Evidence:        fmt.Sprintf("Azure Blob Storage confirmed via service headers (Server: %s, x-ms-request-id: %s)", serverHdr, msReqID),
			Metadata:        metadata,
			Limitations:     "Service headers identify Azure Blob storage; container read boundaries deferred to Phase 2.2",
			InScope:         true,
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	return DiscoveredService{
		Technology:      TechAzureBlob,
		Family:          FamilyObjectStorage,
		Outcome:         OutcomeNotDetected,
		Endpoint:        containerURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("HTTP status %d returned without Azure Blob signatures", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}

// ProbeGCS executes safe HTTP verification against a Google Cloud Storage bucket without enumeration.
func ProbeGCS(ctx context.Context, client *Client, bucketURL string) DiscoveredService {
	parsed, err := url.Parse(bucketURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechGCS,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     bucketURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	probeURL := strings.TrimRight(bucketURL, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, "HEAD", probeURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechGCS,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     bucketURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		reqGET, errGET := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if errGET != nil {
			return DiscoveredService{
				Technology:      TechGCS,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeInconclusive,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
		resp, err = client.Do(ctx, reqGET)
		if err != nil {
			return DiscoveredService{
				Technology:      TechGCS,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeInconclusive,
				Endpoint:        bucketURL,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
	}

	serverHdr := resp.Header.Get("Server")
	googGen := resp.Header.Get("x-goog-generation")

	isGCS := strings.Contains(serverHdr, "UploadServer") || strings.Contains(serverHdr, "GSE") || googGen != ""

	if isGCS {
		metadata := map[string]any{
			"server": serverHdr,
		}
		if googGen != "" {
			metadata["goog_generation"] = googGen
		}

		authRequired := resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized

		return DiscoveredService{
			Technology:      TechGCS,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        bucketURL,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    authRequired,
			PublicAccess:    false, // Non-enumerating probe; storage permissions deferred to Phase 2.2
			Evidence:        fmt.Sprintf("Google Cloud Storage confirmed via service headers (Server: %s)", serverHdr),
			Metadata:        metadata,
			Limitations:     "Service headers identify GCS bucket; public read permissions deferred to Phase 2.2",
			InScope:         true,
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return DiscoveredService{
			Technology:      TechGCS,
			Family:          FamilyObjectStorage,
			Outcome:         OutcomeNotDetected,
			Endpoint:        bucketURL,
			Host:            parsed.Hostname(),
			DetectionMethod: "HTTP_PROBE",
			Evidence:        "GCS bucket does not exist (HTTP 404 NoSuchBucket)",
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	return DiscoveredService{
		Technology:      TechGCS,
		Family:          FamilyObjectStorage,
		Outcome:         OutcomeNotDetected,
		Endpoint:        bucketURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("HTTP status %d returned without GCS signatures", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}

// ProbeMinIO executes safe HTTP verification against a candidate MinIO server.
func ProbeMinIO(ctx context.Context, client *Client, baseURL string) DiscoveredService {
	cleanBase := strings.TrimRight(baseURL, "/")
	parsed, err := url.Parse(cleanBase)
	if err != nil {
		return DiscoveredService{
			Technology:   TechMinIO,
			Family:       FamilyObjectStorage,
			Outcome:      OutcomeError,
			Endpoint:     baseURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	now := time.Now().UTC()

	// Step 1: Probe health endpoint /minio/health/ready
	healthURL := cleanBase + "/minio/health/ready"
	reqH, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err == nil {
		if respH, err := client.Do(ctx, reqH); err == nil && respH.StatusCode == http.StatusOK {
			return DiscoveredService{
				Technology:      TechMinIO,
				Family:          FamilyObjectStorage,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        cleanBase,
				Host:            parsed.Hostname(),
				Port:            9000,
				Protocol:        parsed.Scheme,
				DetectionMethod: "HTTP_PROBE",
				AuthRequired:    false,
				PublicAccess:    false, // Health endpoint reachability does NOT prove object-storage exposure
				Evidence:        "MinIO deployment confirmed reachable via health endpoint (/minio/health/ready)",
				Limitations:     "Health check establishes service reachability; object storage data permissions require Phase 2.2 verification",
				InScope:         true,
				DiscoveredAt:    now,
			}
		}
	}

	// Step 2: Probe MinIO Console /minio/login
	loginURL := cleanBase + "/minio/login"
	reqL, err := http.NewRequestWithContext(ctx, "GET", loginURL, nil)
	if err == nil {
		if respL, err := client.Do(ctx, reqL); err == nil {
			bodyStr := string(respL.Body)
			if strings.Contains(bodyStr, "MinIO Console") || strings.Contains(bodyStr, "<title>MinIO</title>") {
				return DiscoveredService{
					Technology:      TechMinIO,
					Family:          FamilyObjectStorage,
					Outcome:         OutcomeDetected,
					Confidence:      ConfidenceHigh,
					Endpoint:        cleanBase,
					Host:            parsed.Hostname(),
					Port:            9000,
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					AuthRequired:    true,
					PublicAccess:    false,
					Evidence:        "MinIO web console login interface identified",
					InScope:         true,
					DiscoveredAt:    now,
				}
			}
		}
	}

	// Step 3: Probe root endpoint for MinIO Server header
	reqR, err := http.NewRequestWithContext(ctx, "HEAD", cleanBase+"/", nil)
	if err == nil {
		if respR, err := client.Do(ctx, reqR); err == nil {
			serverHdr := respR.Header.Get("Server")
			minioDepID := respR.Header.Get("x-minio-deployment-id")

			if strings.Contains(serverHdr, "MinIO") || minioDepID != "" {
				return DiscoveredService{
					Technology:      TechMinIO,
					Family:          FamilyObjectStorage,
					Outcome:         OutcomeDetected,
					Confidence:      ConfidenceHigh,
					Endpoint:        cleanBase,
					Host:            parsed.Hostname(),
					Port:            9000,
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					AuthRequired:    true,
					PublicAccess:    false,
					Evidence:        fmt.Sprintf("MinIO server signature confirmed in response (Server: %q, DeploymentID: %q)", serverHdr, minioDepID),
					Metadata: map[string]any{
						"server":        serverHdr,
						"deployment_id": minioDepID,
					},
					InScope:      true,
					DiscoveredAt: now,
				}
			}
		}
	}

	return DiscoveredService{
		Technology:      TechMinIO,
		Family:          FamilyObjectStorage,
		Outcome:         OutcomeNotDetected,
		Endpoint:        cleanBase,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        "No MinIO server headers or endpoints observed",
		DiscoveredAt:    now,
	}
}
