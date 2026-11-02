package cloudsec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudStorageMock provides a deterministic loopback mock server simulating AWS S3,
// Google Cloud Storage (GCS), and Azure Blob Storage endpoints for security auditing.
type CloudStorageMock struct {
	server       *httptest.Server
	URL          string
	mu           sync.RWMutex
	requestCount int
	requestLog   []StorageMockRequest
}

// StorageMockRequest records requests processed by the mock for test assertions.
type StorageMockRequest struct {
	Method  string
	Path    string
	Query   string
	Headers http.Header
	Time    time.Time
}

// NewCloudStorageMock creates and starts a loopback mock server with synthetic cloud storage fixtures.
func NewCloudStorageMock() *CloudStorageMock {
	mock := &CloudStorageMock{
		requestLog: make([]StorageMockRequest, 0),
	}

	mux := http.NewServeMux()

	// 1. AWS S3 Fixtures
	mux.HandleFunc("/s3-public-list/", mock.handleS3PublicList)
	mux.HandleFunc("/s3-public-list", mock.handleS3PublicList)
	mux.HandleFunc("/s3-public-obj/", mock.handleS3PublicObj)
	mux.HandleFunc("/s3-private/", mock.handleS3Private)
	mux.HandleFunc("/s3-private", mock.handleS3Private)
	mux.HandleFunc("/s3-missing/", mock.handleS3Missing)
	mux.HandleFunc("/s3-missing", mock.handleS3Missing)
	mux.HandleFunc("/s3-write-policy/", mock.handleS3WritePolicy)
	mux.HandleFunc("/s3-write-policy", mock.handleS3WritePolicy)
	mux.HandleFunc("/s3-public-acl/", mock.handleS3PublicACL)
	mux.HandleFunc("/s3-public-acl", mock.handleS3PublicACL)

	// 2. Google Cloud Storage (GCS) Fixtures
	mux.HandleFunc("/gcs-public-list/", mock.handleGCSPublicList)
	mux.HandleFunc("/gcs-public-list", mock.handleGCSPublicList)
	mux.HandleFunc("/storage/v1/b/gcs-public-list/o", mock.handleGCSPublicListJSON)
	mux.HandleFunc("/gcs-public-obj/", mock.handleGCSPublicObj)
	mux.HandleFunc("/gcs-private/", mock.handleGCSPrivate)
	mux.HandleFunc("/gcs-private", mock.handleGCSPrivate)
	mux.HandleFunc("/gcs-missing/", mock.handleGCSMissing)
	mux.HandleFunc("/gcs-missing", mock.handleGCSMissing)
	mux.HandleFunc("/gcs-allusers-iam/", mock.handleGCSAllUsersIAM)
	mux.HandleFunc("/gcs-allusers-iam", mock.handleGCSAllUsersIAM)

	// 3. Azure Blob Storage Fixtures
	mux.HandleFunc("/azure-public-list", mock.handleAzurePublicList)
	mux.HandleFunc("/azure-public-blob/", mock.handleAzurePublicBlob)
	mux.HandleFunc("/azure-private", mock.handleAzurePrivate)
	mux.HandleFunc("/azure-missing", mock.handleAzureMissing)
	mux.HandleFunc("/azure-public-config", mock.handleAzurePublicConfig)

	// 4. False-Positive Controls & Network Edge Cases
	mux.HandleFunc("/fp-html-200/", mock.handleFPHTML200)
	mux.HandleFunc("/fp-html-200", mock.handleFPHTML200)
	mux.HandleFunc("/fp-cdn-cache/", mock.handleFPCDNCache)
	mux.HandleFunc("/fp-rate-limit/", mock.handleFPRateLimit)
	mux.HandleFunc("/fp-malformed-xml/", mock.handleFPMalformedXML)
	mux.HandleFunc("/redirect-loop/", mock.handleRedirectLoop)
	mux.HandleFunc("/redirect-ssrf/", mock.handleRedirectSSRF)

	mock.server = httptest.NewServer(mux)
	mock.URL = mock.server.URL
	return mock
}

// Close terminates the mock server.
func (m *CloudStorageMock) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

func (m *CloudStorageMock) record(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestCount++
	m.requestLog = append(m.requestLog, StorageMockRequest{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		Headers: r.Header.Clone(),
		Time:    time.Now(),
	})
}

// RequestCount returns total recorded requests.
func (m *CloudStorageMock) RequestCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.requestCount
}

// -------------------------------------------------------------------------
// AWS S3 Handlers
// -------------------------------------------------------------------------

func (m *CloudStorageMock) handleS3PublicList(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", "SYNTHETIC-S3-REQ-001")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>s3-public-list</Name>
    <Prefix></Prefix>
    <Marker></Marker>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>audit_report.pdf</Key>
        <LastModified>2026-10-31T00:00:00.000Z</LastModified>
        <ETag>&quot;synthetic-etag-1&quot;</ETag>
        <Size>12800</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
    <Contents>
        <Key>customer_export.csv</Key>
        <LastModified>2026-10-31T01:00:00.000Z</LastModified>
        <ETag>&quot;synthetic-etag-2&quot;</ETag>
        <Size>45200</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
</ListBucketResult>`)
}

func (m *CloudStorageMock) handleS3PublicObj(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", "SYNTHETIC-S3-OBJ-002")

	if strings.HasSuffix(r.URL.Path, "sample.txt") || strings.HasSuffix(r.URL.Path, "audit_report.pdf") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "FELIX-SYNTHETIC-OBJECT-CONTENT-VERIFIED")
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
    <RequestId>SYNTHETIC-DENY-001</RequestId>
</Error>`)
}

func (m *CloudStorageMock) handleS3Private(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", "SYNTHETIC-S3-PRIVATE-003")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
    <RequestId>SYNTHETIC-DENY-002</RequestId>
</Error>`)
}

func (m *CloudStorageMock) handleS3Missing(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Server", "AmazonS3")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NoSuchBucket</Code>
    <Message>The specified bucket does not exist</Message>
    <BucketName>s3-missing</BucketName>
    <RequestId>SYNTHETIC-MISSING-001</RequestId>
</Error>`)
}

func (m *CloudStorageMock) handleS3WritePolicy(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "AmazonS3")
	if r.URL.Query().Has("policy") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		policyJSON := map[string]any{
			"Version": "2012-10-17",
			"Statement": []map[string]any{
				{
					"Sid":       "PublicPutObjectAccess",
					"Effect":    "Allow",
					"Principal": "*",
					"Action": []string{
						"s3:PutObject",
						"s3:PutObjectAcl",
						"s3:GetObject",
					},
					"Resource": "arn:aws:s3:::s3-write-policy/*",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(policyJSON)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<Error><Code>AccessDenied</Code></Error>`)
}

func (m *CloudStorageMock) handleS3PublicACL(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "AmazonS3")
	if r.URL.Query().Has("acl") {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>synthetic-owner-id</ID>
        <DisplayName>synthetic-owner</DisplayName>
    </Owner>
    <AccessControlList>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee>
            <Permission>READ</Permission>
        </Grant>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee>
            <Permission>WRITE</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>`)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<Error><Code>AccessDenied</Code></Error>`)
}

// -------------------------------------------------------------------------
// Google Cloud Storage (GCS) Handlers
// -------------------------------------------------------------------------

func (m *CloudStorageMock) handleGCSPublicList(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/xml; charset=UTF-8")
	w.Header().Set("Server", "UploadServer")
	w.Header().Set("x-goog-generation", "1730300000000000")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
    <Name>gcs-public-list</Name>
    <Prefix></Prefix>
    <Marker></Marker>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>dataset.parquet</Key>
        <Generation>1730300000100000</Generation>
        <Size>102400</Size>
    </Contents>
</ListBucketResult>`)
}

func (m *CloudStorageMock) handleGCSPublicListJSON(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{
    "kind": "storage#objects",
    "items": [
        {
            "kind": "storage#object",
            "id": "gcs-public-list/config.json/1730300000",
            "name": "config.json",
            "bucket": "gcs-public-list",
            "size": "2048",
            "contentType": "application/json"
        }
    ]
}`)
}

func (m *CloudStorageMock) handleGCSPublicObj(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "UploadServer")
	if strings.HasSuffix(r.URL.Path, "sample.txt") || strings.HasSuffix(r.URL.Path, "dataset.parquet") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "FELIX-SYNTHETIC-GCS-OBJECT-CONTENT-OK")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `{"error":{"code":403,"message":"Access denied for GCS bucket"}}`)
}

func (m *CloudStorageMock) handleGCSPrivate(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `{
    "error": {
        "code": 403,
        "message": "Access denied. Anonymous caller does not have storage.objects.list access to the Google Cloud Storage bucket.",
        "errors": [
            {
                "message": "Access denied",
                "domain": "global",
                "reason": "forbidden"
            }
        ]
    }
}`)
}

func (m *CloudStorageMock) handleGCSMissing(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, `{
    "error": {
        "code": 404,
        "message": "The specified bucket does not exist.",
        "errors": [
            {
                "message": "Not Found",
                "domain": "global",
                "reason": "notFound"
            }
        ]
    }
}`)
}

func (m *CloudStorageMock) handleGCSAllUsersIAM(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{
    "kind": "storage#policy",
    "resourceId": "projects/_/buckets/gcs-allusers-iam",
    "bindings": [
        {
            "role": "roles/storage.objectViewer",
            "members": ["allUsers"]
        },
        {
            "role": "roles/storage.legacyBucketWriter",
            "members": ["allUsers"]
        }
    ]
}`)
}

// -------------------------------------------------------------------------
// Azure Blob Storage Handlers
// -------------------------------------------------------------------------

func (m *CloudStorageMock) handleAzurePublicList(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0")
	w.Header().Set("x-ms-version", "2021-08-06")

	if r.URL.Query().Get("restype") == "container" && r.URL.Query().Get("comp") == "list" {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://127.0.0.1/" ContainerName="azure-public-list">
    <Blobs>
        <Blob>
            <Name>diagnostics.log</Name>
            <Properties>
                <Content-Length>8192</Content-Length>
                <Content-Type>text/plain</Content-Type>
                <BlobType>BlockBlob</BlobType>
            </Properties>
        </Blob>
    </Blobs>
    <NextMarker />
</EnumerationResults>`)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<Error><Code>AuthorizationFailure</Code></Error>`)
}

func (m *CloudStorageMock) handleAzurePublicBlob(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0")
	w.Header().Set("x-ms-blob-type", "BlockBlob")

	if strings.HasSuffix(r.URL.Path, "sample.txt") || strings.HasSuffix(r.URL.Path, "diagnostics.log") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "FELIX-SYNTHETIC-AZURE-BLOB-CONTENT-OK")
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<Error><Code>AuthorizationFailure</Code></Error>`)
}

func (m *CloudStorageMock) handleAzurePrivate(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0")
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<Error>
    <Code>AuthorizationFailure</Code>
    <Message>This request is not authorized to perform this operation.</Message>
</Error>`)
}

func (m *CloudStorageMock) handleAzureMissing(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0")
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<Error>
    <Code>ContainerNotFound</Code>
    <Message>The specified container does not exist.</Message>
</Error>`)
}

func (m *CloudStorageMock) handleAzurePublicConfig(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Server", "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0")
	w.Header().Set("x-ms-blob-public-access", "container")
	w.WriteHeader(http.StatusOK)
}

// -------------------------------------------------------------------------
// False-Positive & Edge Case Handlers
// -------------------------------------------------------------------------

func (m *CloudStorageMock) handleFPHTML200(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Corporate Portal Login</title></head>
<body>
    <h1>Welcome to Corporate Portal</h1>
    <p>Please authenticate with your Single Sign-On credentials.</p>
</body>
</html>`)
}

func (m *CloudStorageMock) handleFPCDNCache(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Server", "cloudflare")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `<html><head><title>521 Web server is down</title></head><body>Error 521 CDN Cache Splash</body></html>`)
}

func (m *CloudStorageMock) handleFPRateLimit(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = fmt.Fprint(w, "Slow Down: Rate Limit Exceeded")
}

func (m *CloudStorageMock) handleFPMalformedXML(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `<UnclosedTag><BrokenXml>`)
}

func (m *CloudStorageMock) handleRedirectLoop(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	http.Redirect(w, r, "/redirect-loop/", http.StatusFound)
}

func (m *CloudStorageMock) handleRedirectSSRF(w http.ResponseWriter, r *http.Request) {
	m.record(r)
	http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
}

// BuildTargetURL returns a full URL pointing to a named mock resource on this mock server.
func (m *CloudStorageMock) BuildTargetURL(path string) string {
	base := strings.TrimRight(m.URL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// BuildS3URL returns a virtual path or query formatted URL for AWS S3 simulation.
func (m *CloudStorageMock) BuildS3URL(bucket string, key string) string {
	u, _ := url.Parse(m.URL)
	if key != "" {
		return fmt.Sprintf("http://%s/%s/%s", u.Host, bucket, key)
	}
	return fmt.Sprintf("http://%s/%s/", u.Host, bucket)
}

// BuildGCSURL returns a formatted URL for GCS simulation.
func (m *CloudStorageMock) BuildGCSURL(bucket string, key string) string {
	u, _ := url.Parse(m.URL)
	if key != "" {
		return fmt.Sprintf("http://%s/%s/%s", u.Host, bucket, key)
	}
	return fmt.Sprintf("http://%s/%s/", u.Host, bucket)
}

// BuildAzureURL returns a formatted URL for Azure Blob simulation.
func (m *CloudStorageMock) BuildAzureURL(container string, blob string, isList bool) string {
	u, _ := url.Parse(m.URL)
	if isList {
		return fmt.Sprintf("http://%s/%s?restype=container&comp=list", u.Host, container)
	}
	if blob != "" {
		return fmt.Sprintf("http://%s/%s/%s", u.Host, container, blob)
	}
	return fmt.Sprintf("http://%s/%s?restype=container", u.Host, container)
}
