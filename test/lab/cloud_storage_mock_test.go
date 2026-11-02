package lab

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCloudStorageMock_S3_Handlers(t *testing.T) {
	mock := NewCloudStorageMock()
	defer mock.Close()

	// S3 Public List
	resp, err := http.Get(mock.BuildS3URL("s3-public-list", ""))
	if err != nil {
		t.Fatalf("failed GET s3-public-list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<ListBucketResult") {
		t.Fatalf("expected ListBucketResult in body")
	}

	// S3 Private
	respPriv, err := http.Get(mock.BuildS3URL("s3-private", ""))
	if err != nil {
		t.Fatalf("failed GET s3-private: %v", err)
	}
	defer respPriv.Body.Close()
	if respPriv.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respPriv.StatusCode)
	}
}

func TestCloudStorageMock_GCS_Handlers(t *testing.T) {
	mock := NewCloudStorageMock()
	defer mock.Close()

	// GCS Public List
	resp, err := http.Get(mock.BuildGCSURL("gcs-public-list", ""))
	if err != nil {
		t.Fatalf("failed GET gcs-public-list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// GCS Missing
	respMiss, err := http.Get(mock.BuildGCSURL("gcs-missing", ""))
	if err != nil {
		t.Fatalf("failed GET gcs-missing: %v", err)
	}
	defer respMiss.Body.Close()
	if respMiss.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", respMiss.StatusCode)
	}
}

func TestCloudStorageMock_Azure_Handlers(t *testing.T) {
	mock := NewCloudStorageMock()
	defer mock.Close()

	// Azure Container List
	resp, err := http.Get(mock.BuildAzureURL("azure-public-list", "", true))
	if err != nil {
		t.Fatalf("failed GET azure-public-list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<EnumerationResults") {
		t.Fatalf("expected EnumerationResults in body")
	}
}

func TestCloudStorageMock_EdgeCases(t *testing.T) {
	mock := NewCloudStorageMock()
	defer mock.Close()

	// HTML 200
	resp, err := http.Get(mock.BuildTargetURL("fp-html-200/"))
	if err != nil {
		t.Fatalf("failed GET fp-html-200: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<html") {
		t.Fatalf("expected html tag in body")
	}

	// Rate limit
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, mock.BuildTargetURL("fp-rate-limit/"), nil)
	respRL, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed GET fp-rate-limit: %v", err)
	}
	defer respRL.Body.Close()
	if respRL.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", respRL.StatusCode)
	}
}
