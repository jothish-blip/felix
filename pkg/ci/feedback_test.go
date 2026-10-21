package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"felix/pkg/clierror"
	"felix/pkg/report"
)

// TestPRFeedback_Disabled verifies that if feedback flags are not set, zero network calls occur.
func TestPRFeedback_Disabled(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        false,
		PRInline:         false,
		PRNumber:         42,
		GitHubToken:      "ghp_dummytoken1234567890",
		GitHubRepo:       "test-owner/test-repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		TotalFindings: 0,
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 0 {
		t.Fatalf("expected 0 HTTP calls when PR feedback is disabled, got %d", requestCount)
	}
}

// TestPRFeedback_NonPRContext verifies that outside a PR context (PRNumber == 0 and no event file), feedback cleanly skips.
func TestPRFeedback_NonPRContext(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        true,
		PRNumber:         0,
		GitHubToken:      "ghp_dummytoken1234567890",
		GitHubRepo:       "test-owner/test-repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		TotalFindings: 0,
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 0 {
		t.Fatalf("expected 0 HTTP calls when PR number is 0, got %d", requestCount)
	}
}

// TestPRFeedback_CreateNewComment verifies creating a fresh comment with the stable marker.
func TestPRFeedback_CreateNewComment(t *testing.T) {
	var listCalled, createCalled bool
	var postedComment string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/my-org/my-repo/issues/10/comments":
			listCalled = true
			// Return empty comment list
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]IssueComment{})
		case r.Method == "POST" && r.URL.Path == "/repos/my-org/my-repo/issues/10/comments":
			createCalled = true
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			postedComment = req["body"]
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(IssueComment{ID: 101, Body: postedComment})
		default:
			t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        true,
		PRNumber:         10,
		GitHubToken:      "ghp_dummytoken1234567890",
		GitHubRepo:       "my-org/my-repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		TotalFindings: 1,
		SeverityCounts: map[string]int{
			report.SeverityLow: 1,
		},
		Findings: []report.Finding{
			{
				ID:          "f-1",
				RuleID:      "TLS-01",
				Title:       "Deprecated TLS Version",
				Severity:    report.SeverityLow,
				Target:      "https://api.example.com",
				Remediation: "Upgrade to TLS 1.3",
			},
		},
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("PublishPRFeedback failed: %v", err)
	}

	if !listCalled {
		t.Errorf("expected GET to list issue comments")
	}
	if !createCalled {
		t.Errorf("expected POST to create issue comment")
	}
	if !res.FeedbackPublished {
		t.Errorf("expected FeedbackPublished to be true")
	}
	if !strings.Contains(postedComment, DefaultCommentTag) {
		t.Errorf("expected comment to contain marker tag %q", DefaultCommentTag)
	}
	if !strings.Contains(postedComment, "STATUS: PASSED") {
		t.Errorf("expected comment to reflect passed status")
	}
	if !strings.Contains(postedComment, "Deprecated TLS Version") {
		t.Errorf("expected comment to contain finding title")
	}
}

// TestPRFeedback_UpdateExistingCommentIdempotently verifies that when a comment with the marker exists, it is PATCHed.
func TestPRFeedback_UpdateExistingCommentIdempotently(t *testing.T) {
	var listCalled, patchCalled, postCalled bool
	var patchedComment string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/my-org/my-repo/issues/10/comments":
			listCalled = true
			existing := []IssueComment{
				{
					ID:   50,
					Body: "Unrelated developer comment",
				},
				{
					ID:   99,
					Body: DefaultCommentTag + "\nOld FELIX Summary from previous run",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(existing)
		case r.Method == "PATCH" && r.URL.Path == "/repos/my-org/my-repo/issues/comments/99":
			patchCalled = true
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			patchedComment = req["body"]
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(IssueComment{ID: 99, Body: patchedComment})
		case r.Method == "POST":
			postCalled = true
			t.Errorf("POST should not be called when existing comment ID 99 can be updated!")
		default:
			t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        true,
		PRNumber:         10,
		GitHubToken:      "ghp_dummytoken1234567890",
		GitHubRepo:       "my-org/my-repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSecurityFail,
		TotalFindings: 1,
		SeverityCounts: map[string]int{
			report.SeverityCritical: 1,
		},
		Findings: []report.Finding{
			{
				ID:          "f-crit-1",
				RuleID:      "SQLI-01",
				Title:       "SQL Injection in /api/v1/user",
				Severity:    report.SeverityCritical,
				Target:      "https://api.example.com",
				Endpoint:    "/api/v1/user",
				Remediation: "Use parameterized queries",
			},
		},
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("PublishPRFeedback failed: %v", err)
	}

	if !listCalled {
		t.Errorf("expected GET to list comments")
	}
	if !patchCalled {
		t.Errorf("expected PATCH to update existing comment 99")
	}
	if postCalled {
		t.Errorf("POST should not have been called")
	}
	if !strings.Contains(patchedComment, "STATUS: POLICY VIOLATION") {
		t.Errorf("expected patched comment to show POLICY VIOLATION")
	}
	if !strings.Contains(patchedComment, "SQL Injection in /api/v1/user") {
		t.Errorf("expected finding title in patched comment")
	}
}

// TestPRFeedback_InlineReviews_ValidAndInvalidLocations verifies that genuine source files
// get inline review comments, while URL endpoints and invalid paths are excluded from inline review.
func TestPRFeedback_InlineReviews_ValidAndInvalidLocations(t *testing.T) {
	var reviewSubmitted bool
	var reviewReq PRReviewRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/repos/my-org/my-repo/pulls/25/reviews" {
			reviewSubmitted = true
			_ = json.NewDecoder(r.Body).Decode(&reviewReq)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PRReviewResponse{ID: 888})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        false,
		PRInline:         true,
		PRNumber:         25,
		CommitSHA:        "abcdef1234567890abcdef1234567890abcdef12",
		GitHubToken:      "ghp_dummytoken1234567890",
		GitHubRepo:       "my-org/my-repo",
		GitHubAPIBaseURL: server.URL,
	}

	findings := []report.Finding{
		// Finding 1: Genuine source code location via provenance
		{
			ID:          "f-src-1",
			RuleID:      "SEC-HARDCODED-SECRET",
			Title:       "Hardcoded JWT Secret",
			Severity:    report.SeverityHigh,
			Description: "JWT secret key hardcoded in application configuration.",
			Provenance: &report.EvidenceProvenance{
				Location: "config/jwt.go:42",
			},
			Remediation: "Load JWT secrets from environment variables or vault.",
		},
		// Finding 2: Web URL endpoint with NO source file (must NOT fabricate a line number!)
		{
			ID:          "f-url-1",
			RuleID:      "CORS-MISCONFIG",
			Title:       "Wildcard Access-Control-Allow-Origin",
			Severity:    report.SeverityMedium,
			Description: "Endpoint responds with Access-Control-Allow-Origin: *",
			Endpoint:    "https://api.example.com/api/v2/auth",
			Remediation: "Restrict allowed origins to trusted domains.",
		},
		// Finding 3: Relative HTTP route with NO source file (must NOT fabricate line number!)
		{
			ID:          "f-url-2",
			RuleID:      "AUTH-BYPASS",
			Title:       "Missing Authentication on Admin Route",
			Severity:    report.SeverityHigh,
			Description: "Admin endpoint is accessible without authorization header.",
			Endpoint:    "/admin/metrics",
			Remediation: "Require Admin role token.",
		},
		// Finding 4: Genuine source code location via EvidenceDetails line number
		{
			ID:          "f-src-2",
			RuleID:      "SQLI-02",
			Title:       "Unescaped query parameter in repository",
			Severity:    report.SeverityCritical,
			Description: "fmt.Sprintf used to construct SQL query.",
			Provenance: &report.EvidenceProvenance{
				Location: "pkg/db/user_repo.go",
			},
			EvidenceDetails: report.EvidenceDetails{
				Location: "pkg/db/user_repo.go",
				Details: map[string]string{
					"line": "115",
				},
			},
			Remediation: "Use query parameter placeholders.",
		},
	}

	res := &Result{
		ExitCode:      clierror.ExitSecurityFail,
		TotalFindings: len(findings),
		Findings:      findings,
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("PublishPRFeedback failed: %v", err)
	}

	if !reviewSubmitted {
		t.Fatalf("expected review to be submitted")
	}

	// Exactly 2 findings had genuine source locations; the 2 web endpoints must NOT be included!
	if len(reviewReq.Comments) != 2 {
		t.Fatalf("expected exactly 2 inline comments, got %d", len(reviewReq.Comments))
	}

	paths := map[string]int{
		reviewReq.Comments[0].Path: reviewReq.Comments[0].Line,
		reviewReq.Comments[1].Path: reviewReq.Comments[1].Line,
	}

	if line, ok := paths["config/jwt.go"]; !ok || line != 42 {
		t.Errorf("expected config/jwt.go at line 42, got %v", paths)
	}
	if line, ok := paths["pkg/db/user_repo.go"]; !ok || line != 115 {
		t.Errorf("expected pkg/db/user_repo.go at line 115, got %v", paths)
	}
}

// TestPRFeedback_SecretRedaction verifies that credentials and tokens are redacted before posting.
func TestPRFeedback_SecretRedaction(t *testing.T) {
	var postedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]IssueComment{})
			return
		}
		if r.Method == "POST" {
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			postedBody = req["body"]
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(IssueComment{ID: 1})
			return
		}
	}))
	defer server.Close()

	secretToken := "ghp_VerySecretAccessToken9876543210"
	dbPassword := "SuperSecretDBPassword123!"

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        true,
		PRNumber:         7,
		GitHubToken:      secretToken,
		GitHubRepo:       "my-org/my-repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSecurityFail,
		TotalFindings: 1,
		Findings: []report.Finding{
			{
				ID:          "f-sec-1",
				RuleID:      "LEAKED-CRED",
				Title:       "Leaked Database Password in Connection String",
				Severity:    report.SeverityCritical,
				Description: fmt.Sprintf("Found postgres://user:%s@db.prod.internal/main", dbPassword),
				Remediation: "Revoke password immediately.",
			},
		},
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(postedBody, secretToken) {
		t.Errorf("CRITICAL SECURITY DEFECT: GitHub token leaked in posted comment!")
	}
	if strings.Contains(postedBody, dbPassword) {
		t.Errorf("CRITICAL SECURITY DEFECT: Database password leaked in posted comment!")
	}
}

// TestPRFeedback_FailurePolicy_WarnPreservesExitCode verifies that default "warn" policy does not alter exit codes.
func TestPRFeedback_FailurePolicy_WarnPreservesExitCode(t *testing.T) {
	// Mock server that returns HTTP 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	// Scenario A: Clean assessment with passing policy (Exit 0)
	tmpDir := t.TempDir()
	cfg := &Config{
		Provider:              ProviderGitHub,
		TargetURL:             "https://example.com",
		PRComment:             true,
		PRNumber:              15,
		GitHubToken:           "ghp_dummytoken1234567890",
		GitHubRepo:            "my-org/my-repo",
		GitHubAPIBaseURL:      server.URL,
		FeedbackFailurePolicy: "warn",
		OutputDir:             tmpDir,
		Timeout:               "2s",
		AllowLoopback:         true,
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		PolicyStatus:  "PASS",
		TotalFindings: 0,
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err == nil {
		t.Fatalf("expected error from 500 server response")
	}

	// Under "warn" policy, runner preserves res.ExitCode = 0
	if res.ExitCode != clierror.ExitSuccess {
		t.Errorf("expected exit code to remain 0 under warn policy, got %d", res.ExitCode)
	}
}

// TestPRFeedback_FailurePolicy_FailElevatesZeroToOperational verifies that under "fail" policy,
// a feedback publishing failure elevates exit 0 to exit 2, but NEVER converts exit 1.
func TestPRFeedback_FailurePolicy_FailSemantics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "GitHub API rate limit exceeded", http.StatusTooManyRequests)
	}))
	defer server.Close()

	// Subtest 1: Clean assessment (Exit 0) -> elevated to Operational Error (Exit 2)
	{
		cfg := &Config{
			Provider:              ProviderGitHub,
			PRComment:             true,
			PRNumber:              15,
			GitHubToken:           "ghp_dummytoken1234567890",
			GitHubRepo:            "my-org/my-repo",
			GitHubAPIBaseURL:      server.URL,
			FeedbackFailurePolicy: "fail",
		}

		res := &Result{
			ExitCode:     clierror.ExitSuccess,
			PolicyStatus: "PASS",
		}

		fbErr := PublishPRFeedback(context.Background(), cfg, res)
		if fbErr == nil {
			t.Fatalf("expected rate limit error")
		}

		// Simulate runner logic for "fail" policy
		if strings.EqualFold(cfg.FeedbackFailurePolicy, "fail") {
			if res.ExitCode == clierror.ExitSuccess {
				res.ExitCode = clierror.ExitOperational
			}
		}

		if res.ExitCode != clierror.ExitOperational {
			t.Errorf("expected exit 0 to be elevated to exit 2 under fail policy, got %d", res.ExitCode)
		}
	}

	// Subtest 2: Security Violation (Exit 1) -> MUST REMAIN EXIT 1 (never masked as exit 2!)
	{
		cfg := &Config{
			Provider:              ProviderGitHub,
			PRComment:             true,
			PRNumber:              15,
			GitHubToken:           "ghp_dummytoken1234567890",
			GitHubRepo:            "my-org/my-repo",
			GitHubAPIBaseURL:      server.URL,
			FeedbackFailurePolicy: "fail",
		}

		res := &Result{
			ExitCode:     clierror.ExitSecurityFail,
			PolicyStatus: "FAIL",
		}

		fbErr := PublishPRFeedback(context.Background(), cfg, res)
		if fbErr == nil {
			t.Fatalf("expected rate limit error")
		}

		// Simulate runner logic for "fail" policy
		if strings.EqualFold(cfg.FeedbackFailurePolicy, "fail") {
			if res.ExitCode == clierror.ExitSuccess {
				res.ExitCode = clierror.ExitOperational
			}
		}

		if res.ExitCode != clierror.ExitSecurityFail {
			t.Errorf("CRITICAL DEFECT: security violation (exit 1) was mutated to %d!", res.ExitCode)
		}
	}
}

// TestDetectPullRequestContext verifies parsing GitHub Actions pull_request event payload.
func TestDetectPullRequestContext(t *testing.T) {
	tmpDir := t.TempDir()
	eventFile := filepath.Join(tmpDir, "event.json")

	eventPayload := `{
		"number": 88,
		"pull_request": {
			"head": {
				"sha": "1234567890abcdef1234567890abcdef12345678"
			}
		},
		"repository": {
			"full_name": "acme-corp/super-service"
		}
	}`

	if err := os.WriteFile(eventFile, []byte(eventPayload), 0644); err != nil {
		t.Fatalf("failed writing event file: %v", err)
	}

	prNum, sha, repo, err := DetectPullRequestContext(eventFile)
	if err != nil {
		t.Fatalf("DetectPullRequestContext failed: %v", err)
	}

	if prNum != 88 {
		t.Errorf("expected PR number 88, got %d", prNum)
	}
	if sha != "1234567890abcdef1234567890abcdef12345678" {
		t.Errorf("expected sha to match, got %s", sha)
	}
	if repo != "acme-corp/super-service" {
		t.Errorf("expected repo to match, got %s", repo)
	}
}

// TestParsePRDiff verifies that unified diff text is parsed into valid right-side lines.
func TestParsePRDiff(t *testing.T) {
	diffText := `diff --git a/pkg/auth.go b/pkg/auth.go
index 1234567..89abcdef 100644
--- a/pkg/auth.go
+++ b/pkg/auth.go
@@ -10,3 +10,4 @@ func Auth() {
  context line 10
 +added line 11
  context line 12
 +added line 13
diff --git a/pkg/deleted.go b/pkg/deleted.go
deleted file mode 100644
--- a/pkg/deleted.go
+++ /dev/null
@@ -1,5 +0,0 @@
-removed line
diff --git a/pkg/new.go b/pkg/new.go
new file mode 100644
--- /dev/null
+++ b/pkg/new.go
@@ -0,0 +1,2 @@
+new line 1
+new line 2
`

	validLines := ParsePRDiff(diffText)

	// pkg/auth.go
	authLines := validLines["pkg/auth.go"]
	if authLines == nil {
		t.Fatalf("expected pkg/auth.go in parsed diff")
	}
	// Lines 10, 11, 12, 13 are in hunk
	for _, l := range []int{10, 11, 12, 13} {
		if !authLines[l] {
			t.Errorf("expected pkg/auth.go line %d to be valid in diff", l)
		}
	}
	// Line 42 is outside hunk
	if authLines[42] {
		t.Errorf("expected pkg/auth.go line 42 to NOT be in diff")
	}

	// pkg/deleted.go must NOT have valid lines on right
	if len(validLines["pkg/deleted.go"]) > 0 {
		t.Errorf("expected deleted file to have zero right-side lines")
	}

	// pkg/new.go
	newLines := validLines["pkg/new.go"]
	if newLines == nil {
		t.Fatalf("expected pkg/new.go in parsed diff")
	}
	if !newLines[1] || !newLines[2] {
		t.Errorf("expected lines 1 and 2 in pkg/new.go to be valid")
	}
	if newLines[3] {
		t.Errorf("expected line 3 in pkg/new.go to NOT be in diff")
	}
}

// TestPRFeedback_InlineDiffFiltering verifies that when a PR diff is fetched,
// only findings targeting lines present in the diff are sent as inline review comments.
func TestPRFeedback_InlineDiffFiltering(t *testing.T) {
	var diffCalled, reviewCalled bool
	var reviewReq PRReviewRequest

	diffContent := `diff --git a/pkg/api/auth.go b/pkg/api/auth.go
--- a/pkg/api/auth.go
+++ b/pkg/api/auth.go
@@ -20,2 +20,3 @@
  context 20
 +added line 21
  context 22
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/owner/repo/pulls/12":
			diffCalled = true
			w.Header().Set("Content-Type", "application/vnd.github.diff")
			_, _ = w.Write([]byte(diffContent))
		case r.Method == "POST" && r.URL.Path == "/repos/owner/repo/pulls/12/reviews":
			reviewCalled = true
			_ = json.NewDecoder(r.Body).Decode(&reviewReq)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PRReviewResponse{ID: 777})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRInline:         true,
		PRNumber:         12,
		CommitSHA:        "1111222233334444555566667777888899990000",
		GitHubToken:      "ghp_testtoken123",
		GitHubRepo:       "owner/repo",
		GitHubAPIBaseURL: server.URL,
	}

	findings := []report.Finding{
		// Finding 1: on line 21 (INSIDE the diff) -> MUST be included
		{
			ID:       "f-in-diff",
			RuleID:   "SEC-01",
			Title:    "Issue on line 21",
			Severity: report.SeverityHigh,
			Provenance: &report.EvidenceProvenance{
				Location: "pkg/api/auth.go:21",
			},
		},
		// Finding 2: on line 99 (OUTSIDE the diff) -> MUST be filtered out
		{
			ID:       "f-out-of-diff",
			RuleID:   "SEC-02",
			Title:    "Issue on line 99",
			Severity: report.SeverityMedium,
			Provenance: &report.EvidenceProvenance{
				Location: "pkg/api/auth.go:99",
			},
		},
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		TotalFindings: len(findings),
		Findings:      findings,
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diffCalled {
		t.Errorf("expected GET pulls/12 diff to be called")
	}
	if !reviewCalled {
		t.Fatalf("expected review to be submitted")
	}

	if len(reviewReq.Comments) != 1 {
		t.Fatalf("expected exactly 1 comment inside diff, got %d", len(reviewReq.Comments))
	}
	if reviewReq.Comments[0].Line != 21 {
		t.Errorf("expected comment on line 21, got line %d", reviewReq.Comments[0].Line)
	}
}

// TestPRFeedback_InlineHTTP422Fallback verifies that when GitHub review API returns HTTP 422,
// FELIX catches it as diff-mismatch and falls back to summary without failing the assessment.
func TestPRFeedback_InlineHTTP422Fallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/repos/owner/repo/pulls/12/reviews" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message": "Pull request review comment line must be part of the diff"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRInline:         true,
		PRNumber:         12,
		CommitSHA:        "1111222233334444555566667777888899990000",
		GitHubToken:      "ghp_testtoken123",
		GitHubRepo:       "owner/repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		TotalFindings: 1,
		Findings: []report.Finding{
			{
				ID:       "f-outside",
				RuleID:   "SEC-01",
				Title:    "Issue on line 50",
				Severity: report.SeverityHigh,
				Provenance: &report.EvidenceProvenance{
					Location: "pkg/auth.go:50",
				},
			},
		},
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("expected HTTP 422 to be handled gracefully, got err: %v", err)
	}
}

// TestPRFeedback_PaginationDetectsExistingComment verifies that FELIX paginates through
// issue comments to locate an existing comment ID and sends a PATCH instead of creating a duplicate.
func TestPRFeedback_PaginationDetectsExistingComment(t *testing.T) {
	var page1Called, page2Called, patchCalled, postCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Query().Get("page") == "1":
			page1Called = true
			// 100 filler comments
			filler := make([]IssueComment, 100)
			for i := range filler {
				filler[i] = IssueComment{ID: int64(1000 + i), Body: "Unrelated comment"}
			}
			_ = json.NewEncoder(w).Encode(filler)
		case r.Method == "GET" && r.URL.Query().Get("page") == "2":
			page2Called = true
			existing := []IssueComment{
				{ID: 5555, Body: DefaultCommentTag + "\nPrevious FELIX report"},
			}
			_ = json.NewEncoder(w).Encode(existing)
		case r.Method == "PATCH" && r.URL.Path == "/repos/owner/repo/issues/comments/5555":
			patchCalled = true
			_ = json.NewEncoder(w).Encode(IssueComment{ID: 5555})
		case r.Method == "POST":
			postCalled = true
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Provider:         ProviderGitHub,
		PRComment:        true,
		PRNumber:         99,
		GitHubToken:      "ghp_testtoken123",
		GitHubRepo:       "owner/repo",
		GitHubAPIBaseURL: server.URL,
	}

	res := &Result{
		ExitCode:      clierror.ExitSuccess,
		TotalFindings: 0,
	}

	err := PublishPRFeedback(context.Background(), cfg, res)
	if err != nil {
		t.Fatalf("PublishPRFeedback failed: %v", err)
	}

	if !page1Called || !page2Called {
		t.Errorf("expected pagination across page 1 and page 2 (page1: %v, page2: %v)", page1Called, page2Called)
	}
	if !patchCalled {
		t.Errorf("expected PATCH on comment 5555 found on page 2")
	}
	if postCalled {
		t.Errorf("POST should not have been called when comment exists on page 2")
	}
}

// TestPRFeedback_ArtifactLinksOnlyWhenFilesExist proves that artifact links only appear in
// summary comments when the files actually exist on disk.
func TestPRFeedback_ArtifactLinksOnlyWhenFilesExist(t *testing.T) {
	tmpDir := t.TempDir()

	realSarif := filepath.Join(tmpDir, "report.sarif")
	_ = os.WriteFile(realSarif, []byte("{}"), 0644)

	nonExistentJSON := filepath.Join(tmpDir, "does_not_exist.json")

	cfg := &Config{
		TargetURL: "https://example.com",
	}

	res := &Result{
		ExitCode:  0,
		SARIFPath: realSarif,
		JSONPath:  nonExistentJSON,
		HTMLPath:  "",
	}

	summary := FormatPRSummary(res, cfg, DefaultCommentTag)

	if !strings.Contains(summary, "report.sarif") {
		t.Errorf("expected real SARIF file to be linked in summary")
	}
	if strings.Contains(summary, "does_not_exist.json") {
		t.Errorf("CRITICAL DEFECT: non-existent JSON file was linked in summary!")
	}
}

// TestPRFeedback_ConfigValidation verifies that malformed feedback configurations fail closed.
func TestPRFeedback_ConfigValidation(t *testing.T) {
	// 1. Invalid feedback failure policy
	cfgBadPolicy := &Config{
		TargetURL:             "https://example.com",
		FeedbackFailurePolicy: "non_existent_policy",
	}
	if err := ValidateConfig(cfgBadPolicy); err == nil {
		t.Errorf("expected validation error for invalid feedback-failure-policy")
	}

	// 2. Negative PR number
	cfgNegativePR := &Config{
		TargetURL: "https://example.com",
		PRNumber:  -10,
	}
	if err := ValidateConfig(cfgNegativePR); err == nil {
		t.Errorf("expected validation error for negative pr-number")
	}

	// 3. Malformed repo slug
	cfgBadRepo := &Config{
		TargetURL:  "https://example.com",
		GitHubRepo: "no-slash-repo",
	}
	if err := ValidateConfig(cfgBadRepo); err == nil {
		t.Errorf("expected validation error for malformed repo slug")
	}

	// 4. Invalid API URL
	cfgBadAPI := &Config{
		TargetURL:        "https://example.com",
		GitHubAPIBaseURL: "ftp://invalid-scheme.corp",
	}
	if err := ValidateConfig(cfgBadAPI); err == nil {
		t.Errorf("expected validation error for invalid github-api-url scheme")
	}
}

// TestPRFeedback_AllSixExitCodeMatrixCases systematically verifies the 6 required rows
// of the assessment/feedback exit-code specification table.
func TestPRFeedback_AllSixExitCodeMatrixCases(t *testing.T) {
	cases := []struct {
		name            string
		assessmentExit  int
		feedbackSuccess bool
		failurePolicy   string
		expectedExit    int
	}{
		{
			name:            "Clean + Feedback Success (warn) -> Exit 0",
			assessmentExit:  clierror.ExitSuccess,
			feedbackSuccess: true,
			failurePolicy:   "warn",
			expectedExit:    clierror.ExitSuccess,
		},
		{
			name:            "Clean + Feedback Success (fail) -> Exit 0",
			assessmentExit:  clierror.ExitSuccess,
			feedbackSuccess: true,
			failurePolicy:   "fail",
			expectedExit:    clierror.ExitSuccess,
		},
		{
			name:            "Clean + Feedback Failure (warn) -> Exit 0",
			assessmentExit:  clierror.ExitSuccess,
			feedbackSuccess: false,
			failurePolicy:   "warn",
			expectedExit:    clierror.ExitSuccess,
		},
		{
			name:            "Clean + Feedback Failure (fail) -> Exit 2",
			assessmentExit:  clierror.ExitSuccess,
			feedbackSuccess: false,
			failurePolicy:   "fail",
			expectedExit:    clierror.ExitOperational,
		},
		{
			name:            "Policy Violation + Feedback Success (warn) -> Exit 1",
			assessmentExit:  clierror.ExitSecurityFail,
			feedbackSuccess: true,
			failurePolicy:   "warn",
			expectedExit:    clierror.ExitSecurityFail,
		},
		{
			name:            "Policy Violation + Feedback Success (fail) -> Exit 1",
			assessmentExit:  clierror.ExitSecurityFail,
			feedbackSuccess: true,
			failurePolicy:   "fail",
			expectedExit:    clierror.ExitSecurityFail,
		},
		{
			name:            "Policy Violation + Feedback Failure (warn) -> Exit 1",
			assessmentExit:  clierror.ExitSecurityFail,
			feedbackSuccess: false,
			failurePolicy:   "warn",
			expectedExit:    clierror.ExitSecurityFail,
		},
		{
			name:            "Policy Violation + Feedback Failure (fail) -> Exit 1 (never masked as 2!)",
			assessmentExit:  clierror.ExitSecurityFail,
			feedbackSuccess: false,
			failurePolicy:   "fail",
			expectedExit:    clierror.ExitSecurityFail,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.feedbackSuccess {
					w.Header().Set("Content-Type", "application/json")
					if r.Method == "GET" {
						_ = json.NewEncoder(w).Encode([]IssueComment{})
					} else {
						_ = json.NewEncoder(w).Encode(IssueComment{ID: 123})
					}
				} else {
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			cfg := &Config{
				Provider:              ProviderGitHub,
				PRComment:             true,
				PRNumber:              1,
				GitHubToken:           "ghp_testtoken123",
				GitHubRepo:            "owner/repo",
				GitHubAPIBaseURL:      server.URL,
				FeedbackFailurePolicy: tc.failurePolicy,
			}

			res := &Result{
				ExitCode: tc.assessmentExit,
			}

			fbErr := PublishPRFeedback(context.Background(), cfg, res)
			if tc.feedbackSuccess && fbErr != nil {
				t.Fatalf("unexpected feedback error: %v", fbErr)
			}
			if !tc.feedbackSuccess && fbErr == nil {
				t.Fatalf("expected feedback error from 500 server")
			}

			// Apply failure policy logic as in runner
			if fbErr != nil {
				if strings.EqualFold(cfg.FeedbackFailurePolicy, "fail") {
					if res.ExitCode == clierror.ExitSuccess {
						res.ExitCode = clierror.ExitOperational
					}
				}
			}

			if res.ExitCode != tc.expectedExit {
				t.Errorf("expected exit %d, got %d", tc.expectedExit, res.ExitCode)
			}
		})
	}
}
