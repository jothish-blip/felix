package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// newBenchmarkStore creates an isolated SQLite store in a temporary directory for benchmarking.
func newBenchmarkStore(b *testing.B) (*SQLiteStore, func()) {
	b.Helper()
	dir := b.TempDir()
	dbPath := filepath.Join(dir, "bench_assessment.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		b.Fatalf("failed to create benchmark store: %v", err)
	}
	return store, func() {
		_ = store.Close()
	}
}

// generateBenchmarkAssessmentFindings generates synthetic assessment findings for persistence benchmarks.
func generateBenchmarkAssessmentFindings(asmID, execID string, targetIDs []string, count int) []AssessmentFinding {
	categories := []string{"sql-injection", "broken-auth", "idor", "ssrf", "xss", "security-headers", "cors-misconfig"}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	findings := make([]AssessmentFinding, count)
	for i := 0; i < count; i++ {
		origID := fmt.Sprintf("RAW-FND-%06d", i)
		id := ComputeAssessmentFindingID(asmID, origID)
		cat := categories[i%len(categories)]
		sev := severities[i%len(severities)]
		method := methods[i%len(methods)]
		endpoint := fmt.Sprintf("/api/v1/resource/%d", i%100)
		targetID := targetIDs[i%len(targetIDs)]
		targetURL := fmt.Sprintf("https://target-%d.example.com", (i/10)%20)

		findings[i] = AssessmentFinding{
			ID:                 id,
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			OriginalFindingID:  origID,
			Title:              fmt.Sprintf("Vulnerability in resource %d", i),
			Category:           cat,
			Severity:           sev,
			Confidence:         "HIGH",
			VerificationStatus: report.VerificationVerified,
			TargetURL:          targetURL,
			Endpoint:           endpoint,
			Method:             method,
			Fingerprint:        fmt.Sprintf("fp-%06d", i),
			Score:              75,
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"route": endpoint,
				},
			},
			VerificationRecord: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
			Remediation: "Upgrade affected dependency",
			CreatedAt:   time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC),
		}
	}
	return findings
}

// -----------------------------------------------------------------------------
// Stage A: Assessment Initialization & Setup Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkAssessmentInitialization(b *testing.B) {
	store, cleanup := newBenchmarkStore(b)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Benchmark Corp"})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		asmID := fmt.Sprintf("asm-bench-%06d", i)
		asmRef := fmt.Sprintf("ASM-BENCH-%06d", i)
		asm := &Assessment{
			ID:        asmID,
			Ref:       asmRef,
			ClientID:  clientID,
			Name:      fmt.Sprintf("Benchmark Assessment %d", i),
			Status:    StatusDraft,
			ScopeMode: "same-origin",
		}
		if err := store.CreateAssessment(asm); err != nil {
			b.Fatalf("failed to create assessment: %v", err)
		}

		tgt := &AssessmentTarget{
			ID:           fmt.Sprintf("tgt-%06d", i),
			AssessmentID: asmID,
			TargetURL:    "https://bench.example.com",
			TargetType:   TargetWebsite,
			ScopeStatus:  "APPROVED",
		}
		if err := store.AddTarget(tgt); err != nil {
			b.Fatalf("failed to add target: %v", err)
		}

		now := time.Now().UTC()
		future := now.Add(24 * time.Hour)
		auth := &AuthorizationRecord{
			ID:                  fmt.Sprintf("auth-%06d", i),
			AssessmentID:        asmID,
			AuthorizingParty:    "Security Admin",
			AuthorizationMethod: "TICKET",
			DateReceived:        now,
			ValidUntil:          &future,
			Status:              AuthApproved,
		}
		if err := store.SetAuthorization(auth); err != nil {
			b.Fatalf("failed to set authorization: %v", err)
		}
	}
}

// -----------------------------------------------------------------------------
// Stage D: Persistence - SaveFindings Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkPersistence_SaveFindings(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			store, cleanup := newBenchmarkStore(b)
			defer cleanup()

			clientID := uuid.New().String()
			_ = store.CreateClient(&Client{ID: clientID, Name: "Acme"})
			asmID := uuid.New().String()
			_ = store.CreateAssessment(&Assessment{ID: asmID, Ref: "ASM-REF", ClientID: clientID, Name: "Bench", Status: StatusRunning})
			execID := uuid.New().String()
			_ = store.CreateExecution(&AssessmentExecution{ID: execID, AssessmentID: asmID, Status: StatusRunning, StartedAt: time.Now().UTC()})
			tgtID := uuid.New().String()
			_ = store.AddTarget(&AssessmentTarget{ID: tgtID, AssessmentID: asmID, TargetURL: "https://target-0.example.com", TargetType: TargetWebsite, ScopeStatus: "APPROVED"})

			fixtures := generateBenchmarkAssessmentFindings(asmID, execID, []string{tgtID}, sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if err := store.SaveFindings(fixtures); err != nil {
					b.Fatalf("SaveFindings failed: %v", err)
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage D: Persistence - GetFindings Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkPersistence_GetFindings(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			store, cleanup := newBenchmarkStore(b)
			defer cleanup()

			clientID := uuid.New().String()
			_ = store.CreateClient(&Client{ID: clientID, Name: "Acme"})
			asmID := uuid.New().String()
			_ = store.CreateAssessment(&Assessment{ID: asmID, Ref: "ASM-REF", ClientID: clientID, Name: "Bench", Status: StatusRunning})
			execID := uuid.New().String()
			_ = store.CreateExecution(&AssessmentExecution{ID: execID, AssessmentID: asmID, Status: StatusRunning, StartedAt: time.Now().UTC()})
			tgtID := uuid.New().String()
			_ = store.AddTarget(&AssessmentTarget{ID: tgtID, AssessmentID: asmID, TargetURL: "https://target-0.example.com", TargetType: TargetWebsite, ScopeStatus: "APPROVED"})

			fixtures := generateBenchmarkAssessmentFindings(asmID, execID, []string{tgtID}, sc.count)
			if err := store.SaveFindings(fixtures); err != nil {
				b.Fatalf("initial SaveFindings failed: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				findings, err := store.GetFindings(asmID, execID)
				if err != nil {
					b.Fatalf("GetFindings failed: %v", err)
				}
				if len(findings) != sc.count {
					b.Fatalf("expected %d findings, got %d", sc.count, len(findings))
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage D: Persistence - Snapshot Creation & Retrieval Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkPersistence_CreateSnapshot(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			store, cleanup := newBenchmarkStore(b)
			defer cleanup()

			clientID := uuid.New().String()
			_ = store.CreateClient(&Client{ID: clientID, Name: "Acme"})
			asmID := uuid.New().String()
			_ = store.CreateAssessment(&Assessment{ID: asmID, Ref: "ASM-REF", ClientID: clientID, Name: "Bench", Status: StatusRunning})
			tgtID := uuid.New().String()
			_ = store.AddTarget(&AssessmentTarget{ID: tgtID, AssessmentID: asmID, TargetURL: "https://target-0.example.com", TargetType: TargetWebsite, ScopeStatus: "APPROVED"})

			now := time.Now().UTC()
			snap := &AssessmentSnapshot{
				AssessmentID:   asmID,
				ClientID:       clientID,
				AssessmentType: "full",
				Status:         StatusCompleted,
				IsComplete:     true,
				FindingCount:   sc.count,
				ScopedTargets:  []string{"https://target-0.example.com"},
				StartedAt:      now.Add(-time.Hour),
				CompletedAt:    &now,
				CreatedAt:      now,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				iterAsmID := fmt.Sprintf("asm-%s-%d", sc.name, i)
				iterAsmRef := fmt.Sprintf("ASM-%s-%d", sc.name, i)
				_ = store.CreateAssessment(&Assessment{ID: iterAsmID, Ref: iterAsmRef, ClientID: clientID, Name: "Bench", Status: StatusCompleted})
				iterTgtID := fmt.Sprintf("tgt-%s-%d", sc.name, i)
				_ = store.AddTarget(&AssessmentTarget{ID: iterTgtID, AssessmentID: iterAsmID, TargetURL: "https://target-0.example.com", TargetType: TargetWebsite, ScopeStatus: "APPROVED"})
				execID := fmt.Sprintf("exec-%s-%d", sc.name, i)
				if err := store.CreateExecution(&AssessmentExecution{
					ID:           execID,
					AssessmentID: iterAsmID,
					ClientID:     clientID,
					Status:       StatusCompleted,
					StartedAt:    now.Add(-time.Minute),
					CompletedAt:  &now,
				}); err != nil {
					b.Fatalf("CreateExecution failed: %v", err)
				}
				iterFindings := generateBenchmarkAssessmentFindings(iterAsmID, execID, []string{iterTgtID}, sc.count)
				iterSnap := *snap
				iterSnap.ID = fmt.Sprintf("snap-%s-%d", sc.name, i)
				iterSnap.SnapshotRef = fmt.Sprintf("SNP-%s-%d", sc.name, i)
				iterSnap.AssessmentID = iterAsmID
				iterSnap.ExecutionID = execID
				b.StartTimer()

				if err := store.CreateSnapshot(&iterSnap, iterFindings, nil); err != nil {
					b.Fatalf("CreateSnapshot failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkPersistence_GetSnapshot(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			store, cleanup := newBenchmarkStore(b)
			defer cleanup()

			clientID := uuid.New().String()
			_ = store.CreateClient(&Client{ID: clientID, Name: "Acme"})
			asmID := uuid.New().String()
			_ = store.CreateAssessment(&Assessment{ID: asmID, Ref: "ASM-REF", ClientID: clientID, Name: "Bench", Status: StatusRunning})
			execID := uuid.New().String()
			_ = store.CreateExecution(&AssessmentExecution{ID: execID, AssessmentID: asmID, Status: StatusRunning, StartedAt: time.Now().UTC()})
			tgtID := uuid.New().String()
			_ = store.AddTarget(&AssessmentTarget{ID: tgtID, AssessmentID: asmID, TargetURL: "https://target-0.example.com", TargetType: TargetWebsite, ScopeStatus: "APPROVED"})

			fixtures := generateBenchmarkAssessmentFindings(asmID, execID, []string{tgtID}, sc.count)
			authCtx := TenantAuthContext{ClientID: clientID, isAdmin: true}

			now := time.Now().UTC()
			snap := &AssessmentSnapshot{
				ID:             uuid.New().String(),
				SnapshotRef:    fmt.Sprintf("SNAP-%s", sc.name),
				AssessmentID:   asmID,
				ExecutionID:    execID,
				ClientID:       clientID,
				AssessmentType: "full",
				Status:         StatusCompleted,
				IsComplete:     true,
				FindingCount:   sc.count,
				ScopedTargets:  []string{"https://target-0.example.com"},
				StartedAt:      now.Add(-time.Hour),
				CompletedAt:    &now,
				CreatedAt:      now,
			}

			if err := store.CreateSnapshot(snap, fixtures, nil); err != nil {
				b.Fatalf("initial CreateSnapshot failed: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				retrieved, err := store.GetSnapshot(snap.ID, authCtx)
				if err != nil || retrieved == nil {
					b.Fatalf("GetSnapshot failed: %v", err)
				}
				findings, err := store.GetSnapshotFindings(snap.ID, authCtx)
				if err != nil || len(findings) != sc.count {
					b.Fatalf("GetSnapshotFindings failed: %v, count: %d", err, len(findings))
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage F: Full Local Assessment Workflow Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkFullLocalAssessmentWorkflow(b *testing.B) {
	// Setup hermetic local HTTP test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `
				<!DOCTYPE html>
				<html>
				<head><title>App Root</title></head>
				<body>
					<a href="/login">Login</a>
					<a href="/api/v1/users">Users API</a>
					<a href="/api/v1/posts">Posts API</a>
					<a href="/dashboard">Dashboard</a>
					<form action="/search" method="GET">
						<input type="text" name="q" value="test" />
						<button type="submit">Search</button>
					</form>
				</body>
				</html>
			`)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><form method="POST" action="/auth"><input name="user"/><input name="pass"/></form></body></html>`)
		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"id": 1, "username": "admin", "role": "root"}, {"id": 2, "username": "guest"}]`)
		case "/api/v1/posts":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"id": 101, "title": "Security Note", "body": "Sensitive memo"}]`)
		case "/dashboard":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><h1>Welcome Dashboard</h1></body></html>`)
		case "/search":
			w.Header().Set("Content-Type", "text/html")
			q := r.URL.Query().Get("q")
			fmt.Fprintf(w, `<html><body>Search result for: %s</body></html>`, q)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	b.Run("Small_1Target_6Endpoints_LocalWorkflow", func(b *testing.B) {
		store, cleanup := newBenchmarkStore(b)
		defer cleanup()

		ctrl := NewController(store)
		clientID := uuid.New().String()
		_ = store.CreateClient(&Client{ID: clientID, Name: "Local Workflow Corp"})

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			asmID := fmt.Sprintf("asm-workflow-%d", i)
			asmRef := fmt.Sprintf("REF-WF-%d", i)
			_ = store.CreateAssessment(&Assessment{
				ID:        asmID,
				Ref:       asmRef,
				ClientID:  clientID,
				Name:      "Local Workflow Assessment",
				Status:    StatusReady,
				ScopeMode: "same-origin",
			})
			_ = store.AddTarget(&AssessmentTarget{
				ID:           fmt.Sprintf("tgt-wf-%d", i),
				AssessmentID: asmID,
				TargetURL:    server.URL,
				TargetType:   TargetWebsite,
				ScopeStatus:  "APPROVED",
			})
			now := time.Now().UTC()
			future := now.Add(24 * time.Hour)
			_ = store.SetAuthorization(&AuthorizationRecord{
				ID:                  fmt.Sprintf("auth-wf-%d", i),
				AssessmentID:        asmID,
				AuthorizingParty:    "Bench Tester",
				AuthorizationMethod: "DIRECT",
				DateReceived:        now,
				ValidUntil:          &future,
				Status:              AuthApproved,
			})

			tmpDir := b.TempDir()
			htmlPath := filepath.Join(tmpDir, "report.html")
			jsonPath := filepath.Join(tmpDir, "report.json")

			opts := ExecutionOptions{
				TimeoutDuration: 10 * time.Second,
				Concurrency:     2,
				MaxAssets:       20,
				ExportHTMLPath:  htmlPath,
				ExportJSONPath:  jsonPath,
				FelixVersion:    "2.0.0",
				BuildID:         "benchmark",
				AllowLoopback:   true,
			}
			b.StartTimer()

			res, err := ctrl.RunAssessment(context.Background(), asmID, opts)
			if err != nil {
				b.Fatalf("RunAssessment failed: %v", err)
			}
			if res.Execution.Status != StatusCompleted {
				b.Fatalf("expected status COMPLETED, got %s", res.Execution.Status)
			}
		}
	})
}
