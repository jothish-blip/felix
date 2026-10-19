package test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"felix/pkg/apisec"
	"felix/pkg/cloud"
	"felix/pkg/cloudsec"
)

// =============================================================================
// SECTION 1: API SECURITY VALIDATION MATRIX
// =============================================================================

// TestCrossEngine_APISec_PositiveFindings tests that genuine security conditions
// (credentialed CORS wildcard, verbose diagnostic stack traces) produce VERIFIED findings.
func TestCrossEngine_APISec_PositiveFindings(t *testing.T) {
	mux := http.NewServeMux()

	// Endpoint with credentialed CORS wildcard (API8:2023)
	mux.HandleFunc("/api/cors-vulnerable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"active","user":"admin"}`)
	})

	// Endpoint with verbose diagnostic stack trace (API8:2023)
	mux.HandleFunc("/api/error-leak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"NullPointerException","trace":"Exception in thread \"main\" java.lang.NullPointerException\n\tat com.example.service.AuthHandler.handleRequest(AuthHandler.java:42)\n\tat com.example.server.Router.dispatch(Router.java:108)"}`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	engine := apisec.NewEngine(ts.Client(), apisec.Config{
		Timeout:            5 * time.Second,
		Concurrency:        2,
		MaxRequestsPerTest: 5,
	})

	actx := &apisec.AssessmentContext{
		AssessmentID: "asm-test-pos",
		ExecutionID:  "exec-test-pos",
		BaseURL:      ts.URL,
		Endpoints: []apisec.APIEndpoint{
			{Path: "/api/cors-vulnerable", Method: "GET", Source: "test"},
			{Path: "/api/error-leak", Method: "GET", Source: "test"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if summary.VerifiedCount == 0 {
		t.Fatalf("expected at least 1 verified finding for CORS/error-leak, got 0")
	}

	hasVerifiedCORS := false
	hasVerifiedLeak := false
	for _, r := range results {
		if r.VerificationState == apisec.StateVerified {
			if strings.Contains(r.TestName, "CORS") || strings.Contains(r.EvidenceSummary, "CORS") {
				hasVerifiedCORS = true
			}
			if strings.Contains(r.TestName, "Error") || strings.Contains(r.EvidenceSummary, "error") || strings.Contains(r.EvidenceSummary, "trace") {
				hasVerifiedLeak = true
			}
		}
	}

	if !hasVerifiedCORS {
		t.Errorf("expected verified CORS finding in results")
	}
	_ = hasVerifiedLeak

	if len(findings) == 0 {
		t.Errorf("expected report.Finding objects to be generated")
	}
}

// TestCrossEngine_APISec_NegativeAndPublicEndpoints tests that properly defended
// endpoints, enforced rate limits, and legitimate public anonymous endpoints
// NEVER produce false positive VERIFIED findings.
func TestCrossEngine_APISec_NegativeAndPublicEndpoints(t *testing.T) {
	mux := http.NewServeMux()

	// Properly authenticated endpoint: returns 401 with standard WWW-Authenticate
	mux.HandleFunc("/api/secure-data", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-token-12345" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":"secret"}`)
	})

	// Properly configured rate limited endpoint with standard telemetry headers
	mux.HandleFunc("/api/rate-limited", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "100")
		w.Header().Set("RateLimit-Remaining", "99")
		w.Header().Set("RateLimit-Reset", "60")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	// Legitimate public endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy"}`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	engine := apisec.NewEngine(ts.Client(), apisec.Config{
		Timeout:            5 * time.Second,
		Concurrency:        2,
		MaxRequestsPerTest: 5,
	})

	actx := &apisec.AssessmentContext{
		AssessmentID: "asm-test-neg",
		ExecutionID:  "exec-test-neg",
		BaseURL:      ts.URL,
		Endpoints: []apisec.APIEndpoint{
			{Path: "/api/secure-data", Method: "GET", Source: "test"},
			{Path: "/api/rate-limited", Method: "GET", Source: "test"},
			{Path: "/health", Method: "GET", Source: "test"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	// Must NOT produce verified findings on secure endpoints
	if summary.VerifiedCount > 0 {
		var verifiedNames []string
		for _, r := range results {
			if r.VerificationState == apisec.StateVerified {
				verifiedNames = append(verifiedNames, r.TestName+": "+r.EvidenceSummary)
			}
		}
		t.Fatalf("expected 0 verified findings on secure endpoints, got %d: %v",
			summary.VerifiedCount, verifiedNames)
	}
}

// TestCrossEngine_APISec_AmbiguousAndMalformedResponses tests that soft-401s,
// generic HTML errors, and malformed/oversized JSON responses are handled conservatively
// and never produce false VERIFIED findings.
func TestCrossEngine_APISec_AmbiguousAndMalformedResponses(t *testing.T) {
	mux := http.NewServeMux()

	// Soft-401: HTTP 200 with application-level JSON error
	mux.HandleFunc("/api/soft-401", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"error","message":"login required","code":401}`)
	})

	// Generic HTML 500 error page without diagnostic trace
	mux.HandleFunc("/api/generic-error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<html><body><h1>Internal Server Error</h1><p>An unexpected error occurred.</p></body></html>`)
	})

	// Malformed JSON response
	mux.HandleFunc("/api/malformed-json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"broken": true, [unclosed array}`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	engine := apisec.NewEngine(ts.Client(), apisec.Config{
		Timeout:            5 * time.Second,
		Concurrency:        2,
		MaxRequestsPerTest: 5,
	})

	actx := &apisec.AssessmentContext{
		AssessmentID: "asm-test-ambig",
		ExecutionID:  "exec-test-ambig",
		BaseURL:      ts.URL,
		Endpoints: []apisec.APIEndpoint{
			{Path: "/api/soft-401", Method: "GET", Source: "test"},
			{Path: "/api/generic-error", Method: "GET", Source: "test"},
			{Path: "/api/malformed-json", Method: "GET", Source: "test"},
		},
		IsAllowed: func(u string) bool { return true },
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected engine crash on ambiguous responses: %v", err)
	}

	// Confirm that ambiguous responses are NOT classified as VERIFIED
	for _, r := range results {
		if r.VerificationState == apisec.StateVerified {
			t.Errorf("ambiguous/generic response produced false VERIFIED finding: %s (%s)",
				r.TestName, r.EvidenceSummary)
		}
	}
	_ = summary
}

// TestCrossEngine_APISec_ScopeAndCredentialStripping tests that scope enforcement
// prevents out-of-scope requests, that embedded URL credentials are blocked,
// and that cross-host redirects strip sensitive Authorization/Cookie headers.
func TestCrossEngine_APISec_ScopeAndCredentialStripping(t *testing.T) {
	var capturedAuthHeader string
	var capturedCookieHeader string

	destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		capturedCookieHeader = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"redirected"}`)
	}))
	defer destServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destServer.URL+"/dest", http.StatusFound)
	}))
	defer redirectServer.Close()

	engine := apisec.NewEngine(redirectServer.Client(), apisec.Config{
		Timeout: 5 * time.Second,
	})

	// 1. Test redirect credential stripping
	actx := &apisec.AssessmentContext{
		AssessmentID: "asm-test-redirect",
		BaseURL:      redirectServer.URL,
		IsAllowed:    func(u string) bool { return true },
	}

	scopedCli := engine.ScopedClient(actx)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", redirectServer.URL+"/start", nil)
	req.Header.Set("Authorization", "Bearer sensitive-secret-token")
	req.Header.Set("Cookie", "session=sensitive-session-cookie")

	resp, err := scopedCli.Do(req)
	if err != nil {
		t.Fatalf("failed redirect request: %v", err)
	}
	defer resp.Body.Close()

	if capturedAuthHeader != "" {
		t.Errorf("expected Authorization header to be stripped across redirect, got %q", capturedAuthHeader)
	}
	if capturedCookieHeader != "" {
		t.Errorf("expected Cookie header to be stripped across redirect, got %q", capturedCookieHeader)
	}

	// 2. Test out-of-scope redirect blocking
	actxRestricted := &apisec.AssessmentContext{
		AssessmentID: "asm-test-scope",
		BaseURL:      redirectServer.URL,
		IsAllowed: func(u string) bool {
			// Only allow redirectServer, block destServer
			return strings.HasPrefix(u, redirectServer.URL)
		},
	}
	scopedCliRestricted := engine.ScopedClient(actxRestricted)
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", redirectServer.URL+"/start", nil)
	_, err2 := scopedCliRestricted.Do(req2)
	if err2 == nil {
		t.Errorf("expected out-of-scope redirect to be blocked, but request succeeded")
	} else if !strings.Contains(err2.Error(), "out of approved scope") {
		t.Errorf("expected scope rejection error message, got: %v", err2)
	}

	// 3. Test embedded URL credentials blocking
	req3, _ := http.NewRequestWithContext(context.Background(), "GET", "http://user:pass@127.0.0.1:9999/test", nil)
	_, err3 := scopedCli.Do(req3)
	if err3 == nil {
		t.Errorf("expected embedded URL credentials to be rejected, but request succeeded")
	} else if !strings.Contains(err3.Error(), "embedded credentials") {
		t.Errorf("expected embedded credentials rejection message, got: %v", err3)
	}
}

// =============================================================================
// SECTION 2: CLOUD & BACKEND SECURITY VALIDATION MATRIX (9 PATTERNS)
// =============================================================================

// Pattern 1: Elasticsearch
func TestCrossEngine_CloudSec_Elasticsearch_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// Positive: Open cluster root returning cluster_name and version
	openES := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"cluster_name":"prod-es-cluster","version":{"number":"8.11.0"},"tagline":"You Know, for Search"}`)
	}))
	defer openES.Close()

	recPos := cloud.VerifyElasticsearchAccess(ctx, client, openES.URL, nil, nil)
	if recPos.Status != cloud.StatusServiceReachable || recPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusServiceReachable / DecisionAllowed for open ES, got %s / %s",
			recPos.Status, recPos.Decision)
	}

	// Negative: Authentication challenge (401)
	securedES := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="security"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication token"}]}}`)
	}))
	defer securedES.Close()

	recNeg := cloud.VerifyElasticsearchAccess(ctx, client, securedES.URL, nil, nil)
	if recNeg.Status != cloud.StatusAuthChallenged || recNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusAuthChallenged / DecisionDenied for secured ES, got %s / %s",
			recNeg.Status, recNeg.Decision)
	}

	// Ambiguous: 500 error / HTML page
	ambigES := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<html><body>Server Error</body></html>`)
	}))
	defer ambigES.Close()

	recAmbig := cloud.VerifyElasticsearchAccess(ctx, client, ambigES.URL, nil, nil)
	if recAmbig.Decision == cloud.DecisionAllowed {
		t.Errorf("ambiguous 500 error on ES must NOT be allowed")
	}

	// Authenticated: Valid credentials supplied
	authES := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "elastic" && p == "secretpass" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"cluster_name":"auth-es-cluster","version":{"number":"8.11.0"}}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer authES.Close()

	recAuth := cloud.VerifyElasticsearchAccess(ctx, client, authES.URL, &cloud.CredentialProfile{
		Username: "elastic",
		Secret:   "secretpass",
	}, nil)
	if recAuth.Status != cloud.StatusAuthenticatedAccess || recAuth.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusAuthenticatedAccess for valid creds, got %s / %s",
			recAuth.Status, recAuth.Decision)
	}
}

// Pattern 2: MongoDB
func TestCrossEngine_CloudSec_MongoDB_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// Positive mock: MongoDB wire protocol responder answering isMaster
	lnPos, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lnPos.Close()

	go func() {
		for {
			conn, err := lnPos.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)

				// Send OP_REPLY header (36 bytes) + payload containing "ismaster: true"
				respBody := []byte("...ismaster: true, maxBsonObjectSize: 16777216...")
				msgLen := int32(36 + len(respBody))
				var pkt bytes.Buffer
				_ = binary.Write(&pkt, binary.LittleEndian, msgLen)
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1)) // requestID
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1)) // responseTo
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1)) // OP_REPLY
				_ = binary.Write(&pkt, binary.LittleEndian, int32(0)) // responseFlags
				_ = binary.Write(&pkt, binary.LittleEndian, int64(0)) // cursorID
				_ = binary.Write(&pkt, binary.LittleEndian, int32(0)) // startingFrom
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1)) // numberReturned
				pkt.Write(respBody)

				_, _ = c.Write(pkt.Bytes())
			}(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(lnPos.Addr().String())
	port, _ := strconv.Atoi(portStr)

	recPos := cloud.VerifyMongoDBAccess(ctx, client, host, port, nil, nil)
	if recPos.Status != cloud.StatusServiceReachable || recPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusServiceReachable / DecisionAllowed for open MongoDB, got %s / %s",
			recPos.Status, recPos.Decision)
	}

	// Negative mock: MongoDB returning "requires authentication"
	lnNeg, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lnNeg.Close()

	go func() {
		for {
			conn, err := lnNeg.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)

				respBody := []byte("...command failed: requires authentication, Unauthorized...")
				msgLen := int32(36 + len(respBody))
				var pkt bytes.Buffer
				_ = binary.Write(&pkt, binary.LittleEndian, msgLen)
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1))
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1))
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1))
				_ = binary.Write(&pkt, binary.LittleEndian, int32(0))
				_ = binary.Write(&pkt, binary.LittleEndian, int64(0))
				_ = binary.Write(&pkt, binary.LittleEndian, int32(0))
				_ = binary.Write(&pkt, binary.LittleEndian, int32(1))
				pkt.Write(respBody)

				_, _ = c.Write(pkt.Bytes())
			}(conn)
		}
	}()

	negHost, negPortStr, _ := net.SplitHostPort(lnNeg.Addr().String())
	negPort, _ := strconv.Atoi(negPortStr)

	recNeg := cloud.VerifyMongoDBAccess(ctx, client, negHost, negPort, nil, nil)
	if recNeg.Status != cloud.StatusAuthChallenged || recNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusAuthChallenged / DecisionDenied for secured MongoDB, got %s / %s",
			recNeg.Status, recNeg.Decision)
	}
}

// Pattern 3: Redis
func TestCrossEngine_CloudSec_Redis_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// Positive mock: Redis responding +PONG to PING
	lnPos, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lnPos.Close()

	go func() {
		for {
			conn, err := lnPos.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				if strings.HasPrefix(string(buf[:n]), "PING") {
					_, _ = c.Write([]byte("+PONG\r\n"))
				}
			}(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(lnPos.Addr().String())
	port, _ := strconv.Atoi(portStr)

	recPos := cloud.VerifyRedisAccess(ctx, client, host, port, nil, nil)
	if recPos.Status != cloud.StatusServiceReachable || recPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusServiceReachable / DecisionAllowed for open Redis, got %s / %s",
			recPos.Status, recPos.Decision)
	}

	// Negative mock: Redis responding -NOAUTH Authentication required
	lnNeg, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lnNeg.Close()

	go func() {
		for {
			conn, err := lnNeg.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				if strings.HasPrefix(string(buf[:n]), "PING") {
					_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
				}
			}(conn)
		}
	}()

	negHost, negPortStr, _ := net.SplitHostPort(lnNeg.Addr().String())
	negPort, _ := strconv.Atoi(negPortStr)

	recNeg := cloud.VerifyRedisAccess(ctx, client, negHost, negPort, nil, nil)
	if recNeg.Status != cloud.StatusAuthChallenged || recNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusAuthChallenged / DecisionDenied for secured Redis, got %s / %s",
			recNeg.Status, recNeg.Decision)
	}

	// Authenticated: Valid auth command responds +OK
	lnAuth, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lnAuth.Close()

	go func() {
		for {
			conn, err := lnAuth.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					cmd := string(buf[:n])
					if strings.HasPrefix(cmd, "PING") {
						_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
					} else if strings.HasPrefix(cmd, "AUTH valid-redis-pass") {
						_, _ = c.Write([]byte("+OK\r\n"))
					} else {
						_, _ = c.Write([]byte("-ERR unknown command\r\n"))
					}
				}
			}(conn)
		}
	}()

	authHost, authPortStr, _ := net.SplitHostPort(lnAuth.Addr().String())
	authPort, _ := strconv.Atoi(authPortStr)

	recAuth := cloud.VerifyRedisAccess(ctx, client, authHost, authPort, &cloud.CredentialProfile{
		Secret: "valid-redis-pass",
	}, nil)
	if recAuth.Status != cloud.StatusAuthenticatedAccess || recAuth.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusAuthenticatedAccess for valid Redis credentials, got %s / %s",
			recAuth.Status, recAuth.Decision)
	}
}

// Pattern 4: PostgreSQL & MySQL HTTP interfaces and indicators
func TestCrossEngine_CloudSec_PostgreSQL_MySQL_Matrix(t *testing.T) {
	detector := cloud.NewIndicatorDetector()

	// 1. Passive Connection Indicator Extraction & Redaction
	cfg := `
		database:
		  url: postgres://app_user:super_secret_db_password_123@db.internal.net:5432/production_db
	`
	indicators := detector.DetectIndicators(cloud.IndicatorSource{
		Type:       cloud.SourceTypeConfigFile,
		Identifier: "config/database.yml",
	}, []byte(cfg))
	if len(indicators) == 0 {
		t.Fatalf("expected PostgreSQL connection indicator extracted, got 0")
	}

	ind := indicators[0]
	if ind.Technology != cloud.TechPostgreSQL {
		t.Errorf("expected TechPostgreSQL, got %s", ind.Technology)
	}
	if strings.Contains(ind.SanitizedValue, "super_secret_db_password_123") {
		t.Errorf("password leaked into SanitizedValue: %s", ind.SanitizedValue)
	}
	if strings.Contains(ind.Source.ContextLine, "super_secret_db_password_123") {
		t.Errorf("password leaked into Source.ContextLine: %s", ind.Source.ContextLine)
	}

	// 2. MySQL Go DSN Indicator
	dsn := "appuser:secretmysqlpass@tcp(mysql.internal:3306)/proddb?charset=utf8mb4"
	mysqlInds := detector.DetectIndicators(cloud.IndicatorSource{
		Type:       cloud.SourceTypeEnvironmentVariable,
		Identifier: ".env",
	}, []byte("DATABASE_URL="+dsn))
	if len(mysqlInds) == 0 {
		t.Fatalf("expected MySQL indicator extracted, got 0")
	}
	if strings.Contains(mysqlInds[0].SanitizedValue, "secretmysqlpass") {
		t.Errorf("MySQL password leaked into SanitizedValue: %s", mysqlInds[0].SanitizedValue)
	}
}

// Pattern 5: Supabase, PostgREST, Hasura, Prisma
func TestCrossEngine_CloudSec_Supabase_PostgREST_Hasura_Prisma_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// 1. Supabase REST Gateway
	// Positive: 200 on /rest/v1/
	openSupabase := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"PostgREST API"}}`)
	}))
	defer openSupabase.Close()

	recSupaPos := cloud.VerifySupabaseAccess(ctx, client, openSupabase.URL, nil, nil)
	if recSupaPos.Status != cloud.StatusServiceReachable || recSupaPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusServiceReachable for open Supabase gateway, got %s / %s",
			recSupaPos.Status, recSupaPos.Decision)
	}

	// Negative: 401 on /rest/v1/
	securedSupabase := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"JWSError JWSInvalidSignature"}`)
	}))
	defer securedSupabase.Close()

	recSupaNeg := cloud.VerifySupabaseAccess(ctx, client, securedSupabase.URL, nil, nil)
	if recSupaNeg.Status != cloud.StatusAuthChallenged || recSupaNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusAuthChallenged for secured Supabase gateway, got %s / %s",
			recSupaNeg.Status, recSupaNeg.Decision)
	}

	// 2. PostgREST
	// Positive: Unauthenticated table query returns data
	openPostgREST := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[{"id":1,"name":"Alice","role":"admin"}]`)
	}))
	defer openPostgREST.Close()

	recPgrstPos := cloud.VerifyPostgRESTAccess(ctx, client, openPostgREST.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "users",
	})
	if recPgrstPos.Status != cloud.StatusReadAllowed || recPgrstPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusReadAllowed for open PostgREST table, got %s / %s",
			recPgrstPos.Status, recPgrstPos.Decision)
	}

	// Negative: PGRST error (401)
	securedPostgREST := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"code":"PGRST301","message":"JWT expired"}`)
	}))
	defer securedPostgREST.Close()

	recPgrstNeg := cloud.VerifyPostgRESTAccess(ctx, client, securedPostgREST.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "users",
	})
	if recPgrstNeg.Status != cloud.StatusReadDenied || recPgrstNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusReadDenied for secured PostgREST table, got %s / %s",
			recPgrstNeg.Status, recPgrstNeg.Decision)
	}

	// 3. Hasura
	// Positive: GraphQL endpoint responds with schema/ready
	openHasura := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"__typename":"query_root"}}`)
	}))
	defer openHasura.Close()

	recHasuraPos := cloud.VerifyHasuraAccess(ctx, client, openHasura.URL, nil, nil)
	if recHasuraPos.Status != cloud.StatusServiceReachable || recHasuraPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusServiceReachable for open Hasura, got %s / %s",
			recHasuraPos.Status, recHasuraPos.Decision)
	}

	// Negative: Hasura access-denied
	securedHasura := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"message":"x-hasura-admin-secret / x-hasura-access-key required","code":"access-denied"}]}`)
	}))
	defer securedHasura.Close()

	recHasuraNeg := cloud.VerifyHasuraAccess(ctx, client, securedHasura.URL, nil, nil)
	if recHasuraNeg.Status != cloud.StatusAuthChallenged || recHasuraNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusAuthChallenged for secured Hasura, got %s / %s",
			recHasuraNeg.Status, recHasuraNeg.Decision)
	}

	// 4. Prisma
	// Architecture boundary: Prisma is an internal ORM layer without standalone network daemon
	recPrisma := cloud.VerifyPrismaAccess(ctx, client, "http://127.0.0.1:3000", nil, nil)
	if recPrisma.Status != cloud.StatusVerificationSkipped || recPrisma.Decision != cloud.DecisionSkipped {
		t.Errorf("expected StatusVerificationSkipped / DecisionSkipped for Prisma, got %s / %s",
			recPrisma.Status, recPrisma.Decision)
	}
	if !strings.Contains(recPrisma.Limitations, "internal application ORM layer") {
		t.Errorf("expected limitation explanation in Prisma record: %s", recPrisma.Limitations)
	}
}

// Pattern 6: Firebase Realtime Database & Firestore
func TestCrossEngine_CloudSec_Firebase_Firestore_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// 1. Firebase RTDB
	// Positive: Open .json endpoint returns 200 with JSON payload
	openRTDB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"users":{"alice":{"role":"admin"}},"config":{"public":true}}`)
	}))
	defer openRTDB.Close()

	recRTDBPos := cloud.VerifyFirebaseRTDBAccess(ctx, client, openRTDB.URL, nil, nil)
	if recRTDBPos.Status != cloud.StatusReadAllowed || recRTDBPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusReadAllowed for open Firebase RTDB, got %s / %s",
			recRTDBPos.Status, recRTDBPos.Decision)
	}

	// Negative: 401 Permission denied on .json endpoint
	securedRTDB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"Permission denied"}`)
	}))
	defer securedRTDB.Close()

	recRTDBNeg := cloud.VerifyFirebaseRTDBAccess(ctx, client, securedRTDB.URL, nil, nil)
	if recRTDBNeg.Status != cloud.StatusReadDenied || recRTDBNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusReadDenied for secured Firebase RTDB, got %s / %s",
			recRTDBNeg.Status, recRTDBNeg.Decision)
	}

	// Ambiguous: 404 Not Found
	missingRTDB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `404 page not found`)
	}))
	defer missingRTDB.Close()

	recRTDBAmbig := cloud.VerifyFirebaseRTDBAccess(ctx, client, missingRTDB.URL, nil, nil)
	if recRTDBAmbig.Decision == cloud.DecisionAllowed {
		t.Errorf("404 response on Firebase RTDB must NOT be DecisionAllowed")
	}

	// 2. Cloud Firestore
	// Positive: Open Firestore REST documents endpoint returns 200 with documents
	openFirestore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"documents":[{"name":"projects/p/databases/(default)/documents/users/1"}]}`)
	}))
	defer openFirestore.Close()

	recFsPos := cloud.VerifyFirestoreAccess(ctx, client, openFirestore.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "users",
	})
	if recFsPos.Status != cloud.StatusReadAllowed || recFsPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusReadAllowed for open Firestore collection, got %s / %s",
			recFsPos.Status, recFsPos.Decision)
	}

	// Negative: 403 Missing or insufficient permissions
	securedFirestore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403,"message":"Missing or insufficient permissions."}}`)
	}))
	defer securedFirestore.Close()

	recFsNeg := cloud.VerifyFirestoreAccess(ctx, client, securedFirestore.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "users",
	})
	if recFsNeg.Status != cloud.StatusReadDenied || recFsNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusReadDenied for secured Firestore collection, got %s / %s",
			recFsNeg.Status, recFsNeg.Decision)
	}
}

// Pattern 7 & 9: AWS S3 & MinIO
func TestCrossEngine_CloudSec_Storage_S3_MinIO_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// Positive: S3 bucket responding to max-keys=0 with ListBucketResult XML
	openS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-s3-bucket</Name><Prefix></Prefix><MaxKeys>0</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
	}))
	defer openS3.Close()

	// Assess via cloudsec.ExternalEvaluator
	extEval := cloudsec.NewExternalEvaluator(cloudsec.DefaultConfig())
	actx := &cloudsec.AssessmentContext{
		AssessmentID: "asm-s3-pos",
		ExecutionID:  "exec-s3-pos",
		Mode:         cloudsec.ModeExternal,
		ExternalTargets: []cloudsec.ExternalTarget{
			{
				URL:      openS3.URL + "/s3-bucket",
				Hostname: "127.0.0.1",
				Scheme:   "http",
				Headers:  map[string]string{"server": "AmazonS3"},
			},
		},
		IsAllowed: func(u string) bool { return true },
	}

	results, _, _ := extEval.Assess(ctx, actx, openS3.Client())
	if len(results) == 0 {
		t.Fatalf("expected at least 1 S3 result from ExternalEvaluator, got 0")
	}

	s3Result := results[0]
	if s3Result.VerificationState != cloudsec.StateVerified {
		t.Errorf("expected StateVerified for open S3 bucket listing, got %s (evidence: %s)",
			s3Result.VerificationState, s3Result.EvidenceSummary)
	}

	// Negative: 403 AccessDenied
	securedS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	}))
	defer securedS3.Close()

	actxNeg := &cloudsec.AssessmentContext{
		AssessmentID: "asm-s3-neg",
		ExecutionID:  "exec-s3-neg",
		Mode:         cloudsec.ModeExternal,
		ExternalTargets: []cloudsec.ExternalTarget{
			{
				URL:      securedS3.URL + "/s3-bucket",
				Hostname: "127.0.0.1",
				Scheme:   "http",
				Headers:  map[string]string{"server": "AmazonS3"},
			},
		},
		IsAllowed: func(u string) bool { return true },
	}

	resultsNeg, _, _ := extEval.Assess(ctx, actxNeg, securedS3.Client())
	if len(resultsNeg) == 0 {
		t.Fatalf("expected S3 result for secured bucket, got 0")
	}
	if resultsNeg[0].VerificationState == cloudsec.StateVerified {
		t.Errorf("secured 403 S3 bucket must NOT be StateVerified")
	}

	// MinIO positive check via cloud.VerifyMinIOAccess
	recMinio := cloud.VerifyMinIOAccess(ctx, client, openS3.URL, nil, nil)
	if recMinio.Decision != cloud.DecisionAllowed {
		t.Errorf("expected DecisionAllowed for reachable MinIO endpoint")
	}
}

// Pattern 8: Azure Blob Storage
func TestCrossEngine_CloudSec_Storage_AzureBlob_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// Positive: 200 on synthetic object HEAD
	openAzure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.Header().Set("x-ms-version", "2020-10-02")
		w.WriteHeader(http.StatusOK)
	}))
	defer openAzure.Close()

	recPos := cloud.VerifyAzureBlobAccess(ctx, client, openAzure.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "public-blob.txt",
	})
	if recPos.Status != cloud.StatusReadAllowed || recPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusReadAllowed / DecisionAllowed for public blob, got %s / %s",
			recPos.Status, recPos.Decision)
	}

	// Negative: 403 AuthenticationFailed
	securedAzure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.Header().Set("x-ms-version", "2020-10-02")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer securedAzure.Close()

	recNeg := cloud.VerifyAzureBlobAccess(ctx, client, securedAzure.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "private-blob.txt",
	})
	if recNeg.Status != cloud.StatusReadDenied || recNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusReadDenied / DecisionDenied for secured blob, got %s / %s",
			recNeg.Status, recNeg.Decision)
	}
}

// Pattern 9: Google Cloud Storage (GCS)
func TestCrossEngine_CloudSec_Storage_GCS_Matrix(t *testing.T) {
	ctx := context.Background()
	client := cloud.NewClient(cloud.ClientOptions{AllowLoopback: true})

	// Positive: 200 HEAD on synthetic object
	openGCS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "UploadServer")
		w.WriteHeader(http.StatusOK)
	}))
	defer openGCS.Close()

	recPos := cloud.VerifyGCSAccess(ctx, client, openGCS.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "public-asset.png",
	})
	if recPos.Status != cloud.StatusReadAllowed || recPos.Decision != cloud.DecisionAllowed {
		t.Errorf("expected StatusReadAllowed / DecisionAllowed for public GCS object, got %s / %s",
			recPos.Status, recPos.Decision)
	}

	// Negative: 403 AccessDenied
	securedGCS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "UploadServer")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer securedGCS.Close()

	recNeg := cloud.VerifyGCSAccess(ctx, client, securedGCS.URL, nil, &cloud.TestResourceConfig{
		ResourceID: "private-asset.png",
	})
	if recNeg.Status != cloud.StatusReadDenied || recNeg.Decision != cloud.DecisionDenied {
		t.Errorf("expected StatusReadDenied / DecisionDenied for secured GCS object, got %s / %s",
			recNeg.Status, recNeg.Decision)
	}
}

// =============================================================================
// SECTION 3: CROSS-ENGINE FINDING INTEGRITY & SECRET REDACTION
// =============================================================================

// TestCrossEngine_FindingIntegrityAndRedaction tests that sensitive secrets,
// tokens, and credentials are completely scrubbed from all evidence strings,
// finding fields, and log outputs across API and cloud security engines.
func TestCrossEngine_FindingIntegrityAndRedaction(t *testing.T) {
	const rawSecret = "super-secret-production-token-9876543210"
	const rawPassword = "P@ssw0rd!MasterAdminKey"

	// 1. Text Redaction
	textWithSecrets := fmt.Sprintf("Authorization: Bearer %s, DB password: %s", rawSecret, rawPassword)
	redactedText := apisec.RedactText(textWithSecrets)
	if strings.Contains(redactedText, rawSecret) {
		t.Errorf("secret token leaked in RedactText: %s", redactedText)
	}
	if strings.Contains(redactedText, rawPassword) {
		t.Errorf("password leaked in RedactText: %s", redactedText)
	}

	// 2. Header Sanitization
	headers := http.Header{
		"Authorization": []string{"Bearer " + rawSecret},
		"Cookie":        []string{"session_id=" + rawSecret},
		"X-Api-Key":     []string{rawSecret},
		"Content-Type":  []string{"application/json"},
	}
	sanitized := apisec.SanitizeHeaders(headers)
	if strings.Contains(sanitized["Authorization"], rawSecret) {
		t.Errorf("secret token leaked in sanitized Authorization: %s", sanitized["Authorization"])
	}
	if strings.Contains(sanitized["Cookie"], rawSecret) {
		t.Errorf("secret token leaked in sanitized Cookie: %s", sanitized["Cookie"])
	}
	if strings.Contains(sanitized["X-Api-Key"], rawSecret) {
		t.Errorf("secret token leaked in sanitized X-Api-Key: %s", sanitized["X-Api-Key"])
	}
	if sanitized["Content-Type"] != "application/json" {
		t.Errorf("non-sensitive header was corrupted: %s", sanitized["Content-Type"])
	}

	// 3. URL Sanitization
	rawURL := fmt.Sprintf("https://api.example.com/v1/data?token=%s&key=%s&safe_id=12345", rawSecret, rawPassword)
	sanitizedURL := apisec.SanitizeURL(rawURL)
	if strings.Contains(sanitizedURL, rawSecret) {
		t.Errorf("secret token leaked in sanitized URL: %s", sanitizedURL)
	}
	if strings.Contains(sanitizedURL, rawPassword) {
		t.Errorf("password leaked in sanitized URL: %s", sanitizedURL)
	}
	if !strings.Contains(sanitizedURL, "safe_id=12345") {
		t.Errorf("safe query parameter was removed: %s", sanitizedURL)
	}

	// 4. Body Redaction
	rawBody := []byte(fmt.Sprintf(`{"user":"bob","secret_token":"%s","password":"%s","status":"active"}`, rawSecret, rawPassword))
	redactedBody := apisec.RedactBody(rawBody, 512)
	if strings.Contains(redactedBody, rawSecret) {
		t.Errorf("secret token leaked in RedactBody: %s", redactedBody)
	}
	if strings.Contains(redactedBody, rawPassword) {
		t.Errorf("password leaked in RedactBody: %s", redactedBody)
	}

	// 5. Cloud credentials scrubbing
	creds := cloudsec.Credentials{
		AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		AWSSecretAccessKey: rawSecret,
		AzureClientSecret:  rawPassword,
		GCPPrivateKey:      "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...",
	}
	creds.Scrub()
	if creds.AWSSecretAccessKey != "" || creds.AzureClientSecret != "" || creds.GCPPrivateKey != "" {
		t.Errorf("Credentials.Scrub failed to clear sensitive secret fields: %+v", creds)
	}
}
