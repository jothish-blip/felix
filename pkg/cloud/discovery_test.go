package cloud

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Helper to create test client allowing loopback for mock servers
func newLoopbackTestClient() *Client {
	return NewClient(ClientOptions{
		Timeout:         2 * time.Second,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	})
}

// -------------------------------------------------------------
// Group A: Direct Database & Search
// -------------------------------------------------------------

// 1. Elasticsearch
func TestProbeElasticsearch(t *testing.T) {
	// A. Open Elasticsearch instance (200 OK)
	serverOpen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-elastic-product", "Elasticsearch")
		fmt.Fprintln(w, `{
			"name": "node-1",
			"cluster_name": "es-production",
			"tagline": "You Know, for Search",
			"version": {"number": "8.11.0"}
		}`)
	}))
	defer serverOpen.Close()

	client := newLoopbackTestClient()
	resOpen := ProbeElasticsearch(context.Background(), client, serverOpen.URL)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open ES, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (discovery root does not imply indices access), got true")
	}
	if !strings.Contains(resOpen.Limitations, "indices read permissions require Phase 2.2") {
		t.Errorf("expected limitations note about indices read permissions, got %s", resOpen.Limitations)
	}
	if resOpen.Version != "8.11.0" {
		t.Errorf("expected version 8.11.0, got %s", resOpen.Version)
	}

	// B. Authenticated Elasticsearch (401 security_exception)
	serverAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="security" charset="UTF-8"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication credentials"}],"type":"security_exception"}}`)
	}))
	defer serverAuth.Close()

	resAuth := ProbeElasticsearch(context.Background(), client, serverAuth.URL)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for 401 security_exception, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true, got false")
	}

	// C. Non-Elasticsearch server
	serverOther := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello World Nginx")
	}))
	defer serverOther.Close()

	resOther := ProbeElasticsearch(context.Background(), client, serverOther.URL)
	if resOther.Outcome != OutcomeNotDetected {
		t.Errorf("expected OutcomeNotDetected, got %s", resOther.Outcome)
	}
}

// 2. MongoDB
func TestProbeMongoDB(t *testing.T) {
	client := newLoopbackTestClient()

	// A. HTTP Driver Port check (28017 / 27017)
	serverHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "It looks like you are trying to access MongoDB over HTTP on the native driver port.")
	}))
	defer serverHTTP.Close()

	u, _ := serverHTTP.Listener.Addr().(*net.TCPAddr)
	resHTTP := ProbeMongoDB(context.Background(), client, u.IP.String(), u.Port)
	if resHTTP.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for MongoDB HTTP notice, got %s", resHTTP.Outcome)
	}

	// B. Safe TCP Probe on mock MongoDB server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n == 0 {
					return
				}
				resp := []byte("...ismaster...isWritablePrimary...maxBsonObjectSize...")
				_, _ = c.Write(resp)
			}(conn)
		}
	}()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	resTCP := ProbeMongoDB(context.Background(), client, tcpAddr.IP.String(), tcpAddr.Port)
	if resTCP.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for MongoDB TCP probe, got %s", resTCP.Outcome)
	}
	if resTCP.Technology != TechMongoDB {
		t.Errorf("expected TechMongoDB, got %s", resTCP.Technology)
	}
}

// 3. Redis
func TestProbeRedis(t *testing.T) {
	client := newLoopbackTestClient()

	// A. Unauthenticated Redis (+PONG)
	lOpen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer lOpen.Close()

	go func() {
		conn, err := lOpen.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("+PONG\r\n"))
	}()

	addrOpen := lOpen.Addr().(*net.TCPAddr)
	resOpen := ProbeRedis(context.Background(), client, addrOpen.IP.String(), addrOpen.Port)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Redis PONG, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open Redis, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (PONG confirms protocol identity, not keyspace access), got true")
	}
	if !strings.Contains(resOpen.Limitations, "PING response confirms active Redis protocol") {
		t.Errorf("expected limitations note about Redis protocol confirmation, got %s", resOpen.Limitations)
	}

	// B. Authenticated Redis (-NOAUTH)
	lAuth, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer lAuth.Close()

	go func() {
		conn, err := lAuth.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
	}()

	addrAuth := lAuth.Addr().(*net.TCPAddr)
	resAuth := ProbeRedis(context.Background(), client, addrAuth.IP.String(), addrAuth.Port)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Redis NOAUTH, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for NOAUTH Redis, got false")
	}

	// C. Protected mode Redis (-DENIED)
	lDenied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer lDenied.Close()

	go func() {
		conn, err := lDenied.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("-DENIED Redis is running in protected mode\r\n"))
	}()

	addrDenied := lDenied.Addr().(*net.TCPAddr)
	resDenied := ProbeRedis(context.Background(), client, addrDenied.IP.String(), addrDenied.Port)
	if resDenied.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for protected mode Redis, got %s", resDenied.Outcome)
	}
	if !resDenied.AuthRequired {
		t.Errorf("expected AuthRequired=true for protected mode Redis, got false")
	}
}

// 4. PostgreSQL
func TestProbePostgreSQL(t *testing.T) {
	client := newLoopbackTestClient()

	// Server returning 'S' (SSL supported) to SSLRequest
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		if n == 8 && bytes.Equal(buf[:8], []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}) {
			_, _ = conn.Write([]byte{'S'})
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	res := ProbePostgreSQL(context.Background(), client, addr.IP.String(), addr.Port)
	if res.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for PostgreSQL SSLRequest, got %s", res.Outcome)
	}
	if res.Technology != TechPostgreSQL {
		t.Errorf("expected TechPostgreSQL, got %s", res.Technology)
	}
	if res.AuthRequired {
		t.Errorf("expected AuthRequired=false (SSL negotiation does not challenge credentials), got true")
	}
	if res.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
	if !strings.Contains(res.Limitations, "SSL negotiation confirms PostgreSQL protocol") {
		t.Errorf("expected limitations note about SSL negotiation, got %s", res.Limitations)
	}
}

// 5. MySQL
func TestProbeMySQL(t *testing.T) {
	client := newLoopbackTestClient()

	// A. Initial Handshake Packet (Protocol 10 with version 8.0.32)
	lHandshake, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer lHandshake.Close()

	go func() {
		conn, err := lHandshake.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Packet: 3 bytes length, 1 byte sequence (0x00), protocol (0x0A), version string null-terminated
		ver := "8.0.32-community\x00"
		payload := append([]byte{0x0A}, []byte(ver)...)
		pktLen := len(payload)
		header := []byte{byte(pktLen), 0x00, 0x00, 0x00}
		_, _ = conn.Write(append(header, payload...))
	}()

	addrH := lHandshake.Addr().(*net.TCPAddr)
	resH := ProbeMySQL(context.Background(), client, addrH.IP.String(), addrH.Port)
	if resH.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for MySQL Handshake, got %s", resH.Outcome)
	}
	if resH.Version != "8.0.32-community" {
		t.Errorf("expected version 8.0.32-community, got %s", resH.Version)
	}
	if resH.AuthRequired {
		t.Errorf("expected AuthRequired=false (handshake initiates protocol without credentials), got true")
	}
	if resH.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
	if !strings.Contains(resH.Limitations, "Initial Handshake Packet confirms MySQL protocol") {
		t.Errorf("expected limitations note about MySQL protocol, got %s", resH.Limitations)
	}

	// B. Error packet (Code 1130: Host not allowed)
	lErr, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer lErr.Close()

	go func() {
		conn, err := lErr.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var pkt bytes.Buffer
		pkt.Write([]byte{0x10, 0x00, 0x00, 0x00}) // len 16, seq 0
		pkt.WriteByte(0xFF)                      // error indicator
		var codeBytes [2]byte
		binary.LittleEndian.PutUint16(codeBytes[:], 1130)
		pkt.Write(codeBytes[:])
		pkt.WriteString("Host is not allowed to connect to this MySQL server")
		_, _ = conn.Write(pkt.Bytes())
	}()

	addrErr := lErr.Addr().(*net.TCPAddr)
	resErr := ProbeMySQL(context.Background(), client, addrErr.IP.String(), addrErr.Port)
	if resErr.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for MySQL error packet, got %s", resErr.Outcome)
	}
	if !strings.Contains(resErr.Evidence, "1130") {
		t.Errorf("expected error code 1130 in evidence, got %s", resErr.Evidence)
	}
}

// -------------------------------------------------------------
// Group B: Database Administration Interfaces
// -------------------------------------------------------------

// 6. Mongo Express
func TestProbeMongoExpress(t *testing.T) {
	client := newLoopbackTestClient()

	// A. Open UI (200 OK)
	serverOpen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><head><title>Mongo Express</title></head><body><h1>Database Administration</h1></body></html>")
	}))
	defer serverOpen.Close()

	resOpen := ProbeMongoExpress(context.Background(), client, serverOpen.URL)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for open Mongo Express, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open Mongo Express, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
	if !strings.Contains(resOpen.Limitations, "Admin dashboard presence confirmed") {
		t.Errorf("expected limitations note about admin dashboard, got %s", resOpen.Limitations)
	}

	// B. Authenticated (401 with mongo-express realm)
	serverAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="mongo-express"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Access denied")
	}))
	defer serverAuth.Close()

	resAuth := ProbeMongoExpress(context.Background(), client, serverAuth.URL)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for authenticated Mongo Express, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for 401 Mongo Express, got false")
	}
}

// -------------------------------------------------------------
// Group C: Backend & Database Interfaces
// -------------------------------------------------------------

// 7. Supabase
func TestProbeSupabase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			w.Header().Set("sb-gateway-mode", "api")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"message":"Invalid API key"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newLoopbackTestClient()
	engine := NewServiceDiscoveryEngine(client, func(s string) bool { return true })

	cand := DiscoveredService{
		Technology: TechSupabase,
		Family:     FamilyBackendInterface,
		Endpoint:   server.URL,
	}
	res := engine.VerifyCandidate(context.Background(), cand)
	if res.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Supabase REST gateway, got %s", res.Outcome)
	}
	if !res.AuthRequired {
		t.Errorf("expected AuthRequired=true, got false")
	}
}

// 8. PostgREST
func TestProbePostgREST(t *testing.T) {
	client := newLoopbackTestClient()

	// A. Range-Unit: items header
	serverRange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Range-Unit", "items")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "[]")
	}))
	defer serverRange.Close()

	resRange := ProbePostgREST(context.Background(), client, serverRange.URL)
	if resRange.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Range-Unit: items, got %s", resRange.Outcome)
	}

	// B. OpenAPI specification title
	serverOpenAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"swagger":"2.0","info":{"title":"PostgREST API","version":"10.0.0"}}`)
	}))
	defer serverOpenAPI.Close()

	resAPI := ProbePostgREST(context.Background(), client, serverOpenAPI.URL)
	if resAPI.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for PostgREST OpenAPI, got %s", resAPI.Outcome)
	}
	if resAPI.Version != "10.0.0" {
		t.Errorf("expected version 10.0.0, got %s", resAPI.Version)
	}
}

// 9. Hasura
func TestProbeHasura(t *testing.T) {
	client := newLoopbackTestClient()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/version" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"version":"v2.18.0"}`)
			return
		}
		if r.URL.Path == "/v1/graphql" {
			w.Header().Set("x-hasura-role", "anonymous")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"errors":[{"message":"validation-failed","code":"validation-failed"}]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	res := ProbeHasura(context.Background(), client, server.URL)
	if res.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Hasura, got %s", res.Outcome)
	}
	if res.Version != "v2.18.0" {
		t.Errorf("expected version v2.18.0, got %s", res.Version)
	}
}

// 10. Prisma
func TestAssessPrisma(t *testing.T) {
	// A. Client reference in bundle
	jsContent := []byte(`import { PrismaClient } from "@prisma/client"; const prisma = new PrismaClient();`)
	resDetected := AssessPrisma("bundle.js", jsContent)
	if resDetected.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Prisma client, got %s", resDetected.Outcome)
	}

	// B. Error code P2002
	errContent := []byte(`{"error": "Unique constraint failed on the fields: (email)", "code": "P2002"}`)
	resErr := AssessPrisma("api_response.json", errContent)
	if resErr.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for P2002 error, got %s", resErr.Outcome)
	}

	// C. Negative case with explicit limitation
	cleanContent := []byte(`console.log("standard web application without orm markers");`)
	resNeg := AssessPrisma("clean.js", cleanContent)
	if resNeg.Outcome != OutcomeNotDetected {
		t.Fatalf("expected OutcomeNotDetected, got %s", resNeg.Outcome)
	}
	if resNeg.Limitations == "" {
		t.Errorf("expected explicit limitation note for black-box Prisma detection")
	}
}

// -------------------------------------------------------------
// Group D: Firebase Databases
// -------------------------------------------------------------

// 11. Firebase Realtime Database
func TestProbeFirebaseRTDB(t *testing.T) {
	client := newLoopbackTestClient()

	// A. 200 OK (Open database)
	serverOpen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" && r.Method != "GET" {
			t.Errorf("unexpected HTTP method: %s", r.Method)
		}
		if strings.Contains(r.URL.RawQuery, "shallow") {
			t.Errorf("discovery probe must not include shallow=true key enumeration: %s", r.URL.String())
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"users": true, "settings": true}`)
	}))
	defer serverOpen.Close()

	resOpen := ProbeFirebaseRTDB(context.Background(), client, serverOpen.URL)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for open RTDB, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open RTDB, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (detailed key read boundaries deferred to Phase 2.2), got true")
	}

	// B. 401 Permission Denied (Protected database)
	serverAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"error": "Permission denied"}`)
	}))
	defer serverAuth.Close()

	resAuth := ProbeFirebaseRTDB(context.Background(), client, serverAuth.URL)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for protected RTDB, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for 401 RTDB, got false")
	}
	if resAuth.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
}

// 12. Cloud Firestore
func TestProbeFirestore(t *testing.T) {
	// A. Mock server simulating Firestore REST endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "documents") {
			t.Errorf("probe requested documents collection, violating non-enumeration rule: %s", r.URL.Path)
		}
		if strings.Contains(r.URL.Path, "projects/test-proj-1/databases/(default)") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"error": {"code": 403, "message": "Missing or insufficient permissions.", "status": "PERMISSION_DENIED"}}`)
			return
		}
		if strings.Contains(r.URL.Path, "projects/test-proj-open/databases/(default)") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"name": "projects/test-proj-open/databases/(default)"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Custom client directing request to mock server
	client := NewClient(ClientOptions{
		Timeout:       2 * time.Second,
		AllowLoopback: true,
		HTTPClient: &http.Client{
			Transport: &rewriteTransport{
				targetServer: server.URL,
			},
		},
	})

	res := ProbeFirestore(context.Background(), client, "test-proj-1")
	if res.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for Firestore PERMISSION_DENIED, got %s", res.Outcome)
	}
	if !res.AuthRequired {
		t.Errorf("expected AuthRequired=true, got false")
	}
	if res.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}

	resOpen := ProbeFirestore(context.Background(), client, "test-proj-open")
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for open Firestore, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open Firestore, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (metadata does not imply collection access), got true")
	}
	if !strings.Contains(resOpen.Limitations, "document read boundary verification deferred to Phase 2.2") {
		t.Errorf("expected limitations note about document read boundaries, got %s", resOpen.Limitations)
	}
}

// -------------------------------------------------------------
// Group E: Cloud & Object Storage
// -------------------------------------------------------------

// 13. AWS S3
func TestProbeAWSS3(t *testing.T) {
	client := newLoopbackTestClient()

	// A. 200 OK HEAD response
	serverOpen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" && r.Method != "GET" {
			t.Errorf("expected HEAD/GET probe, got %s", r.Method)
		}
		if strings.Contains(r.URL.RawQuery, "max-keys") {
			t.Errorf("ordinary discovery probe must not contain max-keys enumeration query: %s", r.URL.String())
		}
		w.Header().Set("Server", "AmazonS3")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>public-assets</Name></ListBucketResult>`)
	}))
	defer serverOpen.Close()

	resOpen := ProbeAWSS3(context.Background(), client, serverOpen.URL)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for open S3, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open S3, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (object read/write boundaries deferred to Phase 2.2), got true")
	}

	// B. 403 AccessDenied with x-amz-request-id
	serverAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("x-amz-request-id", "REQ-123456789")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	}))
	defer serverAuth.Close()

	resAuth := ProbeAWSS3(context.Background(), client, serverAuth.URL)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for protected S3, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for 403 S3, got false")
	}
	if resAuth.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
}

// 14. Azure Blob Storage
func TestProbeAzureBlob(t *testing.T) {
	client := newLoopbackTestClient()

	// A. 200 OK HEAD response
	serverOpen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" && r.Method != "GET" {
			t.Errorf("expected HEAD/GET probe, got %s", r.Method)
		}
		if strings.Contains(r.URL.RawQuery, "comp=list") {
			t.Errorf("discovery probe must not contain comp=list container enumeration query: %s", r.URL.String())
		}
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.Header().Set("x-ms-request-id", "ms-req-open")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ContainerName="public"></EnumerationResults>`)
	}))
	defer serverOpen.Close()

	resOpen := ProbeAzureBlob(context.Background(), client, serverOpen.URL)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for open Azure container, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open Azure container, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (blob permissions deferred to Phase 2.2), got true")
	}

	// B. 403 AuthenticationFailed
	serverAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Windows-Azure-Blob/1.0")
		w.Header().Set("x-ms-request-id", "ms-req-auth")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>AuthenticationFailed</Code></Error>`)
	}))
	defer serverAuth.Close()

	resAuth := ProbeAzureBlob(context.Background(), client, serverAuth.URL)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for protected Azure container, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for 403 Azure container, got false")
	}
	if resAuth.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
}

// 15. Google Cloud Storage
func TestProbeGCS(t *testing.T) {
	client := newLoopbackTestClient()

	// A. 200 OK HEAD response
	serverOpen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" && r.Method != "GET" {
			t.Errorf("expected HEAD/GET probe, got %s", r.Method)
		}
		if strings.Contains(r.URL.RawQuery, "max-keys") {
			t.Errorf("discovery probe must not contain max-keys enumeration query: %s", r.URL.String())
		}
		w.Header().Set("Server", "UploadServer")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<ListBucketResult><Name>gcs-public</Name></ListBucketResult>`)
	}))
	defer serverOpen.Close()

	resOpen := ProbeGCS(context.Background(), client, serverOpen.URL)
	if resOpen.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for open GCS, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open GCS, got true")
	}
	if resOpen.PublicAccess {
		t.Errorf("expected PublicAccess=false (GCS object read boundaries deferred to Phase 2.2), got true")
	}

	// B. 403 AccessDenied with GSE server
	serverAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GSE")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `<Error><Code>AccessDenied</Code></Error>`)
	}))
	defer serverAuth.Close()

	resAuth := ProbeGCS(context.Background(), client, serverAuth.URL)
	if resAuth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for protected GCS, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for 403 GCS, got false")
	}
	if resAuth.PublicAccess {
		t.Errorf("expected PublicAccess=false, got true")
	}
}

// 16. MinIO
func TestProbeMinIO(t *testing.T) {
	client := newLoopbackTestClient()

	// A. Health check endpoint (/minio/health/ready)
	serverHealth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/minio/health/ready" {
			w.Header().Set("Server", "MinIO")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer serverHealth.Close()

	resHealth := ProbeMinIO(context.Background(), client, serverHealth.URL)
	if resHealth.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for MinIO health endpoint, got %s", resHealth.Outcome)
	}
	if resHealth.PublicAccess {
		t.Errorf("expected PublicAccess=false (health check reachability does NOT prove object exposure), got true")
	}
	if !strings.Contains(resHealth.Limitations, "Health check establishes service reachability") {
		t.Errorf("expected limitations note about reachability, got %s", resHealth.Limitations)
	}

	// B. MinIO Console Login (/minio/login)
	serverConsole := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/minio/login" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "<html><head><title>MinIO Console</title></head><body>Login</body></html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer serverConsole.Close()

	resConsole := ProbeMinIO(context.Background(), client, serverConsole.URL)
	if resConsole.Outcome != OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for MinIO Console, got %s", resConsole.Outcome)
	}
	if !resConsole.AuthRequired {
		t.Errorf("expected AuthRequired=true for MinIO Console login, got false")
	}
}

// -------------------------------------------------------------
// Scope & SSRF Security Tests
// -------------------------------------------------------------

func TestServiceDiscoveryScopeAndSSRFProtection(t *testing.T) {
	// 1. SSRF Blocking on Dial: 169.254.169.254 (Cloud metadata)
	strictClient := NewClient(ClientOptions{
		Timeout:       1 * time.Second,
		AllowLoopback: false,
	})

	_, err := strictClient.SafeDialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatalf("expected SSRF error when dialing cloud metadata IP, got nil")
	}

	// 2. Out-of-scope candidate skipped
	engine := NewServiceDiscoveryEngine(strictClient, func(target string) bool {
		return strings.Contains(target, "authorized.com")
	})

	outOfScopeCand := DiscoveredService{
		Technology: TechElasticsearch,
		Family:     FamilyDirectDatabase,
		Endpoint:   "http://unauthorized-elastic.com:9200/",
		Host:       "unauthorized-elastic.com",
		Port:       9200,
	}

	res := engine.VerifyCandidate(context.Background(), outOfScopeCand)
	if res.InScope {
		t.Errorf("expected InScope=false for out-of-scope candidate, got true")
	}
	if !strings.Contains(res.Limitations, "outside authorized assessment scope") {
		t.Errorf("expected limitations note about scope, got %s", res.Limitations)
	}
}

// -------------------------------------------------------------
// Helper Transport for Mocking External Services
// -------------------------------------------------------------

type rewriteTransport struct {
	targetServer string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := req.URL.Parse(t.targetServer)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}

// -------------------------------------------------------------
// Universal SeverityInfo and Scope Finding Tests
// -------------------------------------------------------------

func TestDiscoveredService_ToFinding_AllSeverityInfo(t *testing.T) {
	allTechs := []ServiceTechnology{
		TechElasticsearch, TechMongoDB, TechRedis, TechPostgreSQL, TechMySQL,
		TechMongoExpress,
		TechSupabase, TechPostgREST, TechHasura, TechPrisma,
		TechFirebaseRTDB, TechFirestore,
		TechAWSS3, TechAzureBlob, TechGCS, TechMinIO,
	}

	for _, tech := range allTechs {
		t.Run(string(tech)+"_InScope", func(t *testing.T) {
			ds := DiscoveredService{
				Technology:      tech,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        "https://example.com/endpoint",
				Host:            "example.com",
				DetectionMethod: "HTTP_PROBE",
				InScope:         true,
			}
			finding, ok := ds.ToFinding()
			if !ok {
				t.Fatalf("expected finding for detected service %s, got false", tech)
			}
			if finding.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for discovery finding %s, got %s", tech, finding.Severity)
			}
			expectedCat := fmt.Sprintf("Service Discovery: %s", tech)
			if finding.Category != expectedCat {
				t.Errorf("expected category %q, got %q", expectedCat, finding.Category)
			}
		})

		t.Run(string(tech)+"_OutOfScope", func(t *testing.T) {
			ds := DiscoveredService{
				Technology:      tech,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        "https://out-of-scope.example.com",
				Host:            "out-of-scope.example.com",
				DetectionMethod: "PASSIVE_ANALYSIS",
				InScope:         false,
			}
			finding, ok := ds.ToFinding()
			if !ok {
				t.Fatalf("expected finding for out-of-scope service %s, got false", tech)
			}
			if finding.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for out-of-scope finding %s, got %s", tech, finding.Severity)
			}
			if finding.Category != "Discovered Cloud Service (Out of Scope)" {
				t.Errorf("expected category 'Discovered Cloud Service (Out of Scope)', got %q", finding.Category)
			}
		})
	}
}

