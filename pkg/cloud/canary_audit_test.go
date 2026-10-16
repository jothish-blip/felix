package cloud

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestCanary_Redis_LifecycleSafety tests all Redis canary lifecycle edge cases.
func TestCanary_Redis_LifecycleSafety(t *testing.T) {
	client := NewClient(ClientOptions{AllowLoopback: true})

	// 1. Pre-existing resource: pre-check must abort before writing
	t.Run("Redis_PreExistingResource", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			// Return :1 (key exists)
			_, _ = conn.Write([]byte(":1\r\n"))
		}()

		op := &RedisCanaryOperation{
			Client:    client,
			Addr:      ln.Addr().String(),
			CanaryKey: "felix:canary:existing",
			CanaryVal: "test-val",
		}

		err = ExecuteCanaryLifecycle(context.Background(), op)
		if err == nil {
			t.Fatal("expected ExecuteCanaryLifecycle to fail on pre-existing resource")
		}
		if !strings.Contains(err.Error(), "already exists in Redis") {
			t.Fatalf("unexpected error message: %v", err)
		}
		if op.written {
			t.Fatal("expected op.written to be false")
		}
	})

	// 2. Failed creation: SETNX rejected, cleanup must not execute
	t.Run("Redis_FailedCreation", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			// PreCheck conn
			conn1, _ := ln.Accept()
			if conn1 != nil {
				buf := make([]byte, 128)
				_, _ = conn1.Read(buf)
				_, _ = conn1.Write([]byte(":0\r\n")) // Key does not exist
				conn1.Close()
			}
			// Execute conn (SETNX rejected)
			conn2, _ := ln.Accept()
			if conn2 != nil {
				buf := make([]byte, 128)
				_, _ = conn2.Read(buf)
				_, _ = conn2.Write([]byte("$-1\r\n")) // SETNX nil / failed
				conn2.Close()
			}
		}()

		op := &RedisCanaryOperation{
			Client:    client,
			Addr:      ln.Addr().String(),
			CanaryKey: "felix:canary:setnx_fail",
			CanaryVal: "test-val",
		}

		err = ExecuteCanaryLifecycle(context.Background(), op)
		if err == nil {
			t.Fatal("expected ExecuteCanaryLifecycle to fail on SETNX rejection")
		}
		if op.written {
			t.Fatal("expected op.written to be false")
		}
		// Calling cleanup directly on unwritten operation must be a safe no-op
		if err := op.Cleanup(context.Background()); err != nil {
			t.Fatalf("cleanup on unwritten operation should be safe no-op, got %v", err)
		}
	})

	// 3. Failed verification: Verify read-back mismatch
	t.Run("Redis_FailedVerification", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			// PreCheck
			c1, _ := ln.Accept()
			if c1 != nil {
				buf := make([]byte, 128)
				_, _ = c1.Read(buf)
				_, _ = c1.Write([]byte(":0\r\n"))
				c1.Close()
			}
			// Execute
			c2, _ := ln.Accept()
			if c2 != nil {
				buf := make([]byte, 128)
				_, _ = c2.Read(buf)
				_, _ = c2.Write([]byte("+OK\r\n"))
				c2.Close()
			}
			// Verify: returns different value
			c3, _ := ln.Accept()
			if c3 != nil {
				buf := make([]byte, 128)
				_, _ = c3.Read(buf)
				_, _ = c3.Write([]byte("$9\r\nsomething\r\n"))
				c3.Close()
			}
			// Cleanup defer: EVAL compare-and-delete returns :0 (ownership mismatch)
			c4, _ := ln.Accept()
			if c4 != nil {
				buf := make([]byte, 256)
				_, _ = c4.Read(buf)
				_, _ = c4.Write([]byte(":0\r\n"))
				c4.Close()
			}
		}()

		op := &RedisCanaryOperation{
			Client:    client,
			Addr:      ln.Addr().String(),
			CanaryKey: "felix:canary:verify_fail",
			CanaryVal: "expected-val",
		}

		err = ExecuteCanaryLifecycle(context.Background(), op)
		if err == nil {
			t.Fatal("expected ExecuteCanaryLifecycle to fail on verification read-back mismatch")
		}
		if !strings.Contains(err.Error(), "canary verification read-back failed") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	// 4. Concurrent replacement & Ownership mismatch: Key was replaced before cleanup
	t.Run("Redis_ConcurrentReplacement_OwnershipMismatch", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				defer conn.Close()
				buf := make([]byte, 256)
				_, _ = conn.Read(buf)
				// EVAL compare-and-delete: server returns :0 because key value != CanaryVal
				_, _ = conn.Write([]byte(":0\r\n"))
			}
		}()

		op := &RedisCanaryOperation{
			Client:    client,
			Addr:      ln.Addr().String(),
			CanaryKey: "felix:canary:concurrent",
			CanaryVal: "felix-owned-val",
			written:   true,
		}

		err = op.Cleanup(context.Background())
		if err == nil {
			t.Fatal("expected cleanup to fail when key ownership has changed")
		}
		if !strings.Contains(err.Error(), "ownership mismatch") {
			t.Fatalf("unexpected cleanup error: %v", err)
		}
	})

	// 5. Repeated cleanup: second cleanup must be a safe no-op
	t.Run("Redis_RepeatedCleanup", func(t *testing.T) {
		var evalCount int
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				defer conn.Close()
				buf := make([]byte, 256)
				_, _ = conn.Read(buf)
				evalCount++
				_, _ = conn.Write([]byte(":1\r\n")) // Successfully deleted
			}
		}()

		op := &RedisCanaryOperation{
			Client:    client,
			Addr:      ln.Addr().String(),
			CanaryKey: "felix:canary:repeat",
			CanaryVal: "felix-val",
			written:   true,
		}

		// First cleanup
		if err := op.Cleanup(context.Background()); err != nil {
			t.Fatalf("first cleanup failed: %v", err)
		}
		if !op.cleaned {
			t.Fatal("expected op.cleaned to be true after successful cleanup")
		}

		// Second cleanup: must not make any network calls or error
		if err := op.Cleanup(context.Background()); err != nil {
			t.Fatalf("second cleanup should be safe no-op, got %v", err)
		}
		if evalCount != 1 {
			t.Fatalf("expected exactly 1 EVAL call, got %d", evalCount)
		}
	})
}

// TestCanary_S3_LifecycleSafety tests all S3/MinIO canary lifecycle edge cases.
func TestCanary_S3_LifecycleSafety(t *testing.T) {
	client := NewClient(ClientOptions{AllowLoopback: true})

	// 1. Pre-existing resource: pre-check HEAD returns 200 -> abort
	t.Run("S3_PreExistingResource", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" {
				w.WriteHeader(http.StatusOK) // Object already exists
				return
			}
			t.Fatalf("unexpected request method %s during precheck", r.Method)
		}))
		defer ts.Close()

		op := &S3CanaryOperation{
			Client:    client,
			TargetURL: ts.URL,
			Resource:  "felix-canary/test-existing.txt",
			Payload:   "content",
		}

		err := ExecuteCanaryLifecycle(context.Background(), op)
		if err == nil {
			t.Fatal("expected canary lifecycle to abort on pre-existing object")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("unexpected error: %v", err)
		}
		if op.written {
			t.Fatal("expected op.written to be false")
		}
	})

	// 2. Failed creation: PUT rejected (e.g. 412 If-None-Match failed)
	t.Run("S3_FailedCreation", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == "PUT" {
				w.WriteHeader(http.StatusPreconditionFailed) // 412
				return
			}
			t.Fatalf("unexpected request method %s", r.Method)
		}))
		defer ts.Close()

		op := &S3CanaryOperation{
			Client:    client,
			TargetURL: ts.URL,
			Resource:  "felix-canary/test-put-fail.txt",
			Payload:   "content",
		}

		err := ExecuteCanaryLifecycle(context.Background(), op)
		if err == nil {
			t.Fatal("expected lifecycle to fail when PUT rejected")
		}
		if op.written {
			t.Fatal("expected op.written to be false")
		}
		// Direct cleanup call on unwritten operation must be safe no-op
		if err := op.Cleanup(context.Background()); err != nil {
			t.Fatalf("cleanup on unwritten S3 operation should be no-op, got %v", err)
		}
	})

	// 3. Failed verification: ETag mismatch on read-back
	t.Run("S3_FailedVerification_ETagMismatch", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" && r.Header.Get("If-Match") == "" {
				// Verify or Precheck HEAD
				if r.Header.Get("X-Precheck") == "1" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("ETag", `"etag-different"`)
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "PUT" {
				w.Header().Set("ETag", `"etag-original"`)
				w.WriteHeader(http.StatusCreated)
				return
			}
			if r.Method == "DELETE" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}))
		defer ts.Close()

		op := &S3CanaryOperation{
			Client:      client,
			TargetURL:   ts.URL,
			Resource:    "felix-canary/verify-fail.txt",
			Payload:     "content",
			canaryToken: "token-123",
			written:     true,
			createdETag: `"etag-original"`,
		}

		err := op.Verify(context.Background())
		if err == nil {
			t.Fatal("expected verify to fail on ETag mismatch")
		}
		if !strings.Contains(err.Error(), "ETag mismatch") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	// 4. Concurrent replacement: Object was replaced before cleanup (ETag changed)
	t.Run("S3_ConcurrentReplacement_CleanupRefused", func(t *testing.T) {
		var deleteAttempted bool
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" {
				// Pre-cleanup check returns a replaced ETag
				w.Header().Set("ETag", `"etag-foreign-replaced"`)
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "DELETE" {
				deleteAttempted = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}))
		defer ts.Close()

		op := &S3CanaryOperation{
			Client:      client,
			TargetURL:   ts.URL,
			Resource:    "felix-canary/replaced-object.txt",
			Payload:     "content",
			canaryToken: "my-token",
			createdETag: `"etag-my-run"`,
			written:     true,
		}

		err := op.Cleanup(context.Background())
		if err == nil {
			t.Fatal("expected cleanup to fail when object has been replaced concurrently")
		}
		if !strings.Contains(err.Error(), "ownership mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleteAttempted {
			t.Fatal("cleanup should NOT have issued DELETE request against replaced object")
		}
	})

	// 5. Repeated cleanup: must be safe no-op
	t.Run("S3_RepeatedCleanup", func(t *testing.T) {
		var deleteCount int
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "HEAD" {
				w.Header().Set("ETag", `"etag-valid"`)
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "DELETE" {
				deleteCount++
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}))
		defer ts.Close()

		op := &S3CanaryOperation{
			Client:      client,
			TargetURL:   ts.URL,
			Resource:    "felix-canary/repeat-del.txt",
			Payload:     "content",
			createdETag: `"etag-valid"`,
			written:     true,
		}

		// First cleanup
		if err := op.Cleanup(context.Background()); err != nil {
			t.Fatalf("first cleanup failed: %v", err)
		}
		if !op.cleaned {
			t.Fatal("expected op.cleaned to be true")
		}

		// Second cleanup
		if err := op.Cleanup(context.Background()); err != nil {
			t.Fatalf("second cleanup should be safe no-op, got %v", err)
		}
		if deleteCount != 1 {
			t.Fatalf("expected exactly 1 DELETE request, got %d", deleteCount)
		}
	})
}

// TestDatabaseBoundedQueries_EmpiricalVerification verifies that table/collection bounded queries
// are empirically executed and accurately distinguish reachability from table read access.
func TestDatabaseBoundedQueries_EmpiricalVerification(t *testing.T) {
	client := NewClient(ClientOptions{AllowLoopback: true})

	// 1. MongoDB Bounded Query
	t.Run("MongoDB_BoundedRead_Denied", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// 1. Read isMaster
			hBuf := make([]byte, 36)
			_, _ = conn.Read(hBuf)
			dBuf := make([]byte, 128)
			_, _ = conn.Read(dBuf)
			// Send isMaster response (succeeds)
			resp := []byte("ismaster maxBsonObjectSize 16777216")
			_, _ = conn.Write(make([]byte, 36))
			_, _ = conn.Write(resp)

			// 2. Read OP_QUERY on collection
			_, _ = conn.Read(hBuf)
			_, _ = conn.Read(dBuf)
			// Return Unauthorized response
			errResp := []byte(`{ "ok": 0.0, "errmsg": "command find requires authentication", "code": 13 }`)
			_, _ = conn.Write(make([]byte, 36))
			_, _ = conn.Write(errResp)
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMongoDBAccess(context.Background(), client, host, port, nil, &TestResourceConfig{
			ResourceID: "sensitive_data",
		})
		wg.Wait()

		if rec.Status != StatusReadDenied || rec.Decision != DecisionDenied {
			t.Fatalf("expected ReadDenied/Denied on MongoDB auth error for collection, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// 2. PostgreSQL Bounded Query
	t.Run("PostgreSQL_BoundedRead_Denied", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 128)
			_, _ = conn.Read(buf) // SSLRequest
			_, _ = conn.Write([]byte{'N'})
			_, _ = conn.Read(buf) // StartupMessage

			// Send AuthenticationOk ('R', code 0)
			authOk := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
			_, _ = conn.Write(authOk)

			// Read Query 'Q'
			qType := make([]byte, 1)
			_, _ = conn.Read(qType)
			qRest := make([]byte, 128)
			_, _ = conn.Read(qRest)

			// Send ErrorResponse ('E')
			_, _ = conn.Write([]byte{'E', 0, 0, 0, 10, 'S', 'E', 'R', 'R', 'O', 'R', 0})
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyPostgreSQLAccess(context.Background(), client, host, port, nil, &TestResourceConfig{
			ResourceID: "restricted_table",
		})
		wg.Wait()

		if rec.Status != StatusReadDenied || rec.Decision != DecisionDenied {
			t.Fatalf("expected ReadDenied/Denied on PostgreSQL table Query Error, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// 3. MySQL Bounded Query
	t.Run("MySQL_BoundedRead_Denied", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// 1. Initial Handshake Packet
			initPayload := []byte{10, '8', '.', '0', '.', '3', '0', 0, 1, 0, 0, 0}
			initHdr := []byte{byte(len(initPayload)), 0, 0, 0}
			_, _ = conn.Write(initHdr)
			_, _ = conn.Write(initPayload)

			// 2. Read Handshake Response
			respHdr := make([]byte, 4)
			_, _ = conn.Read(respHdr)
			rLen := int(respHdr[0]) | int(respHdr[1])<<8 | int(respHdr[2])<<16
			rBuf := make([]byte, rLen)
			_, _ = conn.Read(rBuf)

			// Accept login: Send OK packet (0x00)
			okPayload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
			okHdr := []byte{byte(len(okPayload)), 0, 0, 2}
			_, _ = conn.Write(okHdr)
			_, _ = conn.Write(okPayload)

			// 3. Read COM_QUERY
			qHdr := make([]byte, 4)
			_, _ = conn.Read(qHdr)
			qLen := int(qHdr[0]) | int(qHdr[1])<<8 | int(qHdr[2])<<16
			qBuf := make([]byte, qLen)
			_, _ = conn.Read(qBuf)

			// Return Error packet (0xFF) e.g. Access denied for user to table
			errPayload := []byte{0xFF, 0x15, 0x04, '#', '4', '2', '0', '0', '0', 'S', 'E', 'L', 'E', 'C', 'T', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}
			errHdr := []byte{byte(len(errPayload)), 0, 0, 3}
			_, _ = conn.Write(errHdr)
			_, _ = conn.Write(errPayload)
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMySQLAccess(context.Background(), client, host, port, nil, &TestResourceConfig{
			ResourceID: "restricted_table",
		})
		wg.Wait()

		if rec.Status != StatusReadDenied || rec.Decision != DecisionDenied {
			t.Fatalf("expected ReadDenied/Denied on MySQL table COM_QUERY error, got %s/%s", rec.Status, rec.Decision)
		}
	})
}
