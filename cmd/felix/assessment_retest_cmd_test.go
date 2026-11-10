package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/assessment"
)

func TestCLI_ResolveRetestAuth(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "auth_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed initializing test store: %v", err)
	}
	defer store.Close()

	// Seed legitimate client
	client := &assessment.Client{
		ID:           "client-verified-01",
		Name:         "Verified Enterprise Client",
		Organization: "Corp",
		CreatedAt:    time.Now().UTC(),
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed creating test client: %v", err)
	}

	// 1. Missing authorization context -> fails closed
	_, err = resolveRetestAuth("", "", "", "", "", store)
	if err == nil {
		t.Error("expected error for empty authorization context, got nil")
	}

	// 2. Admin role requested without FELIX_ADMIN_TOKEN configured in environment -> fails closed
	_ = os.Unsetenv("FELIX_ADMIN_TOKEN")
	_, err = resolveRetestAuth("admin", "", "", "", "some-token", store)
	if err == nil {
		t.Error("expected error when FELIX_ADMIN_TOKEN is unset, got nil")
	}

	// 3. Admin token provided without FELIX_ADMIN_TOKEN configured -> fails closed
	_, err = resolveRetestAuth("", "", "", "", "some-token", store)
	if err == nil {
		t.Error("expected error for --admin-token without FELIX_ADMIN_TOKEN in environment, got nil")
	}

	// 4. Admin role requested with FELIX_ADMIN_TOKEN configured, but wrong token -> fails closed
	t.Setenv("FELIX_ADMIN_TOKEN", "trusted-secret-token-999")
	_, err = resolveRetestAuth("admin", "", "", "", "wrong-token", store)
	if err == nil {
		t.Error("expected error for invalid admin token, got nil")
	}

	// 5. Admin role requested with correct token -> succeeds
	authAdmin, err := resolveRetestAuth("admin", "", "", "", "trusted-secret-token-999", store)
	if err != nil {
		t.Errorf("expected success for valid admin token, got: %v", err)
	}
	if !authAdmin.IsAdmin() {
		t.Error("expected IsAdmin() = true for verified admin context")
	}

	// 6. Direct admin token without role flag with correct token -> succeeds
	authDirect, err := resolveRetestAuth("", "", "", "", "trusted-secret-token-999", store)
	if err != nil {
		t.Errorf("expected success for direct valid admin token, got: %v", err)
	}
	if !authDirect.IsAdmin() {
		t.Error("expected IsAdmin() = true for direct verified admin token")
	}

	// 7. Non-admin request without client ID -> fails closed
	_, err = resolveRetestAuth("", "", "tenant-1", "acct-1", "", store)
	if err == nil {
		t.Error("expected error for non-admin request without client ID, got nil")
	}

	// 8. Non-admin request with non-existent client ID -> fails closed
	_, err = resolveRetestAuth("", "client-nonexistent", "", "", "", store)
	if err == nil {
		t.Error("expected error for non-existent client ID, got nil")
	}

	// 9. Non-admin request with legitimate verified client ID -> succeeds
	authClient, err := resolveRetestAuth("", "client-verified-01", "", "", "", store)
	if err != nil {
		t.Errorf("expected success for verified client ID, got: %v", err)
	}
	if authClient.IsAdmin() {
		t.Error("expected IsAdmin() = false for client context")
	}
	if authClient.ClientID != "client-verified-01" {
		t.Errorf("expected ClientID 'client-verified-01', got: %s", authClient.ClientID)
	}

	// 10. Tenant boundary enforcement: context must refuse mismatched client
	if authClient.Authorizes("client-victim-99", "", "") {
		t.Error("expected authClient to refuse access to client-victim-99")
	}
	if !authClient.Authorizes("client-verified-01", "", "") {
		t.Error("expected authClient to authorize client-verified-01")
	}
}
