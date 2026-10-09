package auth

/*
Package auth - Future Architectural Specification: Explicit Client-Provided Test Accounts

Section 7 Design Contract:
This file documents the future architectural design for authenticated assessment testing in subsequent
Felix stages. In Stage 3, automated credential use and authenticated execution are strictly NOT implemented.

-------------------------------------------------------------------------------------------------------------
1. Dual Authorization Governance Model
-------------------------------------------------------------------------------------------------------------
Felix strictly distinguishes two separate authorization layers:
  a) Platform Authorization (Stage 1):
     Authorization from infrastructure owners to perform network auditing against the host origin/IP.
  b) Application-Level Credential Authorization (Future Stage 4+):
     Explicit authorization to authenticate within the application under specified tenant/user identities.
     Having authorization to audit example.com DOES NOT imply authorization to log in as user A or admin.

-------------------------------------------------------------------------------------------------------------
2. Named Role-Based Identity Model
-------------------------------------------------------------------------------------------------------------
Future authenticated assessments will define discrete testing identities:
  - Role A: Standard Tenant User (e.g., test_user_a@client.example)
  - Role B: Peer Tenant User (e.g., test_user_b@client.example, for horizontal privilege boundary testing)
  - Role Admin: Elevated Tenant Administrator (for vertical privilege boundary testing)
  - Role ReadOnly: Auditor / Read-only viewer

-------------------------------------------------------------------------------------------------------------
3. Secure Ephemeral Credential Injection
-------------------------------------------------------------------------------------------------------------
Rules for credential handling:
  - ZERO Plaintext Persistence: Passwords, OTP seeds, or private keys are NEVER written to SQLite or disk.
  - Ephemeral Memory Enclave: Credentials injected via protected environment variables or secure interactive
    prompt at run initiation (`FELIX_AUTH_ROLE_A_SECRET`).
  - Automatic In-Memory Scrubbing: Secrets wiped from process memory when assessment completes or halts.
  - Redacted Logging: All authorization headers, session cookies, and login POST payloads strictly masked
    in terminal outputs, SQLite audit trails, and HTML/JSON reports.

-------------------------------------------------------------------------------------------------------------
4. Session Lifecycle & Isolation
-------------------------------------------------------------------------------------------------------------
  - Separate HTTP cookie jars per role: Role A and Role B sessions will never share connection pools or cookies.
  - Bounded Session Lifetimes: Sessions auto-expire after scan timeout.
  - Post-Assessment Revocation: Active logout dispatched upon assessment completion to invalidate test sessions.
  - Strict Scope Enforcement: Authenticated requests confined to authorized origin; credentials never forwarded
    on cross-origin redirects.
*/

// FutureRoleDefinition represents a proposed client-declared test role for authenticated auditing.
type FutureRoleDefinition struct {
	RoleName            string   `json:"role_name"`             // E.g. "TENANT_USER_A", "TENANT_ADMIN"
	Description         string   `json:"description"`
	ExpectedPermissions []string `json:"expected_permissions"` // E.g. ["read:own_profile", "write:own_profile"]
	ProhibitedActions   []string `json:"prohibited_actions"`   // E.g. ["access:billing", "delete:tenant"]
}
