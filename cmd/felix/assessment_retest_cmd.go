package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"felix/pkg/assessment"
)

func runAssessmentRetest(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printRetestHelp()
		return 0
	}

	var positional []string
	var (
		format          string = "table"
		jsonOutput      bool
		targetedMode    bool
		role            string = "" // Default to empty; do NOT grant administrative privileges by default
		adminToken      string
		clientID        string
		tenantID        string
		accountID       string
		operatorID      string = "cli-operator"
		dbPath          string
		keyID           string
		privKeyHex      string
		allowLoopback   bool = true
		allowPrivate    bool = true
		insecureTLS     bool
		timeoutSec      int  = 30
		concurrency     int  = 4
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--targeted":
			targetedMode = true
		case "--json":
			jsonOutput = true
			format = "json"
		case "--format":
			if i+1 < len(args) {
				format = strings.ToLower(args[i+1])
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		case "--admin-token":
			if i+1 < len(args) {
				adminToken = args[i+1]
				i++
			}
		case "--client":
			if i+1 < len(args) {
				clientID = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				tenantID = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				accountID = args[i+1]
				i++
			}
		case "--operator":
			if i+1 < len(args) {
				operatorID = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--key-id":
			if i+1 < len(args) {
				keyID = args[i+1]
				i++
			}
		case "--private-key":
			if i+1 < len(args) {
				privKeyHex = args[i+1]
				i++
			}
		case "--allow-loopback":
			allowLoopback = true
		case "--allow-private":
			allowPrivate = true
		case "--insecure":
			insecureTLS = true
		case "--timeout":
			if i+1 < len(args) {
				if sec, err := strconv.Atoi(args[i+1]); err == nil && sec > 0 {
					timeoutSec = sec
				}
				i++
			}
		case "--concurrency":
			if i+1 < len(args) {
				if conc, err := strconv.Atoi(args[i+1]); err == nil && conc > 0 {
					concurrency = conc
				}
				i++
			}
		case "--help", "-h":
			printRetestHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") {
				positional = append(positional, arg)
			}
		}
	}

	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "[-] Error: baseline assessment ID or reference is required (e.g. felix assessment retest <assessment-id>)")
		printRetestHelp()
		return 2
	}

	assessmentRef := positional[0]

	store, err := openStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open database: %v\n", err)
		return 2
	}
	defer store.Close()

	authCtx, err := resolveRetestAuth(role, clientID, tenantID, accountID, adminToken, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Authorization error: %v\n", err)
		return 2
	}

	mode := assessment.RetestModeFull
	if targetedMode {
		mode = assessment.RetestModeTargeted
	}

	opts := assessment.DefaultRetestOptions()
	opts.Mode = mode
	opts.Auth = authCtx
	opts.OperatorID = operatorID
	opts.TimeoutDuration = time.Duration(timeoutSec) * time.Second
	opts.Concurrency = concurrency
	opts.AllowLoopback = allowLoopback
	opts.AllowPrivateIPs = allowPrivate
	opts.InsecureSkipVerify = insecureTLS

	// Optional Phase 9.1 Signing Key
	if keyID != "" && privKeyHex != "" {
		privBytes, errHex := hex.DecodeString(strings.TrimSpace(privKeyHex))
		if errHex != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: invalid private key hex string: %v\n", errHex)
			return 2
		}
		if len(privBytes) == ed25519.PrivateKeySize {
			privKey := ed25519.PrivateKey(privBytes)
			pubKey := privKey.Public().(ed25519.PublicKey)
			signer, errSigner := assessment.NewInMemoryEd25519Signer(keyID, pubKey, privKey)
			if errSigner != nil {
				fmt.Fprintf(os.Stderr, "[-] Error constructing attestation signer: %v\n", errSigner)
				return 2
			}
			opts.SigningKey = signer
		} else {
			fmt.Fprintf(os.Stderr, "[-] Error: invalid private key size (expected %d bytes, got %d)\n", ed25519.PrivateKeySize, len(privBytes))
			return 2
		}
	}

	if !jsonOutput && format != "json" {
		opts.ProgressFunc = func(msg string) {
			fmt.Printf("[*] %s\n", msg)
		}
	}

	engine := assessment.NewRetestEngine(store)
	ctx := context.Background()

	result, err := engine.ExecuteRetest(ctx, assessmentRef, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Retest execution failed: %v\n", err)
		return 1
	}

	if jsonOutput || format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to marshal JSON output: %v\n", err)
			return 1
		}
		return 0
	}

	// Output clean CLI table
	fmt.Print(assessment.FormatRetestComparisonTable(result.Comparison))
	fmt.Printf("\nAttestation Status : %s\n", result.AttestationStatus)
	fmt.Printf("Attestation Reason : %s\n", result.AttestationReason)
	if result.Attestation != nil {
		fmt.Printf("Attestation Letter : %s (Key ID: %s)\n", result.Attestation.LetterID, result.Attestation.Signature.KeyID)
	}
	fmt.Printf("Child Assessment ID: %s (%s)\n", result.ChildAssessment.ID, result.ChildAssessment.Ref)
	fmt.Printf("Child Execution ID : %s\n\n", result.ChildExecution.ID)

	return 0
}

func printRetestHelp() {
	fmt.Println("Usage: felix assessment retest <assessment-id> [flags]")
	fmt.Println("\nExecutes remediation retesting against an existing baseline assessment.")
	fmt.Println("Compares baseline vs fresh outcomes, runs deterministic proof probes,")
	fmt.Println("and produces an auditable state-transition comparison.")
	fmt.Println("\nOperating Modes:")
	fmt.Println("  (default)    Full Reassessment mode: Re-runs discovery, inventory, scans,")
	fmt.Println("               and proof probes to evaluate regressions, unresolved defects,")
	fmt.Println("               and newly introduced vulnerabilities across authorized scope.")
	fmt.Println("  --targeted   Targeted Retest mode: Replays proof probes ONLY against previously")
	fmt.Println("               verified defect paths/parameters. Skips crawl and inventory,")
	fmt.Println("               and explicitly documents skipped checks.")
	fmt.Println("\nFlags:")
	fmt.Println("  --targeted              Run targeted proof probe retest mode only")
	fmt.Println("  --db <path>             Path to SQLite database file")
	fmt.Println("  --json                  Output structured retest results and comparison as JSON")
	fmt.Println("  --format <table|json>   Output format (default: table)")
	fmt.Println("  --role <role>           Authorization role (requires trusted credentials)")
	fmt.Println("  --admin-token <token>   Trusted administrative token for admin role authorization")
	fmt.Println("  --client <id>           Authorized client ID boundary (mandatory for client retest)")
	fmt.Println("  --tenant <id>           Tenant ID filter")
	fmt.Println("  --account <id>          Account ID filter")
	fmt.Println("  --operator <id>         Operator ID recording the retest (default: cli-operator)")
	fmt.Println("  --key-id <id>           Ed25519 Key ID for sealing Attestation Letter")
	fmt.Println("  --private-key <hex>     Ed25519 Private Key in hex format")
	fmt.Println("  --timeout <sec>         HTTP request timeout in seconds (default: 30)")
	fmt.Println("  --concurrency <int>     Maximum concurrent probe executions (default: 4)")
	fmt.Println("  --allow-loopback        Permit testing loopback addresses (127.0.0.1, localhost)")
	fmt.Println("  --allow-private         Permit testing RFC1918 private IP ranges")
	fmt.Println("  --insecure              Skip TLS certificate verification")
	fmt.Println("  -h, --help              Show this help message")
}

// resolveRetestAuth strictly enforces authorization boundaries for remediation retesting.
// Truth in engineering & defensive fail-closed rules:
// 1. Missing authorization context fails closed.
// 2. Administrative role & token validation requires trusted authority FELIX_ADMIN_TOKEN configured
//    in the environment. Passing --admin-token without matching FELIX_ADMIN_TOKEN fails closed.
// 3. Client retests require a valid client boundary matching the assessment's tenant boundary
//    and verified to exist in the store.
// 4. Limitation Note: Local CLI tenant isolation enforces tenancy boundary matching in the SQLite store.
//    Because the standalone local CLI lacks an external Identity Provider (OAuth2/OIDC/SAML), caller
//    identity is asserted via CLI flag rather than authenticated via external IdP tokens.
func resolveRetestAuth(role, clientID, tenantID, accountID, adminToken string, store assessment.Store) (assessment.TenantAuthContext, error) {
	// 1. Fail closed when no authorization context is supplied at all
	if role == "" && clientID == "" && tenantID == "" && accountID == "" && adminToken == "" {
		return assessment.TenantAuthContext{}, fmt.Errorf("missing authorization context: must specify authorized client scope (--client <id>) or trusted administrative credentials (--admin-token)")
	}

	roleLower := strings.ToLower(strings.TrimSpace(role))
	isAdminRole := roleLower == "admin" || roleLower == "system_admin" || roleLower == "operator_admin"

	// 2. Reject self-asserted administrative role or admin token without trusted environment authority
	if isAdminRole || adminToken != "" {
		trustedToken := os.Getenv("FELIX_ADMIN_TOKEN")
		if trustedToken == "" {
			return assessment.TenantAuthContext{}, fmt.Errorf("authorization refused: administrative authorization requires trusted authority FELIX_ADMIN_TOKEN configured in environment; no trusted admin authority exists")
		}
		if adminToken == "" {
			return assessment.TenantAuthContext{}, fmt.Errorf("authorization refused: administrative role %q requires --admin-token", role)
		}
		if subtle.ConstantTimeCompare([]byte(adminToken), []byte(trustedToken)) != 1 {
			return assessment.TenantAuthContext{}, fmt.Errorf("authorization refused: invalid administrative token")
		}
		return assessment.AuthorizeAdminContext("admin")
	}

	// 3. Scoped tenant/client authorization
	if clientID == "" {
		return assessment.TenantAuthContext{}, fmt.Errorf("authorization refused: non-admin retest execution requires valid client ID (--client <id>)")
	}

	if store != nil {
		clientRecord, err := store.GetClient(clientID)
		if err != nil || clientRecord == nil {
			return assessment.TenantAuthContext{}, fmt.Errorf("authorization refused: client %q does not exist in store", clientID)
		}
	}

	return assessment.ResolveAuthContext("", clientID, tenantID, accountID)
}
