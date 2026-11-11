package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/crawler"
	"github.com/google/uuid"
)

// runDirectModule provides secure, authorized execution for direct capability commands (e.g. felix web, felix api).
// It supports both existing assessment references (felix web ASM-01 --run) and direct targets (felix web https://example.com).
// Direct target testing strictly enforces authorization certification and SSRF scope controls.
func runDirectModule(moduleName string, runner func([]string) int, args []string) int {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return runner(args)
		}
	}

	if len(args) == 0 {
		return runner(args)
	}

	var (
		targetURL        string
		authorizingParty string
		authConfirm      bool
		allowLoopback    bool
		allowPrivate     bool
		hasRunFlag       bool
		hasDryRun        bool
		cleanedArgs      []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--run":
			hasRunFlag = true
			cleanedArgs = append(cleanedArgs, arg)
		case arg == "--dry-run":
			hasDryRun = true
			cleanedArgs = append(cleanedArgs, arg)
		case arg == "--auth-confirm":
			authConfirm = true
		case arg == "--authorizing-party" || arg == "--auth-party":
			if i+1 < len(args) {
				authorizingParty = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--authorizing-party="):
			authorizingParty = strings.TrimPrefix(arg, "--authorizing-party=")
		case arg == "--allow-loopback":
			allowLoopback = true
			cleanedArgs = append(cleanedArgs, arg)
		case arg == "--allow-private":
			allowPrivate = true
			cleanedArgs = append(cleanedArgs, arg)
		case arg == "--target" || arg == "-t":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(arg, "-") && targetURL == "" {
				if strings.Contains(arg, "://") || strings.HasPrefix(arg, "localhost") || strings.HasPrefix(arg, "127.0.0.1") {
					targetURL = arg
					continue
				}
			}
			cleanedArgs = append(cleanedArgs, arg)
		}
	}

	// If no direct URL was provided, pass through to existing assessment runner
	if targetURL == "" {
		return runner(args)
	}

	// 1. Authorisation Certification Enforcement
	// Active direct target testing NEVER assumes authorization.
	if !hasDryRun && !authConfirm && authorizingParty == "" {
		fmt.Fprintf(os.Stderr, "[-] Security refusal: Active security assessment requires explicit authorization certification.\n")
		fmt.Fprintf(os.Stderr, "    Direct target testing never assumes authorization.\n")
		fmt.Fprintf(os.Stderr, "    Specify --authorizing-party <name> or --auth-confirm to certify explicit authorization to test the target.\n\n")
		return 2
	}

	// 2. Protocol & Target Scope Validation
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		if strings.HasPrefix(targetURL, "localhost") || strings.HasPrefix(targetURL, "127.0.0.1") {
			targetURL = "http://" + targetURL
		} else {
			targetURL = "https://" + targetURL
		}
	}

	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: invalid target URL %q\n", targetURL)
		return 2
	}

	// 3. DNS Resolution & SSRF Scope Validation
	host := parsed.Hostname()
	ips, _ := net.LookupIP(host)
	allowLoop := allowLoopback || os.Getenv("FELIX_ALLOW_LOOPBACK") == "true"
	allowPriv := allowPrivate || os.Getenv("FELIX_ALLOW_PRIVATE") == "true"

	if len(ips) > 0 {
		for _, ip := range ips {
			if prohibited, reason := crawler.ProhibitedIPReason(ip, allowLoop, allowPriv); prohibited {
				fmt.Fprintf(os.Stderr, "[-] Security refusal: destination %s resolves to prohibited address (%s: %s).\n", targetURL, ip.String(), reason)
				fmt.Fprintf(os.Stderr, "    Direct target testing enforces strict RFC 1918 and loopback boundaries.\n")
				fmt.Fprintf(os.Stderr, "    Pass --allow-loopback or --allow-private if this is an authorized internal laboratory target.\n")
				return 2
			}
		}
	}

	// 4. Provision Ad-Hoc Assessment with Traceable Acknowledgement Record
	store, err := getAssessmentStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Assessment database error: %v\n", err)
		return 1
	}
	defer store.Close()

	client, err := store.GetClient("client-adhoc-default")
	if err != nil || client == nil {
		client = &assessment.Client{
			ID:        "client-adhoc-default",
			Name:      "Direct CLI Operator",
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		_ = store.CreateClient(client)
	}

	now := time.Now().UTC()
	u := uuid.New().String()
	asmID := fmt.Sprintf("asm-adhoc-%s-%s", moduleName, u[:8])
	asmRef := fmt.Sprintf("ADHOC-%s-%s", strings.ToUpper(moduleName), strings.ToUpper(u[:6]))

	partyName := authorizingParty
	if partyName == "" {
		partyName = "CLI Operator (Explicit --auth-confirm)"
	}

	asm := assessment.Assessment{
		ID:          asmID,
		Ref:         asmRef,
		ClientID:    client.ID,
		Name:        fmt.Sprintf("Ad-Hoc %s Assessment: %s", strings.ToUpper(moduleName), targetURL),
		Description: "Ad-hoc assessment initialized via direct CLI command. Authorization recorded as CLI_OPERATOR_ACKNOWLEDGEMENT; this certifies operator operational acknowledgement, NOT legally verified written customer authorization.",
		Status:      assessment.StatusDraft,
		ScopeMode:   "explicit",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := store.CreateAssessment(&asm); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create ad-hoc assessment: %v\n", err)
		return 1
	}

	target := assessment.AssessmentTarget{
		ID:           fmt.Sprintf("tgt-%s", u[:8]),
		AssessmentID: asm.ID,
		TargetURL:    targetURL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    now,
	}
	_ = store.AddTarget(&target)

	past := now.Add(-1 * time.Hour)
	future := now.Add(24 * time.Hour)
	authRec := assessment.AuthorizationRecord{
		ID:                  fmt.Sprintf("auth-%s", u[:8]),
		AssessmentID:        asm.ID,
		AuthorizingParty:    partyName,
		AuthorizationMethod: "CLI_OPERATOR_ACKNOWLEDGEMENT",
		Status:              assessment.AuthApproved,
		ValidFrom:           &past,
		ValidUntil:          &future,
		DateReceived:        past,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	_ = store.SetAuthorization(&authRec)

	// Reassemble arguments with new assessment reference
	finalArgs := []string{asm.Ref}
	if !hasRunFlag && !hasDryRun {
		finalArgs = append(finalArgs, "--run")
	}
	finalArgs = append(finalArgs, cleanedArgs...)

	return runner(finalArgs)
}
