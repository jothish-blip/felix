package cloud

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// AccessVerificationEngine orchestrates safe, authorized access verification across all 16 target services.
type AccessVerificationEngine struct {
	client                 *Client
	isAllowed              func(string) bool
	isExcluded             func(string) bool
	allowWriteVerification bool
	guardrails             *CanaryGuardrailChecker
}

// AccessEngineOptions configures the access verification engine.
type AccessEngineOptions struct {
	Client                 *Client
	IsAllowed              func(string) bool
	IsExcluded             func(string) bool
	AllowWriteVerification bool
}

// NewAccessVerificationEngine initializes the shared verification engine.
func NewAccessVerificationEngine(opts AccessEngineOptions) *AccessVerificationEngine {
	client := opts.Client
	if client == nil {
		client = NewClient(ClientOptions{
			IsAllowed:  opts.IsAllowed,
			IsExcluded: opts.IsExcluded,
		})
	}

	guard := &CanaryGuardrailChecker{
		AllowWriteVerification: opts.AllowWriteVerification,
		ScopeValidator:         opts.IsAllowed,
		ExclusionValidator:     opts.IsExcluded,
	}

	return &AccessVerificationEngine{
		client:                 client,
		isAllowed:              opts.IsAllowed,
		isExcluded:             opts.IsExcluded,
		allowWriteVerification: opts.AllowWriteVerification,
		guardrails:             guard,
	}
}

// VerifyServiceAccess runs the appropriate safe access verification check for a discovered service.
func (e *AccessVerificationEngine) VerifyServiceAccess(
	ctx context.Context,
	svc DiscoveredService,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
	canary *CanaryConfig,
) AccessVerificationRecord {
	target := svc.Endpoint
	if target == "" && svc.Host != "" {
		if svc.Port > 0 {
			target = net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))
		} else {
			target = svc.Host
		}
	}

	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              target,
		Technology:          svc.Technology,
		Family:              svc.Family,
		Status:              StatusVerificationSkipped,
		Decision:            DecisionSkipped,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	// 1. Scope and Exclusion Check before any network transmission
	if e.isExcluded != nil && (e.isExcluded(target) || e.isExcluded(svc.Host)) {
		record.ErrorClassification = ErrClassScopeExcluded
		record.Limitations = "verification blocked: target matches exclusion rule"
		return record
	}

	if e.isAllowed != nil && !e.isAllowed(target) && !e.isAllowed(svc.Host) && !e.isAllowed("http://"+target) && !e.isAllowed("https://"+target) && !e.isAllowed("tcp://"+target) {
		record.ErrorClassification = ErrClassScopeOutOfScope
		record.Limitations = "verification skipped: target is outside authorized assessment scope"
		return record
	}

	// 2. Dispatch to specific provider access verifier
	switch svc.Technology {
	// Group A: Direct database & search engines
	case TechElasticsearch:
		record = VerifyElasticsearchAccess(ctx, e.client, target, cred, resConfig)
	case TechMongoDB:
		port := svc.Port
		if port <= 0 {
			port = 27017
		}
		record = VerifyMongoDBAccess(ctx, e.client, svc.Host, port, cred, resConfig)
	case TechRedis:
		port := svc.Port
		if port <= 0 {
			port = 6379
		}
		record = VerifyRedisAccess(ctx, e.client, svc.Host, port, cred, resConfig)
	case TechPostgreSQL:
		port := svc.Port
		if port <= 0 {
			port = 5432
		}
		record = VerifyPostgreSQLAccess(ctx, e.client, svc.Host, port, cred, resConfig)
	case TechMySQL:
		port := svc.Port
		if port <= 0 {
			port = 3306
		}
		record = VerifyMySQLAccess(ctx, e.client, svc.Host, port, cred, resConfig)

	// Group B: Database admin interfaces
	case TechMongoExpress:
		record = VerifyMongoExpressAccess(ctx, e.client, target, cred, resConfig)

	// Group C: Backend & database interfaces
	case TechSupabase:
		record = VerifySupabaseAccess(ctx, e.client, target, cred, resConfig)
	case TechPostgREST:
		record = VerifyPostgRESTAccess(ctx, e.client, target, cred, resConfig)
	case TechHasura:
		record = VerifyHasuraAccess(ctx, e.client, target, cred, resConfig)
	case TechPrisma:
		record = VerifyPrismaAccess(ctx, e.client, target, cred, resConfig)

	// Group D: Firebase databases
	case TechFirebaseRTDB:
		record = VerifyFirebaseRTDBAccess(ctx, e.client, target, cred, resConfig)
	case TechFirestore:
		projectID := ""
		if svc.Metadata != nil {
			if pid, ok := svc.Metadata["project_id"].(string); ok {
				projectID = pid
			}
		}
		if projectID == "" {
			projectID = svc.Host
		}
		record = VerifyFirestoreAccess(ctx, e.client, projectID, cred, resConfig)

	// Group E: Cloud & object storage
	case TechAWSS3:
		record = VerifyAWSS3Access(ctx, e.client, target, cred, resConfig)
	case TechAzureBlob:
		record = VerifyAzureBlobAccess(ctx, e.client, target, cred, resConfig)
	case TechGCS:
		record = VerifyGCSAccess(ctx, e.client, target, cred, resConfig)
	case TechMinIO:
		record = VerifyMinIOAccess(ctx, e.client, target, cred, resConfig)

	default:
		record.Status = StatusVerificationSkipped
		record.Decision = DecisionSkipped
		record.ErrorClassification = ErrClassUnsupported
		record.Limitations = fmt.Sprintf("unsupported service technology: %s", svc.Technology)
	}

	// 3. Optional Canary Write Verification (only when enabled and authorized)
	if canary != nil && canary.Enabled {
		record = e.evaluateAndRunCanary(ctx, target, svc.Technology, *canary, cred, record)
	}

	return record
}

// evaluateAndRunCanary executes canary write verification if all 8 guardrails pass.
func (e *AccessVerificationEngine) evaluateAndRunCanary(
	ctx context.Context,
	target string,
	tech ServiceTechnology,
	canary CanaryConfig,
	cred *CredentialProfile,
	currentRec AccessVerificationRecord,
) AccessVerificationRecord {
	isMinPriv := cred != nil && cred.Role == "least_privilege_test"
	eval := e.guardrails.EvaluateConditions(target, tech, canary, isMinPriv)
	if !eval.Allowed {
		currentRec.Limitations = fmt.Sprintf("%s; canary write skipped: %s", currentRec.Limitations, eval.Reason)
		return currentRec
	}

	op, err := BuildCanaryOperation(e.client, target, tech, canary, cred)
	if err != nil {
		currentRec.Limitations = fmt.Sprintf("%s; canary write unsupported: %v", currentRec.Limitations, err)
		return currentRec
	}

	currentRec.Operation = OpControlledCanary
	currentRec.ResourceScope = canary.TargetResource

	if err := ExecuteCanaryLifecycle(ctx, op); err != nil {
		currentRec.Status = StatusWriteDenied
		currentRec.Decision = DecisionDenied
		currentRec.Evidence = fmt.Sprintf("Canary write failed on %s: %v", tech, err)
		return currentRec
	}

	currentRec.Status = StatusWriteVerified
	currentRec.Decision = DecisionAllowed
	currentRec.Evidence = fmt.Sprintf("Isolated canary write and cleanup verified on %s on resource %q", tech, canary.TargetResource)
	if currentRec.AuthContext == AuthContextUnauthenticated {
		currentRec.FindingSuitable = true
	}

	return currentRec
}

// VerifyServicesConcurrently verifies multiple discovered services within concurrency limits.
func (e *AccessVerificationEngine) VerifyServicesConcurrently(
	ctx context.Context,
	services []DiscoveredService,
	creds map[string]*CredentialProfile,
	resConfigs map[string]*TestResourceConfig,
	canary *CanaryConfig,
) []AccessVerificationRecord {
	var records []AccessVerificationRecord
	var mu sync.Mutex

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, svc := range services {
		svcCopy := svc
		wg.Add(1)

		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			var c *CredentialProfile
			if creds != nil {
				c = creds[string(svcCopy.Technology)]
				if c == nil {
					c = creds[svcCopy.CanonicalID()]
				}
			}

			var rc *TestResourceConfig
			if resConfigs != nil {
				rc = resConfigs[string(svcCopy.Technology)]
				if rc == nil {
					rc = resConfigs[svcCopy.CanonicalID()]
				}
			}

			rec := e.VerifyServiceAccess(ctx, svcCopy, c, rc, canary)
			mu.Lock()
			records = append(records, rec)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return records
}
