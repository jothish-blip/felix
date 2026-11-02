package cloudsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/report"
)

// -------------------------------------------------------------------------
// 1. Universal IAM Data Model (Section 4)
// -------------------------------------------------------------------------

// IAMNodeType represents normalized, provider-independent cloud identity node types.
type IAMNodeType string

const (
	NodeTypeUser              IAMNodeType = "USER"
	NodeTypeGroup             IAMNodeType = "GROUP"
	NodeTypeServiceAccount    IAMNodeType = "SERVICE_ACCOUNT"
	NodeTypeServicePrincipal  IAMNodeType = "SERVICE_PRINCIPAL"
	NodeTypeRole              IAMNodeType = "ROLE"
	NodeTypePolicy            IAMNodeType = "POLICY"
	NodeTypePermission        IAMNodeType = "PERMISSION"
	NodeTypeResource          IAMNodeType = "RESOURCE"
	NodeTypeOrganization      IAMNodeType = "ORGANIZATION"
	NodeTypeProject           IAMNodeType = "PROJECT"
	NodeTypeSubscription      IAMNodeType = "SUBSCRIPTION"
	NodeTypeAccount           IAMNodeType = "ACCOUNT"
	NodeTypeWorkloadIdentity  IAMNodeType = "WORKLOAD_IDENTITY"
	NodeTypeTrustRelationship IAMNodeType = "TRUST_RELATIONSHIP"
)

// IAMRelationType represents normalized cloud identity and permission relationship types.
type IAMRelationType string

const (
	RelationMemberOf         IAMRelationType = "MEMBER_OF"
	RelationAssignedTo       IAMRelationType = "ASSIGNED_TO"
	RelationInherits         IAMRelationType = "INHERITS"
	RelationHasPolicy        IAMRelationType = "HAS_POLICY"
	RelationGrantsPermission IAMRelationType = "GRANTS_PERMISSION"
	RelationCanAssume        IAMRelationType = "CAN_ASSUME"
	RelationCanImpersonate   IAMRelationType = "CAN_IMPERSONATE"
	RelationCanPassRole      IAMRelationType = "CAN_PASS_ROLE"
	RelationTrusts           IAMRelationType = "TRUSTS"
	RelationCanModify        IAMRelationType = "CAN_MODIFY"
	RelationCanDelegate      IAMRelationType = "CAN_DELEGATE"
	RelationAppliesTo        IAMRelationType = "APPLIES_TO"
	RelationScopedTo         IAMRelationType = "SCOPED_TO"
)

// IAMNode represents a single vertex in the normalized privilege graph.
type IAMNode struct {
	ID               string            `json:"id"`
	Type             IAMNodeType       `json:"type"`
	Provider         Provider          `json:"provider"`
	DisplayName      string            `json:"display_name"`
	ResourceScope    string            `json:"resource_scope"`
	IsAdmin          bool              `json:"is_admin"`
	IsPrivileged     bool              `json:"is_privileged"`
	SourceEvidence   string            `json:"source_evidence,omitempty"`
	PolicyReferences []string          `json:"policy_references,omitempty"`
	Confidence       string            `json:"confidence"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// IAMEdge represents a directed relationship between two nodes in the privilege graph.
type IAMEdge struct {
	ID             string                    `json:"id"`
	Source         string                    `json:"source"`
	Target         string                    `json:"target"`
	Relation       IAMRelationType           `json:"relation"`
	Provider       Provider                  `json:"provider"`
	Permissions    []string                  `json:"permissions,omitempty"`
	Conditions     map[string]string         `json:"conditions,omitempty"`
	RawConditions  map[string]map[string]any `json:"raw_conditions,omitempty"`
	ConditionExpr  string                    `json:"condition_expr,omitempty"`
	ConditionState ConditionEvaluationState  `json:"condition_state,omitempty"`
	HasCondition   bool                      `json:"has_condition"`
	IsTransitive   bool                      `json:"is_transitive"`
	SourcePolicy   string                    `json:"source_policy,omitempty"`
	Confidence     string                    `json:"confidence"`
	Metadata       map[string]string         `json:"metadata,omitempty"`
}

// IAMGraph represents the full normalized, in-memory directed privilege graph.
type IAMGraph struct {
	Nodes    map[string]*IAMNode  `json:"nodes"`
	OutEdges map[string][]*IAMEdge `json:"out_edges"`
	InEdges  map[string][]*IAMEdge `json:"in_edges"`
	mu       sync.RWMutex
}

// NewIAMGraph initializes an empty, thread-safe IAMGraph.
func NewIAMGraph() *IAMGraph {
	return &IAMGraph{
		Nodes:    make(map[string]*IAMNode),
		OutEdges: make(map[string][]*IAMEdge),
		InEdges:  make(map[string][]*IAMEdge),
	}
}

// AddNode adds or updates a node in the graph idempotently.
func (g *IAMGraph) AddNode(node *IAMNode) *IAMNode {
	if node == nil || node.ID == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	existing, exists := g.Nodes[node.ID]
	if !exists {
		if node.Metadata == nil {
			node.Metadata = make(map[string]string)
		}
		if node.Confidence == "" {
			node.Confidence = report.ConfidenceHigh
		}
		g.Nodes[node.ID] = node
		return node
	}

	// Merge attributes preserving elevated privilege indicators
	if node.IsAdmin {
		existing.IsAdmin = true
	}
	if node.IsPrivileged {
		existing.IsPrivileged = true
	}
	if node.DisplayName != "" && existing.DisplayName == "" {
		existing.DisplayName = node.DisplayName
	}
	if node.ResourceScope != "" && existing.ResourceScope == "" {
		existing.ResourceScope = node.ResourceScope
	}
	for _, ref := range node.PolicyReferences {
		if !containsString(existing.PolicyReferences, ref) {
			existing.PolicyReferences = append(existing.PolicyReferences, ref)
		}
	}
	for k, v := range node.Metadata {
		existing.Metadata[k] = v
	}
	return existing
}

// AddEdge inserts a directed relationship edge idempotently.
func (g *IAMGraph) AddEdge(edge *IAMEdge) *IAMEdge {
	if edge == nil || edge.Source == "" || edge.Target == "" || edge.Relation == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if edge.ID == "" {
		edge.ID = computeDeterministicEdgeID(edge.Source, string(edge.Relation), edge.Target)
	}
	if edge.Metadata == nil {
		edge.Metadata = make(map[string]string)
	}
	if edge.Confidence == "" {
		edge.Confidence = report.ConfidenceHigh
	}

	// Prevent duplicate edges
	for _, existing := range g.OutEdges[edge.Source] {
		if existing.ID == edge.ID || (existing.Target == edge.Target && existing.Relation == edge.Relation) {
			// Merge permissions
			for _, p := range edge.Permissions {
				if !containsString(existing.Permissions, p) {
					existing.Permissions = append(existing.Permissions, p)
				}
			}
			return existing
		}
	}

	g.OutEdges[edge.Source] = append(g.OutEdges[edge.Source], edge)
	g.InEdges[edge.Target] = append(g.InEdges[edge.Target], edge)

	if _, exists := g.Nodes[edge.Target]; !exists {
		lower := strings.ToLower(edge.Target)
		isAdmin := strings.Contains(lower, "admin") || strings.Contains(lower, "owner") || strings.Contains(lower, "root")
		g.Nodes[edge.Target] = &IAMNode{
			ID:          edge.Target,
			Type:        NodeTypeRole,
			Provider:    edge.Provider,
			DisplayName: edge.Target,
			IsAdmin:     isAdmin,
		}
	}
	return edge
}

// GetNode retrieves a node by its unique ID.
func (g *IAMGraph) GetNode(id string) (*IAMNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, exists := g.Nodes[id]
	return n, exists
}

// GetOutEdges returns a copy of outgoing edges for a given source node.
func (g *IAMGraph) GetOutEdges(sourceID string) []*IAMEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := g.OutEdges[sourceID]
	res := make([]*IAMEdge, len(edges))
	copy(res, edges)
	return res
}

// GetInEdges returns a copy of incoming edges for a given target node.
func (g *IAMGraph) GetInEdges(targetID string) []*IAMEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := g.InEdges[targetID]
	res := make([]*IAMEdge, len(edges))
	copy(res, edges)
	return res
}

// NodeCount returns total vertices in the graph.
func (g *IAMGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.Nodes)
}

// EdgeCount returns total directed edges in the graph.
func (g *IAMGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, edges := range g.OutEdges {
		count += len(edges)
	}
	return count
}

// -------------------------------------------------------------------------
// 2. Effective Permission Analysis (Section 7) & Condition Semantics
// -------------------------------------------------------------------------

// ConditionEvaluationState represents explicit condition evaluation outcomes.
type ConditionEvaluationState string

const (
	ConditionSatisfied    ConditionEvaluationState = "CONDITION_SATISFIED"
	ConditionNotSatisfied ConditionEvaluationState = "CONDITION_NOT_SATISFIED"
	ConditionUnresolved   ConditionEvaluationState = "CONDITION_UNRESOLVED"
	ConditionNotPresent   ConditionEvaluationState = "CONDITION_NOT_PRESENT"
)

// PathFeasibility represents whether an attack path is proven feasible, potential, or blocked.
type PathFeasibility string

const (
	FeasibilityConfirmed    PathFeasibility = "CONFIRMED"
	FeasibilityPotential    PathFeasibility = "POTENTIAL"
	FeasibilityInconclusive PathFeasibility = "INCONCLUSIVE"
	FeasibilityBlocked      PathFeasibility = "BLOCKED"
)

// EvaluationContext provides request-time context for condition and policy evaluation.
type EvaluationContext struct {
	PrincipalID string            `json:"principal_id,omitempty"`
	Action      string            `json:"action,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	ContextKeys map[string]string `json:"context_keys,omitempty"`
}

// WithKey adds a context key to the evaluation context.
func (c EvaluationContext) WithKey(k, v string) EvaluationContext {
	if c.ContextKeys == nil {
		c.ContextKeys = make(map[string]string)
	}
	c.ContextKeys[k] = v
	return c
}

// PermissionStatus represents the evaluated status of an action on a resource.
type PermissionStatus string

const (
	PermissionGranted            PermissionStatus = "GRANTED"
	PermissionPotentiallyGranted PermissionStatus = "POTENTIALLY_GRANTED"
	PermissionRestricted         PermissionStatus = "RESTRICTED"
	PermissionDenied             PermissionStatus = "DENIED"
	PermissionUnresolved         PermissionStatus = "UNRESOLVED"
	PermissionUnknown            PermissionStatus = "UNKNOWN"
)

// PermissionEvaluationResult captures the detailed outcome of an effective permission query.
type PermissionEvaluationResult struct {
	Status             PermissionStatus         `json:"status"`
	ConditionState     ConditionEvaluationState `json:"condition_state"`
	ExplicitDeny       bool                     `json:"explicit_deny"`
	DenyingPolicy      string                   `json:"denying_policy,omitempty"`
	GrantingPolicy     string                   `json:"granting_policy,omitempty"`
	BoundaryRestricted bool                     `json:"boundary_restricted"`
	ConditionsPresent  bool                     `json:"conditions_present"`
	PolicyType         string                   `json:"policy_type,omitempty"`
	Explanation        string                   `json:"explanation"`
	SupportingEvidence []string                 `json:"supporting_evidence,omitempty"`
}

// EvaluateEffectivePermission evaluates whether a principal is granted, restricted, or denied an action on a resource using default context.
func (e *IAMPrivilegeGraphEngine) EvaluateEffectivePermission(principalID, action, resource string) PermissionEvaluationResult {
	return e.EvaluateEffectivePermissionWithContext(principalID, action, resource, EvaluationContext{
		PrincipalID: principalID,
		Action:      action,
		Resource:    resource,
		ContextKeys: make(map[string]string),
	})
}

// EvaluateEffectivePermissionWithContext evaluates effective permissions considering explicit context, conditions, and boundaries.
func (e *IAMPrivilegeGraphEngine) EvaluateEffectivePermissionWithContext(
	principalID, action, resource string,
	evalCtx EvaluationContext,
) PermissionEvaluationResult {
	e.graph.mu.RLock()
	defer e.graph.mu.RUnlock()

	res := PermissionEvaluationResult{
		Status:         PermissionDenied,
		ConditionState: ConditionNotPresent,
		Explanation:    fmt.Sprintf("Action %q on %q is denied by default for %q (implicit deny)", action, resource, principalID),
	}

	_, exists := e.graph.Nodes[principalID]
	if !exists {
		res.Status = PermissionUnknown
		res.Explanation = fmt.Sprintf("Principal %q not found in IAM graph", principalID)
		return res
	}

	// Collect all policy edges attached directly to principal or via group membership
	var policyEdges []*IAMEdge
	for _, edge := range e.graph.OutEdges[principalID] {
		if edge.Relation == RelationHasPolicy {
			policyEdges = append(policyEdges, edge)
		} else if edge.Relation == RelationMemberOf {
			// Inherited via Group
			for _, gEdge := range e.graph.OutEdges[edge.Target] {
				if gEdge.Relation == RelationHasPolicy {
					policyEdges = append(policyEdges, gEdge)
				}
			}
		}
	}

	// Also check GCP organization/project deny policies or Azure deny assignments
	var orgDenyEdges []*IAMEdge
	for _, node := range e.graph.Nodes {
		if node.Type == NodeTypePolicy && node.Metadata["policy_type"] == "DENY_POLICY" {
			orgDenyEdges = append(orgDenyEdges, e.graph.OutEdges[node.ID]...)
		}
	}

	var hasAllow bool
	var grantingPolicy string
	var hasBoundary bool
	var boundaryPolicy string
	var bestConditionState ConditionEvaluationState = ConditionNotPresent
	var hasUnresolvedDeny bool
	var unresolvedDenyReason string

	// Step 1: Scan for Explicit Deny across applicable policies
	for _, pEdge := range append(policyEdges, orgDenyEdges...) {
		permEdges := e.graph.OutEdges[pEdge.Target]
		for _, permEdge := range permEdges {
			permNode, permExists := e.graph.Nodes[permEdge.Target]
			if !permExists {
				continue
			}

			// Validate Action and Resource match
			if permMatchesAction(permNode.DisplayName, action) && resourceMatches(permNode.ResourceScope, resource) {
				if permEdge.Metadata["effect"] == "Deny" {
					// Check conditions on Deny statement
					if permEdge.HasCondition && len(permEdge.RawConditions) > 0 {
						cState, cReason := EvaluateAWSConditions(permEdge.RawConditions, evalCtx)
						if cState == ConditionNotSatisfied {
							// Deny condition not satisfied -> Deny does NOT apply
							continue
						} else if cState == ConditionUnresolved {
							hasUnresolvedDeny = true
							unresolvedDenyReason = cReason
							continue
						}
					} else if permEdge.HasCondition && permEdge.ConditionExpr != "" {
						cState, cReason := EvaluateGCPCondition(&GCPCondition{Expression: permEdge.ConditionExpr}, evalCtx)
						if cState == ConditionNotSatisfied {
							continue
						} else if cState == ConditionUnresolved {
							hasUnresolvedDeny = true
							unresolvedDenyReason = cReason
							continue
						}
					}

					// Explicit Deny applies!
					res.Status = PermissionDenied
					res.ExplicitDeny = true
					res.ConditionState = ConditionSatisfied
					res.DenyingPolicy = pEdge.SourcePolicy
					res.PolicyType = permEdge.Metadata["policy_type"]
					if res.PolicyType == "" {
						res.PolicyType = "IDENTITY_POLICY"
					}
					res.Explanation = fmt.Sprintf("Action %q on %q is explicitly DENIED by policy %q", action, resource, pEdge.SourcePolicy)
					res.SupportingEvidence = append(res.SupportingEvidence, fmt.Sprintf("Explicit Deny matched: action=%s, resource=%s in policy=%s", action, resource, pEdge.SourcePolicy))
					return res
				}

				if permEdge.Metadata["effect"] == "Allow" {
					// Evaluate conditions on Allow statement
					allowCondState := ConditionNotPresent
					if permEdge.HasCondition && len(permEdge.RawConditions) > 0 {
						cState, _ := EvaluateAWSConditions(permEdge.RawConditions, evalCtx)
						allowCondState = cState
					} else if permEdge.HasCondition && permEdge.ConditionExpr != "" {
						cState, _ := EvaluateGCPCondition(&GCPCondition{Expression: permEdge.ConditionExpr}, evalCtx)
						allowCondState = cState
					}

					if allowCondState == ConditionNotSatisfied {
						// Condition failed, cannot grant
						continue
					}

					hasAllow = true
					grantingPolicy = pEdge.SourcePolicy
					bestConditionState = allowCondState

					if permEdge.Metadata["has_boundary"] == "true" {
						hasBoundary = true
						boundaryPolicy = permEdge.Metadata["boundary_policy"]
					}
				}
			}
		}
	}

	if hasUnresolvedDeny {
		res.Status = PermissionUnresolved
		res.ConditionState = ConditionUnresolved
		res.Explanation = fmt.Sprintf("Action %q on %q has an unresolved conditional deny: %s", action, resource, unresolvedDenyReason)
		return res
	}

	if !hasAllow {
		return res // Implicit Deny
	}

	res.GrantingPolicy = grantingPolicy
	res.ConditionState = bestConditionState
	res.SupportingEvidence = append(res.SupportingEvidence, fmt.Sprintf("Allow statement matched in policy %q for action %q on %q", grantingPolicy, action, resource))

	// Step 2: Permission Boundary Enforcement
	if hasBoundary {
		res.BoundaryRestricted = true
		res.Status = PermissionRestricted
		bDesc := boundaryPolicy
		if bDesc == "" {
			bDesc = "attached permission boundary"
		}
		res.Explanation = fmt.Sprintf("Action %q allowed by %q but restricted by permission boundary %q", action, grantingPolicy, bDesc)
		res.SupportingEvidence = append(res.SupportingEvidence, fmt.Sprintf("Permission boundary %q restricts action %q", bDesc, action))
		return res
	}

	// Step 3: Condition Evaluation Outcome
	if bestConditionState == ConditionUnresolved {
		res.ConditionsPresent = true
		res.Status = PermissionPotentiallyGranted
		res.Explanation = fmt.Sprintf("Action %q conditionally granted by %q, but context condition could not be resolved", action, grantingPolicy)
		return res
	}

	if bestConditionState == ConditionSatisfied {
		res.ConditionsPresent = true
		res.Status = PermissionGranted
		res.Explanation = fmt.Sprintf("Action %q conditionally GRANTED and context condition SATISFIED by policy %q", action, grantingPolicy)
		return res
	}

	res.Status = PermissionGranted
	res.Explanation = fmt.Sprintf("Action %q unconditionally GRANTED on %q by policy %q", action, resource, grantingPolicy)
	return res
}

// awsOperatorInfo describes parsed attributes of an AWS condition operator.
type awsOperatorInfo struct {
	baseOp      string
	hasIfExists bool
	isNegated   bool
	isSupported bool
}

// parseAWSOperator inspects and validates an AWS IAM condition operator.
func parseAWSOperator(op string) awsOperatorInfo {
	opNorm := strings.ToLower(strings.TrimSpace(op))
	hasIfExists := false
	baseOp := opNorm

	if strings.HasSuffix(opNorm, "ifexists") {
		hasIfExists = true
		baseOp = strings.TrimSuffix(opNorm, "ifexists")
	}

	// Null condition operator cannot be combined with IfExists in AWS IAM
	if baseOp == "null" {
		if hasIfExists {
			return awsOperatorInfo{baseOp: baseOp, hasIfExists: true, isNegated: false, isSupported: false}
		}
		return awsOperatorInfo{baseOp: baseOp, hasIfExists: false, isNegated: false, isSupported: true}
	}

	isNegated := false
	isSupported := false

	switch baseOp {
	case "stringequals", "stringequalsignorecase", "stringlike",
		"arnequals", "arnlike",
		"ipaddress", "bool",
		"numericequals", "numericlessthan", "numericgreaterthan":
		isSupported = true
		isNegated = false

	case "stringnotequals", "stringnotequalsignorecase", "stringnotlike",
		"arnnotequals", "arnnotlike",
		"notipaddress", "numericnotequals":
		isSupported = true
		isNegated = true

	default:
		isSupported = false
	}

	return awsOperatorInfo{
		baseOp:      baseOp,
		hasIfExists: hasIfExists,
		isNegated:   isNegated,
		isSupported: isSupported,
	}
}

// EvaluateAWSConditions evaluates AWS condition operators and context keys against an evaluation context.
func EvaluateAWSConditions(condBlock map[string]map[string]any, ctx EvaluationContext) (ConditionEvaluationState, string) {
	if len(condBlock) == 0 {
		return ConditionNotPresent, "No condition block present"
	}

	hasUnresolved := false
	var unresolvedReasons []string

	for op, kvMap := range condBlock {
		opInfo := parseAWSOperator(op)
		if !opInfo.isSupported {
			if opInfo.baseOp == "null" && opInfo.hasIfExists {
				return ConditionUnresolved, fmt.Sprintf("Malformed AWS condition: Null operator cannot be combined with IfExists in %q", op)
			}
			return ConditionUnresolved, fmt.Sprintf("Unsupported AWS condition operator: %s", op)
		}

		for key, targetVal := range kvMap {
			valStr, valPresent := ctx.ContextKeys[key]
			if !valPresent {
				if opInfo.baseOp == "null" {
					targetList := normalizeToStringSlice(targetVal)
					if len(targetList) == 0 {
						return ConditionUnresolved, fmt.Sprintf("Malformed AWS Null condition: target value missing for key %q", key)
					}
					isTargetTrue := strings.EqualFold(targetList[0], "true")
					// Null: true -> key must not exist (satisfied = !valPresent = true)
					// Null: false -> key must exist (satisfied = valPresent = false)
					if !isTargetTrue {
						return ConditionNotSatisfied, fmt.Sprintf("Condition Null on key %q not satisfied (key absent, expected present)", key)
					}
					continue
				}

				if opInfo.hasIfExists {
					// In AWS IAM, IfExists condition evaluates to true if context key is absent.
					// When evaluated on an explicit Deny with negated operator (e.g., StringNotEqualsIfExists),
					// this satisfied evaluation triggers the explicit Deny, preventing Deny bypass.
					continue
				}

				if strings.EqualFold(key, "aws:PrincipalArn") && ctx.PrincipalID != "" {
					valStr = ctx.PrincipalID
					valPresent = true
				}
			}

			if !valPresent {
				hasUnresolved = true
				unresolvedReasons = append(unresolvedReasons, fmt.Sprintf("Context key %q not supplied in evaluation context", key))
				continue
			}

			targetList := normalizeToStringSlice(targetVal)
			if len(targetList) == 0 {
				return ConditionUnresolved, fmt.Sprintf("Malformed AWS condition: target value for key %q is empty", key)
			}

			satisfied := false

			switch opInfo.baseOp {
			case "stringequals":
				for _, t := range targetList {
					if valStr == t {
						satisfied = true
						break
					}
				}
			case "stringequalsignorecase":
				for _, t := range targetList {
					if strings.EqualFold(valStr, t) {
						satisfied = true
						break
					}
				}
			case "stringnotequals":
				satisfied = true
				for _, t := range targetList {
					if valStr == t {
						satisfied = false
						break
					}
				}
			case "stringnotequalsignorecase":
				satisfied = true
				for _, t := range targetList {
					if strings.EqualFold(valStr, t) {
						satisfied = false
						break
					}
				}
			case "stringlike":
				for _, t := range targetList {
					if wildcardMatch(t, valStr) {
						satisfied = true
						break
					}
				}
			case "stringnotlike":
				satisfied = true
				for _, t := range targetList {
					if wildcardMatch(t, valStr) {
						satisfied = false
						break
					}
				}
			case "arnequals", "arnlike":
				for _, t := range targetList {
					if wildcardMatch(strings.ToLower(t), strings.ToLower(valStr)) {
						satisfied = true
						break
					}
				}
			case "arnnotequals", "arnnotlike":
				satisfied = true
				for _, t := range targetList {
					if wildcardMatch(strings.ToLower(t), strings.ToLower(valStr)) {
						satisfied = false
						break
					}
				}
			case "ipaddress":
				ip := net.ParseIP(valStr)
				if ip == nil {
					return ConditionNotSatisfied, fmt.Sprintf("Invalid IP address %q in context", valStr)
				}
				for _, cidr := range targetList {
					if !strings.Contains(cidr, "/") {
						cidr += "/32"
					}
					_, ipnet, err := net.ParseCIDR(cidr)
					if err != nil {
						return ConditionUnresolved, fmt.Sprintf("Malformed CIDR %q in target condition: %v", cidr, err)
					}
					if ipnet.Contains(ip) {
						satisfied = true
						break
					}
				}
			case "notipaddress":
				ip := net.ParseIP(valStr)
				if ip == nil {
					return ConditionNotSatisfied, fmt.Sprintf("Invalid IP address %q in context", valStr)
				}
				matchedAny := false
				for _, cidr := range targetList {
					if !strings.Contains(cidr, "/") {
						cidr += "/32"
					}
					_, ipnet, err := net.ParseCIDR(cidr)
					if err != nil {
						return ConditionUnresolved, fmt.Sprintf("Malformed CIDR %q in target condition: %v", cidr, err)
					}
					if ipnet.Contains(ip) {
						matchedAny = true
						break
					}
				}
				satisfied = !matchedAny
			case "bool":
				valBool := strings.EqualFold(valStr, "true")
				for _, t := range targetList {
					if strings.EqualFold(t, "true") == valBool {
						satisfied = true
						break
					}
				}
			case "numericequals":
				valNum, err1 := strconv.ParseFloat(valStr, 64)
				if err1 != nil {
					return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: context value %q is not a valid number", valStr)
				}
				for _, t := range targetList {
					tNum, err2 := strconv.ParseFloat(t, 64)
					if err2 != nil {
						return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: target value %q is not a valid number", t)
					}
					if valNum == tNum {
						satisfied = true
						break
					}
				}
			case "numericnotequals":
				valNum, err1 := strconv.ParseFloat(valStr, 64)
				if err1 != nil {
					return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: context value %q is not a valid number", valStr)
				}
				satisfied = true
				for _, t := range targetList {
					tNum, err2 := strconv.ParseFloat(t, 64)
					if err2 != nil {
						return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: target value %q is not a valid number", t)
					}
					if valNum == tNum {
						satisfied = false
						break
					}
				}
			case "numericlessthan":
				valNum, err1 := strconv.ParseFloat(valStr, 64)
				if err1 != nil {
					return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: context value %q is not a valid number", valStr)
				}
				for _, t := range targetList {
					tNum, err2 := strconv.ParseFloat(t, 64)
					if err2 != nil {
						return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: target value %q is not a valid number", t)
					}
					if valNum < tNum {
						satisfied = true
						break
					}
				}
			case "numericgreaterthan":
				valNum, err1 := strconv.ParseFloat(valStr, 64)
				if err1 != nil {
					return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: context value %q is not a valid number", valStr)
				}
				for _, t := range targetList {
					tNum, err2 := strconv.ParseFloat(t, 64)
					if err2 != nil {
						return ConditionUnresolved, fmt.Sprintf("Malformed numeric condition: target value %q is not a valid number", t)
					}
					if valNum > tNum {
						satisfied = true
						break
					}
				}
			case "null":
				isTargetTrue := strings.EqualFold(targetList[0], "true")
				// valPresent is true here
				satisfied = !isTargetTrue
			default:
				// Unsupported operator: must not assume satisfied
				return ConditionUnresolved, fmt.Sprintf("Unsupported AWS condition operator: %s", op)
			}

			if !satisfied {
				return ConditionNotSatisfied, fmt.Sprintf("Condition %s on key %q not satisfied (value: %s)", op, key, valStr)
			}
		}
	}

	if hasUnresolved {
		return ConditionUnresolved, strings.Join(unresolvedReasons, "; ")
	}

	return ConditionSatisfied, "All AWS condition constraints satisfied by evaluation context"
}

// EvaluateGCPCondition evaluates supported GCP CEL condition expressions.
// Bounded CEL patterns supported:
// 1. Temporal: request.time < timestamp("...") and request.time > timestamp("...")
// 2. Resource Name: resource.name.startsWith("...")
// 3. Resource Type: resource.type == "..."
// 4. Identity: request.auth.claims.email == "..."
// 5. Compound expressions joined by "&&"
// All other expressions (unsupported macros, custom functions, unparseable syntax) return ConditionUnresolved.
func EvaluateGCPCondition(cond *GCPCondition, ctx EvaluationContext) (ConditionEvaluationState, string) {
	if cond == nil || strings.TrimSpace(cond.Expression) == "" {
		return ConditionNotPresent, "No GCP condition expression present"
	}

	expr := strings.TrimSpace(cond.Expression)

	// Compound expression support: expr1 && expr2
	if strings.Contains(expr, "&&") {
		subExprs := strings.Split(expr, "&&")
		hasUnresolved := false
		var unresolvedReasons []string
		for _, rawSub := range subExprs {
			sub := strings.TrimSpace(rawSub)
			if sub == "" {
				continue
			}
			subState, subReason := evaluateSingleGCPCEL(sub, ctx)
			if subState == ConditionNotSatisfied {
				return ConditionNotSatisfied, fmt.Sprintf("Compound CEL clause %q not satisfied: %s", sub, subReason)
			}
			if subState == ConditionUnresolved {
				hasUnresolved = true
				unresolvedReasons = append(unresolvedReasons, subReason)
			}
		}
		if hasUnresolved {
			return ConditionUnresolved, strings.Join(unresolvedReasons, "; ")
		}
		return ConditionSatisfied, "All compound GCP CEL expressions satisfied by evaluation context"
	}

	return evaluateSingleGCPCEL(expr, ctx)
}

func evaluateSingleGCPCEL(expr string, ctx EvaluationContext) (ConditionEvaluationState, string) {
	expr = strings.TrimSpace(expr)

	// 1. request.time < timestamp("...") or request.time > timestamp("...")
	if strings.Contains(expr, "request.time") && strings.Contains(expr, "timestamp(") {
		val, ok := ctx.ContextKeys["request.time"]
		if !ok || val == "" {
			return ConditionUnresolved, "Context key 'request.time' not supplied for CEL timestamp evaluation"
		}
		reqTime, err := time.Parse(time.RFC3339, val)
		if err != nil {
			return ConditionNotSatisfied, fmt.Sprintf("Malformed request.time timestamp %q in context: %v", val, err)
		}

		startIdx := strings.Index(expr, "timestamp(")
		endIdx := strings.Index(expr[startIdx:], ")")
		if startIdx != -1 && endIdx != -1 {
			rawTs := strings.Trim(expr[startIdx+10:startIdx+endIdx], `'" `)
			targetTime, err2 := time.Parse(time.RFC3339, rawTs)
			if err2 != nil {
				return ConditionUnresolved, fmt.Sprintf("Malformed timestamp %q in GCP CEL expression: %v", rawTs, err2)
			}
			if strings.Contains(expr, "<") {
				if reqTime.Before(targetTime) {
					return ConditionSatisfied, fmt.Sprintf("request.time %s is before %s", reqTime, targetTime)
				}
				return ConditionNotSatisfied, fmt.Sprintf("request.time %s is not before %s", reqTime, targetTime)
			} else if strings.Contains(expr, ">") {
				if reqTime.After(targetTime) {
					return ConditionSatisfied, fmt.Sprintf("request.time %s is after %s", reqTime, targetTime)
				}
				return ConditionNotSatisfied, fmt.Sprintf("request.time %s is not after %s", reqTime, targetTime)
			}
		} else {
			return ConditionUnresolved, fmt.Sprintf("Malformed GCP CEL timestamp syntax in expression: %s", expr)
		}
	}

	// 2. resource.name.startsWith("...")
	if strings.Contains(expr, "resource.name.startsWith(") {
		val := ctx.Resource
		if val == "" {
			val = ctx.ContextKeys["resource.name"]
		}
		if val == "" {
			return ConditionUnresolved, "Resource name not supplied for CEL resource.name evaluation"
		}
		start := strings.Index(expr, "startsWith(")
		end := strings.Index(expr[start:], ")")
		if start != -1 && end != -1 {
			prefix := strings.Trim(expr[start+11:start+end], `'" `)
			if strings.HasPrefix(val, prefix) {
				return ConditionSatisfied, fmt.Sprintf("Resource %q starts with prefix %q", val, prefix)
			}
			return ConditionNotSatisfied, fmt.Sprintf("Resource %q does not start with prefix %q", val, prefix)
		}
		return ConditionUnresolved, fmt.Sprintf("Malformed GCP CEL startsWith syntax in expression: %s", expr)
	}

	// 3. resource.type == "..."
	if strings.Contains(expr, "resource.type") && strings.Contains(expr, "==") {
		val, ok := ctx.ContextKeys["resource.type"]
		if !ok || val == "" {
			return ConditionUnresolved, "Context key 'resource.type' not supplied for CEL evaluation"
		}
		parts := strings.Split(expr, "==")
		if len(parts) == 2 {
			targetType := strings.Trim(parts[1], `'" `)
			if strings.EqualFold(val, targetType) {
				return ConditionSatisfied, fmt.Sprintf("Resource type %q matches %q", val, targetType)
			}
			return ConditionNotSatisfied, fmt.Sprintf("Resource type %q does not match %q", val, targetType)
		}
	}

	// 4. request.auth.claims.email == "..."
	if strings.Contains(expr, "request.auth.claims.email") {
		val, ok := ctx.ContextKeys["request.auth.claims.email"]
		if !ok || val == "" {
			return ConditionUnresolved, "Context key 'request.auth.claims.email' not supplied for CEL evaluation"
		}
		parts := strings.Split(expr, "==")
		if len(parts) == 2 {
			targetEmail := strings.Trim(parts[1], `'" `)
			if strings.EqualFold(val, targetEmail) {
				return ConditionSatisfied, fmt.Sprintf("Email claim %q matches %q", val, targetEmail)
			}
			return ConditionNotSatisfied, fmt.Sprintf("Email claim %q does not match %q", val, targetEmail)
		}
	}

	return ConditionUnresolved, fmt.Sprintf("Unsupported or unresolvable GCP CEL expression (engine supports temporal, resource, and identity CEL patterns only): %s", expr)
}

// EvaluateAzureConditionWithVersion evaluates an Azure condition expression taking conditionVersion into account.
func EvaluateAzureConditionWithVersion(condStr string, version string, ctx EvaluationContext) (ConditionEvaluationState, string) {
	cond := strings.TrimSpace(condStr)
	if cond == "" {
		return ConditionNotPresent, "No Azure condition expression present"
	}
	vTrim := strings.TrimSpace(version)
	if vTrim == "" {
		return ConditionUnresolved, "Missing Azure Deny Assignment conditionVersion (version '2.0' required)"
	}
	if vTrim != "2.0" {
		return ConditionUnresolved, fmt.Sprintf("Unsupported Azure conditionVersion %q (supported version: 2.0)", vTrim)
	}
	return EvaluateAzureCondition(cond, ctx)
}

// EvaluateAzureCondition evaluates supported Azure role assignment conditions (ABAC).
// Supports @Resource[...], @Principal[...], @Request[...], and @Action[...] predicates with StringEquals, StringNotEquals, and StringStartsWith operators.
func EvaluateAzureCondition(condStr string, ctx EvaluationContext) (ConditionEvaluationState, string) {
	if strings.TrimSpace(condStr) == "" {
		return ConditionNotPresent, "No Azure role assignment condition"
	}
	s := strings.TrimSpace(condStr)

	// Compound condition support: term1 && term2 or term1 AND term2
	delims := []string{"&&", " AND "}
	for _, delim := range delims {
		if strings.Contains(s, delim) {
			parts := strings.Split(s, delim)
			hasUnresolved := false
			var unresolvedReasons []string
			for _, p := range parts {
				pTrim := strings.TrimSpace(p)
				if pTrim == "" {
					continue
				}
				subState, subReason := evaluateSingleAzureCondition(pTrim, ctx)
				if subState == ConditionNotSatisfied {
					return ConditionNotSatisfied, fmt.Sprintf("Compound Azure condition clause %q not satisfied: %s", pTrim, subReason)
				}
				if subState == ConditionUnresolved {
					hasUnresolved = true
					unresolvedReasons = append(unresolvedReasons, subReason)
				}
			}
			if hasUnresolved {
				return ConditionUnresolved, strings.Join(unresolvedReasons, "; ")
			}
			return ConditionSatisfied, "All compound Azure ABAC clauses satisfied"
		}
	}

	return evaluateSingleAzureCondition(s, ctx)
}

func evaluateSingleAzureCondition(s string, ctx EvaluationContext) (ConditionEvaluationState, string) {
	s = strings.TrimSpace(s)

	isResource := strings.HasPrefix(s, "@Resource[")
	isPrincipal := strings.HasPrefix(s, "@Principal[")
	isRequest := strings.HasPrefix(s, "@Request[")
	isAction := strings.HasPrefix(s, "@Action[")

	if !isResource && !isPrincipal && !isRequest && !isAction {
		return ConditionUnresolved, fmt.Sprintf("Unsupported Azure ABAC condition syntax (expected @Resource, @Principal, @Request, or @Action): %s", s)
	}

	bracketStart := strings.Index(s, "[")
	bracketEnd := strings.Index(s, "]")
	if bracketStart == -1 || bracketEnd == -1 || bracketEnd <= bracketStart {
		return ConditionUnresolved, fmt.Sprintf("Malformed Azure ABAC syntax (unclosed brackets): %s", s)
	}
	attrKey := strings.TrimSpace(s[bracketStart+1 : bracketEnd])
	rest := strings.TrimSpace(s[bracketEnd+1:])

	startQ := strings.Index(rest, "'")
	endQ := strings.LastIndex(rest, "'")
	if startQ == -1 || endQ == -1 || endQ <= startQ {
		return ConditionUnresolved, fmt.Sprintf("Malformed Azure ABAC syntax (missing string quotes): %s", s)
	}
	targetVal := rest[startQ+1 : endQ]
	opPart := strings.TrimSpace(rest[:startQ])

	var ctxVal string
	var valFound bool

	if isResource {
		if v, ok := ctx.ContextKeys[attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		} else if v, ok := ctx.ContextKeys["resource."+attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		} else if (strings.EqualFold(attrKey, "name") || strings.EqualFold(attrKey, "id") || strings.EqualFold(attrKey, "resource") || strings.HasSuffix(strings.ToLower(attrKey), ":name") || strings.HasSuffix(strings.ToLower(attrKey), ":id")) && ctx.Resource != "" {
			ctxVal = ctx.Resource
			valFound = true
		} else if strings.EqualFold(attrKey, "resource_name") {
			if v, ok := ctx.ContextKeys["resource_name"]; ok && v != "" {
				ctxVal = v
				valFound = true
			} else if ctx.Resource != "" {
				ctxVal = ctx.Resource
				valFound = true
			}
		}
	} else if isPrincipal {
		if v, ok := ctx.ContextKeys[attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		} else if v, ok := ctx.ContextKeys["principal."+attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		} else if (strings.EqualFold(attrKey, "name") || strings.EqualFold(attrKey, "id") || strings.EqualFold(attrKey, "principal_id") || strings.HasSuffix(strings.ToLower(attrKey), ":name") || strings.HasSuffix(strings.ToLower(attrKey), ":id")) && ctx.PrincipalID != "" {
			ctxVal = ctx.PrincipalID
			valFound = true
		} else if strings.EqualFold(attrKey, "principal_name") {
			if v, ok := ctx.ContextKeys["principal_name"]; ok && v != "" {
				ctxVal = v
				valFound = true
			} else if ctx.PrincipalID != "" {
				ctxVal = ctx.PrincipalID
				valFound = true
			}
		}
	} else if isRequest {
		if v, ok := ctx.ContextKeys[attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		} else if v, ok := ctx.ContextKeys["request."+attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		}
	} else if isAction {
		if v, ok := ctx.ContextKeys[attrKey]; ok && v != "" {
			ctxVal = v
			valFound = true
		} else if ctx.Action != "" && (strings.EqualFold(attrKey, "name") || strings.EqualFold(attrKey, "action")) {
			ctxVal = ctx.Action
			valFound = true
		}
	}

	if !valFound {
		return ConditionUnresolved, fmt.Sprintf("Context attribute %q not supplied for Azure ABAC condition evaluation", attrKey)
	}

	switch {
	case strings.EqualFold(opPart, "StringEquals") || strings.EqualFold(opPart, "StringEqualsIgnoreCase"):
		if strings.EqualFold(ctxVal, targetVal) || strings.HasSuffix(ctxVal, "/"+targetVal) {
			return ConditionSatisfied, fmt.Sprintf("Azure condition target %q matches context value %q", targetVal, ctxVal)
		}
		return ConditionNotSatisfied, fmt.Sprintf("Azure condition target %q does not match context value %q", targetVal, ctxVal)
	case strings.EqualFold(opPart, "StringNotEquals") || strings.EqualFold(opPart, "StringNotEqualsIgnoreCase"):
		if strings.EqualFold(ctxVal, targetVal) || strings.HasSuffix(ctxVal, "/"+targetVal) {
			return ConditionNotSatisfied, fmt.Sprintf("Azure condition target %q equals context value %q (expected not equals)", targetVal, ctxVal)
		}
		return ConditionSatisfied, fmt.Sprintf("Azure condition target %q does not match context value %q", targetVal, ctxVal)
	case strings.EqualFold(opPart, "StringStartsWith") || strings.EqualFold(opPart, "StringStartsWithIgnoreCase"):
		if strings.HasPrefix(strings.ToLower(ctxVal), strings.ToLower(targetVal)) {
			return ConditionSatisfied, fmt.Sprintf("Azure condition context value %q starts with target %q", ctxVal, targetVal)
		}
		return ConditionNotSatisfied, fmt.Sprintf("Azure condition context value %q does not start with target %q", ctxVal, targetVal)
	default:
		return ConditionUnresolved, fmt.Sprintf("Unsupported Azure ABAC operator %q in: %s", opPart, s)
	}
}

func wildcardMatch(pattern, text string) bool {
	if pattern == "*" || pattern == text {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == text
	}
	if !strings.HasPrefix(text, parts[0]) {
		return false
	}
	remainder := text[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(remainder, parts[i])
		if idx == -1 {
			return false
		}
		remainder = remainder[idx+len(parts[i]):]
	}
	return strings.HasSuffix(remainder, parts[len(parts)-1])
}

func normalizeToStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		return []string{v}
	case []any:
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	case []string:
		return v
	default:
		return []string{fmt.Sprint(v)}
	}
}

func permMatchesAction(pattern, target string) bool {
	p := strings.ToLower(pattern)
	t := strings.ToLower(target)
	if p == "*" || p == t {
		return true
	}
	if strings.HasSuffix(p, ":*") {
		prefix := strings.TrimSuffix(p, "*")
		return strings.HasPrefix(t, prefix)
	}
	if strings.Contains(p, "*") {
		return wildcardMatch(p, t)
	}
	return false
}

func resourceMatches(pattern, target string) bool {
	if pattern == "" || pattern == "*" || target == "" || target == "*" {
		return true
	}
	p := strings.ToLower(pattern)
	t := strings.ToLower(target)
	if p == t {
		return true
	}
	if strings.Contains(p, "*") {
		return wildcardMatch(p, t)
	}
	return false
}

// -------------------------------------------------------------------------
// 3. Attack Path & Privilege Escalation Models (Sections 6, 8, 9)
// -------------------------------------------------------------------------

// EscalationPath captures an explainable attack path from a starting identity to a target.
type EscalationPath struct {
	ID                 string                   `json:"id"`
	Category           string                   `json:"category"`
	Provider           Provider                 `json:"provider"`
	SourceIdentity     *IAMNode                 `json:"source_identity"`
	TargetIdentity     *IAMNode                 `json:"target_identity"`
	Nodes              []*IAMNode               `json:"nodes"`
	Edges              []*IAMEdge               `json:"edges"`
	Permissions        []string                 `json:"permissions"`
	Severity           string                   `json:"severity"`
	Confidence         string                   `json:"confidence"`
	RiskScore          int                      `json:"risk_score"`
	RiskExplanation    string                   `json:"risk_explanation"`
	Remediation        string                   `json:"remediation"`
	IsExploitable      bool                     `json:"is_exploitable"`
	Feasibility        PathFeasibility          `json:"feasibility"`
	ConditionState     ConditionEvaluationState `json:"condition_state"`
	SupportingEvidence []string                 `json:"supporting_evidence,omitempty"`
	Limitations        string                   `json:"limitations,omitempty"`
	Metadata           map[string]string        `json:"metadata,omitempty"`
}

// PathFindingOptions configures bounded graph traversal.
type PathFindingOptions struct {
	MaxDepth                   int               `json:"max_depth"`
	MaxPathsPerSource          int               `json:"max_paths_per_source"`
	StartingNodeIDs            []string          `json:"starting_node_ids,omitempty"`
	TargetNodeIDs              []string          `json:"target_node_ids,omitempty"`
	RequirePrivilegedTarget    bool              `json:"require_privileged_target"`
	IncludeConditionRestricted bool              `json:"include_condition_restricted"`
	Context                    EvaluationContext `json:"context,omitempty"`
}

// DefaultPathFindingOptions returns safe, bounded path discovery defaults.
func DefaultPathFindingOptions() PathFindingOptions {
	return PathFindingOptions{
		MaxDepth:                8,
		MaxPathsPerSource:       50,
		RequirePrivilegedTarget: true,
	}
}

// -------------------------------------------------------------------------
// 4. IAM Privilege Graph Engine (Section 5)
// -------------------------------------------------------------------------

// IAMPrivilegeGraphEngine analyzes IAM policies and discovers privilege escalation vectors.
type IAMPrivilegeGraphEngine struct {
	graph                *IAMGraph
	options              PathFindingOptions
	azureDenyAssignments []AzureDenyAssignment
}

// NewIAMPrivilegeGraphEngine instantiates an engine over an existing or new graph.
func NewIAMPrivilegeGraphEngine(graph *IAMGraph, opts PathFindingOptions) *IAMPrivilegeGraphEngine {
	if graph == nil {
		graph = NewIAMGraph()
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 8
	}
	if opts.MaxPathsPerSource <= 0 {
		opts.MaxPathsPerSource = 50
	}
	return &IAMPrivilegeGraphEngine{
		graph:   graph,
		options: opts,
	}
}

// Graph returns the underlying IAMGraph.
func (e *IAMPrivilegeGraphEngine) Graph() *IAMGraph {
	return e.graph
}

// -------------------------------------------------------------------------
// 5. AWS IAM Parser & Ingestion (Section 3.1)
// -------------------------------------------------------------------------

// AWSPolicyStatement represents an individual AWS IAM policy statement.
type AWSPolicyStatement struct {
	Sid          string                            `json:"Sid,omitempty"`
	Effect       string                            `json:"Effect"`
	Principal    any                               `json:"Principal,omitempty"`
	Action       any                               `json:"Action,omitempty"`
	NotAction    any                               `json:"NotAction,omitempty"`
	Resource     any                               `json:"Resource,omitempty"`
	NotResource  any                               `json:"NotResource,omitempty"`
	Condition    map[string]map[string]any         `json:"Condition,omitempty"`
}

// AWSPolicyDocument represents an AWS IAM policy JSON payload.
type AWSPolicyDocument struct {
	Version   string               `json:"Version,omitempty"`
	Statement any                  `json:"Statement"` // Can be AWSPolicyStatement or []AWSPolicyStatement
}

// IngestAWSPolicyJSON parses and normalizes an AWS IAM policy into the privilege graph.
func (e *IAMPrivilegeGraphEngine) IngestAWSPolicyJSON(policyID, policyName, targetPrincipalID string, docBytes []byte, boundaryBytes []byte) error {
	if len(docBytes) == 0 {
		return errors.New("empty AWS policy document")
	}
	if len(docBytes) > 10*1024*1024 {
		return errors.New("AWS policy document exceeds maximum allowed size (10 MB)")
	}

	var rawDoc struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(docBytes, &rawDoc); err != nil {
		return fmt.Errorf("malformed AWS policy document JSON: %w", err)
	}

	statements, err := parseAWSStatements(rawDoc.Statement)
	if err != nil {
		return err
	}

	// Create or ensure Policy Node
	policyNode := e.graph.AddNode(&IAMNode{
		ID:            policyID,
		Type:          NodeTypePolicy,
		Provider:      ProviderAWS,
		DisplayName:   policyName,
		ResourceScope: "global",
		Confidence:    report.ConfidenceHigh,
	})

	// Check boundary if supplied
	var boundaryStatements []AWSPolicyStatement
	if len(boundaryBytes) > 0 {
		var rawBoundary struct {
			Statement json.RawMessage `json:"Statement"`
		}
		if json.Unmarshal(boundaryBytes, &rawBoundary) == nil {
			boundaryStatements, _ = parseAWSStatements(rawBoundary.Statement)
		}
	}

	// Link Target Principal to Policy
	if targetPrincipalID != "" {
		e.graph.AddEdge(&IAMEdge{
			Source:       targetPrincipalID,
			Target:       policyNode.ID,
			Relation:     RelationHasPolicy,
			Provider:     ProviderAWS,
			SourcePolicy: policyID,
		})
	}

	// Parse Statements
	for idx, stmt := range statements {
		isDeny := strings.EqualFold(stmt.Effect, "Deny")
		actions := normalizeAWSStringOrSlice(stmt.Action)
		resources := normalizeAWSStringOrSlice(stmt.Resource)
		hasConditions := len(stmt.Condition) > 0

		// Identify dangerous actions
		for _, act := range actions {
			actLower := strings.ToLower(act)
			isWildcard := actLower == "*" || actLower == "iam:*"
			isAdminPerm := isWildcard || actLower == "administratoraccess" ||
				actLower == "iam:attachuserpolicy" || actLower == "iam:attachrolepolicy" ||
				actLower == "iam:putuserpolicy" || actLower == "iam:putrolepolicy" ||
				actLower == "iam:createpolicyversion" || actLower == "iam:setdefaultpolicyversion" ||
				actLower == "iam:passrole" || actLower == "sts:assumerole"

			permNodeID := fmt.Sprintf("aws:perm:%s", actLower)
			e.graph.AddNode(&IAMNode{
				ID:            permNodeID,
				Type:          NodeTypePermission,
				Provider:      ProviderAWS,
				DisplayName:   act,
				IsAdmin:       isWildcard,
				IsPrivileged:  isAdminPerm,
				ResourceScope: strings.Join(resources, ", "),
			})

			// Add relationship: Policy GRANTS_PERMISSION Permission
			rel := RelationGrantsPermission
			if isDeny {
				rel = RelationCanModify // Marked as deny in edge metadata
			}

			edgeMeta := make(map[string]string)
			if isDeny {
				edgeMeta["effect"] = "Deny"
			} else {
				edgeMeta["effect"] = "Allow"
			}
			if len(boundaryStatements) > 0 {
				edgeMeta["has_boundary"] = "true"
				edgeMeta["boundary_policy"] = "PermissionBoundary"
			}

			e.graph.AddEdge(&IAMEdge{
				ID:            computeDeterministicEdgeID(policyNode.ID, fmt.Sprintf("%s:%d", actLower, idx), permNodeID),
				Source:        policyNode.ID,
				Target:        permNodeID,
				Relation:      rel,
				Provider:      ProviderAWS,
				Permissions:   []string{act},
				RawConditions: stmt.Condition,
				HasCondition:  hasConditions,
				SourcePolicy:  policyID,
				Metadata:      edgeMeta,
			})

			// If action is sts:AssumeRole, resolve target roles
			if strings.EqualFold(actLower, "sts:assumerole") && !isDeny && targetPrincipalID != "" {
				for _, res := range resources {
					if res != "" && res != "*" {
						targetRoleID := res
						e.graph.AddNode(&IAMNode{
							ID:            targetRoleID,
							Type:          NodeTypeRole,
							Provider:      ProviderAWS,
							DisplayName:   extractResourceNameFromARN(targetRoleID),
							ResourceScope: targetRoleID,
							IsPrivileged:  strings.Contains(strings.ToLower(targetRoleID), "admin") || strings.Contains(strings.ToLower(targetRoleID), "root"),
						})

						e.graph.AddEdge(&IAMEdge{
							Source:        targetPrincipalID,
							Target:        targetRoleID,
							Relation:      RelationCanAssume,
							Provider:      ProviderAWS,
							Permissions:   []string{"sts:AssumeRole"},
							RawConditions: stmt.Condition,
							HasCondition:  hasConditions,
							SourcePolicy:  policyID,
						})
					}
				}
			}

			// If action is iam:PassRole, add CAN_PASS_ROLE edge
			if strings.EqualFold(actLower, "iam:passrole") && !isDeny && targetPrincipalID != "" {
				for _, res := range resources {
					if res == "*" || res == "" {
						targetRoleID := "arn:aws:iam::*:role/*"
						e.graph.AddNode(&IAMNode{
							ID:            targetRoleID,
							Type:          NodeTypeRole,
							Provider:      ProviderAWS,
							DisplayName:   "*",
							ResourceScope: "*",
							IsAdmin:       true,
							IsPrivileged:  true,
						})

						e.graph.AddEdge(&IAMEdge{
							Source:        targetPrincipalID,
							Target:        targetRoleID,
							Relation:      RelationCanPassRole,
							Provider:      ProviderAWS,
							Permissions:   []string{"iam:PassRole"},
							RawConditions: stmt.Condition,
							HasCondition:  hasConditions,
							SourcePolicy:  policyID,
						})
					} else {
						targetRoleID := res
						lower := strings.ToLower(targetRoleID)
						isPriv := strings.Contains(lower, "admin") || strings.Contains(lower, "privileg") || strings.Contains(lower, "root") || strings.Contains(lower, "exec") || strings.Contains(lower, "power")
						e.graph.AddNode(&IAMNode{
							ID:            targetRoleID,
							Type:          NodeTypeRole,
							Provider:      ProviderAWS,
							DisplayName:   extractResourceNameFromARN(targetRoleID),
							ResourceScope: targetRoleID,
							IsPrivileged:  isPriv,
							IsAdmin:       strings.Contains(lower, "admin"),
						})

						e.graph.AddEdge(&IAMEdge{
							Source:        targetPrincipalID,
							Target:        targetRoleID,
							Relation:      RelationCanPassRole,
							Provider:      ProviderAWS,
							Permissions:   []string{"iam:PassRole"},
							RawConditions: stmt.Condition,
							HasCondition:  hasConditions,
							SourcePolicy:  policyID,
						})
					}
				}
			}
		}
	}

	return nil
}

// IngestAWSTrustPolicyJSON parses an AWS IAM Role trust policy (AssumeRolePolicyDocument).
func (e *IAMPrivilegeGraphEngine) IngestAWSTrustPolicyJSON(roleARN string, trustDocBytes []byte) error {
	if len(trustDocBytes) == 0 {
		return nil
	}

	var rawDoc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(trustDocBytes, &rawDoc); err != nil {
		return fmt.Errorf("malformed AWS trust policy JSON: %w", err)
	}

	stmts, err := parseAWSStatements(rawDoc.Statement)
	if err != nil {
		return err
	}

	roleNode := e.graph.AddNode(&IAMNode{
		ID:            roleARN,
		Type:          NodeTypeRole,
		Provider:      ProviderAWS,
		DisplayName:   extractResourceNameFromARN(roleARN),
		ResourceScope: roleARN,
		IsPrivileged:  strings.Contains(strings.ToLower(roleARN), "admin") || strings.Contains(strings.ToLower(roleARN), "root"),
	})

	for _, stmt := range stmts {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}

		principals := extractAWSPrincipals(stmt.Principal)
		hasConditions := len(stmt.Condition) > 0

		for _, p := range principals {
			pType := NodeTypeUser
			if strings.Contains(p, ":role/") {
				pType = NodeTypeRole
			} else if strings.Contains(p, "service:") || strings.HasSuffix(p, ".amazonaws.com") {
				pType = NodeTypeServicePrincipal
			} else if strings.Contains(p, ":root") || strings.Contains(p, ":account/") {
				pType = NodeTypeAccount
			}

			pNode := e.graph.AddNode(&IAMNode{
				ID:            p,
				Type:          pType,
				Provider:      ProviderAWS,
				DisplayName:   extractResourceNameFromARN(p),
				ResourceScope: p,
			})

			if pType == NodeTypeServicePrincipal || p == "*" {
				if roleNode.Metadata == nil {
					roleNode.Metadata = make(map[string]string)
				}
				ts := roleNode.Metadata["trusted_services"]
				if ts == "" {
					roleNode.Metadata["trusted_services"] = p
				} else if !strings.Contains(ts, p) {
					roleNode.Metadata["trusted_services"] = ts + "," + p
				}
			}

			// Add relationship: Principal CAN_ASSUME Role / Role TRUSTS Principal
			e.graph.AddEdge(&IAMEdge{
				Source:        pNode.ID,
				Target:        roleNode.ID,
				Relation:      RelationCanAssume,
				Provider:      ProviderAWS,
				Permissions:   []string{"sts:AssumeRole"},
				RawConditions: stmt.Condition,
				HasCondition:  hasConditions,
				Confidence:    report.ConfidenceHigh,
			})
		}
	}

	return nil
}

// -------------------------------------------------------------------------
// 6. Google Cloud IAM Parser & Ingestion (Section 3.2)
// -------------------------------------------------------------------------

// GCPBinding represents a single IAM binding in a GCP policy document.
type GCPBinding struct {
	Role      string         `json:"role"`
	Members   []string       `json:"members"`
	Condition *GCPCondition `json:"condition,omitempty"`
}

// GCPCondition represents a CEL expression constraint on a GCP IAM binding.
type GCPCondition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"`
}

// IngestGCPIAMPolicyJSON parses a GCP project, organization, or resource IAM policy.
func (e *IAMPrivilegeGraphEngine) IngestGCPIAMPolicyJSON(resourceScope string, policyBytes []byte) error {
	if len(policyBytes) == 0 {
		return errors.New("empty GCP IAM policy document")
	}

	var doc struct {
		Bindings []GCPBinding `json:"bindings"`
	}
	if err := json.Unmarshal(policyBytes, &doc); err != nil {
		return fmt.Errorf("malformed GCP IAM policy JSON: %w", err)
	}

	resType := NodeTypeProject
	if strings.HasPrefix(resourceScope, "organizations/") {
		resType = NodeTypeOrganization
	}

	resourceNode := e.graph.AddNode(&IAMNode{
		ID:            resourceScope,
		Type:          resType,
		Provider:      ProviderGCP,
		DisplayName:   resourceScope,
		ResourceScope: resourceScope,
	})

	for _, b := range doc.Bindings {
		roleLower := strings.ToLower(b.Role)
		isAdminRole := roleLower == "roles/owner" || roleLower == "roles/resourcemanager.organizationadmin"
		isImpersonationRole := roleLower == "roles/iam.serviceaccountuser" || roleLower == "roles/iam.serviceaccounttokencreator"

		roleNode := e.graph.AddNode(&IAMNode{
			ID:            b.Role,
			Type:          NodeTypeRole,
			Provider:      ProviderGCP,
			DisplayName:   b.Role,
			ResourceScope: resourceScope,
			IsAdmin:       isAdminRole,
			IsPrivileged:  isAdminRole || roleLower == "roles/editor",
		})

		// Resource SCOPED_TO Role
		e.graph.AddEdge(&IAMEdge{
			Source:   roleNode.ID,
			Target:   resourceNode.ID,
			Relation: RelationScopedTo,
			Provider: ProviderGCP,
		})

		for _, m := range b.Members {
			memberID := m
			mType := NodeTypeUser
			displayName := m

			if strings.HasPrefix(m, "serviceAccount:") {
				mType = NodeTypeServiceAccount
				memberID = strings.TrimPrefix(m, "serviceAccount:")
				displayName = memberID
			} else if strings.HasPrefix(m, "user:") {
				mType = NodeTypeUser
				memberID = strings.TrimPrefix(m, "user:")
				displayName = memberID
			} else if strings.HasPrefix(m, "group:") {
				mType = NodeTypeGroup
				memberID = strings.TrimPrefix(m, "group:")
				displayName = memberID
			}

			memberNode := e.graph.AddNode(&IAMNode{
				ID:            memberID,
				Type:          mType,
				Provider:      ProviderGCP,
				DisplayName:   displayName,
				ResourceScope: resourceScope,
			})

			hasCond := b.Condition != nil && b.Condition.Expression != ""
			edgeMeta := make(map[string]string)
			condExpr := ""
			if hasCond {
				condExpr = b.Condition.Expression
				edgeMeta["condition"] = b.Condition.Expression
			}

			// Add relationship: Member ASSIGNED_TO Role
			e.graph.AddEdge(&IAMEdge{
				Source:        memberNode.ID,
				Target:        roleNode.ID,
				Relation:      RelationAssignedTo,
				Provider:      ProviderGCP,
				Permissions:   []string{b.Role},
				ConditionExpr: condExpr,
				HasCondition:  hasCond,
				Metadata:      edgeMeta,
			})

			// If role is TokenCreator or ServiceAccountUser on a specific service account, link CAN_IMPERSONATE
			if isImpersonationRole && strings.Contains(resourceScope, "@") {
				targetSANode := e.graph.AddNode(&IAMNode{
					ID:            resourceScope,
					Type:          NodeTypeServiceAccount,
					Provider:      ProviderGCP,
					DisplayName:   resourceScope,
					ResourceScope: resourceScope,
				})

				impMeta := make(map[string]string)
				for k, v := range edgeMeta {
					impMeta[k] = v
				}
				if roleLower == "roles/iam.serviceaccounttokencreator" {
					impMeta["impersonation_type"] = "TOKEN_CREATION"
				} else {
					impMeta["impersonation_type"] = "WORKLOAD_USER"
				}

				e.graph.AddEdge(&IAMEdge{
					Source:        memberNode.ID,
					Target:        targetSANode.ID,
					Relation:      RelationCanImpersonate,
					Provider:      ProviderGCP,
					Permissions:   []string{b.Role},
					ConditionExpr: condExpr,
					HasCondition:  hasCond,
					Metadata:      impMeta,
				})
			}
		}
	}

	return nil
}

// -------------------------------------------------------------------------
// 7. Microsoft Azure IAM / RBAC Parser & Ingestion (Section 3.3)
// -------------------------------------------------------------------------

// AzureRoleAssignment represents an Azure RBAC role assignment definition.
type AzureRoleAssignment struct {
	ID               string `json:"id"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType,omitempty"`
	Scope            string `json:"scope"`
	Condition        string `json:"condition,omitempty"`
}

// AzureRoleDefinition represents an Azure RBAC role definition JSON structure.
type AzureRoleDefinition struct {
	ID               string   `json:"id"`
	RoleName         string   `json:"roleName"`
	RoleType         string   `json:"roleType,omitempty"`
	Description      string   `json:"description,omitempty"`
	AssignableScopes []string `json:"assignableScopes,omitempty"`
	Permissions      []struct {
		Actions        []string `json:"actions"`
		NotActions     []string `json:"notActions"`
		DataActions    []string `json:"dataActions"`
		NotDataActions []string `json:"notDataActions"`
	} `json:"permissions"`
}

// Azure REST constants for SystemDefined All Principals identity.
const (
	AzureAllPrincipalsID   = "00000000-0000-0000-0000-000000000000"
	AzureAllPrincipalsType = "SystemDefined"
)

// AzurePrincipal represents an identity in an Azure Deny Assignment.
type AzurePrincipal struct {
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
}

// AzureDenyPermission represents a permissions entry in an Azure Deny Assignment.
type AzureDenyPermission struct {
	Actions          []string `json:"actions,omitempty"`
	NotActions       []string `json:"notActions,omitempty"`
	DataActions      []string `json:"dataActions,omitempty"`
	NotDataActions   []string `json:"notDataActions,omitempty"`
	Condition        string   `json:"condition,omitempty"`
	ConditionVersion string   `json:"conditionVersion,omitempty"`
}

// AzureDenyAssignment represents an Azure Deny Assignment document.
type AzureDenyAssignment struct {
	ID                      string                `json:"id"`
	DenyAssignmentName      string                `json:"denyAssignmentName,omitempty"`
	Scope                   string                `json:"scope"`
	DoNotApplyToChildScopes bool                  `json:"doNotApplyToChildScopes,omitempty"`
	Principals              []AzurePrincipal      `json:"principals,omitempty"`
	ExcludePrincipals       []AzurePrincipal      `json:"excludePrincipals,omitempty"`
	Permissions             []AzureDenyPermission `json:"permissions,omitempty"`
	Condition               string                `json:"condition,omitempty"`
	ConditionVersion        string                `json:"conditionVersion,omitempty"`

	// Aggregate slices preserved for backward compatibility and fast summary access:
	Actions        []string `json:"actions,omitempty"`
	NotActions     []string `json:"notActions,omitempty"`
	DataActions    []string `json:"dataActions,omitempty"`
	NotDataActions []string `json:"notDataActions,omitempty"`
}

// azurePrincipalTypeMatches checks if an internal node type corresponds to an Azure principal type string.
func azurePrincipalTypeMatches(nodeType IAMNodeType, azureType string) bool {
	at := strings.ToLower(strings.TrimSpace(azureType))
	if at == "" {
		return false
	}
	switch nodeType {
	case NodeTypeUser:
		return at == "user"
	case NodeTypeGroup:
		return at == "group"
	case NodeTypeServicePrincipal, NodeTypeServiceAccount:
		return at == "serviceprincipal"
	default:
		return strings.EqualFold(string(nodeType), at)
	}
}

// splitAndTrim splits string s by sep and trims whitespace from elements.
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	var res []string
	for _, part := range strings.Split(s, sep) {
		part = strings.TrimSpace(part)
		if part != "" {
			res = append(res, part)
		}
	}
	return res
}

// AzureScopeTier represents the hierarchy levels in Azure ARM RBAC.
type AzureScopeTier int

const (
	AzureScopeTierGlobal          AzureScopeTier = 0
	AzureScopeTierManagementGroup AzureScopeTier = 1
	AzureScopeTierSubscription    AzureScopeTier = 2
	AzureScopeTierResourceGroup   AzureScopeTier = 3
	AzureScopeTierResource        AzureScopeTier = 4
	AzureScopeTierUnknown         AzureScopeTier = -1
)

// AzureScopeDetails provides parsed breakdown of an Azure ARM scope URI.
type AzureScopeDetails struct {
	RawScope        string
	Tier            AzureScopeTier
	ManagementGroup string
	SubscriptionID  string
	ResourceGroup   string
	ResourcePath    string
}

// parseAzureScopeDetails parses an ARM scope into hierarchy components.
func parseAzureScopeDetails(scope string) AzureScopeDetails {
	s := strings.ToLower(strings.TrimSpace(scope))
	s = strings.TrimRight(s, "/")
	if s == "" || s == "/" {
		return AzureScopeDetails{RawScope: "/", Tier: AzureScopeTierGlobal}
	}

	details := AzureScopeDetails{RawScope: s}

	// 1. Management Group: /providers/microsoft.management/managementgroups/{mg}
	if strings.HasPrefix(s, "/providers/microsoft.management/managementgroups/") {
		remainder := strings.TrimPrefix(s, "/providers/microsoft.management/managementgroups/")
		parts := strings.Split(remainder, "/")
		details.ManagementGroup = parts[0]
		if len(parts) == 1 {
			details.Tier = AzureScopeTierManagementGroup
			return details
		}
		if len(parts) >= 3 && parts[1] == "subscriptions" {
			details.SubscriptionID = parts[2]
			if len(parts) == 3 {
				details.Tier = AzureScopeTierSubscription
				return details
			}
			if len(parts) >= 5 && parts[3] == "resourcegroups" {
				details.ResourceGroup = parts[4]
				if len(parts) == 5 {
					details.Tier = AzureScopeTierResourceGroup
					return details
				}
				details.Tier = AzureScopeTierResource
				details.ResourcePath = strings.Join(parts[5:], "/")
				return details
			}
		}
	}

	// 2. Subscription, Resource Group, Resource: /subscriptions/{sub}...
	if strings.HasPrefix(s, "/subscriptions/") {
		remainder := strings.TrimPrefix(s, "/subscriptions/")
		parts := strings.Split(remainder, "/")
		details.SubscriptionID = parts[0]
		if len(parts) == 1 {
			details.Tier = AzureScopeTierSubscription
			return details
		}
		if len(parts) >= 3 && parts[1] == "resourcegroups" {
			details.ResourceGroup = parts[2]
			if len(parts) == 3 {
				details.Tier = AzureScopeTierResourceGroup
				return details
			}
			details.Tier = AzureScopeTierResource
			details.ResourcePath = strings.Join(parts[3:], "/")
			return details
		}
		if len(parts) >= 2 && parts[1] == "providers" {
			details.Tier = AzureScopeTierResource
			details.ResourcePath = strings.Join(parts[1:], "/")
			return details
		}
	}

	details.Tier = AzureScopeTierUnknown
	return details
}

// isAzureSubScope checks if subScope is equal to or a sub-scope (descendant) of parentScope.
func isAzureSubScope(subScope, parentScope string) bool {
	sub := strings.ToLower(strings.TrimSpace(subScope))
	parent := strings.ToLower(strings.TrimSpace(parentScope))
	if parent == "" || parent == "/" {
		return true
	}
	if sub == "" {
		return false
	}
	sub = strings.TrimRight(sub, "/")
	parent = strings.TrimRight(parent, "/")
	if sub == parent {
		return true
	}
	// e.g., /subscriptions/sub-111/resourcegroups/rg-1 is sub-scope of /subscriptions/sub-111
	return strings.HasPrefix(sub, parent+"/")
}

// isAzureScopeReachable evaluates whether a target Azure role definition is assignable at assignScope.
// Returns (isReachable bool, isAmbiguous bool).
func (e *IAMPrivilegeGraphEngine) isAzureScopeReachable(assignScope string, targetRole *IAMNode) (bool, bool) {
	assignScope = strings.ToLower(strings.TrimSpace(assignScope))
	if assignScope == "" {
		return false, true // ambiguous: scope missing from graph
	}

	roleType := ""
	if targetRole.Metadata != nil {
		roleType = targetRole.Metadata["role_type"]
	}

	isGlobalBuiltIn := (strings.EqualFold(roleType, "BuiltInRole") ||
		strings.EqualFold(targetRole.DisplayName, "Owner") ||
		strings.EqualFold(targetRole.DisplayName, "Contributor") ||
		strings.EqualFold(targetRole.DisplayName, "Reader") ||
		strings.EqualFold(targetRole.DisplayName, "User Access Administrator")) &&
		(targetRole.ResourceScope == "/" || targetRole.ResourceScope == "")

	if isGlobalBuiltIn {
		return true, false // Global built-in roles are assignable at any scope
	}

	// For custom roles, check explicit assignable scopes
	var assignableScopes []string
	if targetRole.Metadata != nil && targetRole.Metadata["assignable_scopes"] != "" {
		for _, s := range strings.Split(targetRole.Metadata["assignable_scopes"], ",") {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" {
				assignableScopes = append(assignableScopes, s)
			}
		}
	}
	if len(assignableScopes) == 0 && targetRole.ResourceScope != "" && targetRole.ResourceScope != "/" {
		assignableScopes = []string{strings.ToLower(strings.TrimSpace(targetRole.ResourceScope))}
	}

	if len(assignableScopes) == 0 {
		return false, true // ambiguous / insufficient scope information
	}

	assignDetails := parseAzureScopeDetails(assignScope)
	hasAmbiguous := false

	for _, aScope := range assignableScopes {
		aScope = strings.ToLower(strings.TrimSpace(aScope))
		if aScope == "/" || aScope == "" {
			return true, false
		}

		// Direct ARM hierarchical sub-scope check
		// Case A: assignScope is child of aScope (e.g. role assignable at Sub, assignment made at Sub or child RG/Resource)
		if isAzureSubScope(assignScope, aScope) {
			return true, false
		}

		// Case B: aScope is child of assignScope (e.g. role assignable at RG, admin has write at parent Sub)
		if isAzureSubScope(aScope, assignScope) {
			return true, false
		}

		aDetails := parseAzureScopeDetails(aScope)

		// Check Management Group hierarchy transition if string prefix check didn't match directly
		// E.g., one scope is a Management Group and the other is a Subscription/RG/Resource
		if aDetails.Tier == AzureScopeTierManagementGroup || assignDetails.Tier == AzureScopeTierManagementGroup {
			mgName := aDetails.ManagementGroup
			otherDetails := assignDetails
			if assignDetails.Tier == AzureScopeTierManagementGroup {
				mgName = assignDetails.ManagementGroup
				otherDetails = aDetails
			}

			// If both are different MGs -> unrelated sibling scopes
			if aDetails.Tier == AzureScopeTierManagementGroup && assignDetails.Tier == AzureScopeTierManagementGroup {
				if !strings.EqualFold(aDetails.ManagementGroup, assignDetails.ManagementGroup) {
					continue
				}
				return true, false
			}

			// If other scope is Subscription, RG, or Resource: check graph linkage
			if e != nil && e.graph != nil {
				isLinked, isDisproven := e.checkAzureMGLinkage(mgName, otherDetails)
				if isLinked {
					return true, false
				}
				if isDisproven {
					continue
				}
			}

			// Incomplete management group hierarchy information -> Ambiguous / Inconclusive
			hasAmbiguous = true
			continue
		}

		// Check sibling scopes:
		// Different subscriptions or different resource groups in same subscription have NO inheritance
	}

	if hasAmbiguous {
		return false, true
	}

	return false, false
}

// checkAzureMGLinkage checks if a subscription or resource is linked to a management group in the IAMGraph.
// Returns (isLinked bool, isDisproven bool).
func (e *IAMPrivilegeGraphEngine) checkAzureMGLinkage(mgName string, targetScope AzureScopeDetails) (bool, bool) {
	if e == nil || e.graph == nil {
		return false, false
	}

	targetSubID := targetScope.SubscriptionID
	mgFull := "/providers/microsoft.management/managementgroups/" + strings.ToLower(mgName)

	for _, node := range e.graph.Nodes {
		if node.Provider != ProviderAzure {
			continue
		}

		nodeScopeDetails := parseAzureScopeDetails(node.ResourceScope)
		if nodeScopeDetails.SubscriptionID != "" && strings.EqualFold(nodeScopeDetails.SubscriptionID, targetSubID) {
			if node.Metadata != nil {
				nodeMG := strings.ToLower(strings.TrimSpace(node.Metadata["management_group"]))
				if nodeMG != "" {
					if nodeMG == strings.ToLower(mgName) || nodeMG == mgFull {
						return true, false
					}
					// Explicitly linked to a different management group
					return false, true
				}
			}
		}

		// Check direct node ID match
		if strings.EqualFold(node.ID, targetScope.RawScope) || (targetSubID != "" && strings.EqualFold(node.ID, "/subscriptions/"+targetSubID)) {
			if node.Metadata != nil {
				nodeMG := strings.ToLower(strings.TrimSpace(node.Metadata["management_group"]))
				if nodeMG != "" {
					if nodeMG == strings.ToLower(mgName) || nodeMG == mgFull {
						return true, false
					}
					return false, true
				}
			}
		}
	}

	// Check graph edges connecting mg node to target scope
	for _, edgeList := range e.graph.OutEdges {
		for _, edge := range edgeList {
			srcLower := strings.ToLower(edge.Source)
			tgtLower := strings.ToLower(edge.Target)
			isMG := strings.Contains(srcLower, strings.ToLower(mgName)) || strings.Contains(srcLower, mgFull)
			isTarget := (targetSubID != "" && strings.Contains(tgtLower, targetSubID)) || strings.Contains(tgtLower, targetScope.RawScope)
			if isMG && isTarget {
				return true, false
			}
		}
	}

	return false, false
}

// Standalone isAzureScopeReachable for external callers without an engine reference.
func isAzureScopeReachable(assignScope string, targetRole *IAMNode) (bool, bool) {
	return (*IAMPrivilegeGraphEngine)(nil).isAzureScopeReachable(assignScope, targetRole)
}

// IngestAzureRBACJSON parses Azure role definitions and role assignments.
func (e *IAMPrivilegeGraphEngine) IngestAzureRBACJSON(assignmentsBytes, definitionsBytes []byte) error {
	roleDefMap := make(map[string]AzureRoleDefinition)

	if len(definitionsBytes) > 0 {
		var defs []AzureRoleDefinition
		if err := json.Unmarshal(definitionsBytes, &defs); err == nil {
			for _, d := range defs {
				roleDefMap[d.ID] = d
				roleDefMap[d.RoleName] = d

				isAdmin := false
				isPrivileged := false
				var actions []string
				for _, perm := range d.Permissions {
					actions = append(actions, perm.Actions...)
					for _, act := range perm.Actions {
						if act == "*" {
							if len(perm.NotActions) == 0 {
								isAdmin = true
							}
							isPrivileged = true
						} else if strings.EqualFold(act, "Microsoft.Authorization/*") ||
							strings.EqualFold(act, "Microsoft.Authorization/roleAssignments/write") ||
							strings.EqualFold(act, "Microsoft.Authorization/roleDefinitions/write") {
							isPrivileged = true
						}
					}
				}
				if strings.EqualFold(d.RoleName, "Owner") {
					isAdmin = true
					isPrivileged = true
				} else if strings.EqualFold(d.RoleName, "Contributor") || strings.EqualFold(d.RoleName, "User Access Administrator") {
					isPrivileged = true
				}

				nodeMeta := make(map[string]string)
				if d.RoleType != "" {
					nodeMeta["role_type"] = d.RoleType
				} else if strings.EqualFold(d.RoleName, "Owner") || strings.EqualFold(d.RoleName, "Contributor") || strings.EqualFold(d.RoleName, "Reader") || strings.EqualFold(d.RoleName, "User Access Administrator") {
					nodeMeta["role_type"] = "BuiltInRole"
				} else {
					nodeMeta["role_type"] = "CustomRole"
				}
				if len(d.AssignableScopes) > 0 {
					nodeMeta["assignable_scopes"] = strings.Join(d.AssignableScopes, ",")
				}

				defScope := "/"
				if idx := strings.Index(d.ID, "/providers/"); idx > 0 {
					defScope = d.ID[:idx]
				}

				e.graph.AddNode(&IAMNode{
					ID:            d.ID,
					Type:          NodeTypeRole,
					Provider:      ProviderAzure,
					DisplayName:   d.RoleName,
					ResourceScope: defScope,
					IsAdmin:       isAdmin,
					IsPrivileged:  isPrivileged,
					Metadata:      nodeMeta,
				})
			}
		}
	}

	if len(assignmentsBytes) > 0 {
		var assignments []AzureRoleAssignment
		if err := json.Unmarshal(assignmentsBytes, &assignments); err != nil {
			return fmt.Errorf("malformed Azure role assignments JSON: %w", err)
		}

		for _, a := range assignments {
			roleName := a.RoleDefinitionID
			isAdmin := false
			isPrivileged := false
			actions := []string{}
			defScope := a.Scope
			nodeMeta := make(map[string]string)

			if def, found := roleDefMap[a.RoleDefinitionID]; found {
				roleName = def.RoleName
				if def.RoleType != "" {
					nodeMeta["role_type"] = def.RoleType
				}
				if len(def.AssignableScopes) > 0 {
					nodeMeta["assignable_scopes"] = strings.Join(def.AssignableScopes, ",")
				}
				if idx := strings.Index(def.ID, "/providers/"); idx > 0 {
					defScope = def.ID[:idx]
				}
				for _, perm := range def.Permissions {
					actions = append(actions, perm.Actions...)
					for _, act := range perm.Actions {
						if act == "*" {
							if len(perm.NotActions) == 0 {
								isAdmin = true
							}
							isPrivileged = true
						} else if strings.EqualFold(act, "Microsoft.Authorization/*") ||
							strings.EqualFold(act, "Microsoft.Authorization/roleAssignments/write") ||
							strings.EqualFold(act, "Microsoft.Authorization/roleDefinitions/write") {
							isPrivileged = true
						}
					}
				}
			}

			if strings.EqualFold(roleName, "Owner") {
				isAdmin = true
				isPrivileged = true
			} else if strings.EqualFold(roleName, "Contributor") || strings.EqualFold(roleName, "User Access Administrator") {
				isPrivileged = true
			}

			roleNode := e.graph.AddNode(&IAMNode{
				ID:            a.RoleDefinitionID,
				Type:          NodeTypeRole,
				Provider:      ProviderAzure,
				DisplayName:   roleName,
				ResourceScope: defScope,
				IsAdmin:       isAdmin,
				IsPrivileged:  isPrivileged,
				Metadata:      nodeMeta,
			})

			pType := NodeTypeUser
			switch strings.ToLower(a.PrincipalType) {
			case "serviceprincipal":
				pType = NodeTypeServicePrincipal
			case "group":
				pType = NodeTypeGroup
			}

			principalNode := e.graph.AddNode(&IAMNode{
				ID:            a.PrincipalID,
				Type:          pType,
				Provider:      ProviderAzure,
				DisplayName:   a.PrincipalID,
				ResourceScope: a.Scope,
			})

			hasCond := a.Condition != ""
			edgeMeta := make(map[string]string)
			condExpr := ""
			if hasCond {
				condExpr = a.Condition
				edgeMeta["condition"] = a.Condition
			}
			edgeMeta["scope"] = a.Scope

			e.graph.AddEdge(&IAMEdge{
				Source:        principalNode.ID,
				Target:        roleNode.ID,
				Relation:      RelationAssignedTo,
				Provider:      ProviderAzure,
				Permissions:   actions,
				ConditionExpr: condExpr,
				HasCondition:  hasCond,
				Metadata:      edgeMeta,
			})
		}
	}

	return nil
}

// IngestAzureDenyAssignmentsJSON parses Azure Deny Assignment definitions.
func (e *IAMPrivilegeGraphEngine) IngestAzureDenyAssignmentsJSON(denyBytes []byte) error {
	if len(denyBytes) == 0 {
		return nil
	}

	type armPrincipal struct {
		ID   string `json:"id"`
		Type string `json:"type,omitempty"`
	}
	type armPermission struct {
		Actions          []string `json:"actions"`
		NotActions       []string `json:"notActions"`
		DataActions      []string `json:"dataActions"`
		NotDataActions   []string `json:"notDataActions"`
		Condition        string   `json:"condition,omitempty"`
		ConditionVersion string   `json:"conditionVersion,omitempty"`
	}
	type armDenyDoc struct {
		ID         string `json:"id"`
		Name       string `json:"name,omitempty"`
		Type       string `json:"type,omitempty"`
		Properties struct {
			DenyAssignmentName      string          `json:"denyAssignmentName"`
			Scope                   string          `json:"scope"`
			DoNotApplyToChildScopes bool            `json:"doNotApplyToChildScopes"`
			Principals              []armPrincipal  `json:"principals"`
			ExcludePrincipals       []armPrincipal  `json:"excludePrincipals"`
			Permissions             []armPermission `json:"permissions"`
			Condition               string          `json:"condition,omitempty"`
			ConditionVersion        string          `json:"conditionVersion,omitempty"`
		} `json:"properties"`

		// Also support flat JSON format
		Scope                   string             `json:"scope,omitempty"`
		DoNotApplyToChildScopes bool               `json:"doNotApplyToChildScopes,omitempty"`
		Principals              json.RawMessage    `json:"principals,omitempty"`
		ExcludePrincipals       json.RawMessage    `json:"excludePrincipals,omitempty"`
		Permissions             []armPermission    `json:"permissions,omitempty"`
		Actions                 []string           `json:"actions,omitempty"`
		NotActions              []string           `json:"notActions,omitempty"`
		DataActions             []string           `json:"dataActions,omitempty"`
		NotDataActions          []string           `json:"notDataActions,omitempty"`
		Condition               string             `json:"condition,omitempty"`
		ConditionVersion        string             `json:"conditionVersion,omitempty"`
	}

	var armWrapper struct {
		Value []armDenyDoc `json:"value"`
	}
	var armList []armDenyDoc
	if err := json.Unmarshal(denyBytes, &armWrapper); err == nil && len(armWrapper.Value) > 0 {
		armList = armWrapper.Value
	} else if err2 := json.Unmarshal(denyBytes, &armList); err2 != nil {
		var single armDenyDoc
		if err3 := json.Unmarshal(denyBytes, &single); err3 != nil {
			return fmt.Errorf("malformed Azure deny assignments JSON: %w", err3)
		}
		armList = []armDenyDoc{single}
	}

	for _, item := range armList {
		da := AzureDenyAssignment{
			ID: item.ID,
		}

		if item.Properties.Scope != "" || len(item.Properties.Permissions) > 0 || len(item.Properties.Principals) > 0 {
			da.DenyAssignmentName = item.Properties.DenyAssignmentName
			da.Scope = item.Properties.Scope
			da.DoNotApplyToChildScopes = item.Properties.DoNotApplyToChildScopes
			da.Condition = item.Properties.Condition
			da.ConditionVersion = item.Properties.ConditionVersion

			for _, p := range item.Properties.Principals {
				cleanID := strings.TrimSpace(p.ID)
				cleanType := strings.TrimSpace(p.Type)
				// Explicitly normalize convenience aliases at input boundary
				if cleanID == "*" || strings.EqualFold(cleanID, "everyone") {
					cleanID = AzureAllPrincipalsID
					if cleanType == "" {
						cleanType = AzureAllPrincipalsType
					}
				}
				da.Principals = append(da.Principals, AzurePrincipal{
					ID:   cleanID,
					Type: cleanType,
				})
			}
			for _, ep := range item.Properties.ExcludePrincipals {
				cleanID := strings.TrimSpace(ep.ID)
				cleanType := strings.TrimSpace(ep.Type)
				da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{
					ID:   cleanID,
					Type: cleanType,
				})
			}
			for _, perm := range item.Properties.Permissions {
				dp := AzureDenyPermission{
					Actions:          perm.Actions,
					NotActions:       perm.NotActions,
					DataActions:      perm.DataActions,
					NotDataActions:   perm.NotDataActions,
					Condition:        perm.Condition,
					ConditionVersion: perm.ConditionVersion,
				}
				da.Permissions = append(da.Permissions, dp)
				da.Actions = append(da.Actions, perm.Actions...)
				da.NotActions = append(da.NotActions, perm.NotActions...)
				da.DataActions = append(da.DataActions, perm.DataActions...)
				da.NotDataActions = append(da.NotDataActions, perm.NotDataActions...)
			}
		} else {
			da.DenyAssignmentName = item.Name
			da.Scope = item.Scope
			da.DoNotApplyToChildScopes = item.DoNotApplyToChildScopes
			da.Condition = item.Condition
			da.ConditionVersion = item.ConditionVersion

			// Parse principals in flat JSON (can be []armPrincipal or []string)
			if len(item.Principals) > 0 {
				var pObjs []armPrincipal
				if err := json.Unmarshal(item.Principals, &pObjs); err == nil && len(pObjs) > 0 && pObjs[0].ID != "" {
					for _, p := range pObjs {
						cleanID := strings.TrimSpace(p.ID)
						cleanType := strings.TrimSpace(p.Type)
						if cleanID == "*" || strings.EqualFold(cleanID, "everyone") {
							cleanID = AzureAllPrincipalsID
							if cleanType == "" {
								cleanType = AzureAllPrincipalsType
							}
						}
						da.Principals = append(da.Principals, AzurePrincipal{ID: cleanID, Type: cleanType})
					}
				} else {
					var pStrs []string
					if err := json.Unmarshal(item.Principals, &pStrs); err == nil {
						for _, s := range pStrs {
							clean := strings.TrimSpace(s)
							if clean == "*" || strings.EqualFold(clean, "everyone") {
								da.Principals = append(da.Principals, AzurePrincipal{
									ID:   AzureAllPrincipalsID,
									Type: AzureAllPrincipalsType,
								})
							} else if clean != "" {
								da.Principals = append(da.Principals, AzurePrincipal{
									ID:   clean,
									Type: "User",
								})
							}
						}
					}
				}
			}

			// Parse excludePrincipals in flat JSON
			if len(item.ExcludePrincipals) > 0 {
				var epObjs []armPrincipal
				if err := json.Unmarshal(item.ExcludePrincipals, &epObjs); err == nil && len(epObjs) > 0 && epObjs[0].ID != "" {
					for _, ep := range epObjs {
						cleanID := strings.TrimSpace(ep.ID)
						cleanType := strings.TrimSpace(ep.Type)
						da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{ID: cleanID, Type: cleanType})
					}
				} else {
					var epStrs []string
					if err := json.Unmarshal(item.ExcludePrincipals, &epStrs); err == nil {
						for _, s := range epStrs {
							clean := strings.TrimSpace(s)
							if clean != "" {
								da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{
									ID:   clean,
									Type: "User",
								})
							}
						}
					}
				}
			}

			if len(item.Permissions) > 0 {
				for _, perm := range item.Permissions {
					dp := AzureDenyPermission{
						Actions:          perm.Actions,
						NotActions:       perm.NotActions,
						DataActions:      perm.DataActions,
						NotDataActions:   perm.NotDataActions,
						Condition:        perm.Condition,
						ConditionVersion: perm.ConditionVersion,
					}
					da.Permissions = append(da.Permissions, dp)
					da.Actions = append(da.Actions, perm.Actions...)
					da.NotActions = append(da.NotActions, perm.NotActions...)
					da.DataActions = append(da.DataActions, perm.DataActions...)
					da.NotDataActions = append(da.NotDataActions, perm.NotDataActions...)
				}
			} else {
				da.Actions = item.Actions
				da.NotActions = item.NotActions
				da.DataActions = item.DataActions
				da.NotDataActions = item.NotDataActions
				da.Permissions = []AzureDenyPermission{
					{
						Actions:          item.Actions,
						NotActions:       item.NotActions,
						DataActions:      item.DataActions,
						NotDataActions:   item.NotDataActions,
						Condition:        item.Condition,
						ConditionVersion: item.ConditionVersion,
					},
				}
			}
		}

		e.azureDenyAssignments = append(e.azureDenyAssignments, da)

		denyNodeID := da.ID
		if denyNodeID == "" {
			denyNodeID = fmt.Sprintf("deny-%s-%d", da.Scope, len(e.azureDenyAssignments))
		}

		var pMeta []string
		for _, p := range da.Principals {
			if p.Type != "" {
				pMeta = append(pMeta, fmt.Sprintf("%s:%s", p.ID, p.Type))
			} else {
				pMeta = append(pMeta, p.ID)
			}
		}
		var epMeta []string
		for _, ep := range da.ExcludePrincipals {
			if ep.Type != "" {
				epMeta = append(epMeta, fmt.Sprintf("%s:%s", ep.ID, ep.Type))
			} else {
				epMeta = append(epMeta, ep.ID)
			}
		}
		permsJSON, _ := json.Marshal(da.Permissions)

		e.graph.AddNode(&IAMNode{
			ID:            denyNodeID,
			Type:          NodeTypePolicy,
			Provider:      ProviderAzure,
			DisplayName:   da.DenyAssignmentName,
			ResourceScope: da.Scope,
			Metadata: map[string]string{
				"policy_type":                  "DENY_POLICY",
				"scope":                        da.Scope,
				"do_not_apply_to_child_scopes": fmt.Sprintf("%v", da.DoNotApplyToChildScopes),
				"principals":                   strings.Join(pMeta, ","),
				"exclude_principals":           strings.Join(epMeta, ","),
				"actions":                      strings.Join(da.Actions, ","),
				"not_actions":                  strings.Join(da.NotActions, ","),
				"data_actions":                 strings.Join(da.DataActions, ","),
				"not_data_actions":             strings.Join(da.NotDataActions, ","),
				"condition":                    da.Condition,
				"condition_version":            da.ConditionVersion,
				"permissions_json":             string(permsJSON),
			},
		})
	}

	return nil
}

// EvaluateAzureDenyAssignment evaluates whether an Azure Deny Assignment blocks the specified action using default context.
// Returns (isBlocked bool, isInconclusive bool, reason string).
func (e *IAMPrivilegeGraphEngine) EvaluateAzureDenyAssignment(principal *IAMNode, targetScope string, reqAction string, isDataAction bool) (bool, bool, string) {
	evalCtx := EvaluationContext{
		PrincipalID: "",
		Action:      reqAction,
		Resource:    targetScope,
		ContextKeys: make(map[string]string),
	}
	if principal != nil {
		evalCtx.PrincipalID = principal.ID
	}
	if e != nil && e.options.Context.ContextKeys != nil {
		for k, v := range e.options.Context.ContextKeys {
			evalCtx.ContextKeys[k] = v
		}
	}
	return e.EvaluateAzureDenyAssignmentWithContext(principal, targetScope, reqAction, isDataAction, evalCtx)
}

// EvaluateAzureDenyAssignmentWithContext evaluates whether an Azure Deny Assignment blocks the specified action considering explicit context.
// Returns (isBlocked bool, isInconclusive bool, reason string).
func (e *IAMPrivilegeGraphEngine) EvaluateAzureDenyAssignmentWithContext(
	principal *IAMNode,
	targetScope string,
	reqAction string,
	isDataAction bool,
	evalCtx EvaluationContext,
) (bool, bool, string) {
	if principal == nil || strings.TrimSpace(principal.ID) == "" {
		return false, true, "Missing principal information for Azure Deny Assignment evaluation"
	}

	targetScope = strings.ToLower(strings.TrimSpace(targetScope))
	if targetScope == "" {
		return false, true, "Missing target scope for Azure Deny Assignment evaluation"
	}

	targetDetails := parseAzureScopeDetails(targetScope)
	hasInconclusive := false
	var inconclusiveReason string

	// Collect all deny assignments: both explicitly ingested and graph-derived
	var allDenies []AzureDenyAssignment
	allDenies = append(allDenies, e.azureDenyAssignments...)

	// Derive from graph nodes with policy_type == "DENY_POLICY"
	if e.graph != nil {
		for _, node := range e.graph.Nodes {
			if node.Provider == ProviderAzure && node.Metadata != nil && node.Metadata["policy_type"] == "DENY_POLICY" {
				alreadyPresent := false
				for _, d := range allDenies {
					if d.ID == node.ID {
						alreadyPresent = true
						break
					}
				}
				if !alreadyPresent {
					da := AzureDenyAssignment{
						ID:                      node.ID,
						DenyAssignmentName:      node.DisplayName,
						Scope:                   node.Metadata["scope"],
						DoNotApplyToChildScopes: strings.EqualFold(node.Metadata["do_not_apply_to_child_scopes"], "true"),
						Condition:               node.Metadata["condition"],
						ConditionVersion:        node.Metadata["condition_version"],
						Actions:                 splitAndTrim(node.Metadata["actions"], ","),
						NotActions:              splitAndTrim(node.Metadata["not_actions"], ","),
						DataActions:             splitAndTrim(node.Metadata["data_actions"], ","),
						NotDataActions:          splitAndTrim(node.Metadata["not_data_actions"], ","),
					}
					if node.Metadata["permissions_json"] != "" {
						_ = json.Unmarshal([]byte(node.Metadata["permissions_json"]), &da.Permissions)
					}
					for _, rawP := range splitAndTrim(node.Metadata["principals"], ",") {
						if strings.Contains(rawP, ":") {
							parts := strings.SplitN(rawP, ":", 2)
							da.Principals = append(da.Principals, AzurePrincipal{ID: parts[0], Type: parts[1]})
						} else {
							da.Principals = append(da.Principals, AzurePrincipal{ID: rawP, Type: ""})
						}
					}
					for _, rawEP := range splitAndTrim(node.Metadata["exclude_principals"], ",") {
						if strings.Contains(rawEP, ":") {
							parts := strings.SplitN(rawEP, ":", 2)
							da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{ID: parts[0], Type: parts[1]})
						} else {
							da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{ID: rawEP, Type: ""})
						}
					}
					allDenies = append(allDenies, da)
				}
			}
		}

		// Derive from graph edges with effect == "Deny"
		for _, edgeList := range e.graph.OutEdges {
			for _, edge := range edgeList {
				if edge.Provider != ProviderAzure {
					continue
				}
				if edge.Metadata != nil && (edge.Metadata["effect"] == "Deny" || edge.Metadata["deny"] == "true") {
					da := AzureDenyAssignment{
						ID:                      edge.Target,
						Scope:                   edge.Metadata["scope"],
						DoNotApplyToChildScopes: strings.EqualFold(edge.Metadata["do_not_apply_to_child_scopes"], "true"),
						Condition:               edge.ConditionExpr,
						ConditionVersion:        edge.Metadata["condition_version"],
					}
					if edge.Metadata["principals"] != "" {
						for _, rawP := range splitAndTrim(edge.Metadata["principals"], ",") {
							if strings.Contains(rawP, ":") {
								parts := strings.SplitN(rawP, ":", 2)
								da.Principals = append(da.Principals, AzurePrincipal{ID: parts[0], Type: parts[1]})
							} else {
								da.Principals = append(da.Principals, AzurePrincipal{ID: rawP, Type: ""})
							}
						}
					} else if edge.Source != "" {
						da.Principals = []AzurePrincipal{{ID: edge.Source, Type: "User"}}
					}
					if edge.Metadata["exclude_principals"] != "" {
						for _, rawEP := range splitAndTrim(edge.Metadata["exclude_principals"], ",") {
							if strings.Contains(rawEP, ":") {
								parts := strings.SplitN(rawEP, ":", 2)
								da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{ID: parts[0], Type: parts[1]})
							} else {
								da.ExcludePrincipals = append(da.ExcludePrincipals, AzurePrincipal{ID: rawEP, Type: ""})
							}
						}
					}
					if len(edge.Permissions) > 0 {
						da.Actions = edge.Permissions
					}
					if edge.Metadata["actions"] != "" {
						da.Actions = append(da.Actions, splitAndTrim(edge.Metadata["actions"], ",")...)
					}
					if edge.Metadata["not_actions"] != "" {
						da.NotActions = splitAndTrim(edge.Metadata["not_actions"], ",")
					}
					if edge.Metadata["data_actions"] != "" {
						da.DataActions = splitAndTrim(edge.Metadata["data_actions"], ",")
					}
					if edge.Metadata["not_data_actions"] != "" {
						da.NotDataActions = splitAndTrim(edge.Metadata["not_data_actions"], ",")
					}
					allDenies = append(allDenies, da)
				}
			}
		}
	}

	for _, deny := range allDenies {
		denyScope := strings.ToLower(strings.TrimSpace(deny.Scope))
		if denyScope == "" {
			hasInconclusive = true
			inconclusiveReason = "Azure Deny Assignment has missing scope specification"
			continue
		}

		// 1. Excluded Principals Check
		isExcluded := false
		for _, ep := range deny.ExcludePrincipals {
			epID := strings.TrimSpace(ep.ID)
			epType := strings.TrimSpace(ep.Type)

			if epID == "" {
				hasInconclusive = true
				inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q has incomplete excludePrincipals entry (empty ID)", deny.ID)
				continue
			}

			// Authoritative matching on principal.ID only (Display names are never treated as authoritative)
			if strings.EqualFold(principal.ID, epID) {
				if epType == "" {
					hasInconclusive = true
					inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q excludePrincipal %q has missing principal type", deny.ID, ep.ID)
					continue
				}
				if principal.Type != "" && !azurePrincipalTypeMatches(principal.Type, epType) {
					continue
				}
				isExcluded = true
				break
			}
		}
		if isExcluded {
			continue // Excluded principal is not blocked
		}

		// 2. Principal Matching Check
		if len(deny.Principals) == 0 {
			hasInconclusive = true
			inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q has missing principal specification", deny.ID)
			continue
		}

		matchesPrincipal := false
		for _, dp := range deny.Principals {
			dpID := strings.TrimSpace(dp.ID)
			dpType := strings.TrimSpace(dp.Type)

			if dpID == "" {
				hasInconclusive = true
				inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q has incomplete principal specification (empty ID)", deny.ID)
				continue
			}

			// Azure REST SystemDefined All Principals (00000000-0000-0000-0000-000000000000)
			if strings.EqualFold(dpID, AzureAllPrincipalsID) {
				if !strings.EqualFold(dpType, AzureAllPrincipalsType) {
					hasInconclusive = true
					inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q has principal %q with missing or incomplete principal type; expected %s", deny.ID, dpID, AzureAllPrincipalsType)
					continue
				}
				matchesPrincipal = true
				break
			}

			// Reject unnormalized convenience aliases in evaluation
			if dpID == "*" || strings.EqualFold(dpID, "everyone") {
				hasInconclusive = true
				inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q contains unnormalized alias %q; valid Azure REST identity required", deny.ID, dpID)
				continue
			}

			// Direct principal ID matching
			if strings.EqualFold(principal.ID, dpID) {
				if dpType == "" {
					hasInconclusive = true
					inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q principal %q has missing principal type", deny.ID, dpID)
					continue
				}
				if principal.Type != "" && !azurePrincipalTypeMatches(principal.Type, dpType) {
					continue
				}
				matchesPrincipal = true
				break
			}
		}

		if !matchesPrincipal {
			continue // Unrelated principal is not blocked
		}

		// 3. Scope Matching and Inheritance
		denyDetails := parseAzureScopeDetails(denyScope)
		isDirectMatch := strings.EqualFold(targetScope, denyScope)
		isDescendant := false

		if !isDirectMatch {
			if isAzureSubScope(targetScope, denyScope) {
				isDescendant = true
			} else if denyDetails.Tier == AzureScopeTierManagementGroup {
				if e.graph != nil {
					isLinked, isDisproven := e.checkAzureMGLinkage(denyDetails.ManagementGroup, targetDetails)
					if isLinked {
						isDescendant = true
					} else if !isDisproven {
						// Missing management group linkage info
						hasInconclusive = true
						inconclusiveReason = fmt.Sprintf("Missing management group hierarchy linkage between Deny scope %q and target scope %q", denyScope, targetScope)
						continue
					}
				}
			}
		}

		if !isDirectMatch && !isDescendant {
			// Sibling scope or child-to-parent -> Deny does not apply
			continue
		}

		// 4. doNotApplyToChildScopes check
		if isDescendant && !isDirectMatch && deny.DoNotApplyToChildScopes {
			// Propagation to child scopes blocked by doNotApplyToChildScopes
			continue
		}

		// 5. Top-Level Condition Evaluation (if present)
		if strings.TrimSpace(deny.Condition) != "" {
			cState, cReason := EvaluateAzureConditionWithVersion(deny.Condition, deny.ConditionVersion, evalCtx)
			if cState == ConditionNotSatisfied {
				// Deny condition not satisfied: does NOT block!
				continue
			}
			if cState == ConditionUnresolved {
				hasInconclusive = true
				inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q top-level condition unresolved: %s", deny.ID, cReason)
				continue
			}
		}

		// 6. Permission-Level Action Matching and Condition Evaluation
		evalPermissions := deny.Permissions
		if len(evalPermissions) == 0 {
			evalPermissions = []AzureDenyPermission{
				{
					Actions:        deny.Actions,
					NotActions:     deny.NotActions,
					DataActions:    deny.DataActions,
					NotDataActions: deny.NotDataActions,
				},
			}
		}

		for _, perm := range evalPermissions {
			if !isDataAction {
				// Management action
				if len(perm.Actions) == 0 {
					continue
				}

				actionBlocked := false
				for _, act := range perm.Actions {
					if act == "*" || permMatchesAction(act, reqAction) {
						actionBlocked = true
						break
					}
				}
				if !actionBlocked {
					continue
				}

				isNotActionExcluded := false
				for _, notAct := range perm.NotActions {
					if notAct == "*" || permMatchesAction(notAct, reqAction) {
						isNotActionExcluded = true
						break
					}
				}
				if isNotActionExcluded {
					continue
				}

				// Check permission condition (if present)
				if strings.TrimSpace(perm.Condition) != "" {
					pState, pReason := EvaluateAzureConditionWithVersion(perm.Condition, perm.ConditionVersion, evalCtx)
					if pState == ConditionNotSatisfied {
						continue // Permission condition not satisfied: does not block
					}
					if pState == ConditionUnresolved {
						hasInconclusive = true
						inconclusiveReason = fmt.Sprintf("Azure Deny Assignment %q permission condition unresolved: %s", deny.ID, pReason)
						continue
					}
					return true, false, fmt.Sprintf("Action %q blocked by Azure Deny Assignment %q at scope %q (condition satisfied: %s)", reqAction, deny.ID, deny.Scope, pReason)
				}

				return true, false, fmt.Sprintf("Action %q blocked by Azure Deny Assignment %q at scope %q", reqAction, deny.ID, deny.Scope)
			} else {
				// Data action
				if len(perm.DataActions) == 0 {
					continue
				}

				dataActionBlocked := false
				for _, dAct := range perm.DataActions {
					if dAct == "*" || permMatchesAction(dAct, reqAction) {
						dataActionBlocked = true
						break
					}
				}
				if !dataActionBlocked {
					continue
				}

				isNotDataExcluded := false
				for _, notDAct := range perm.NotDataActions {
					if notDAct == "*" || permMatchesAction(notDAct, reqAction) {
						isNotDataExcluded = true
						break
					}
				}
				if isNotDataExcluded {
					continue
				}

				// Check permission condition (if present)
				if strings.TrimSpace(perm.Condition) != "" {
					pState, pReason := EvaluateAzureConditionWithVersion(perm.Condition, perm.ConditionVersion, evalCtx)
					if pState == ConditionNotSatisfied {
						continue
					}
					if pState == ConditionUnresolved {
						hasInconclusive = true
						inconclusiveReason = fmt.Sprintf("Data action %q condition unresolved in Azure Deny Assignment %q: %s", reqAction, deny.ID, pReason)
						continue
					}
					return true, false, fmt.Sprintf("Data action %q blocked by Azure Deny Assignment %q at scope %q (condition satisfied: %s)", reqAction, deny.ID, deny.Scope, pReason)
				}

				return true, false, fmt.Sprintf("Data action %q blocked by Azure Deny Assignment %q at scope %q", reqAction, deny.ID, deny.Scope)
			}
		}
	}

	if hasInconclusive {
		return false, true, inconclusiveReason
	}

	return false, false, ""
}

// -------------------------------------------------------------------------
// 8. Privilege Escalation Path Finding (Sections 6, 8)
// -------------------------------------------------------------------------

// FindPrivilegeEscalationPaths traverses the IAMGraph and identifies explainable privilege escalation vectors.
func (e *IAMPrivilegeGraphEngine) FindPrivilegeEscalationPaths(ctx context.Context, opts PathFindingOptions) ([]EscalationPath, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = e.options.MaxDepth
	}
	if opts.MaxPathsPerSource <= 0 {
		opts.MaxPathsPerSource = e.options.MaxPathsPerSource
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var foundPaths []EscalationPath
	visitedPathKeys := make(map[string]bool)

	e.graph.mu.RLock()
	defer e.graph.mu.RUnlock()

	// 1. Scan for Direct Permission-Based Escalation (Section 6.1)
	for _, sourceNode := range e.graph.Nodes {
		select {
		case <-ctx.Done():
			return foundPaths, ctx.Err()
		default:
		}

		if sourceNode.IsAdmin {
			continue // Already admin, skip escalation analysis from admin itself
		}

		// Direct check: examine permissions granted to this identity
		outEdges := e.graph.OutEdges[sourceNode.ID]
		for _, edge := range outEdges {
			// A. Direct policy attachment capabilities
			if edge.Relation == RelationHasPolicy {
				policyEdges := e.graph.OutEdges[edge.Target]
				for _, pEdge := range policyEdges {
					permNode, permExists := e.graph.Nodes[pEdge.Target]
					if permExists && permNode.Type == NodeTypePermission {
						act := strings.ToLower(permNode.DisplayName)
						if act == "*" || act == "iam:*" {
							if pEdge.Metadata["effect"] != "Deny" {
								condState := ConditionNotPresent
								feasibility := FeasibilityConfirmed
								var evidence []string
								if pEdge.HasCondition && len(pEdge.RawConditions) > 0 {
									cState, cReason := EvaluateAWSConditions(pEdge.RawConditions, opts.Context)
									condState = cState
									if cState == ConditionNotSatisfied {
										feasibility = FeasibilityBlocked
									} else if cState == ConditionUnresolved {
										feasibility = FeasibilityPotential
									}
									evidence = append(evidence, cReason)
								}

								if feasibility != FeasibilityBlocked || opts.IncludeConditionRestricted {
									p := e.buildEscalationPath(
										"POLICY_WILDCARD_ADMIN",
										sourceNode.Provider,
										sourceNode,
										permNode,
										[]*IAMNode{sourceNode, e.graph.Nodes[edge.Target], permNode},
										[]*IAMEdge{edge, pEdge},
										[]string{permNode.DisplayName},
										feasibility,
										condState,
										evidence,
									)
									key := fmt.Sprintf("%s:%s:%s", p.Category, sourceNode.ID, permNode.ID)
									if !visitedPathKeys[key] {
										visitedPathKeys[key] = true
										foundPaths = append(foundPaths, p)
									}
								}
							}
						} else if act == "iam:attachuserpolicy" || act == "iam:putuserpolicy" ||
							act == "iam:attachrolepolicy" || act == "iam:putrolepolicy" ||
							act == "iam:createpolicyversion" || act == "iam:setdefaultpolicyversion" ||
							act == "resourcemanager.projects.setiampolicy" ||
							act == "microsoft.authorization/roleassignments/write" {
							if pEdge.Metadata["effect"] != "Deny" {
								condState := ConditionNotPresent
								feasibility := FeasibilityConfirmed
								var evidence []string
								if pEdge.HasCondition && len(pEdge.RawConditions) > 0 {
									cState, cReason := EvaluateAWSConditions(pEdge.RawConditions, opts.Context)
									condState = cState
									if cState == ConditionNotSatisfied {
										feasibility = FeasibilityBlocked
									} else if cState == ConditionUnresolved {
										feasibility = FeasibilityPotential
									}
									evidence = append(evidence, cReason)
								}

								if feasibility != FeasibilityBlocked || opts.IncludeConditionRestricted {
									p := e.buildEscalationPath(
										"DIRECT_PRIVILEGE_ESCALATION",
										sourceNode.Provider,
										sourceNode,
										permNode,
										[]*IAMNode{sourceNode, e.graph.Nodes[edge.Target], permNode},
										[]*IAMEdge{edge, pEdge},
										[]string{permNode.DisplayName},
										feasibility,
										condState,
										evidence,
									)
									key := fmt.Sprintf("%s:%s:%s", p.Category, sourceNode.ID, permNode.ID)
									if !visitedPathKeys[key] {
										visitedPathKeys[key] = true
										foundPaths = append(foundPaths, p)
									}
								}
							}
						}
					}
				}
			}

			// B. Direct PassRole capabilities
			if edge.Relation == RelationCanPassRole {
				targetRole, ok := e.graph.Nodes[edge.Target]
				if ok && (targetRole.IsAdmin || targetRole.IsPrivileged) {
					feasibility, condState, isExploitable, passRoleExpl, passRoleEvidence := e.ValidatePassRoleEscalation(
						sourceNode, targetRole, edge, opts.Context,
					)

					if feasibility != FeasibilityBlocked || opts.IncludeConditionRestricted {
						p := e.buildEscalationPath(
							"DIRECT_PASS_ROLE_ESCALATION",
							sourceNode.Provider,
							sourceNode,
							targetRole,
							[]*IAMNode{sourceNode, targetRole},
							[]*IAMEdge{edge},
							[]string{"iam:PassRole"},
							feasibility,
							condState,
							passRoleEvidence,
						)
						p.IsExploitable = isExploitable
						if passRoleExpl != "" {
							p.RiskExplanation = passRoleExpl
						}
						key := fmt.Sprintf("%s:%s:%s", p.Category, sourceNode.ID, targetRole.ID)
						if !visitedPathKeys[key] {
							visitedPathKeys[key] = true
							foundPaths = append(foundPaths, p)
						}
					}
				}
			}

			// C. Azure Role Assignment write or definition write
			if edge.Relation == RelationAssignedTo && edge.Provider == ProviderAzure {
				hasRoleAssignmentWrite := false
				hasRoleDefWrite := false
				for _, act := range edge.Permissions {
					actLower := strings.ToLower(act)
					if actLower == "*" || actLower == "microsoft.authorization/*" ||
						actLower == "microsoft.authorization/roleassignments/*" ||
						actLower == "microsoft.authorization/roleassignments/write" {
						hasRoleAssignmentWrite = true
					}
					if actLower == "*" || actLower == "microsoft.authorization/*" ||
						actLower == "microsoft.authorization/roledefinitions/*" ||
						actLower == "microsoft.authorization/roledefinitions/write" {
						hasRoleDefWrite = true
					}
				}

				assignScope := edge.Metadata["scope"]
				if assignScope == "" && sourceNode.ResourceScope != "" {
					assignScope = sourceNode.ResourceScope
				}

				if hasRoleAssignmentWrite {
					for _, targetRole := range e.graph.Nodes {
						if targetRole.Type == NodeTypeRole && targetRole.Provider == ProviderAzure &&
							(targetRole.IsAdmin || targetRole.IsPrivileged) && targetRole.ID != edge.Target {
							reachable, isAmbiguous := e.isAzureScopeReachable(assignScope, targetRole)
							if reachable || isAmbiguous {
								condState := ConditionNotPresent
								feasibility := FeasibilityConfirmed
								var evidence []string

								if isAmbiguous {
									feasibility = FeasibilityPotential
									evidence = append(evidence, "Scope hierarchy information incomplete in IAM graph; potential escalation")
								}

								// Check for Azure Deny Assignments
								evalAzureCtx := opts.Context
								if evalAzureCtx.ContextKeys == nil {
									evalAzureCtx.ContextKeys = make(map[string]string)
								}
								if evalAzureCtx.PrincipalID == "" {
									evalAzureCtx.PrincipalID = sourceNode.ID
								}
								evalAzureCtx.Action = "Microsoft.Authorization/roleAssignments/write"
								evalAzureCtx.Resource = assignScope
								isBlocked, isDenyInconclusive, denyReason := e.EvaluateAzureDenyAssignmentWithContext(sourceNode, assignScope, evalAzureCtx.Action, false, evalAzureCtx)
								if isBlocked {
									feasibility = FeasibilityBlocked
									evidence = append(evidence, denyReason)
								} else if isDenyInconclusive {
									feasibility = FeasibilityPotential
									evidence = append(evidence, denyReason)
								}

								if edge.HasCondition && edge.ConditionExpr != "" {
									cState, cReason := EvaluateAzureCondition(edge.ConditionExpr, opts.Context)
									condState = cState
									if cState == ConditionNotSatisfied {
										feasibility = FeasibilityBlocked
									} else if cState == ConditionUnresolved {
										feasibility = FeasibilityPotential
									}
									evidence = append(evidence, cReason)
								}

								if feasibility != FeasibilityBlocked || opts.IncludeConditionRestricted {
									p := e.buildEscalationPath(
										"DIRECT_PRIVILEGE_ESCALATION",
										ProviderAzure,
										sourceNode,
										targetRole,
										[]*IAMNode{sourceNode, e.graph.Nodes[edge.Target], targetRole},
										[]*IAMEdge{edge},
										[]string{"Microsoft.Authorization/roleAssignments/write"},
										feasibility,
										condState,
										evidence,
									)
									p.RiskExplanation = fmt.Sprintf(
										"Identity %q has role assignment write permissions at scope %q allowing assignment of privileged role %q.",
										sourceNode.DisplayName, assignScope, targetRole.DisplayName,
									)
									key := fmt.Sprintf("%s:%s:%s:roleAssignments", p.Category, sourceNode.ID, targetRole.ID)
									if !visitedPathKeys[key] {
										visitedPathKeys[key] = true
										foundPaths = append(foundPaths, p)
									}
								}
							}
						}
					}
				}

				if hasRoleDefWrite {
					for _, targetRole := range e.graph.Nodes {
						if targetRole.Type == NodeTypeRole && targetRole.Provider == ProviderAzure &&
							targetRole.IsAdmin && targetRole.ID != edge.Target {
							reachable, isAmbiguous := e.isAzureScopeReachable(assignScope, targetRole)
							if reachable || isAmbiguous {
								condState := ConditionNotPresent
								feasibility := FeasibilityConfirmed
								var evidence []string

								if isAmbiguous {
									feasibility = FeasibilityPotential
									evidence = append(evidence, "Scope hierarchy information incomplete in IAM graph; potential escalation")
								}

								// Check for Azure Deny Assignments
								evalAzureCtx := opts.Context
								if evalAzureCtx.ContextKeys == nil {
									evalAzureCtx.ContextKeys = make(map[string]string)
								}
								if evalAzureCtx.PrincipalID == "" {
									evalAzureCtx.PrincipalID = sourceNode.ID
								}
								evalAzureCtx.Action = "Microsoft.Authorization/roleDefinitions/write"
								evalAzureCtx.Resource = assignScope
								isBlocked, isDenyInconclusive, denyReason := e.EvaluateAzureDenyAssignmentWithContext(sourceNode, assignScope, evalAzureCtx.Action, false, evalAzureCtx)
								if isBlocked {
									feasibility = FeasibilityBlocked
									evidence = append(evidence, denyReason)
								} else if isDenyInconclusive {
									feasibility = FeasibilityPotential
									evidence = append(evidence, denyReason)
								}

								if edge.HasCondition && edge.ConditionExpr != "" {
									cState, cReason := EvaluateAzureCondition(edge.ConditionExpr, opts.Context)
									condState = cState
									if cState == ConditionNotSatisfied {
										feasibility = FeasibilityBlocked
									} else if cState == ConditionUnresolved {
										feasibility = FeasibilityPotential
									}
									evidence = append(evidence, cReason)
								}

								if feasibility != FeasibilityBlocked || opts.IncludeConditionRestricted {
									p := e.buildEscalationPath(
										"DIRECT_PRIVILEGE_ESCALATION",
										ProviderAzure,
										sourceNode,
										targetRole,
										[]*IAMNode{sourceNode, e.graph.Nodes[edge.Target], targetRole},
										[]*IAMEdge{edge},
										[]string{"Microsoft.Authorization/roleDefinitions/write"},
										feasibility,
										condState,
										evidence,
									)
									p.RiskExplanation = fmt.Sprintf(
										"Identity %q has role definition write permissions at scope %q allowing modification or creation of privileged role definitions.",
										sourceNode.DisplayName, assignScope,
									)
									key := fmt.Sprintf("%s:%s:%s:roleDefinitions", p.Category, sourceNode.ID, targetRole.ID)
									if !visitedPathKeys[key] {
										visitedPathKeys[key] = true
										foundPaths = append(foundPaths, p)
									}
								}
							}
						}
					}
				}
			}
		}

		// 2. Transitive Graph Traversal (Sections 6.2, 8)
		visitedCurrentBranch := make(map[string]bool)
		e.dfsTraverse(
			ctx,
			sourceNode,
			sourceNode,
			[]*IAMNode{sourceNode},
			[]*IAMEdge{},
			visitedCurrentBranch,
			0,
			opts,
			&foundPaths,
			visitedPathKeys,
		)
	}

	// Deterministic sorting: by RiskScore DESC, then Source ID, then Target ID
	sort.Slice(foundPaths, func(i, j int) bool {
		if foundPaths[i].RiskScore != foundPaths[j].RiskScore {
			return foundPaths[i].RiskScore > foundPaths[j].RiskScore
		}
		if foundPaths[i].SourceIdentity.ID != foundPaths[j].SourceIdentity.ID {
			return foundPaths[i].SourceIdentity.ID < foundPaths[j].SourceIdentity.ID
		}
		return foundPaths[i].TargetIdentity.ID < foundPaths[j].TargetIdentity.ID
	})

	return foundPaths, nil
}

// ValidatePassRoleEscalation validates all 6 essential criteria for AWS PassRole escalation.
func (e *IAMPrivilegeGraphEngine) ValidatePassRoleEscalation(
	sourceNode *IAMNode,
	targetRole *IAMNode,
	passRoleEdge *IAMEdge,
	evalCtx EvaluationContext,
) (feasibility PathFeasibility, condState ConditionEvaluationState, isExploitable bool, explanation string, evidence []string) {
	condState = ConditionNotPresent
	feasibility = FeasibilityConfirmed
	isExploitable = true

	// 1. Validate PassRole permission
	evalPassRole := e.EvaluateEffectivePermissionWithContext(sourceNode.ID, "iam:PassRole", targetRole.ID, evalCtx)
	if evalPassRole.ExplicitDeny {
		return FeasibilityBlocked, ConditionNotPresent, false,
			fmt.Sprintf("iam:PassRole is explicitly DENIED by policy %q", evalPassRole.DenyingPolicy),
			[]string{"iam:PassRole explicitly denied"}
	}
	if evalPassRole.BoundaryRestricted {
		return FeasibilityBlocked, ConditionNotPresent, false,
			"iam:PassRole is blocked by attached permission boundary",
			[]string{"Permission boundary blocks iam:PassRole"}
	}
	if evalPassRole.Status == PermissionDenied {
		return FeasibilityBlocked, ConditionNotPresent, false,
			"iam:PassRole is not granted on target role",
			[]string{"Implicit deny on iam:PassRole"}
	}
	if evalPassRole.ConditionState == ConditionNotSatisfied {
		return FeasibilityBlocked, ConditionNotSatisfied, false,
			fmt.Sprintf("iam:PassRole condition not satisfied: %s", evalPassRole.Explanation),
			[]string{evalPassRole.Explanation}
	}
	if evalPassRole.ConditionState == ConditionUnresolved {
		condState = ConditionUnresolved
		feasibility = FeasibilityPotential
		isExploitable = false
		evidence = append(evidence, "iam:PassRole condition unresolved: "+evalPassRole.Explanation)
	} else if evalPassRole.ConditionState == ConditionSatisfied {
		condState = ConditionSatisfied
		evidence = append(evidence, "iam:PassRole condition satisfied")
	}

	// 2. Validate target role resource matching
	if passRoleEdge.Target != "*" && passRoleEdge.Target != targetRole.ID {
		if !resourceMatches(passRoleEdge.Target, targetRole.ID) {
			return FeasibilityBlocked, ConditionNotPresent, false,
				fmt.Sprintf("PassRole target %q does not match permitted role %q", targetRole.ID, passRoleEdge.Target),
				[]string{"Target role resource mismatch"}
		}
	}
	evidence = append(evidence, fmt.Sprintf("Target role %q matches permitted resource scope %q", targetRole.ID, passRoleEdge.Target))

	// 3. Validate role trust policy permits service principal
	var trustedServices []string
	hasTrustPolicy := false
	inEdges := e.graph.InEdges[targetRole.ID]
	for _, inEdge := range inEdges {
		if inEdge.Relation == RelationCanAssume {
			hasTrustPolicy = true
			srcNode, exists := e.graph.Nodes[inEdge.Source]
			if exists && (srcNode.Type == NodeTypeServicePrincipal || strings.HasSuffix(inEdge.Source, ".amazonaws.com") || inEdge.Source == "*") {
				trustedServices = append(trustedServices, strings.ToLower(inEdge.Source))
			}
		}
	}
	if !hasTrustPolicy && targetRole.Metadata != nil && targetRole.Metadata["trusted_services"] != "" {
		hasTrustPolicy = true
		for _, s := range strings.Split(targetRole.Metadata["trusted_services"], ",") {
			trustedServices = append(trustedServices, strings.ToLower(strings.TrimSpace(s)))
		}
	}

	if !hasTrustPolicy {
		// Trust policy not supplied; cannot confirm service principal trust
		return FeasibilityInconclusive, condState, false,
			fmt.Sprintf("Identity %q can escalate privileges to %q via PassRole (potential: target role trust policy not supplied)", sourceNode.DisplayName, targetRole.DisplayName),
			append(evidence, "Target role trust policy unverified")
	}

	if len(trustedServices) == 0 {
		return FeasibilityBlocked, ConditionNotPresent, false,
			"Target role trust policy does not permit any service principal to assume it",
			append(evidence, "No service principal permitted in trust policy")
	}
	evidence = append(evidence, fmt.Sprintf("Role trust policy permits service principals: %s", strings.Join(trustedServices, ", ")))

	// 4 & 5. Validate service operation permission matching trusted service
	servicePermFound := false
	var matchedService string
	var matchedAction string

	serviceActions := map[string]string{
		"ec2.amazonaws.com":            "ec2:RunInstances",
		"lambda.amazonaws.com":         "lambda:CreateFunction",
		"ecs-tasks.amazonaws.com":      "ecs:RunTask",
		"cloudformation.amazonaws.com": "cloudformation:CreateStack",
		"glue.amazonaws.com":           "glue:CreateDevEndpoint",
	}

	for _, ts := range trustedServices {
		if ts == "*" {
			for sPrincipal, sAction := range serviceActions {
				evalSvc := e.EvaluateEffectivePermissionWithContext(sourceNode.ID, sAction, "*", evalCtx)
				if evalSvc.Status == PermissionGranted {
					servicePermFound = true
					matchedService = sPrincipal
					matchedAction = sAction
					evidence = append(evidence, fmt.Sprintf("Identity has compute permission %q matching wildcard service trust", sAction))
					break
				}
			}
			if servicePermFound {
				break
			}
		}

		sAction, isSupported := serviceActions[ts]
		if isSupported {
			evalSvc := e.EvaluateEffectivePermissionWithContext(sourceNode.ID, sAction, "*", evalCtx)
			if evalSvc.ExplicitDeny {
				return FeasibilityBlocked, ConditionNotPresent, false,
					fmt.Sprintf("Service operation %q explicitly DENIED by policy %q", sAction, evalSvc.DenyingPolicy),
					append(evidence, fmt.Sprintf("Service action %q explicitly denied", sAction))
			}
			if evalSvc.BoundaryRestricted {
				return FeasibilityBlocked, ConditionNotPresent, false,
					fmt.Sprintf("Service operation %q restricted by permission boundary", sAction),
					append(evidence, fmt.Sprintf("Permission boundary blocks service action %q", sAction))
			}
			if evalSvc.ConditionState == ConditionNotSatisfied {
				return FeasibilityBlocked, ConditionNotSatisfied, false,
					fmt.Sprintf("Condition for service action %q not satisfied: %s", sAction, evalSvc.Explanation),
					append(evidence, evalSvc.Explanation)
			}
			if evalSvc.ConditionState == ConditionUnresolved {
				condState = ConditionUnresolved
				feasibility = FeasibilityPotential
				isExploitable = false
			}

			if evalSvc.Status == PermissionGranted || evalSvc.Status == PermissionPotentiallyGranted {
				servicePermFound = true
				matchedService = ts
				matchedAction = sAction
				evidence = append(evidence, fmt.Sprintf("Identity has permission %q matching trusted service %q", sAction, ts))
				break
			}
		}
	}

	if !servicePermFound {
		hasOtherCompute := false
		for _, sAction := range serviceActions {
			evalSvc := e.EvaluateEffectivePermissionWithContext(sourceNode.ID, sAction, "*", evalCtx)
			if evalSvc.Status == PermissionGranted {
				hasOtherCompute = true
				break
			}
		}
		if hasOtherCompute {
			return FeasibilityBlocked, ConditionNotPresent, false,
				fmt.Sprintf("Untrusted service principal: target role trusts [%s], but identity only possesses unmatching compute permissions", strings.Join(trustedServices, ", ")),
				append(evidence, "Service principal mismatch")
		}
		return FeasibilityBlocked, ConditionNotPresent, false,
			fmt.Sprintf("Missing service creation permission: identity lacks compute execution permissions (%s) to pass role into", strings.Join(trustedServices, ", ")),
			append(evidence, "Missing required service creation permission")
	}

	explanation = fmt.Sprintf(
		"Identity %q can escalate privileges to %q via PassRole with %s on %s. All required service trust and operation criteria satisfied.",
		sourceNode.DisplayName, targetRole.DisplayName, matchedAction, matchedService,
	)
	return feasibility, condState, isExploitable, explanation, evidence
}

// dfsTraverse performs bounded, cycle-safe depth-first search for multi-hop escalation paths.
func (e *IAMPrivilegeGraphEngine) dfsTraverse(
	ctx context.Context,
	originalSource *IAMNode,
	currentNode *IAMNode,
	nodeHistory []*IAMNode,
	edgeHistory []*IAMEdge,
	branchVisited map[string]bool,
	currentDepth int,
	opts PathFindingOptions,
	results *[]EscalationPath,
	visitedPathKeys map[string]bool,
) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	if currentDepth >= opts.MaxDepth {
		return
	}

	branchVisited[currentNode.ID] = true
	defer func() { branchVisited[currentNode.ID] = false }()

	outEdges := e.graph.OutEdges[currentNode.ID]
	for _, edge := range outEdges {
		if edge.Relation != RelationCanAssume &&
			edge.Relation != RelationCanImpersonate &&
			edge.Relation != RelationMemberOf &&
			edge.Relation != RelationInherits &&
			edge.Relation != RelationAssignedTo {
			continue
		}

		targetNode, exists := e.graph.Nodes[edge.Target]
		if !exists {
			continue
		}

		if branchVisited[targetNode.ID] {
			continue // Prevent infinite cycle
		}

		nextNodeHistory := append(append([]*IAMNode{}, nodeHistory...), targetNode)
		nextEdgeHistory := append(append([]*IAMEdge{}, edgeHistory...), edge)

		// Check if target node is privileged or admin
		if targetNode.IsAdmin || targetNode.IsPrivileged {
			category := "INDIRECT_PRIVILEGE_ESCALATION"
			for _, ed := range nextEdgeHistory {
				if ed.Relation == RelationCanImpersonate {
					if ed.Metadata["impersonation_type"] == "WORKLOAD_USER" {
						category = "SERVICE_ACCOUNT_USER_ATTACH"
					} else {
						category = "SERVICE_ACCOUNT_IMPERSONATION"
					}
					break
				} else if ed.Relation == RelationCanAssume {
					category = "ROLE_ASSUMPTION_CHAIN"
				} else if ed.Relation == RelationCanPassRole {
					category = "DIRECT_PASS_ROLE_ESCALATION"
				} else if ed.Relation == RelationMemberOf && category == "INDIRECT_PRIVILEGE_ESCALATION" {
					category = "GROUP_MEMBERSHIP_INHERITANCE"
				}
			}

			pathCondState := ConditionNotPresent
			pathFeasibility := FeasibilityConfirmed
			var pathEvidence []string

			for _, ed := range nextEdgeHistory {
				if ed.Metadata != nil && (ed.Metadata["effect"] == "Deny" || ed.Metadata["deny"] == "true") {
					pathFeasibility = FeasibilityBlocked
					pathEvidence = append(pathEvidence, "Path blocked by explicit Deny assignment/policy")
					break
				}
				if ed.HasCondition {
					if ed.RawConditions != nil && len(ed.RawConditions) > 0 {
						cState, cReason := EvaluateAWSConditions(ed.RawConditions, opts.Context)
						if cState == ConditionNotSatisfied {
							pathFeasibility = FeasibilityBlocked
							pathCondState = ConditionNotSatisfied
							pathEvidence = append(pathEvidence, "AWS condition not satisfied: "+cReason)
							break
						} else if cState == ConditionUnresolved {
							pathCondState = ConditionUnresolved
							pathFeasibility = FeasibilityPotential
							pathEvidence = append(pathEvidence, "AWS condition unresolved: "+cReason)
						} else if cState == ConditionSatisfied {
							pathCondState = ConditionSatisfied
							pathEvidence = append(pathEvidence, "AWS condition satisfied: "+cReason)
						}
					} else if ed.ConditionExpr != "" {
						if ed.Provider == ProviderGCP {
							cState, cReason := EvaluateGCPCondition(&GCPCondition{Expression: ed.ConditionExpr}, opts.Context)
							if cState == ConditionNotSatisfied {
								pathFeasibility = FeasibilityBlocked
								pathCondState = ConditionNotSatisfied
								pathEvidence = append(pathEvidence, "GCP CEL condition not satisfied: "+cReason)
								break
							} else if cState == ConditionUnresolved {
								pathCondState = ConditionUnresolved
								pathFeasibility = FeasibilityPotential
								pathEvidence = append(pathEvidence, "GCP CEL condition unresolved: "+cReason)
							} else if cState == ConditionSatisfied {
								pathCondState = ConditionSatisfied
								pathEvidence = append(pathEvidence, "GCP CEL condition satisfied: "+cReason)
							}
						} else if ed.Provider == ProviderAzure {
							cState, cReason := EvaluateAzureCondition(ed.ConditionExpr, opts.Context)
							if cState == ConditionNotSatisfied {
								pathFeasibility = FeasibilityBlocked
								pathCondState = ConditionNotSatisfied
								pathEvidence = append(pathEvidence, "Azure condition not satisfied: "+cReason)
								break
							} else if cState == ConditionUnresolved {
								pathCondState = ConditionUnresolved
								pathFeasibility = FeasibilityPotential
								pathEvidence = append(pathEvidence, "Azure condition unresolved: "+cReason)
							} else if cState == ConditionSatisfied {
								pathCondState = ConditionSatisfied
								pathEvidence = append(pathEvidence, "Azure condition satisfied: "+cReason)
							}
						}
					} else {
						pathCondState = ConditionUnresolved
						pathFeasibility = FeasibilityPotential
						pathEvidence = append(pathEvidence, "Unresolved condition present on edge")
					}
				}
			}

			if category == "SERVICE_ACCOUNT_USER_ATTACH" {
				pathFeasibility = FeasibilityPotential
				pathEvidence = append(pathEvidence, "Workload user attachment detected (roles/iam.serviceAccountUser); direct token creation requires compute launch permissions (potential path)")
			} else if category == "SERVICE_ACCOUNT_IMPERSONATION" {
				pathEvidence = append(pathEvidence, fmt.Sprintf("Source principal: %s (%s)", originalSource.DisplayName, originalSource.Type))
				pathEvidence = append(pathEvidence, fmt.Sprintf("Target service account: %s", targetNode.DisplayName))
				for _, ed := range nextEdgeHistory {
					if ed.Relation == RelationCanImpersonate {
						pathEvidence = append(pathEvidence, fmt.Sprintf("Role binding: %s at scope %s", strings.Join(ed.Permissions, ","), ed.Metadata["scope"]))
						pathEvidence = append(pathEvidence, fmt.Sprintf("Token creation capability: %s", ed.Metadata["impersonation_type"]))
						if ed.Metadata != nil && (ed.Metadata["effect"] == "Deny" || ed.Metadata["deny"] == "true") {
							pathFeasibility = FeasibilityBlocked
							pathEvidence = append(pathEvidence, "Impersonation explicitly blocked by GCP IAM Deny policy")
						}
					}
				}
			}

			if pathFeasibility != FeasibilityBlocked || opts.IncludeConditionRestricted {
				perms := make([]string, 0)
				for _, ed := range nextEdgeHistory {
					perms = append(perms, ed.Permissions...)
				}

				path := e.buildEscalationPath(
					category,
					originalSource.Provider,
					originalSource,
					targetNode,
					nextNodeHistory,
					nextEdgeHistory,
					perms,
					pathFeasibility,
					pathCondState,
					pathEvidence,
				)

				pathKey := fmt.Sprintf("%s:%s:%s", path.Category, originalSource.ID, targetNode.ID)
				if !visitedPathKeys[pathKey] {
					visitedPathKeys[pathKey] = true
					*results = append(*results, path)
				}
			}
		}

		// Recurse deeper
		e.dfsTraverse(
			ctx,
			originalSource,
			targetNode,
			nextNodeHistory,
			nextEdgeHistory,
			branchVisited,
			currentDepth+1,
			opts,
			results,
			visitedPathKeys,
		)
	}
}

// buildEscalationPath constructs an explainable EscalationPath and scores its risk (Section 9).
func (e *IAMPrivilegeGraphEngine) buildEscalationPath(
	category string,
	provider Provider,
	source *IAMNode,
	target *IAMNode,
	nodes []*IAMNode,
	edges []*IAMEdge,
	permissions []string,
	feasibility PathFeasibility,
	condState ConditionEvaluationState,
	evidence []string,
) EscalationPath {
	hops := len(nodes) - 1
	riskScore := 20 // baseline

	// Target privilege level
	if target.IsAdmin {
		riskScore += 35
	} else if target.IsPrivileged {
		riskScore += 25
	}

	// Hop distance penalty (shorter paths are more dangerous)
	if hops == 1 {
		riskScore += 25
	} else if hops == 2 {
		riskScore += 15
	} else {
		riskScore += 10
	}

	// Permission breadth
	for _, p := range permissions {
		if p == "*" || p == "iam:*" {
			riskScore += 20
			break
		}
	}

	// Severity mapping based on impact
	severity := report.SeverityLow
	if target.IsAdmin {
		severity = report.SeverityCritical
	} else if target.IsPrivileged {
		severity = report.SeverityHigh
	} else if riskScore >= 50 {
		severity = report.SeverityMedium
	}

	isExploitable := false
	confidence := report.ConfidenceHigh

	switch feasibility {
	case FeasibilityConfirmed:
		isExploitable = true
		confidence = report.ConfidenceHigh
	case FeasibilityPotential:
		isExploitable = false
		confidence = report.ConfidenceMedium
	case FeasibilityInconclusive:
		isExploitable = false
		confidence = report.ConfidenceLow
	case FeasibilityBlocked:
		isExploitable = false
		confidence = report.ConfidenceUnknown
		riskScore = 0
		severity = report.SeverityInfo
	default:
		feasibility = FeasibilityConfirmed
		isExploitable = true
	}

	if riskScore > 100 {
		riskScore = 100
	}

	var pathNames []string
	for _, n := range nodes {
		pathNames = append(pathNames, fmt.Sprintf("%s (%s)", n.DisplayName, n.Type))
	}
	pathStr := strings.Join(pathNames, " ➔ ")

	explanation := fmt.Sprintf(
		"Identity %q can escalate privileges to %q via path: %s. Identified category: %s with %d transition hop(s). Feasibility: %s, Condition State: %s.",
		source.DisplayName, target.DisplayName, pathStr, category, hops, feasibility, condState,
	)
	if len(permissions) > 0 {
		explanation += fmt.Sprintf(" Involves permissions: %s.", strings.Join(permissions, ", "))
	}

	remediation := fmt.Sprintf(
		"Restrict permissions on starting identity %q or enforce strict IAM condition boundaries / least privilege.",
		source.DisplayName,
	)

	return EscalationPath{
		ID:                 computeDeterministicPathID(category, source.ID, target.ID),
		Category:           category,
		Provider:           provider,
		SourceIdentity:     source,
		TargetIdentity:     target,
		Nodes:              nodes,
		Edges:              edges,
		Permissions:        permissions,
		Severity:           severity,
		Confidence:         confidence,
		RiskScore:          riskScore,
		RiskExplanation:    explanation,
		Remediation:        remediation,
		IsExploitable:      isExploitable,
		Feasibility:        feasibility,
		ConditionState:     condState,
		SupportingEvidence: evidence,
	}
}

// -------------------------------------------------------------------------
// 9. Finding Integration (Section 13)
// -------------------------------------------------------------------------

// ToFinding converts an EscalationPath into a standard FELIX report.Finding.
func (p *EscalationPath) ToFinding() *report.Finding {
	findingID := computeDeterministicPathID(p.Category, p.SourceIdentity.ID, p.TargetIdentity.ID)
	title := fmt.Sprintf("[%s] IAM Privilege Escalation: %s ➔ %s (%s)", p.Provider, p.SourceIdentity.DisplayName, p.TargetIdentity.DisplayName, p.Category)

	details := map[string]string{
		"provider":            string(p.Provider),
		"category":            p.Category,
		"source_id":           p.SourceIdentity.ID,
		"source_type":         string(p.SourceIdentity.Type),
		"target_id":           p.TargetIdentity.ID,
		"target_type":         string(p.TargetIdentity.Type),
		"risk_score":          fmt.Sprintf("%d", p.RiskScore),
		"hops":                fmt.Sprintf("%d", len(p.Nodes)-1),
		"permissions":         strings.Join(p.Permissions, ", "),
		"path_chain":          p.Metadata["path_chain"],
	}

	sanitizedTarget := RedactText(p.SourceIdentity.ID)

	f := &report.Finding{
		ID:          findingID,
		Title:       title,
		Description: p.RiskExplanation,
		Severity:    p.Severity,
		Confidence:  p.Confidence,
		Category:    "CloudSec / IAM Privilege Escalation",
		Remediation: p.Remediation,
		Timestamp:   time.Now().UTC(),
		Target:      sanitizedTarget,
		Endpoint:    sanitizedTarget,
		Method:      "IAM_GRAPH_ANALYSIS",
		Evidence:    p.RiskExplanation,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     p.RiskExplanation,
			Location:        sanitizedTarget,
			DetectionMethod: "IAM_PRIVILEGE_GRAPH_ANALYZER",
			Details:         details,
		},
	}
	return f
}

// -------------------------------------------------------------------------
// 10. Synthetic Benchmark Graph Generator (Section 14)
// -------------------------------------------------------------------------

// GenerateSyntheticBenchmarkGraph generates synthetic IAM graphs of scalable sizes (100 to 100,000 nodes).
func GenerateSyntheticBenchmarkGraph(totalNodes int) *IAMGraph {
	g := NewIAMGraph()
	if totalNodes <= 0 {
		totalNodes = 100
	}

	// 1. Root Organization Node
	rootOrg := g.AddNode(&IAMNode{
		ID:            "org-root",
		Type:          NodeTypeOrganization,
		Provider:      ProviderAWS,
		DisplayName:   "Root-Organization",
		ResourceScope: "global",
		Confidence:    report.ConfidenceHigh,
	})

	// 2. Admin Role Node (Target of escalation paths)
	adminRole := g.AddNode(&IAMNode{
		ID:            "arn:aws:iam::111222333444:role/FullAdminRole",
		Type:          NodeTypeRole,
		Provider:      ProviderAWS,
		DisplayName:   "FullAdminRole",
		ResourceScope: "global",
		IsAdmin:       true,
		IsPrivileged:  true,
		Confidence:    report.ConfidenceHigh,
	})

	// Admin Policy
	adminPolicy := g.AddNode(&IAMNode{
		ID:            "arn:aws:iam::aws:policy/AdministratorAccess",
		Type:          NodeTypePolicy,
		Provider:      ProviderAWS,
		DisplayName:   "AdministratorAccess",
		ResourceScope: "global",
		IsAdmin:       true,
		IsPrivileged:  true,
		Confidence:    report.ConfidenceHigh,
	})

	g.AddEdge(&IAMEdge{
		Source:   adminRole.ID,
		Target:   adminPolicy.ID,
		Relation: RelationHasPolicy,
		Provider: ProviderAWS,
	})

	// 3. Generate remaining nodes hierarchically
	remainingNodes := totalNodes - 3
	groupsCount := maxInt(1, remainingNodes/20)
	rolesCount := maxInt(1, remainingNodes/10)
	usersCount := remainingNodes - groupsCount - rolesCount
	if usersCount < 0 {
		usersCount = 0
	}

	// Add Groups
	var groupIDs []string
	for i := 0; i < groupsCount; i++ {
		gid := fmt.Sprintf("group-%05d", i)
		g.AddNode(&IAMNode{
			ID:          gid,
			Type:        NodeTypeGroup,
			Provider:    ProviderAWS,
			DisplayName: fmt.Sprintf("CorporateGroup-%d", i),
		})
		g.AddEdge(&IAMEdge{
			Source:   gid,
			Target:   rootOrg.ID,
			Relation: RelationScopedTo,
			Provider: ProviderAWS,
		})
		groupIDs = append(groupIDs, gid)
	}

	// Add Roles
	var roleIDs []string
	for i := 0; i < rolesCount; i++ {
		rid := fmt.Sprintf("arn:aws:iam::111222333444:role/ServiceRole-%05d", i)
		g.AddNode(&IAMNode{
			ID:          rid,
			Type:        NodeTypeRole,
			Provider:    ProviderAWS,
			DisplayName: fmt.Sprintf("ServiceRole-%d", i),
		})
		roleIDs = append(roleIDs, rid)
	}

	// Add Users and link to Groups
	for i := 0; i < usersCount; i++ {
		uid := fmt.Sprintf("arn:aws:iam::111222333444:user/StandardUser-%05d", i)
		g.AddNode(&IAMNode{
			ID:          uid,
			Type:        NodeTypeUser,
			Provider:    ProviderAWS,
			DisplayName: fmt.Sprintf("StandardUser-%d", i),
		})

		// Link to a group
		if len(groupIDs) > 0 {
			targetGroup := groupIDs[i%len(groupIDs)]
			g.AddEdge(&IAMEdge{
				Source:   uid,
				Target:   targetGroup,
				Relation: RelationMemberOf,
				Provider: ProviderAWS,
			})
		}
	}

	// Inject controlled escalation vectors:
	// A. User-00000 has direct permission escalation to attach admin policy
	if usersCount > 0 {
		u0 := "arn:aws:iam::111222333444:user/StandardUser-00000"
		permNode := g.AddNode(&IAMNode{
			ID:           "aws:perm:iam:attachuserpolicy",
			Type:         NodeTypePermission,
			Provider:     ProviderAWS,
			DisplayName:  "iam:AttachUserPolicy",
			IsPrivileged: true,
		})
		polNode := g.AddNode(&IAMNode{
			ID:          "arn:aws:iam::111222333444:policy/UserPolicy-0",
			Type:        NodeTypePolicy,
			Provider:    ProviderAWS,
			DisplayName: "UserPolicy-0",
		})
		g.AddEdge(&IAMEdge{Source: u0, Target: polNode.ID, Relation: RelationHasPolicy, Provider: ProviderAWS})
		g.AddEdge(&IAMEdge{Source: polNode.ID, Target: permNode.ID, Relation: RelationGrantsPermission, Provider: ProviderAWS, Permissions: []string{"iam:AttachUserPolicy"}})
	}

	// B. Multi-hop role assumption: User-00001 -> Role-0 -> Role-1 -> FullAdminRole
	if usersCount > 1 && len(roleIDs) >= 2 {
		u1 := "arn:aws:iam::111222333444:user/StandardUser-00001"
		g.AddEdge(&IAMEdge{Source: u1, Target: roleIDs[0], Relation: RelationCanAssume, Provider: ProviderAWS, Permissions: []string{"sts:AssumeRole"}})
		g.AddEdge(&IAMEdge{Source: roleIDs[0], Target: roleIDs[1], Relation: RelationCanAssume, Provider: ProviderAWS, Permissions: []string{"sts:AssumeRole"}})
		g.AddEdge(&IAMEdge{Source: roleIDs[1], Target: adminRole.ID, Relation: RelationCanAssume, Provider: ProviderAWS, Permissions: []string{"sts:AssumeRole"}})
	}

	return g
}

// -------------------------------------------------------------------------
// 11. Helper Functions
// -------------------------------------------------------------------------

func parseAWSStatements(raw json.RawMessage) ([]AWSPolicyStatement, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// Try parsing as slice of statements
	var sliceStmts []AWSPolicyStatement
	if err := json.Unmarshal(raw, &sliceStmts); err == nil {
		return sliceStmts, nil
	}

	// Try parsing as single statement object
	var singleStmt AWSPolicyStatement
	if err := json.Unmarshal(raw, &singleStmt); err == nil {
		return []AWSPolicyStatement{singleStmt}, nil
	}

	return nil, errors.New("failed parsing AWS statements: neither slice nor single object")
}

func normalizeAWSStringOrSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		if strings.TrimSpace(val) == "" {
			return nil
		}
		return []string{strings.TrimSpace(val)}
	case []any:
		var res []string
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				res = append(res, strings.TrimSpace(s))
			}
		}
		return res
	case []string:
		return val
	default:
		return nil
	}
}

func extractAWSPrincipals(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case map[string]any:
		var res []string
		for _, item := range val {
			res = append(res, normalizeAWSStringOrSlice(item)...)
		}
		return res
	case []any:
		var res []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	default:
		return nil
	}
}

func extractResourceNameFromARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	colonParts := strings.Split(arn, ":")
	if len(colonParts) > 1 {
		return colonParts[len(colonParts)-1]
	}
	return arn
}

func computeDeterministicEdgeID(source, relation, target string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", source, relation, target)))
	return hex.EncodeToString(h[:16])
}

func computeDeterministicPathID(category, source, target string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", category, source, target)))
	return hex.EncodeToString(h[:16])
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
