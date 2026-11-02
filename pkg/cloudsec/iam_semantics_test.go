package cloudsec

import (
	"context"
	"strings"
	"testing"

	"felix/pkg/report"
)

// -------------------------------------------------------------------------
// 1. Condition Evaluation Tests (Section 1)
// -------------------------------------------------------------------------

func TestIAM_Condition_AWS_Satisfied(t *testing.T) {
	condBlock := map[string]map[string]any{
		"StringEquals": {
			"aws:PrincipalArn": "arn:aws:iam::111222333444:user/contractor-bob",
		},
		"IpAddress": {
			"aws:SourceIp": "192.168.1.0/24",
		},
		"Bool": {
			"aws:SecureTransport": "true",
		},
		"NumericLessThan": {
			"aws:MultiFactorAuthAge": "3600",
		},
	}

	ctx := EvaluationContext{
		PrincipalID: "arn:aws:iam::111222333444:user/contractor-bob",
		ContextKeys: map[string]string{
			"aws:SourceIp":            "192.168.1.55",
			"aws:SecureTransport":     "true",
			"aws:MultiFactorAuthAge": "1800",
		},
	}

	state, reason := EvaluateAWSConditions(condBlock, ctx)
	if state != ConditionSatisfied {
		t.Fatalf("expected ConditionSatisfied, got %s: %s", state, reason)
	}
}

func TestIAM_Condition_AWS_Unsatisfied(t *testing.T) {
	condBlock := map[string]map[string]any{
		"IpAddress": {
			"aws:SourceIp": "192.168.1.0/24",
		},
	}

	ctx := EvaluationContext{
		ContextKeys: map[string]string{
			"aws:SourceIp": "10.0.0.1", // Out of CIDR
		},
	}

	state, _ := EvaluateAWSConditions(condBlock, ctx)
	if state != ConditionNotSatisfied {
		t.Fatalf("expected ConditionNotSatisfied, got %s", state)
	}
}

func TestIAM_Condition_AWS_Unresolved(t *testing.T) {
	condBlock := map[string]map[string]any{
		"IpAddress": {
			"aws:SourceIp": "192.168.1.0/24",
		},
	}

	// aws:SourceIp is not provided in context
	ctx := EvaluationContext{
		ContextKeys: map[string]string{},
	}

	state, _ := EvaluateAWSConditions(condBlock, ctx)
	if state != ConditionUnresolved {
		t.Fatalf("expected ConditionUnresolved for missing context key, got %s", state)
	}
}

func TestIAM_Condition_GCP_CEL(t *testing.T) {
	cond := &GCPCondition{
		Title:      "TimeWindow",
		Expression: "request.time < timestamp('2026-12-31T00:00:00Z')",
	}

	// 1. Satisfied
	ctxSatisfied := EvaluationContext{
		ContextKeys: map[string]string{
			"request.time": "2026-06-01T12:00:00Z",
		},
	}
	st1, _ := EvaluateGCPCondition(cond, ctxSatisfied)
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for GCP CEL, got %s", st1)
	}

	// 2. Unsatisfied
	ctxUnsatisfied := EvaluationContext{
		ContextKeys: map[string]string{
			"request.time": "2027-01-01T00:00:00Z",
		},
	}
	st2, _ := EvaluateGCPCondition(cond, ctxUnsatisfied)
	if st2 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied for GCP CEL, got %s", st2)
	}

	// 3. Unresolved (missing context key)
	ctxUnresolved := EvaluationContext{
		ContextKeys: map[string]string{},
	}
	st3, _ := EvaluateGCPCondition(cond, ctxUnresolved)
	if st3 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for GCP CEL when time is missing, got %s", st3)
	}
}

func TestIAM_Condition_Azure_RoleAssignment(t *testing.T) {
	condStr := "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'corp-public'"

	// 1. Satisfied
	ctxSat := EvaluationContext{
		Resource: "corp-public",
	}
	st1, _ := EvaluateAzureCondition(condStr, ctxSat)
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for Azure, got %s", st1)
	}

	// 2. Unsatisfied
	ctxUnsat := EvaluationContext{
		Resource: "corp-private-vault",
	}
	st2, _ := EvaluateAzureCondition(condStr, ctxUnsat)
	if st2 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied for Azure, got %s", st2)
	}

	// 3. Unresolved
	ctxUnres := EvaluationContext{}
	st3, _ := EvaluateAzureCondition(condStr, ctxUnres)
	if st3 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for Azure when resource empty, got %s", st3)
	}
}

// -------------------------------------------------------------------------
// 2. Explicit Deny & Policy Context Tests (Section 2)
// -------------------------------------------------------------------------

func TestIAM_EffectivePermission_UnrelatedExplicitDeny_DoesNotBlock(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/mixed-user",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "mixed-user",
	})

	// Policy grants iam:AttachUserPolicy on *, but explicitly denies s3:DeleteBucket on private-bucket/*
	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowIAM",
				"Effect": "Allow",
				"Action": "iam:AttachUserPolicy",
				"Resource": "*"
			},
			{
				"Sid": "DenyS3Delete",
				"Effect": "Deny",
				"Action": "s3:DeleteBucket",
				"Resource": "arn:aws:s3:::private-bucket/*"
			}
		]
	}`)

	err := engine.IngestAWSPolicyJSON("pol-mixed", "pol-mixed", user.ID, policyJSON, nil)
	if err != nil {
		t.Fatalf("failed ingesting policy: %v", err)
	}

	// 1. Check iam:AttachUserPolicy -> Must be GRANTED (unrelated deny on s3 does NOT block)
	evalIAM := engine.EvaluateEffectivePermission(user.ID, "iam:AttachUserPolicy", "*")
	if evalIAM.Status != PermissionGranted {
		t.Errorf("expected iam:AttachUserPolicy to be GRANTED, got %s (%s)", evalIAM.Status, evalIAM.Explanation)
	}
	if evalIAM.ExplicitDeny {
		t.Errorf("expected ExplicitDeny = false for iam:AttachUserPolicy")
	}

	// 2. Check s3:DeleteBucket on private-bucket -> Must be DENIED (explicit deny)
	evalS3Denied := engine.EvaluateEffectivePermission(user.ID, "s3:DeleteBucket", "arn:aws:s3:::private-bucket/data.csv")
	if evalS3Denied.Status != PermissionDenied || !evalS3Denied.ExplicitDeny {
		t.Errorf("expected s3:DeleteBucket on private-bucket to be explicitly DENIED, got %s", evalS3Denied.Status)
	}

	// 3. Check s3:DeleteBucket on public-bucket -> Deny must NOT apply because resource does not match
	evalS3Public := engine.EvaluateEffectivePermission(user.ID, "s3:DeleteBucket", "arn:aws:s3:::public-bucket/data.csv")
	if evalS3Public.ExplicitDeny {
		t.Errorf("expected ExplicitDeny = false on unrelated public bucket")
	}
}

func TestIAM_EffectivePermission_ConditionalDeny_NotSatisfied(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/cond-deny-user",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "cond-deny-user",
	})

	// Policy grants s3:GetObject, but explicitly denies if IP is outside 192.168.1.0/24
	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowS3",
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-docs/*"
			},
			{
				"Sid": "DenyOutsideIP",
				"Effect": "Deny",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-docs/*",
				"Condition": {
					"NotIpAddress": {
						"aws:SourceIp": "192.168.1.0/24"
					}
				}
			}
		]
	}`)

	err := engine.IngestAWSPolicyJSON("pol-cond-deny", "pol-cond-deny", user.ID, policyJSON, nil)
	if err != nil {
		t.Fatalf("failed ingesting policy: %v", err)
	}

	// 1. IP inside corporate network (192.168.1.100) -> NotIpAddress condition is NOT satisfied -> Deny does NOT apply!
	ctxInside := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::corp-docs/file.txt",
		ContextKeys: map[string]string{
			"aws:SourceIp": "192.168.1.100",
		},
	}
	evalInside := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:GetObject", "arn:aws:s3:::corp-docs/file.txt", ctxInside)
	if evalInside.Status != PermissionGranted {
		t.Errorf("expected s3:GetObject to be GRANTED when inside IP, got %s (%s)", evalInside.Status, evalInside.Explanation)
	}

	// 2. IP outside corporate network (203.0.113.5) -> NotIpAddress condition IS satisfied -> Deny applies!
	ctxOutside := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::corp-docs/file.txt",
		ContextKeys: map[string]string{
			"aws:SourceIp": "203.0.113.5",
		},
	}
	evalOutside := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:GetObject", "arn:aws:s3:::corp-docs/file.txt", ctxOutside)
	if evalOutside.Status != PermissionDenied || !evalOutside.ExplicitDeny {
		t.Errorf("expected s3:GetObject to be DENIED when outside IP, got %s", evalOutside.Status)
	}
}

// -------------------------------------------------------------------------
// 3. AWS PassRole Positive & Negative Attack-Path Tests (Section 3)
// -------------------------------------------------------------------------

func TestIAM_AWS_PassRole_ValidPath_Confirmed(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-alice",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-alice",
	})

	roleARN := "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"

	// 1. Ingest Role Trust Policy allowing ec2.amazonaws.com
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "ec2.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`)
	if err := engine.IngestAWSTrustPolicyJSON(roleARN, trustJSON); err != nil {
		t.Fatalf("failed ingesting trust policy: %v", err)
	}

	// Mark role as privileged
	roleNode, _ := engine.Graph().GetNode(roleARN)
	roleNode.IsPrivileged = true
	roleNode.IsAdmin = true

	// 2. Ingest User policy granting PassRole on target role AND ec2:RunInstances
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"
			},
			{
				"Effect": "Allow",
				"Action": "ec2:RunInstances",
				"Resource": "*"
			}
		]
	}`)
	if err := engine.IngestAWSPolicyJSON("pol-passrole-valid", "pol-passrole-valid", user.ID, userPolicyJSON, nil); err != nil {
		t.Fatalf("failed ingesting user policy: %v", err)
	}

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("unexpected error finding paths: %v", err)
	}

	var passRolePath *EscalationPath
	for i := range paths {
		if paths[i].Category == "DIRECT_PASS_ROLE_ESCALATION" {
			passRolePath = &paths[i]
			break
		}
	}

	if passRolePath == nil {
		t.Fatalf("expected DIRECT_PASS_ROLE_ESCALATION path detected")
	}

	// All 6 criteria established: must be CONFIRMED and EXPLOITABLE
	if passRolePath.Feasibility != FeasibilityConfirmed {
		t.Errorf("expected FeasibilityConfirmed, got %s", passRolePath.Feasibility)
	}
	if !passRolePath.IsExploitable {
		t.Errorf("expected IsExploitable = true for valid PassRole path")
	}
	if passRolePath.Confidence != report.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %s", passRolePath.Confidence)
	}
}

func TestIAM_AWS_PassRole_WrongRoleResource(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-bob",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-bob",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"

	// Role trust policy permits ec2
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
		]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// User policy ONLY permits passing DevRole, NOT PrivilegedEC2ExecutionRole
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::111222333444:role/DevRole"
			},
			{
				"Effect": "Allow",
				"Action": "ec2:RunInstances",
				"Resource": "*"
			}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-wrong-res", "pol-wrong-res", user.ID, userPolicyJSON, nil)

	// Validate PassRole directly against target role
	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, _, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityBlocked {
		t.Errorf("expected FeasibilityBlocked for mismatched PassRole role resource, got %s", feasibility)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false for wrong role resource")
	}
}

func TestIAM_AWS_PassRole_UntrustedServicePrincipal(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-charlie",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-charlie",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/LambdaOnlyExecutionRole"

	// Target role ONLY permits lambda.amazonaws.com, NOT ec2.amazonaws.com
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
		]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// User has PassRole on the role, but ONLY has ec2:RunInstances (no lambda permissions)
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::111222333444:role/LambdaOnlyExecutionRole"
			},
			{
				"Effect": "Allow",
				"Action": "ec2:RunInstances",
				"Resource": "*"
			}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-untrusted-svc", "pol-untrusted-svc", user.ID, userPolicyJSON, nil)

	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, reason, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityBlocked {
		t.Errorf("expected FeasibilityBlocked due to untrusted service principal, got %s (%s)", feasibility, reason)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false when service principal is not trusted")
	}
	if !strings.Contains(reason, "Untrusted service principal") {
		t.Errorf("expected 'Untrusted service principal' explanation, got: %s", reason)
	}
}

func TestIAM_AWS_PassRole_MissingServiceCreationPermission(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-dave",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-dave",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"

	// Role trusts EC2
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
		]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// User has PassRole, but DOES NOT have ec2:RunInstances (only s3:GetObject)
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"
			},
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "*"
			}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-no-compute", "pol-no-compute", user.ID, userPolicyJSON, nil)

	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, reason, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityBlocked {
		t.Errorf("expected FeasibilityBlocked due to missing service creation permission, got %s (%s)", feasibility, reason)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false when identity lacks service creation permission")
	}
	if !strings.Contains(reason, "Missing service creation permission") {
		t.Errorf("expected 'Missing service creation permission' explanation, got: %s", reason)
	}
}

func TestIAM_AWS_PassRole_ExplicitDeny(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-eve",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-eve",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// User has Allow for PassRole and EC2, but also an explicit Deny on ec2:RunInstances
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["iam:PassRole", "ec2:RunInstances"],
				"Resource": "*"
			},
			{
				"Effect": "Deny",
				"Action": "ec2:RunInstances",
				"Resource": "*"
			}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-deny-passrole", "pol-deny-passrole", user.ID, userPolicyJSON, nil)

	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, reason, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityBlocked {
		t.Errorf("expected FeasibilityBlocked due to explicit deny, got %s (%s)", feasibility, reason)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false when explicit deny is present")
	}
}

func TestIAM_AWS_PassRole_RestrictiveCondition(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-frank",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-frank",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// PassRole is conditioned on source IP 192.168.1.0/24
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole",
				"Condition": {
					"IpAddress": {
						"aws:SourceIp": "192.168.1.0/24"
					}
				}
			},
			{
				"Effect": "Allow",
				"Action": "ec2:RunInstances",
				"Resource": "*"
			}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-ip-passrole", "pol-ip-passrole", user.ID, userPolicyJSON, nil)

	edge := &IAMEdge{Target: targetRoleARN}

	// 1. Unsatisfied IP -> FeasibilityBlocked
	ctxUnsat := EvaluationContext{
		ContextKeys: map[string]string{"aws:SourceIp": "10.0.0.1"},
	}
	feas1, _, exp1, _, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, ctxUnsat)
	if feas1 != FeasibilityBlocked || exp1 {
		t.Errorf("expected FeasibilityBlocked for unsatisfied condition, got %s", feas1)
	}

	// 2. Unresolved IP (not supplied) -> FeasibilityPotential (never treated as confirmed)
	ctxUnres := EvaluationContext{
		ContextKeys: map[string]string{},
	}
	feas2, condState2, exp2, _, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, ctxUnres)
	if feas2 != FeasibilityPotential {
		t.Errorf("expected FeasibilityPotential for unresolved condition, got %s", feas2)
	}
	if condState2 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved, got %s", condState2)
	}
	if exp2 {
		t.Errorf("unresolved condition must NEVER be marked exploitable")
	}

	// 3. Satisfied IP -> FeasibilityConfirmed
	ctxSat := EvaluationContext{
		ContextKeys: map[string]string{"aws:SourceIp": "192.168.1.25"},
	}
	feas3, condState3, exp3, _, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, ctxSat)
	if feas3 != FeasibilityConfirmed {
		t.Errorf("expected FeasibilityConfirmed for satisfied condition, got %s", feas3)
	}
	if condState3 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied, got %s", condState3)
	}
	if !exp3 {
		t.Errorf("expected isExploitable = true for satisfied condition")
	}
}

func TestIAM_AWS_PassRole_PermissionBoundary(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-boundary-user",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-boundary-user",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// User has policy granting PassRole and ec2:RunInstances
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
		]
	}`)

	// But user's permission boundary ONLY allows s3:* (blocks PassRole)
	boundaryJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
		]
	}`)

	_ = engine.IngestAWSPolicyJSON("pol-admin", "pol-admin", user.ID, userPolicyJSON, boundaryJSON)

	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, reason, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityBlocked {
		t.Errorf("expected FeasibilityBlocked due to boundary restriction, got %s (%s)", feasibility, reason)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false when blocked by boundary")
	}
}

// -------------------------------------------------------------------------
// 4. GCP & Azure Path Validation Tests (Section 4)
// -------------------------------------------------------------------------

func TestIAM_GCP_TokenCreator_vs_ServiceAccountUser(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	saARN := "target-sa@project-prod.iam.gserviceaccount.com"

	// Policy grants roles/iam.serviceAccountTokenCreator (direct token creation)
	policyTokenCreator := []byte(`{
		"bindings": [
			{
				"role": "roles/iam.serviceAccountTokenCreator",
				"members": ["user:analyst@example.com"]
			}
		]
	}`)
	_ = engine.IngestGCPIAMPolicyJSON(saARN, policyTokenCreator)

	// Link target SA to Owner role
	engine.Graph().AddNode(&IAMNode{
		ID:          "roles/owner",
		Type:        NodeTypeRole,
		Provider:    ProviderGCP,
		DisplayName: "roles/owner",
		IsAdmin:     true,
	})
	engine.Graph().AddEdge(&IAMEdge{
		Source:   saARN,
		Target:   "roles/owner",
		Relation: RelationAssignedTo,
		Provider: ProviderGCP,
	})

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("unexpected error finding GCP paths: %v", err)
	}

	foundTokenCreator := false
	for _, p := range paths {
		if p.Category == "SERVICE_ACCOUNT_IMPERSONATION" {
			foundTokenCreator = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for direct TokenCreator, got %s", p.Feasibility)
			}
		}
	}

	if !foundTokenCreator {
		t.Errorf("expected SERVICE_ACCOUNT_IMPERSONATION path detected for TokenCreator")
	}
}

func TestIAM_Azure_RoleAssignment_Reachable_vs_Unreachable(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	// 1. Role assignment granting User Access Administrator at subscription scope
	// where Owner role definition is reachable
	roleAssignmentsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleAssignments/ra-01",
			"name": "ra-01",
			"scope": "/subscriptions/sub-111",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5f3-7773c20a72d9",
			"principalId": "azure-user-admin"
		}
	]`)

	roleDefinitionsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5f3-7773c20a72d9",
			"roleName": "User Access Administrator",
			"roleType": "BuiltInRole",
			"description": "Manage user access to Azure resources.",
			"permissions": [
				{
					"actions": ["Microsoft.Authorization/roleAssignments/write"],
					"notActions": []
				}
			]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"roleName": "Owner",
			"roleType": "BuiltInRole",
			"description": "Grants full access to manage all resources.",
			"permissions": [
				{
					"actions": ["*"],
					"notActions": []
				}
			]
		}
	]`)

	err := engine.IngestAzureRBACJSON(roleAssignmentsJSON, roleDefinitionsJSON)
	if err != nil {
		t.Fatalf("failed ingesting Azure RBAC: %v", err)
	}

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("unexpected error finding Azure paths: %v", err)
	}

	foundEscalation := false
	for _, p := range paths {
		if p.Category == "DIRECT_PRIVILEGE_ESCALATION" {
			foundEscalation = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for User Access Administrator, got %s", p.Feasibility)
			}
			if p.Severity != report.SeverityCritical && p.Severity != report.SeverityHigh {
				t.Errorf("expected CRITICAL or HIGH severity, got %s", p.Severity)
			}
		}
	}

	if !foundEscalation {
		t.Errorf("expected DIRECT_PRIVILEGE_ESCALATION for reachable privileged target role in Azure")
	}

	// 2. Unreachable Case: User has roleAssignments/write in sub-999, but Owner is only in sub-111
	engineUnreachable := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	roleAssignmentsUnreachable := []byte(`[
		{
			"id": "/subscriptions/sub-999/providers/Microsoft.Authorization/roleAssignments/ra-999",
			"name": "ra-999",
			"scope": "/subscriptions/sub-999",
			"roleDefinitionId": "/subscriptions/sub-999/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5f3-7773c20a72d9",
			"principalId": "azure-user-isolated"
		}
	]`)
	// User Access Admin at sub-999, but Owner only defined at sub-111
	roleDefsUnreachable := []byte(`[
		{
			"id": "/subscriptions/sub-999/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5f3-7773c20a72d9",
			"roleName": "User Access Administrator",
			"roleType": "BuiltInRole",
			"permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []}]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"roleName": "Owner",
			"roleType": "BuiltInRole",
			"permissions": [{"actions": ["*"], "notActions": []}]
		}
	]`)
	_ = engineUnreachable.IngestAzureRBACJSON(roleAssignmentsUnreachable, roleDefsUnreachable)
	pathsUnreachable, _ := engineUnreachable.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())

	for _, p := range pathsUnreachable {
		if p.Category == "DIRECT_PRIVILEGE_ESCALATION" && p.TargetIdentity.DisplayName == "Owner" {
			t.Errorf("expected no direct privilege escalation to Owner when unreachable across scopes, got path: %+v", p)
		}
	}
}

func TestIAM_Azure_RoleAssignment_vs_RoleDefinition_Write(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	// User A has roleAssignments/write, User B has roleDefinitions/write
	assignmentsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleAssignments/ra-assign-writer",
			"scope": "/subscriptions/sub-111",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/role-assign-mgr",
			"principalId": "user-assign-writer"
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleAssignments/ra-def-writer",
			"scope": "/subscriptions/sub-111",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/role-def-mgr",
			"principalId": "user-def-writer"
		}
	]`)

	defsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/role-assign-mgr",
			"roleName": "Assignment Manager",
			"permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []}]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/role-def-mgr",
			"roleName": "Definition Manager",
			"permissions": [{"actions": ["Microsoft.Authorization/roleDefinitions/write"], "notActions": []}]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/role-owner",
			"roleName": "Owner",
			"permissions": [{"actions": ["*"], "notActions": []}]
		}
	]`)

	err := engine.IngestAzureRBACJSON(assignmentsJSON, defsJSON)
	if err != nil {
		t.Fatalf("failed ingesting Azure RBAC: %v", err)
	}

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("failed finding paths: %v", err)
	}

	foundAssignWrite := false
	foundDefWrite := false

	for _, p := range paths {
		if p.SourceIdentity.ID == "user-assign-writer" {
			for _, perm := range p.Permissions {
				if perm == "Microsoft.Authorization/roleAssignments/write" {
					foundAssignWrite = true
				}
			}
		}
		if p.SourceIdentity.ID == "user-def-writer" {
			for _, perm := range p.Permissions {
				if perm == "Microsoft.Authorization/roleDefinitions/write" {
					foundDefWrite = true
				}
			}
		}
	}

	if !foundAssignWrite {
		t.Errorf("expected path with Microsoft.Authorization/roleAssignments/write for user-assign-writer")
	}
	if !foundDefWrite {
		t.Errorf("expected path with Microsoft.Authorization/roleDefinitions/write for user-def-writer")
	}
}

// -------------------------------------------------------------------------
// 5. Additional Exhaustive Condition Engine Tests (Section 1)
// -------------------------------------------------------------------------

func TestIAM_Condition_AWS_Null_Operator(t *testing.T) {
	// Null: true -> key must NOT be present
	condNullTrue := map[string]map[string]any{
		"Null": {"aws:TokenIssueTime": "true"},
	}
	// Case A: key is absent -> ConditionSatisfied
	st1, _ := EvaluateAWSConditions(condNullTrue, EvaluationContext{ContextKeys: map[string]string{}})
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied when key is absent and Null=true, got %s", st1)
	}
	// Case B: key is present -> ConditionNotSatisfied
	st2, _ := EvaluateAWSConditions(condNullTrue, EvaluationContext{ContextKeys: map[string]string{"aws:TokenIssueTime": "2026-01-01T00:00:00Z"}})
	if st2 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied when key is present and Null=true, got %s", st2)
	}

	// Null: false -> key MUST be present
	condNullFalse := map[string]map[string]any{
		"Null": {"aws:TokenIssueTime": "false"},
	}
	st3, _ := EvaluateAWSConditions(condNullFalse, EvaluationContext{ContextKeys: map[string]string{}})
	if st3 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied when key is absent and Null=false, got %s", st3)
	}
	st4, _ := EvaluateAWSConditions(condNullFalse, EvaluationContext{ContextKeys: map[string]string{"aws:TokenIssueTime": "2026-01-01T00:00:00Z"}})
	if st4 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied when key is present and Null=false, got %s", st4)
	}
}

func TestIAM_Condition_AWS_IfExists_Operator(t *testing.T) {
	condIfExists := map[string]map[string]any{
		"StringEqualsIfExists": {"aws:RequestTag/Environment": "production"},
	}
	// When key is absent, IfExists evaluates to true (satisfied)
	st1, _ := EvaluateAWSConditions(condIfExists, EvaluationContext{ContextKeys: map[string]string{}})
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for StringEqualsIfExists when key is absent, got %s", st1)
	}

	// When key is present and matches -> satisfied
	st2, _ := EvaluateAWSConditions(condIfExists, EvaluationContext{ContextKeys: map[string]string{"aws:RequestTag/Environment": "production"}})
	if st2 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied when key matches, got %s", st2)
	}

	// When key is present but does not match -> not satisfied
	st3, _ := EvaluateAWSConditions(condIfExists, EvaluationContext{ContextKeys: map[string]string{"aws:RequestTag/Environment": "staging"}})
	if st3 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied when key mismatches, got %s", st3)
	}
}

func TestIAM_Condition_AWS_Malformed_and_Unsupported(t *testing.T) {
	// Unsupported operator
	condUnsupported := map[string]map[string]any{
		"BinaryEquals": {"aws:BinaryKey": "AQID"},
	}
	st1, _ := EvaluateAWSConditions(condUnsupported, EvaluationContext{ContextKeys: map[string]string{"aws:BinaryKey": "AQID"}})
	if st1 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for unsupported operator, got %s", st1)
	}

	// Malformed numeric value
	condBadNum := map[string]map[string]any{
		"NumericEquals": {"aws:MultiFactorAuthAge": "not-a-number"},
	}
	st2, _ := EvaluateAWSConditions(condBadNum, EvaluationContext{ContextKeys: map[string]string{"aws:MultiFactorAuthAge": "100"}})
	if st2 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for malformed numeric target, got %s", st2)
	}

	// Malformed CIDR
	condBadCIDR := map[string]map[string]any{
		"IpAddress": {"aws:SourceIp": "invalid-cidr"},
	}
	st3, _ := EvaluateAWSConditions(condBadCIDR, EvaluationContext{ContextKeys: map[string]string{"aws:SourceIp": "192.168.1.1"}})
	if st3 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for malformed CIDR, got %s", st3)
	}
}

func TestIAM_Condition_AWS_Compound(t *testing.T) {
	// Compound: StringEquals AND IpAddress AND NumericLessThan
	condCompound := map[string]map[string]any{
		"StringEquals":    {"aws:RequestedRegion": "us-east-1"},
		"IpAddress":       {"aws:SourceIp": "10.0.0.0/8"},
		"NumericLessThan": {"aws:MultiFactorAuthAge": "7200"},
	}

	// Satisfied when all match
	ctxAllMatch := EvaluationContext{
		ContextKeys: map[string]string{
			"aws:RequestedRegion":    "us-east-1",
			"aws:SourceIp":           "10.5.1.20",
			"aws:MultiFactorAuthAge": "3600",
		},
	}
	st1, _ := EvaluateAWSConditions(condCompound, ctxAllMatch)
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for compound AWS conditions, got %s", st1)
	}

	// Unsatisfied if one fails
	ctxOneFail := EvaluationContext{
		ContextKeys: map[string]string{
			"aws:RequestedRegion":    "us-west-2", // Fails
			"aws:SourceIp":           "10.5.1.20",
			"aws:MultiFactorAuthAge": "3600",
		},
	}
	st2, _ := EvaluateAWSConditions(condCompound, ctxOneFail)
	if st2 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied when one compound constraint fails, got %s", st2)
	}
}

func TestIAM_Condition_GCP_CEL_Compound_and_Malformed(t *testing.T) {
	// Compound CEL expression with &&
	condCompound := &GCPCondition{
		Title:      "SecurityWindow",
		Expression: "request.time < timestamp('2026-12-31T00:00:00Z') && resource.name.startsWith('projects/prod-01/buckets/data')",
	}

	// Satisfied
	ctxAll := EvaluationContext{
		Resource: "projects/prod-01/buckets/data/records.csv",
		ContextKeys: map[string]string{
			"request.time": "2026-06-01T00:00:00Z",
		},
	}
	st1, _ := EvaluateGCPCondition(condCompound, ctxAll)
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for compound GCP CEL, got %s", st1)
	}

	// Unsatisfied
	ctxBadResource := EvaluationContext{
		Resource: "projects/prod-01/buckets/other/records.csv",
		ContextKeys: map[string]string{
			"request.time": "2026-06-01T00:00:00Z",
		},
	}
	st2, _ := EvaluateGCPCondition(condCompound, ctxBadResource)
	if st2 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied for mismatched resource in compound CEL, got %s", st2)
	}

	// Malformed timestamp in expression
	condBadTs := &GCPCondition{
		Title:      "BadTimestamp",
		Expression: "request.time < timestamp('invalid-date')",
	}
	st3, _ := EvaluateGCPCondition(condBadTs, ctxAll)
	if st3 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for malformed CEL timestamp, got %s", st3)
	}

	// Unsupported CEL function/macro
	condUnsupported := &GCPCondition{
		Title:      "UnsupportedMacro",
		Expression: "resource.labels.contains('confidential')",
	}
	st4, _ := EvaluateGCPCondition(condUnsupported, ctxAll)
	if st4 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for unsupported CEL macro, got %s", st4)
	}
}

func TestIAM_Condition_Azure_ABAC_Resource_and_Principal(t *testing.T) {
	// 1. Resource condition
	resCond := "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'finance-vault'"
	ctxRes := EvaluationContext{
		ContextKeys: map[string]string{
			"Microsoft.Storage/storageAccounts/blobServices/containers:name": "finance-vault",
		},
	}
	st1, _ := EvaluateAzureCondition(resCond, ctxRes)
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for Azure resource condition, got %s", st1)
	}

	// 2. Principal condition
	princCond := "@Principal[Claim:department] StringEquals 'secops'"
	ctxPrinc := EvaluationContext{
		ContextKeys: map[string]string{
			"Claim:department": "secops",
		},
	}
	st2, _ := EvaluateAzureCondition(princCond, ctxPrinc)
	if st2 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for Azure principal condition, got %s", st2)
	}

	// 3. Missing context attribute -> Unresolved
	st3, _ := EvaluateAzureCondition(princCond, EvaluationContext{ContextKeys: map[string]string{}})
	if st3 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for missing Azure ABAC attribute, got %s", st3)
	}

	// 4. Malformed syntax -> Unresolved
	st4, _ := EvaluateAzureCondition("bad syntax missing brackets", ctxRes)
	if st4 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for malformed Azure ABAC syntax, got %s", st4)
	}
}

// -------------------------------------------------------------------------
// 6. GCP Impersonation Verification & Negative Tests (Section 2)
// -------------------------------------------------------------------------

func TestIAM_GCP_Impersonation_NegativeScenarios(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	saTarget := "privileged-sa@prod-proj.iam.gserviceaccount.com"
	saOther := "unrelated-sa@prod-proj.iam.gserviceaccount.com"

	// Alice is granted TokenCreator on saTarget
	policy := []byte(`{
		"bindings": [
			{"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:alice@example.com"]},
			{"role": "roles/viewer", "members": ["user:charlie@example.com"]}
		]
	}`)
	_ = engine.IngestGCPIAMPolicyJSON(saTarget, policy)

	// Admin role attached to saTarget
	engine.Graph().AddNode(&IAMNode{ID: "roles/owner", Type: NodeTypeRole, Provider: ProviderGCP, DisplayName: "roles/owner", IsAdmin: true})
	engine.Graph().AddEdge(&IAMEdge{Source: saTarget, Target: "roles/owner", Relation: RelationAssignedTo, Provider: ProviderGCP})

	// Add unrelated SA
	engine.Graph().AddNode(&IAMNode{ID: saOther, Type: NodeTypeServiceAccount, Provider: ProviderGCP, DisplayName: saOther})

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("unexpected error finding paths: %v", err)
	}

	// 1. Alice -> saTarget: MUST be confirmed
	foundAlice := false
	for _, p := range paths {
		if p.SourceIdentity.ID == "alice@example.com" {
			foundAlice = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected Alice path to be FeasibilityConfirmed, got %s", p.Feasibility)
			}
		}
		// 2. Bob (unrelated principal): MUST NOT appear
		if p.SourceIdentity.ID == "bob@example.com" {
			t.Errorf("unrelated principal bob@example.com should not have escalation path")
		}
		// 3. Charlie (missing permission: roles/viewer): MUST NOT appear
		if p.SourceIdentity.ID == "charlie@example.com" {
			t.Errorf("user charlie with only roles/viewer should not have escalation path")
		}
	}
	if !foundAlice {
		t.Errorf("expected confirmed path for Alice on saTarget")
	}
}

func TestIAM_GCP_Impersonation_WorkloadUser_PotentialOnly(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	sa := "worker-sa@prod-proj.iam.gserviceaccount.com"
	// User only has serviceAccountUser (WORKLOAD_USER), not TokenCreator
	policy := []byte(`{
		"bindings": [
			{"role": "roles/iam.serviceAccountUser", "members": ["user:developer@example.com"]}
		]
	}`)
	_ = engine.IngestGCPIAMPolicyJSON(sa, policy)
	engine.Graph().AddNode(&IAMNode{ID: "roles/owner", Type: NodeTypeRole, Provider: ProviderGCP, DisplayName: "roles/owner", IsAdmin: true})
	engine.Graph().AddEdge(&IAMEdge{Source: sa, Target: "roles/owner", Relation: RelationAssignedTo, Provider: ProviderGCP})

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	foundPath := false
	for _, p := range paths {
		if p.SourceIdentity.ID == "developer@example.com" {
			foundPath = true
			if p.Feasibility == FeasibilityConfirmed {
				t.Errorf("expected serviceAccountUser to yield FeasibilityPotential, got %s", p.Feasibility)
			}
			if p.IsExploitable {
				t.Errorf("expected isExploitable = false for workload user attach")
			}
		}
	}
	if !foundPath {
		t.Errorf("expected at least one path found for developer@example.com")
	}
}

// -------------------------------------------------------------------------
// 7. Azure RBAC Scope Semantics Tests (Section 3)
// -------------------------------------------------------------------------

func TestIAM_Azure_CustomRole_AssignableScopes_CrossScope(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	// Custom Role definition with AssignableScopes restricted to rg-finance ONLY
	defsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/custom-finance-admin",
			"roleName": "FinanceAdmin",
			"roleType": "CustomRole",
			"assignableScopes": ["/subscriptions/sub-111/resourceGroups/rg-finance"],
			"permissions": [{"actions": ["*"], "notActions": []}]
		}
	]`)

	// User 1 has roleAssignments/write in rg-finance (within assignable scope) -> Can assign custom-finance-admin
	// User 2 has roleAssignments/write in rg-engineering (outside assignable scope) -> CANNOT assign custom-finance-admin
	assignmentsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/resourceGroups/rg-finance/providers/Microsoft.Authorization/roleAssignments/ra-fin",
			"scope": "/subscriptions/sub-111/resourceGroups/rg-finance",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/manager-fin",
			"principalId": "user-fin-mgr"
		},
		{
			"id": "/subscriptions/sub-111/resourceGroups/rg-engineering/providers/Microsoft.Authorization/roleAssignments/ra-eng",
			"scope": "/subscriptions/sub-111/resourceGroups/rg-engineering",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/manager-eng",
			"principalId": "user-eng-mgr"
		}
	]`)

	managerDefsJSON := []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/manager-fin",
			"roleName": "Finance Manager",
			"permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []}]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/manager-eng",
			"roleName": "Engineering Manager",
			"permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []}]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/custom-finance-admin",
			"roleName": "FinanceAdmin",
			"roleType": "CustomRole",
			"assignableScopes": ["/subscriptions/sub-111/resourceGroups/rg-finance"],
			"permissions": [{"actions": ["*"], "notActions": []}]
		}
	]`)

	_ = engine.IngestAzureRBACJSON(assignmentsJSON, managerDefsJSON)
	_ = defsJSON // referenced above

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())

	foundFin := false
	for _, p := range paths {
		if p.SourceIdentity.ID == "user-fin-mgr" && p.TargetIdentity.DisplayName == "FinanceAdmin" {
			foundFin = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for user in matching scope rg-finance, got %s", p.Feasibility)
			}
		}
		if p.SourceIdentity.ID == "user-eng-mgr" && p.TargetIdentity.DisplayName == "FinanceAdmin" {
			t.Errorf("user-eng-mgr outside assignableScopes should NOT reach FinanceAdmin")
		}
	}
	if !foundFin {
		t.Errorf("expected confirmed path for user-fin-mgr to FinanceAdmin")
	}
}

func TestIAM_Azure_DenyAssignment_BlocksEscalation(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-denied-admin",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-denied-admin",
		ResourceScope: "/subscriptions/sub-111",
	})
	ownerRole := engine.Graph().AddNode(&IAMNode{
		ID:            "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/role-owner",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "Owner",
		ResourceScope: "/subscriptions/sub-111",
		IsAdmin:       true,
	})

	// User has edge granting roleAssignments/write, but edge metadata specifies Deny
	edge := engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      ownerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope":  "/subscriptions/sub-111",
			"effect": "Deny",
		},
	})
	_ = edge

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	for _, p := range paths {
		if p.SourceIdentity.ID == "user-denied-admin" && p.IsExploitable {
			t.Errorf("expected path to be blocked by Deny assignment, got exploitable path: %+v", p)
		}
	}
}

// -------------------------------------------------------------------------
// 8. AWS PassRole Regression & Edge-Case Tests (Section 4)
// -------------------------------------------------------------------------

func TestIAM_AWS_PassRole_MismatchedServiceOperation(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-mismatch",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-mismatch",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/LambdaRoleOnly"
	// Role trust policy trusts lambda.amazonaws.com
	trustJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
	}`)
	_ = engine.IngestAWSTrustPolicyJSON(targetRoleARN, trustJSON)
	rNode, _ := engine.Graph().GetNode(targetRoleARN)
	rNode.IsAdmin = true

	// User has PassRole and ec2:RunInstances, but DOES NOT have lambda:CreateFunction!
	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-mismatch", "pol-mismatch", user.ID, userPolicyJSON, nil)

	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, reason, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityBlocked {
		t.Errorf("expected FeasibilityBlocked due to service operation mismatch, got %s (%s)", feasibility, reason)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false for mismatched service operation")
	}
}

func TestIAM_AWS_PassRole_UnresolvedTrustPolicy(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::111222333444:user/passrole-notrust",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "passrole-notrust",
	})

	targetRoleARN := "arn:aws:iam::111222333444:role/RoleWithoutTrustPolicy"
	// Target role has NO trust policy registered
	rNode := engine.Graph().AddNode(&IAMNode{
		ID:          targetRoleARN,
		Type:        NodeTypeRole,
		Provider:    ProviderAWS,
		DisplayName: "RoleWithoutTrustPolicy",
		IsAdmin:     true,
	})

	userPolicyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-notrust", "pol-notrust", user.ID, userPolicyJSON, nil)

	edge := &IAMEdge{Target: targetRoleARN}
	feasibility, _, isExploitable, _, _ := engine.ValidatePassRoleEscalation(user, rNode, edge, EvaluationContext{})

	if feasibility != FeasibilityInconclusive {
		t.Errorf("expected FeasibilityInconclusive when trust policy is missing, got %s", feasibility)
	}
	if isExploitable {
		t.Errorf("expected isExploitable = false when trust policy is missing")
	}
}

// -------------------------------------------------------------------------
// 9. AWS IfExists & Explicit Deny Semantics Regression Tests
// -------------------------------------------------------------------------

// 1. Positive Allow with missing IfExists key -> Granted
func TestIAM_AWS_IfExists_Allow_MissingKey_Granted(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::123456789012:user/alice",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "alice",
	})

	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-data/*",
				"Condition": {
					"StringEqualsIfExists": {
						"aws:RequestTag/Project": "Felix"
					}
				}
			}
		]
	}`)

	if err := engine.IngestAWSPolicyJSON("pol-ifexists-allow", "pol-ifexists-allow", user.ID, policyJSON, nil); err != nil {
		t.Fatalf("failed ingesting policy: %v", err)
	}

	// Missing context key: aws:RequestTag/Project is absent
	ctxMissing := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::corp-data/file.txt",
		ContextKeys: map[string]string{},
	}

	eval := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:GetObject", "arn:aws:s3:::corp-data/file.txt", ctxMissing)
	if eval.Status != PermissionGranted {
		t.Fatalf("expected PermissionGranted for StringEqualsIfExists when key is missing, got %s: %s", eval.Status, eval.Explanation)
	}
	if eval.ConditionState != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied, got %s", eval.ConditionState)
	}
}

// 2. Negated Deny with missing IfExists key -> Denied
func TestIAM_AWS_IfExists_Deny_MissingKey_Denied(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::123456789012:user/contractor",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "contractor",
	})

	// Policy grants S3 access, but explicitly denies if user is not tagged SecurityAdmin.
	// StringNotEqualsIfExists on missing key evaluates to true in AWS IAM, triggering Deny!
	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowAllS3",
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-vault/*"
			},
			{
				"Sid": "DenyNonAdmins",
				"Effect": "Deny",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-vault/*",
				"Condition": {
					"StringNotEqualsIfExists": {
						"aws:PrincipalTag/Role": "SecurityAdmin"
					}
				}
			}
		]
	}`)

	if err := engine.IngestAWSPolicyJSON("pol-negated-deny", "pol-negated-deny", user.ID, policyJSON, nil); err != nil {
		t.Fatalf("failed ingesting policy: %v", err)
	}

	// Contractor context has NO aws:PrincipalTag/Role tag
	ctxMissingTag := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::corp-vault/secrets.txt",
		ContextKeys: map[string]string{},
	}

	eval := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:GetObject", "arn:aws:s3:::corp-vault/secrets.txt", ctxMissingTag)
	if eval.Status != PermissionDenied || !eval.ExplicitDeny {
		t.Fatalf("expected PermissionDenied (ExplicitDeny) when StringNotEqualsIfExists key is missing, got %s (ExplicitDeny=%v, %s)",
			eval.Status, eval.ExplicitDeny, eval.Explanation)
	}
}

// 3. Negated Deny with matching context -> Not Denied (Allow applies)
func TestIAM_AWS_NegatedDeny_MatchingContext_NotDenied(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::123456789012:user/admin-bob",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "admin-bob",
	})

	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowAllS3",
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-vault/*"
			},
			{
				"Sid": "DenyNonAdmins",
				"Effect": "Deny",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-vault/*",
				"Condition": {
					"StringNotEqualsIfExists": {
						"aws:PrincipalTag/Role": "SecurityAdmin"
					}
				}
			}
		]
	}`)

	if err := engine.IngestAWSPolicyJSON("pol-negated-deny", "pol-negated-deny", user.ID, policyJSON, nil); err != nil {
		t.Fatalf("failed ingesting policy: %v", err)
	}

	// User has tag Role = SecurityAdmin -> StringNotEquals fails -> Deny does NOT apply
	ctxMatching := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::corp-vault/secrets.txt",
		ContextKeys: map[string]string{
			"aws:PrincipalTag/Role": "SecurityAdmin",
		},
	}

	eval := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:GetObject", "arn:aws:s3:::corp-vault/secrets.txt", ctxMatching)
	if eval.Status != PermissionGranted {
		t.Fatalf("expected PermissionGranted for SecurityAdmin matching negated condition, got %s: %s", eval.Status, eval.Explanation)
	}
}

// 4. Negated Deny with nonmatching context -> Denied
func TestIAM_AWS_NegatedDeny_NonMatchingContext_Denied(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::123456789012:user/dev-dave",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "dev-dave",
	})

	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowAllS3",
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-vault/*"
			},
			{
				"Sid": "DenyNonAdmins",
				"Effect": "Deny",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::corp-vault/*",
				"Condition": {
					"StringNotEqualsIfExists": {
						"aws:PrincipalTag/Role": "SecurityAdmin"
					}
				}
			}
		]
	}`)

	if err := engine.IngestAWSPolicyJSON("pol-negated-deny", "pol-negated-deny", user.ID, policyJSON, nil); err != nil {
		t.Fatalf("failed ingesting policy: %v", err)
	}

	// User has tag Role = Developer -> Developer != SecurityAdmin -> StringNotEquals is satisfied -> Deny applies!
	ctxNonMatching := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::corp-vault/secrets.txt",
		ContextKeys: map[string]string{
			"aws:PrincipalTag/Role": "Developer",
		},
	}

	eval := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:GetObject", "arn:aws:s3:::corp-vault/secrets.txt", ctxNonMatching)
	if eval.Status != PermissionDenied || !eval.ExplicitDeny {
		t.Fatalf("expected PermissionDenied (ExplicitDeny) for Developer, got %s: %s", eval.Status, eval.Explanation)
	}
}

// 5. Null true and false semantics + invalid NullIfExists + unsupported IfExists
func TestIAM_AWS_Null_TrueAndFalse_Semantics(t *testing.T) {
	// A: Null: true -> key absent => Satisfied, key present => NotSatisfied
	condNullTrue := map[string]map[string]any{
		"Null": {"aws:TokenIssueTime": "true"},
	}
	st1, _ := EvaluateAWSConditions(condNullTrue, EvaluationContext{ContextKeys: map[string]string{}})
	if st1 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for Null:true on absent key, got %s", st1)
	}
	st2, _ := EvaluateAWSConditions(condNullTrue, EvaluationContext{ContextKeys: map[string]string{"aws:TokenIssueTime": "12345"}})
	if st2 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied for Null:true on present key, got %s", st2)
	}

	// B: Null: false -> key absent => NotSatisfied, key present => Satisfied
	condNullFalse := map[string]map[string]any{
		"Null": {"aws:TokenIssueTime": "false"},
	}
	st3, _ := EvaluateAWSConditions(condNullFalse, EvaluationContext{ContextKeys: map[string]string{}})
	if st3 != ConditionNotSatisfied {
		t.Errorf("expected ConditionNotSatisfied for Null:false on absent key, got %s", st3)
	}
	st4, _ := EvaluateAWSConditions(condNullFalse, EvaluationContext{ContextKeys: map[string]string{"aws:TokenIssueTime": "12345"}})
	if st4 != ConditionSatisfied {
		t.Errorf("expected ConditionSatisfied for Null:false on present key, got %s", st4)
	}

	// C: NullIfExists is invalid and must return ConditionUnresolved
	condNullIfExists := map[string]map[string]any{
		"NullIfExists": {"aws:TokenIssueTime": "true"},
	}
	st5, _ := EvaluateAWSConditions(condNullIfExists, EvaluationContext{ContextKeys: map[string]string{}})
	if st5 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for NullIfExists, got %s", st5)
	}

	// D: Unsupported operator with IfExists must return ConditionUnresolved
	condUnsupportedIfExists := map[string]map[string]any{
		"BinaryEqualsIfExists": {"aws:BinaryKey": "AQID"},
	}
	st6, _ := EvaluateAWSConditions(condUnsupportedIfExists, EvaluationContext{ContextKeys: map[string]string{}})
	if st6 != ConditionUnresolved {
		t.Errorf("expected ConditionUnresolved for BinaryEqualsIfExists on absent key, got %s", st6)
	}
}

// 6. Explicit Deny overriding applicable Allow + Unresolved Deny blocking Allow
func TestIAM_AWS_ExplicitDeny_Overrides_Allow(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	user := engine.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::123456789012:user/eval-user",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "eval-user",
	})

	// Scenario A: Explicit unconditional Deny overrules Allow
	policyA := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::data/*"},
			{"Effect": "Deny", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::data/*"}
		]
	}`)
	_ = engine.IngestAWSPolicyJSON("pol-deny-override", "pol-deny-override", user.ID, policyA, nil)

	ctx := EvaluationContext{
		PrincipalID: user.ID,
		Action:      "s3:PutObject",
		Resource:    "arn:aws:s3:::data/upload.zip",
	}
	evalA := engine.EvaluateEffectivePermissionWithContext(user.ID, "s3:PutObject", "arn:aws:s3:::data/upload.zip", ctx)
	if evalA.Status != PermissionDenied || !evalA.ExplicitDeny {
		t.Errorf("expected Explicit Deny to override Allow, got %s", evalA.Status)
	}

	// Scenario B: Unresolved conditional Deny MUST block applicable Allow
	engineB := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	userB := engineB.Graph().AddNode(&IAMNode{
		ID:          "arn:aws:iam::123456789012:user/user-b",
		Type:        NodeTypeUser,
		Provider:    ProviderAWS,
		DisplayName: "user-b",
	})

	policyB := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::data/*"},
			{
				"Effect": "Deny",
				"Action": "s3:PutObject",
				"Resource": "arn:aws:s3:::data/*",
				"Condition": {
					"StringEquals": {
						"aws:UnprovidedKey": "must-match"
					}
				}
			}
		]
	}`)
	_ = engineB.IngestAWSPolicyJSON("pol-unres-deny", "pol-unres-deny", userB.ID, policyB, nil)

	evalB := engineB.EvaluateEffectivePermissionWithContext(userB.ID, "s3:PutObject", "arn:aws:s3:::data/upload.zip", ctx)
	if evalB.Status != PermissionUnresolved {
		t.Errorf("expected PermissionUnresolved when conditional Deny is unresolved despite Allow, got %s: %s", evalB.Status, evalB.Explanation)
	}
}

// -------------------------------------------------------------------------
// 10. Complete Azure RBAC Scope Hierarchy Regression Tests
// -------------------------------------------------------------------------

// 7. Management Group to Subscription Positive (linked in graph)
func TestIAM_Azure_Hierarchy_MG_to_Subscription_Positive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	mgScope := "/providers/Microsoft.Management/managementGroups/mg-enterprise"
	subScope := "/subscriptions/sub-enterprise-1"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-mg-admin",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-mg-admin",
		ResourceScope: mgScope,
	})

	// Non-privileged manager role that grants role assignment capabilities
	mgManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            mgScope + "/providers/Microsoft.Authorization/roleDefinitions/mg-access-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MGAccessManager",
		ResourceScope: mgScope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	// Role definition assignable at Subscription that represents escalation target
	_ = engine.Graph().AddNode(&IAMNode{
		ID:            subScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-sub-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "SubAdmin",
		ResourceScope: subScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": subScope,
		},
	})

	// Subscription node linked to mg-enterprise
	engine.Graph().AddNode(&IAMNode{
		ID:            subScope,
		Type:          NodeTypeSubscription,
		Provider:      ProviderAzure,
		DisplayName:   "Enterprise Subscription 1",
		ResourceScope: subScope,
		Metadata: map[string]string{
			"management_group": "mg-enterprise",
		},
	})

	// User has roleAssignments/write at MG scope via mgManagerRole
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      mgManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": mgScope,
		},
	})

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("unexpected error finding paths: %v", err)
	}

	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "SubAdmin" {
			found = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for linked MG to Subscription, got %s", p.Feasibility)
			}
		}
	}
	if !found {
		t.Fatalf("expected escalation path found from MG admin to SubAdmin")
	}
}

// 8. Management Group to Subscription Unlinked -> Yields FeasibilityPotential
func TestIAM_Azure_Hierarchy_MG_Unlinked_YieldsPotential(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	mgScope := "/providers/Microsoft.Management/managementGroups/mg-isolated"
	subScope := "/subscriptions/sub-unlinked-999"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-mg-unlinked",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-mg-unlinked",
		ResourceScope: mgScope,
	})

	mgManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            mgScope + "/providers/Microsoft.Authorization/roleDefinitions/isolated-mg-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "IsolatedMGManager",
		ResourceScope: mgScope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            subScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-sub-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "SubAdminUnlinked",
		ResourceScope: subScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": subScope,
		},
	})

	// Subscription node has NO management_group metadata and NO graph edges to MG
	engine.Graph().AddNode(&IAMNode{
		ID:            subScope,
		Type:          NodeTypeSubscription,
		Provider:      ProviderAzure,
		DisplayName:   "Unlinked Subscription",
		ResourceScope: subScope,
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      mgManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": mgScope,
		},
	})

	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	if err != nil {
		t.Fatalf("unexpected error finding paths: %v", err)
	}

	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "SubAdminUnlinked" {
			found = true
			if p.Feasibility != FeasibilityPotential {
				t.Errorf("expected FeasibilityPotential for unlinked MG to Subscription, got %s", p.Feasibility)
			}
		}
	}
	if !found {
		t.Fatalf("expected potential escalation path for unlinked MG to Subscription")
	}
}

// 9. Subscription to Resource Group Positive
func TestIAM_Azure_Hierarchy_Subscription_to_ResourceGroup_Positive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	subScope := "/subscriptions/sub-corp"
	rgScope := "/subscriptions/sub-corp/resourceGroups/rg-backend"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-sub-admin",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-sub-admin",
		ResourceScope: subScope,
	})

	subManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            subScope + "/providers/Microsoft.Authorization/roleDefinitions/sub-access-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "SubAccessManager",
		ResourceScope: subScope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            rgScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-rg-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "BackendAdmin",
		ResourceScope: rgScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": rgScope,
		},
	})

	// User has roleAssignments/write at Subscription level
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      subManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": subScope,
		},
	})

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "BackendAdmin" {
			found = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for Subscription to ResourceGroup, got %s", p.Feasibility)
			}
		}
	}
	if !found {
		t.Fatalf("expected confirmed escalation path from Subscription admin to ResourceGroup role")
	}
}

// 10. Resource Group to Individual Resource Positive
func TestIAM_Azure_Hierarchy_ResourceGroup_to_IndividualResource_Positive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	rgScope := "/subscriptions/sub-corp/resourceGroups/rg-data"
	resScope := "/subscriptions/sub-corp/resourceGroups/rg-data/providers/Microsoft.Compute/virtualMachines/vm-db"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-rg-admin",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-rg-admin",
		ResourceScope: rgScope,
	})

	rgManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            rgScope + "/providers/Microsoft.Authorization/roleDefinitions/rg-access-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "RGAccessManager",
		ResourceScope: rgScope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            resScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-vm-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "VMDBAdmin",
		ResourceScope: resScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": resScope,
		},
	})

	// User has roleAssignments/write at Resource Group level
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      rgManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": rgScope,
		},
	})

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "VMDBAdmin" {
			found = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for ResourceGroup to Resource, got %s", p.Feasibility)
			}
		}
	}
	if !found {
		t.Fatalf("expected confirmed escalation path from ResourceGroup admin to Individual Resource role")
	}
}

// 11. Sibling Resource Groups No Inheritance (Negative)
func TestIAM_Azure_Hierarchy_SiblingResourceGroups_NoInheritance_Negative(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	rgAlpha := "/subscriptions/sub-corp/resourceGroups/rg-alpha"
	rgBeta := "/subscriptions/sub-corp/resourceGroups/rg-beta"

	userAlpha := engine.Graph().AddNode(&IAMNode{
		ID:            "user-alpha-mgr",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-alpha-mgr",
		ResourceScope: rgAlpha,
	})

	alphaManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            rgAlpha + "/providers/Microsoft.Authorization/roleDefinitions/alpha-access-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "AlphaAccessManager",
		ResourceScope: rgAlpha,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            rgBeta + "/providers/Microsoft.Authorization/roleDefinitions/custom-beta-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "BetaAdmin",
		ResourceScope: rgBeta,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": rgBeta,
		},
	})

	// User in rg-alpha has write permission in rg-alpha ONLY
	engine.Graph().AddEdge(&IAMEdge{
		Source:      userAlpha.ID,
		Target:      alphaManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": rgAlpha,
		},
	})

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	for _, p := range paths {
		if p.SourceIdentity.ID == userAlpha.ID && p.TargetIdentity.DisplayName == "BetaAdmin" {
			t.Fatalf("user in rg-alpha must NOT escalate to role restricted to sibling rg-beta: %+v", p)
		}
	}
}

// 12. Custom Role Resource Level Allowed vs Sibling Resource Denied
func TestIAM_Azure_Hierarchy_CustomRole_ResourceLevel_Allowed_vs_SiblingDenied(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	vm1Scope := "/subscriptions/sub-corp/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1"
	vm2Scope := "/subscriptions/sub-corp/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-2"

	user1 := engine.Graph().AddNode(&IAMNode{
		ID:            "user-vm1-lead",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-vm1-lead",
		ResourceScope: vm1Scope,
	})
	user2 := engine.Graph().AddNode(&IAMNode{
		ID:            "user-vm2-lead",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-vm2-lead",
		ResourceScope: vm2Scope,
	})

	vm1ManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            vm1Scope + "/providers/Microsoft.Authorization/roleDefinitions/vm1-access-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "VM1AccessManager",
		ResourceScope: vm1Scope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	vm2ManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            vm2Scope + "/providers/Microsoft.Authorization/roleDefinitions/vm2-access-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "VM2AccessManager",
		ResourceScope: vm2Scope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	// Custom role restricted to vm-1 only
	_ = engine.Graph().AddNode(&IAMNode{
		ID:            vm1Scope + "/providers/Microsoft.Authorization/roleDefinitions/custom-vm1-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "VM1OnlyAdmin",
		ResourceScope: vm1Scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": vm1Scope,
		},
	})

	// User 1 has assignment write at vm-1
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user1.ID,
		Target:      vm1ManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": vm1Scope,
		},
	})

	// User 2 has assignment write at vm-2 (sibling resource)
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user2.ID,
		Target:      vm2ManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": vm2Scope,
		},
	})

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())

	foundUser1 := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user1.ID && p.TargetIdentity.DisplayName == "VM1OnlyAdmin" {
			foundUser1 = true
			if p.Feasibility != FeasibilityConfirmed {
				t.Errorf("expected FeasibilityConfirmed for user at matching resource vm-1, got %s", p.Feasibility)
			}
		}
		if p.SourceIdentity.ID == user2.ID && p.TargetIdentity.DisplayName == "VM1OnlyAdmin" {
			t.Errorf("user at sibling resource vm-2 must NOT escalate to role restricted to vm-1")
		}
	}
	if !foundUser1 {
		t.Fatalf("expected confirmed escalation path for user1 on vm-1")
	}
}

// 13. Azure Deny Assignment at Parent Scope Blocks Child Escalation
func TestIAM_Azure_Hierarchy_DenyAssignment_InheritsDown(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	subScope := "/subscriptions/sub-deny-test"
	rgScope := "/subscriptions/sub-deny-test/resourceGroups/rg-child"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-blocked-operator",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-blocked-operator",
		ResourceScope: rgScope,
	})

	rgManagerRole := engine.Graph().AddNode(&IAMNode{
		ID:            rgScope + "/providers/Microsoft.Authorization/roleDefinitions/rg-child-manager",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "RGChildManager",
		ResourceScope: rgScope,
		IsAdmin:       false,
		IsPrivileged:  false,
		Metadata: map[string]string{
			"role_type": "CustomRole",
		},
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            rgScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-child-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "ChildAdminRole",
		ResourceScope: rgScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"role_type":         "CustomRole",
			"assignable_scopes": rgScope,
		},
	})

	// User has assignment write at rg-child
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      rgManagerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope": rgScope,
		},
	})

	// User also has a Deny Assignment at parent subscription scope
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      subScope + "/providers/Microsoft.Authorization/denyAssignments/deny-sub-write",
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata: map[string]string{
			"scope":  subScope,
			"effect": "Deny",
		},
	})

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	foundPath := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "ChildAdminRole" {
			foundPath = true
			if p.Feasibility != FeasibilityBlocked {
				t.Errorf("expected FeasibilityBlocked due to parent Deny Assignment, got %s", p.Feasibility)
			}
			if p.IsExploitable {
				t.Errorf("expected IsExploitable = false when blocked by parent Deny Assignment")
			}
		}
	}
	if !foundPath {
		// When opts.IncludeConditionRestricted is false (default), blocked paths may not be returned
		// or if returned must be blocked. Let's verify with IncludeConditionRestricted: true
		opts := DefaultPathFindingOptions()
		opts.IncludeConditionRestricted = true
		pathsBlocked, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
		for _, p := range pathsBlocked {
			if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "ChildAdminRole" {
				if p.Feasibility != FeasibilityBlocked {
					t.Errorf("expected FeasibilityBlocked due to parent Deny Assignment, got %s", p.Feasibility)
				}
			}
		}
	}
}

// -------------------------------------------------------------------------
// 11. Azure Deny Assignment Audit Regression Tests (Section 11)
// -------------------------------------------------------------------------

// 1. Applicable Deny Assignment blocks escalation
func TestIAM_Azure_DenyAssignment_Applicable_BlocksEscalation(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-app-1"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-app-admin",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-app-admin",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/manager-role",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "ManagerRole",
		ResourceScope: scope,
	})

	targetRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-role",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminRole",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})
	_ = targetRole

	// Grant roleAssignments/write
	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Ingest applicable Deny Assignment
	denyJSON := []byte(`[
		{
			"id": "/subscriptions/sub-app-1/providers/Microsoft.Authorization/denyAssignments/deny-write-app",
			"denyAssignmentName": "DenyAppWrite",
			"scope": "/subscriptions/sub-app-1",
			"principals": ["user-app-admin"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	if err := engine.IngestAzureDenyAssignmentsJSON(denyJSON); err != nil {
		t.Fatalf("failed ingesting deny assignment: %v", err)
	}

	opts := DefaultPathFindingOptions()
	opts.IncludeConditionRestricted = true
	paths, err := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	if err != nil {
		t.Fatalf("failed finding paths: %v", err)
	}

	foundBlocked := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminRole" {
			if p.Feasibility == FeasibilityBlocked {
				foundBlocked = true
			}
			if p.IsExploitable {
				t.Errorf("expected isExploitable = false when blocked by Deny Assignment")
			}
		}
	}
	if !foundBlocked {
		t.Fatalf("expected path to TargetAdminRole to be FeasibilityBlocked")
	}
}

// 2. Excluded principal is not blocked
func TestIAM_Azure_DenyAssignment_ExcludedPrincipal_NotBlocked(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-app-2"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-breakglass",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-breakglass",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-2",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "Mgr2",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-2",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdmin2",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Deny assignment targets all users, but explicitly excludes user-breakglass
	denyJSON := []byte(`[
		{
			"id": "deny-with-exclusion",
			"scope": "/subscriptions/sub-app-2",
			"principals": ["*"],
			"excludePrincipals": ["user-breakglass"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	if err := engine.IngestAzureDenyAssignmentsJSON(denyJSON); err != nil {
		t.Fatalf("failed ingesting deny assignment: %v", err)
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	foundConfirmed := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdmin2" {
			if p.Feasibility == FeasibilityConfirmed {
				foundConfirmed = true
			}
		}
	}
	if !foundConfirmed {
		t.Fatalf("expected FeasibilityConfirmed for excluded breakglass principal, but was blocked")
	}
}

// 3. Unrelated principal does not cause a block
func TestIAM_Azure_DenyAssignment_UnrelatedPrincipal_NotBlocked(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-app-3"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-engineer",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-engineer",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-3",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "Mgr3",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-3",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdmin3",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Deny assignment explicitly targets ONLY contractor-bob
	denyJSON := []byte(`[
		{
			"id": "deny-contractors-only",
			"scope": "/subscriptions/sub-app-3",
			"principals": ["contractor-bob"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdmin3" {
			if p.Feasibility == FeasibilityConfirmed {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected user-engineer to NOT be blocked by unrelated contractor deny assignment")
	}
}

// 4. Unrelated action does not cause a block
func TestIAM_Azure_DenyAssignment_UnrelatedAction_NotBlocked(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-app-4"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-action-test",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-action-test",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-4",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "Mgr4",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-4",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdmin4",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Deny assignment denies ONLY Microsoft.Compute/virtualMachines/*
	denyJSON := []byte(`[
		{
			"id": "deny-vm-actions",
			"scope": "/subscriptions/sub-app-4",
			"principals": ["user-action-test"],
			"actions": ["Microsoft.Compute/virtualMachines/*"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdmin4" {
			if p.Feasibility == FeasibilityConfirmed {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected unrelated VM deny assignment to NOT block roleAssignments/write")
	}
}

// 5. notActions correctly excludes an action from the Deny
func TestIAM_Azure_DenyAssignment_NotActions_ExcludesAction(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-app-5"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-notactions",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-notactions",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-5",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "Mgr5",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-5",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdmin5",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Deny specifies actions: Microsoft.Authorization/*, but notActions: Microsoft.Authorization/roleAssignments/write
	denyJSON := []byte(`[
		{
			"id": "deny-auth-except-roleassign",
			"scope": "/subscriptions/sub-app-5",
			"principals": ["user-notactions"],
			"actions": ["Microsoft.Authorization/*"],
			"notActions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdmin5" {
			if p.Feasibility == FeasibilityConfirmed {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected notActions to exempt roleAssignments/write from Deny, but was blocked")
	}
}

// 6. Inherited Deny blocks a descendant scope
func TestIAM_Azure_DenyAssignment_Inherited_BlocksDescendantScope(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	childScope := "/subscriptions/sub-parent/resourceGroups/rg-child"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-child-op",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-child-op",
		ResourceScope: childScope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            childScope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-child",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrChild",
		ResourceScope: childScope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            childScope + "/providers/Microsoft.Authorization/roleDefinitions/child-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "ChildAdmin",
		ResourceScope: childScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": childScope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": childScope},
	})

	// Deny Assignment placed at parent subscription with doNotApplyToChildScopes = false
	denyJSON := []byte(`[
		{
			"id": "deny-parent-sub",
			"scope": "/subscriptions/sub-parent",
			"doNotApplyToChildScopes": false,
			"principals": ["user-child-op"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	opts := DefaultPathFindingOptions()
	opts.IncludeConditionRestricted = true
	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundBlocked := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "ChildAdmin" {
			if p.Feasibility == FeasibilityBlocked {
				foundBlocked = true
			}
		}
	}
	if !foundBlocked {
		t.Fatalf("expected inherited parent Deny Assignment to block descendant scope")
	}
}

// 7. doNotApplyToChildScopes prevents descendant propagation
func TestIAM_Azure_DenyAssignment_DoNotApplyToChildScopes_PreventsPropagation(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	childScope := "/subscriptions/sub-parent-nochild/resourceGroups/rg-free"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-child-free",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-child-free",
		ResourceScope: childScope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            childScope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-free",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrFree",
		ResourceScope: childScope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            childScope + "/providers/Microsoft.Authorization/roleDefinitions/free-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "FreeAdmin",
		ResourceScope: childScope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": childScope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": childScope},
	})

	// Parent Deny specifies doNotApplyToChildScopes: true
	denyJSON := []byte(`[
		{
			"id": "deny-parent-local-only",
			"scope": "/subscriptions/sub-parent-nochild",
			"doNotApplyToChildScopes": true,
			"principals": ["user-child-free"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	foundConfirmed := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "FreeAdmin" {
			if p.Feasibility == FeasibilityConfirmed {
				foundConfirmed = true
			}
		}
	}
	if !foundConfirmed {
		t.Fatalf("expected doNotApplyToChildScopes to prevent propagation to child scope, but was blocked")
	}
}

// 8. Data actions do not incorrectly block management-plane actions
func TestIAM_Azure_DenyAssignment_DataActions_DoNotBlockManagementActions(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-data-test"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-mgmt-operator",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-mgmt-operator",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-mgmt",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrMgmt",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-mgmt-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetMgmtAdmin",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Deny assignment has ONLY dataActions (e.g. blobs, queues, secrets)
	denyJSON := []byte(`[
		{
			"id": "deny-data-plane-only",
			"scope": "/subscriptions/sub-data-test",
			"principals": ["user-mgmt-operator"],
			"actions": [],
			"dataActions": [
				"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
				"Microsoft.KeyVault/vaults/secrets/*"
			]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())
	found := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetMgmtAdmin" {
			if p.Feasibility == FeasibilityConfirmed {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected dataActions to NOT block management-plane roleAssignments/write")
	}
}

// 9. Missing principal or scope information produces an inconclusive result
func TestIAM_Azure_DenyAssignment_MissingPrincipalOrScope_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	validUser := &IAMNode{
		ID:          "user-valid",
		Provider:    ProviderAzure,
		DisplayName: "user-valid",
	}

	// Case A: Missing scope produces inconclusive
	isBlocked, isInconclusive, _ := engine.EvaluateAzureDenyAssignment(validUser, "", "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked || !isInconclusive {
		t.Errorf("expected isInconclusive = true when targetScope is empty, got isBlocked=%v, isInconclusive=%v", isBlocked, isInconclusive)
	}

	// Case B: Missing principal produces inconclusive
	isBlockedB, isInconclusiveB, _ := engine.EvaluateAzureDenyAssignment(nil, "/subscriptions/sub-1", "Microsoft.Authorization/roleAssignments/write", false)
	if isBlockedB || !isInconclusiveB {
		t.Errorf("expected isInconclusive = true when principal is nil, got isBlocked=%v, isInconclusive=%v", isBlockedB, isInconclusiveB)
	}

	// Case C: Deny Assignment has missing scope specification
	denyBadScope := []byte(`[
		{
			"id": "deny-no-scope",
			"scope": "",
			"principals": ["user-valid"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyBadScope)
	isBlockedC, isInconclusiveC, _ := engine.EvaluateAzureDenyAssignment(validUser, "/subscriptions/sub-1", "Microsoft.Authorization/roleAssignments/write", false)
	if isBlockedC || !isInconclusiveC {
		t.Errorf("expected isInconclusive = true when Deny has empty scope, got isBlocked=%v, isInconclusive=%v", isBlockedC, isInconclusiveC)
	}
}

// 10. Role assignment modification vs Role definition modification separation
func TestIAM_Azure_DenyAssignment_RoleAssignment_vs_RoleDefinition_Separation(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())

	scope := "/subscriptions/sub-sep-test"
	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-dual-admin",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-dual-admin",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-dual",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrDual",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-priv-role",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetPrivRole",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata: map[string]string{
			"assignable_scopes": scope,
		},
	})

	// User has BOTH roleAssignments/write AND roleDefinitions/write
	engine.Graph().AddEdge(&IAMEdge{
		Source:   user.ID,
		Target:   managerRole.ID,
		Relation: RelationAssignedTo,
		Provider: ProviderAzure,
		Permissions: []string{
			"Microsoft.Authorization/roleAssignments/write",
			"Microsoft.Authorization/roleDefinitions/write",
		},
		Metadata: map[string]string{"scope": scope},
	})

	// Deny Assignment blocks ONLY roleAssignments/write
	denyJSON := []byte(`[
		{
			"id": "deny-only-role-assignments",
			"scope": "/subscriptions/sub-sep-test",
			"principals": ["user-dual-admin"],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), DefaultPathFindingOptions())

	foundRoleDefWrite := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID {
			for _, perm := range p.Permissions {
				if perm == "Microsoft.Authorization/roleDefinitions/write" {
					if p.Feasibility == FeasibilityConfirmed {
						foundRoleDefWrite = true
					}
				}
				if perm == "Microsoft.Authorization/roleAssignments/write" {
					if p.Feasibility == FeasibilityConfirmed {
						t.Errorf("roleAssignments/write was supposed to be blocked, but was confirmed")
					}
				}
			}
		}
	}
	if !foundRoleDefWrite {
		t.Fatalf("expected roleDefinitions/write escalation path to remain viable despite roleAssignments/write deny")
	}
}

// -------------------------------------------------------------------------
// 7. Azure Deny Assignment Conditions & Schema Verification
// -------------------------------------------------------------------------

// 1. Top-Level Condition: Satisfied condition applies restriction and blocks escalation
func TestIAM_Azure_DenyAssignment_Condition_TopLevel_Satisfied_Blocks(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-cond-1"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-fin-mgr",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-fin-mgr",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-fin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrFin",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-fin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminFin",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Top-level condition restricts deny to users in Finance department
	denyJSON := []byte(`[
		{
			"id": "deny-top-cond-satisfied",
			"scope": "/subscriptions/sub-cond-1",
			"principals": [
				{"id": "user-fin-mgr", "type": "User"}
			],
			"condition": "@Principal[department] StringEquals 'Finance'",
			"conditionVersion": "2.0",
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	opts := DefaultPathFindingOptions()
	opts.IncludeConditionRestricted = true
	opts.Context = EvaluationContext{
		ContextKeys: map[string]string{
			"department": "Finance",
		},
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundBlocked := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminFin" {
			if p.Feasibility == FeasibilityBlocked {
				foundBlocked = true
			}
		}
	}
	if !foundBlocked {
		t.Fatalf("expected satisfied top-level Deny Assignment condition to block escalation")
	}
}

// 2. Top-Level Condition: Unsatisfied condition does not block operation
func TestIAM_Azure_DenyAssignment_Condition_TopLevel_Unsatisfied_NotBlocked(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-cond-2"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-eng-mgr",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-eng-mgr",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-eng",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrEng",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-eng",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminEng",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Top-level condition restricts deny to users in Finance department
	denyJSON := []byte(`[
		{
			"id": "deny-top-cond-unsatisfied",
			"scope": "/subscriptions/sub-cond-2",
			"principals": [
				{"id": "user-eng-mgr", "type": "User"}
			],
			"condition": "@Principal[department] StringEquals 'Finance'",
			"conditionVersion": "2.0",
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	opts := DefaultPathFindingOptions()
	opts.Context = EvaluationContext{
		ContextKeys: map[string]string{
			"department": "Engineering", // Does NOT match 'Finance'
		},
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundConfirmed := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminEng" {
			if p.Feasibility == FeasibilityConfirmed {
				foundConfirmed = true
			}
		}
	}
	if !foundConfirmed {
		t.Fatalf("expected unsatisfied Deny Assignment condition to NOT block escalation (remains Confirmed)")
	}
}

// 3. Top-Level Condition: Unresolved condition (missing context attribute) returns inconclusive / potential
func TestIAM_Azure_DenyAssignment_Condition_TopLevel_Unresolved_MissingContext(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-cond-3"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-unres-mgr",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-unres-mgr",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-unres",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrUnres",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-unres",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminUnres",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	denyJSON := []byte(`[
		{
			"id": "deny-top-cond-unres",
			"scope": "/subscriptions/sub-cond-3",
			"principals": [
				{"id": "user-unres-mgr", "type": "User"}
			],
			"condition": "@Principal[department] StringEquals 'Finance'",
			"conditionVersion": "2.0",
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	// Context does NOT supply 'department' key -> unresolved!
	opts := DefaultPathFindingOptions()
	opts.Context = EvaluationContext{
		ContextKeys: map[string]string{},
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundPotential := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminUnres" {
			if p.Feasibility == FeasibilityPotential {
				foundPotential = true
			}
		}
	}
	if !foundPotential {
		t.Fatalf("expected unresolved condition to yield FeasibilityPotential (not confirmed, not blocked)")
	}
}

// 4. Malformed condition syntax returns inconclusive
func TestIAM_Azure_DenyAssignment_Condition_Malformed_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-cond-4"

	user := &IAMNode{
		ID:       "user-malformed",
		Type:     NodeTypeUser,
		Provider: ProviderAzure,
	}

	denyJSON := []byte(`[
		{
			"id": "deny-malformed-cond",
			"scope": "/subscriptions/sub-cond-4",
			"principals": [
				{"id": "user-malformed", "type": "User"}
			],
			"condition": "@Resource[tag StringEquals 'prod'",
			"conditionVersion": "2.0",
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("malformed condition must not be treated as a confirmed block")
	}
	if !isInconclusive {
		t.Fatalf("expected malformed condition to produce inconclusive evaluation")
	}
	if !strings.Contains(reason, "unclosed brackets") {
		t.Errorf("expected syntax error in reason, got: %s", reason)
	}
}

// 5. Unsupported condition syntax returns inconclusive
func TestIAM_Azure_DenyAssignment_Condition_UnsupportedSyntax_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-cond-5"

	user := &IAMNode{
		ID:       "user-unsupp",
		Type:     NodeTypeUser,
		Provider: ProviderAzure,
	}

	denyJSON := []byte(`[
		{
			"id": "deny-unsupp-cond",
			"scope": "/subscriptions/sub-cond-5",
			"principals": [
				{"id": "user-unsupp", "type": "User"}
			],
			"condition": "@CustomMacro[foo] == 'bar'",
			"conditionVersion": "2.0",
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("unsupported condition syntax must not be treated as satisfied")
	}
	if !isInconclusive {
		t.Fatalf("expected unsupported condition syntax to produce inconclusive evaluation")
	}
	if !strings.Contains(reason, "Unsupported Azure ABAC condition syntax") {
		t.Errorf("expected unsupported syntax reason, got: %s", reason)
	}
}

// 6. Unsupported conditionVersion returns inconclusive
func TestIAM_Azure_DenyAssignment_Condition_UnsupportedVersion_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-cond-6"

	user := &IAMNode{
		ID:       "user-unsupp-ver",
		Type:     NodeTypeUser,
		Provider: ProviderAzure,
	}

	denyJSON := []byte(`[
		{
			"id": "deny-unsupp-ver",
			"scope": "/subscriptions/sub-cond-6",
			"principals": [
				{"id": "user-unsupp-ver", "type": "User"}
			],
			"condition": "@Principal[type] StringEquals 'User'",
			"conditionVersion": "3.0",
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("unsupported condition version must not be treated as satisfied")
	}
	if !isInconclusive {
		t.Fatalf("expected unsupported condition version to produce inconclusive evaluation")
	}
	if !strings.Contains(reason, "Unsupported Azure conditionVersion") {
		t.Errorf("expected unsupported conditionVersion reason, got: %s", reason)
	}
}

// 7. Permission-Level Condition: Satisfied condition blocks operation
func TestIAM_Azure_DenyAssignment_PermissionLevel_Condition_Satisfied_Blocks(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-perm-cond-1"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-perm-mgr",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-perm-mgr",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-perm",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrPerm",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-perm",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminPerm",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	denyJSON := []byte(`[
		{
			"id": "deny-perm-cond-sat",
			"scope": "/subscriptions/sub-perm-cond-1",
			"principals": [
				{"id": "user-perm-mgr", "type": "User"}
			],
			"permissions": [
				{
					"actions": ["Microsoft.Authorization/roleAssignments/write"],
					"condition": "@Resource[environment] StringEquals 'production'",
					"conditionVersion": "2.0"
				}
			]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	opts := DefaultPathFindingOptions()
	opts.IncludeConditionRestricted = true
	opts.Context = EvaluationContext{
		ContextKeys: map[string]string{
			"environment": "production",
		},
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundBlocked := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminPerm" {
			if p.Feasibility == FeasibilityBlocked {
				foundBlocked = true
			}
		}
	}
	if !foundBlocked {
		t.Fatalf("expected satisfied permission-level condition to block escalation")
	}
}

// 8. Permission-Level Condition: Unsatisfied condition does not block operation
func TestIAM_Azure_DenyAssignment_PermissionLevel_Condition_Unsatisfied_NotBlocked(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-perm-cond-2"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-perm-free",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-perm-free",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-perm-free",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrPermFree",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-perm-free",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminPermFree",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	denyJSON := []byte(`[
		{
			"id": "deny-perm-cond-unsat",
			"scope": "/subscriptions/sub-perm-cond-2",
			"principals": [
				{"id": "user-perm-free", "type": "User"}
			],
			"permissions": [
				{
					"actions": ["Microsoft.Authorization/roleAssignments/write"],
					"condition": "@Resource[environment] StringEquals 'production'",
					"conditionVersion": "2.0"
				}
			]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	opts := DefaultPathFindingOptions()
	opts.Context = EvaluationContext{
		ContextKeys: map[string]string{
			"environment": "staging", // Does NOT match 'production'
		},
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundConfirmed := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminPermFree" {
			if p.Feasibility == FeasibilityConfirmed {
				foundConfirmed = true
			}
		}
	}
	if !foundConfirmed {
		t.Fatalf("expected unsatisfied permission-level condition to NOT block escalation")
	}
}

// 9. Permission-Level Condition: Unresolved condition yields inconclusive / potential
func TestIAM_Azure_DenyAssignment_PermissionLevel_Condition_Unresolved_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-perm-cond-3"

	user := engine.Graph().AddNode(&IAMNode{
		ID:            "user-perm-unres",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "user-perm-unres",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-perm-unres",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrPermUnres",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-admin-perm-unres",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetAdminPermUnres",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      user.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	denyJSON := []byte(`[
		{
			"id": "deny-perm-cond-unres",
			"scope": "/subscriptions/sub-perm-cond-3",
			"principals": [
				{"id": "user-perm-unres", "type": "User"}
			],
			"permissions": [
				{
					"actions": ["Microsoft.Authorization/roleAssignments/write"],
					"condition": "@Resource[environment] StringEquals 'production'",
					"conditionVersion": "2.0"
				}
			]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	// Context does not provide 'environment'
	opts := DefaultPathFindingOptions()
	opts.Context = EvaluationContext{
		ContextKeys: map[string]string{},
	}

	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)
	foundPotential := false
	for _, p := range paths {
		if p.SourceIdentity.ID == user.ID && p.TargetIdentity.DisplayName == "TargetAdminPermUnres" {
			if p.Feasibility == FeasibilityPotential {
				foundPotential = true
			}
		}
	}
	if !foundPotential {
		t.Fatalf("expected unresolved permission condition to produce FeasibilityPotential")
	}
}

// 10. Realistic ARM REST JSON fixture: SystemDefined All Principals with excludePrincipals
func TestIAM_Azure_DenyAssignment_RealisticARMFixture_AllPrincipals_SystemDefined(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/11111111-2222-3333-4444-555555555555"

	// Standard user
	userStd := engine.Graph().AddNode(&IAMNode{
		ID:            "aaaa1111-0000-0000-0000-000000000001",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "Standard Developer",
		ResourceScope: scope,
	})

	// Breakglass admin user (excluded)
	userBG := engine.Graph().AddNode(&IAMNode{
		ID:            "99999999-9999-9999-9999-999999999999",
		Type:          NodeTypeUser,
		Provider:      ProviderAzure,
		DisplayName:   "Breakglass Emergency User",
		ResourceScope: scope,
	})

	managerRole := engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/mgr-arm-role",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "MgrArmRole",
		ResourceScope: scope,
	})

	_ = engine.Graph().AddNode(&IAMNode{
		ID:            scope + "/providers/Microsoft.Authorization/roleDefinitions/target-arm-admin",
		Type:          NodeTypeRole,
		Provider:      ProviderAzure,
		DisplayName:   "TargetArmAdmin",
		ResourceScope: scope,
		IsAdmin:       true,
		Metadata:      map[string]string{"assignable_scopes": scope},
	})

	engine.Graph().AddEdge(&IAMEdge{
		Source:      userStd.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})
	engine.Graph().AddEdge(&IAMEdge{
		Source:      userBG.ID,
		Target:      managerRole.ID,
		Relation:    RelationAssignedTo,
		Provider:    ProviderAzure,
		Permissions: []string{"Microsoft.Authorization/roleAssignments/write"},
		Metadata:    map[string]string{"scope": scope},
	})

	// Realistic Azure REST ARM JSON fixture with value array and Microsoft.Authorization/denyAssignments type
	armRESTFixture := []byte(`{
		"value": [
			{
				"id": "/subscriptions/11111111-2222-3333-4444-555555555555/providers/Microsoft.Authorization/denyAssignments/deny-arm-prod",
				"type": "Microsoft.Authorization/denyAssignments",
				"name": "deny-arm-prod",
				"properties": {
					"denyAssignmentName": "Deny Write on Role Assignments for All Principals",
					"description": "Enforce strict RBAC lock on roleAssignments except for breakglass",
					"scope": "/subscriptions/11111111-2222-3333-4444-555555555555",
					"doNotApplyToChildScopes": false,
					"principals": [
						{
							"id": "00000000-0000-0000-0000-000000000000",
							"type": "SystemDefined"
						}
					],
					"excludePrincipals": [
						{
							"id": "99999999-9999-9999-9999-999999999999",
							"type": "User"
						}
					],
					"permissions": [
						{
							"actions": [
								"Microsoft.Authorization/roleAssignments/write"
							],
							"notActions": [],
							"dataActions": [],
							"notDataActions": []
						}
					]
				}
			}
		]
	}`)
	if err := engine.IngestAzureDenyAssignmentsJSON(armRESTFixture); err != nil {
		t.Fatalf("failed to ingest realistic Azure REST ARM fixture: %v", err)
	}

	opts := DefaultPathFindingOptions()
	opts.IncludeConditionRestricted = true
	paths, _ := engine.FindPrivilegeEscalationPaths(context.Background(), opts)

	stdBlocked := false
	bgConfirmed := false
	for _, p := range paths {
		if p.TargetIdentity.DisplayName == "TargetArmAdmin" {
			if p.SourceIdentity.ID == userStd.ID && p.Feasibility == FeasibilityBlocked {
				stdBlocked = true
			}
			if p.SourceIdentity.ID == userBG.ID && p.Feasibility == FeasibilityConfirmed {
				bgConfirmed = true
			}
		}
	}
	if !stdBlocked {
		t.Fatalf("expected standard user to be blocked by SystemDefined All Principals deny assignment")
	}
	if !bgConfirmed {
		t.Fatalf("expected excluded breakglass user to remain Confirmed and NOT blocked")
	}
}

// 11. All Principals ID with missing principal type produces an inconclusive evaluation
func TestIAM_Azure_DenyAssignment_AllPrincipals_MissingType_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-missing-type-1"

	user := &IAMNode{
		ID:       "user-anyone",
		Type:     NodeTypeUser,
		Provider: ProviderAzure,
	}

	// 00000000-0000-0000-0000-000000000000 with type omitted / empty
	armFixture := []byte(`{
		"id": "/subscriptions/sub-missing-type-1/providers/Microsoft.Authorization/denyAssignments/deny-bad-type",
		"type": "Microsoft.Authorization/denyAssignments",
		"name": "deny-bad-type",
		"properties": {
			"denyAssignmentName": "Deny Missing Type",
			"scope": "/subscriptions/sub-missing-type-1",
			"principals": [
				{
					"id": "00000000-0000-0000-0000-000000000000",
					"type": ""
				}
			],
			"permissions": [
				{
					"actions": ["Microsoft.Authorization/roleAssignments/write"]
				}
			]
		}
	}`)
	_ = engine.IngestAzureDenyAssignmentsJSON(armFixture)

	isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("All-principals identity with missing type must not blindly block operations")
	}
	if !isInconclusive {
		t.Fatalf("expected missing principal type to yield inconclusive evaluation")
	}
	if !strings.Contains(reason, "missing or incomplete principal type") {
		t.Errorf("expected reason regarding missing principal type, got: %s", reason)
	}
}

// 12. Specific Principal ID with missing type produces an inconclusive evaluation
func TestIAM_Azure_DenyAssignment_SpecificPrincipal_MissingType_Inconclusive(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-missing-type-2"

	targetPrincipalID := "user-specific-guid"
	user := &IAMNode{
		ID:       targetPrincipalID,
		Type:     NodeTypeUser,
		Provider: ProviderAzure,
	}

	armFixture := []byte(`{
		"id": "deny-specific-notype",
		"scope": "/subscriptions/sub-missing-type-2",
		"principals": [
			{
				"id": "user-specific-guid",
				"type": ""
			}
		],
		"actions": ["Microsoft.Authorization/roleAssignments/write"]
	}`)
	_ = engine.IngestAzureDenyAssignmentsJSON(armFixture)

	isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("matching principal with missing type must not be unconditionally blocked")
	}
	if !isInconclusive {
		t.Fatalf("expected missing principal type to yield inconclusive evaluation")
	}
	if !strings.Contains(reason, "missing principal type") {
		t.Errorf("expected reason regarding missing principal type, got: %s", reason)
	}
}

// 13. Display names are informational only and never treated as authoritative principal IDs
func TestIAM_Azure_DenyAssignment_DisplayName_NotAuthoritative(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-display-name-test"

	// User has ID 'user-real-guid' and DisplayName 'user-target-alias'
	user := &IAMNode{
		ID:          "user-real-guid",
		Type:        NodeTypeUser,
		Provider:    ProviderAzure,
		DisplayName: "user-target-alias",
	}

	// Deny assignment targets ID 'user-target-alias'
	denyJSON := []byte(`[
		{
			"id": "deny-name-test",
			"scope": "/subscriptions/sub-display-name-test",
			"principals": [
				{"id": "user-target-alias", "type": "User"}
			],
			"actions": ["Microsoft.Authorization/roleAssignments/write"]
		}
	]`)
	_ = engine.IngestAzureDenyAssignmentsJSON(denyJSON)

	isBlocked, isInconclusive, _ := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("user matched by DisplayName! Display names are informational and must NEVER be used as authoritative principal IDs")
	}
	if isInconclusive {
		t.Fatalf("unrelated principal should be definitively non-blocked, not inconclusive")
	}
}

// 14. Unnormalized convenience aliases in evaluation are rejected as invalid identities
func TestIAM_Azure_DenyAssignment_UnnormalizedAlias_Rejected(t *testing.T) {
	engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
	scope := "/subscriptions/sub-unnorm"

	user := &IAMNode{
		ID:       "user-test-unnorm",
		Type:     NodeTypeUser,
		Provider: ProviderAzure,
	}

	// Manually inject an unnormalized alias directly into engine.azureDenyAssignments
	engine.azureDenyAssignments = []AzureDenyAssignment{
		{
			ID:    "deny-unnormalized-alias",
			Scope: scope,
			Principals: []AzurePrincipal{
				{ID: "*", Type: "User"},
			},
			Actions: []string{"Microsoft.Authorization/roleAssignments/write"},
		},
	}

	isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignment(user, scope, "Microsoft.Authorization/roleAssignments/write", false)
	if isBlocked {
		t.Fatalf("unnormalized alias '*' must not be treated as a valid Azure REST identity")
	}
	if !isInconclusive {
		t.Fatalf("expected unnormalized alias to produce inconclusive evaluation")
	}
	if !strings.Contains(reason, "unnormalized alias") {
		t.Errorf("expected reason regarding unnormalized alias, got: %s", reason)
	}
}

// 15. Deny Assignment ConditionVersion: 2.0 accepted, 1.0/2.1/3.0 rejected as inconclusive, missing version rejected
func TestIAM_Azure_DenyAssignment_ConditionVersion_Matrix(t *testing.T) {
	testCases := []struct {
		name          string
		version       string
		isPermLevel   bool
		expectedIncon bool
		expectedBlock bool
		reasonSubstr  string
	}{
		{
			name:          "TopLevel_Version_2_0_Accepted",
			version:       "2.0",
			isPermLevel:   false,
			expectedIncon: false,
			expectedBlock: true,
			reasonSubstr:  "blocked by Azure Deny Assignment",
		},
		{
			name:          "TopLevel_Version_1_0_Rejected",
			version:       "1.0",
			isPermLevel:   false,
			expectedIncon: true,
			expectedBlock: false,
			reasonSubstr:  "Unsupported Azure conditionVersion \"1.0\"",
		},
		{
			name:          "TopLevel_Version_2_1_Rejected",
			version:       "2.1",
			isPermLevel:   false,
			expectedIncon: true,
			expectedBlock: false,
			reasonSubstr:  "Unsupported Azure conditionVersion \"2.1\"",
		},
		{
			name:          "TopLevel_Version_3_0_Rejected",
			version:       "3.0",
			isPermLevel:   false,
			expectedIncon: true,
			expectedBlock: false,
			reasonSubstr:  "Unsupported Azure conditionVersion \"3.0\"",
		},
		{
			name:          "TopLevel_Version_Missing_Rejected",
			version:       "",
			isPermLevel:   false,
			expectedIncon: true,
			expectedBlock: false,
			reasonSubstr:  "Missing Azure Deny Assignment conditionVersion",
		},
		{
			name:          "PermissionLevel_Version_Missing_Rejected",
			version:       "",
			isPermLevel:   true,
			expectedIncon: true,
			expectedBlock: false,
			reasonSubstr:  "Missing Azure Deny Assignment conditionVersion",
		},
		{
			name:          "PermissionLevel_Version_1_0_Rejected",
			version:       "1.0",
			isPermLevel:   true,
			expectedIncon: true,
			expectedBlock: false,
			reasonSubstr:  "Unsupported Azure conditionVersion \"1.0\"",
		},
		{
			name:          "PermissionLevel_Version_2_0_Accepted",
			version:       "2.0",
			isPermLevel:   true,
			expectedIncon: false,
			expectedBlock: true,
			reasonSubstr:  "condition satisfied",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewIAMPrivilegeGraphEngine(nil, DefaultPathFindingOptions())
			scope := "/subscriptions/sub-matrix-" + tc.name
			user := &IAMNode{
				ID:       "user-matrix",
				Type:     NodeTypeUser,
				Provider: ProviderAzure,
			}

			var da AzureDenyAssignment
			da.ID = "deny-" + tc.name
			da.Scope = scope
			da.Principals = []AzurePrincipal{{ID: "user-matrix", Type: "User"}}

			if tc.isPermLevel {
				da.Permissions = []AzureDenyPermission{
					{
						Actions:          []string{"Microsoft.Authorization/roleAssignments/write"},
						Condition:        "@Principal[department] StringEquals 'Security'",
						ConditionVersion: tc.version,
					},
				}
			} else {
				da.Actions = []string{"Microsoft.Authorization/roleAssignments/write"}
				da.Condition = "@Principal[department] StringEquals 'Security'"
				da.ConditionVersion = tc.version
			}

			engine.azureDenyAssignments = []AzureDenyAssignment{da}

			evalCtx := EvaluationContext{
				PrincipalID: "user-matrix",
				ContextKeys: map[string]string{
					"department": "Security",
				},
			}

			isBlocked, isInconclusive, reason := engine.EvaluateAzureDenyAssignmentWithContext(
				user, scope, "Microsoft.Authorization/roleAssignments/write", false, evalCtx)

			if isBlocked != tc.expectedBlock {
				t.Errorf("[%s] expected isBlocked=%v, got %v (reason: %s)", tc.name, tc.expectedBlock, isBlocked, reason)
			}
			if isInconclusive != tc.expectedIncon {
				t.Errorf("[%s] expected isInconclusive=%v, got %v (reason: %s)", tc.name, tc.expectedIncon, isInconclusive, reason)
			}
			if !strings.Contains(reason, tc.reasonSubstr) {
				t.Errorf("[%s] expected reason to contain %q, got %q", tc.name, tc.reasonSubstr, reason)
			}
		})
	}
}
