package lab

import (
	"encoding/json"
	"testing"
)

func TestIAMMock_AWS_Fixtures(t *testing.T) {
	// 1. Normal User
	var doc1 map[string]any
	if err := json.Unmarshal(MockAWS_NormalUserRestrictedJSON(), &doc1); err != nil {
		t.Fatalf("failed parsing MockAWS_NormalUserRestrictedJSON: %v", err)
	}

	// 2. Excessive IAM User
	var doc2 map[string]any
	if err := json.Unmarshal(MockAWS_UserExcessiveIAMJSON(), &doc2); err != nil {
		t.Fatalf("failed parsing MockAWS_UserExcessiveIAMJSON: %v", err)
	}

	// 3. Dangerous Trust Policy
	var doc3 map[string]any
	if err := json.Unmarshal(MockAWS_RoleDangerousTrustJSON(), &doc3); err != nil {
		t.Fatalf("failed parsing MockAWS_RoleDangerousTrustJSON: %v", err)
	}

	// 4. Cross-Account Assumption
	var doc4 map[string]any
	if err := json.Unmarshal(MockAWS_CrossAccountRoleAssumptionJSON(), &doc4); err != nil {
		t.Fatalf("failed parsing MockAWS_CrossAccountRoleAssumptionJSON: %v", err)
	}

	// 5. PassRole Scenario
	var doc5 map[string]any
	if err := json.Unmarshal(MockAWS_PassRoleScenarioJSON(), &doc5); err != nil {
		t.Fatalf("failed parsing MockAWS_PassRoleScenarioJSON: %v", err)
	}

	// 6. Permission Boundary
	var doc6 map[string]any
	if err := json.Unmarshal(MockAWS_PermissionBoundaryJSON(), &doc6); err != nil {
		t.Fatalf("failed parsing MockAWS_PermissionBoundaryJSON: %v", err)
	}

	// 7. Explicit Deny
	var doc7 map[string]any
	if err := json.Unmarshal(MockAWS_ExplicitDenyJSON(), &doc7); err != nil {
		t.Fatalf("failed parsing MockAWS_ExplicitDenyJSON: %v", err)
	}
}

func TestIAMMock_GCP_Fixtures(t *testing.T) {
	// 1. Normal Service Account
	var doc1 map[string]any
	if err := json.Unmarshal(MockGCP_NormalServiceAccountPolicyJSON(), &doc1); err != nil {
		t.Fatalf("failed parsing MockGCP_NormalServiceAccountPolicyJSON: %v", err)
	}

	// 2. Impersonation Policy
	var doc2 map[string]any
	if err := json.Unmarshal(MockGCP_ServiceAccountImpersonationPolicyJSON(), &doc2); err != nil {
		t.Fatalf("failed parsing MockGCP_ServiceAccountImpersonationPolicyJSON: %v", err)
	}

	// 3. Excessive Project Policy
	var doc3 map[string]any
	if err := json.Unmarshal(MockGCP_ExcessiveProjectPermissionsPolicyJSON(), &doc3); err != nil {
		t.Fatalf("failed parsing MockGCP_ExcessiveProjectPermissionsPolicyJSON: %v", err)
	}

	// 4. Cross-Project Policy
	var doc4 map[string]any
	if err := json.Unmarshal(MockGCP_CrossProjectTrustPolicyJSON(), &doc4); err != nil {
		t.Fatalf("failed parsing MockGCP_CrossProjectTrustPolicyJSON: %v", err)
	}

	// 5. Conditional Binding
	var doc5 map[string]any
	if err := json.Unmarshal(MockGCP_ConditionalBindingPolicyJSON(), &doc5); err != nil {
		t.Fatalf("failed parsing MockGCP_ConditionalBindingPolicyJSON: %v", err)
	}
}

func TestIAMMock_Azure_Fixtures(t *testing.T) {
	// 1. Normal User
	var doc1 []map[string]any
	if err := json.Unmarshal(MockAzure_NormalUserRBACJSON(), &doc1); err != nil {
		t.Fatalf("failed parsing MockAzure_NormalUserRBACJSON: %v", err)
	}

	// 2. Excessive Role Assignment
	var doc2 []map[string]any
	if err := json.Unmarshal(MockAzure_ExcessiveRoleAssignmentJSON(), &doc2); err != nil {
		t.Fatalf("failed parsing MockAzure_ExcessiveRoleAssignmentJSON: %v", err)
	}

	// 3. Managed Identity
	var doc3 []map[string]any
	if err := json.Unmarshal(MockAzure_ManagedIdentityPrivilegePathJSON(), &doc3); err != nil {
		t.Fatalf("failed parsing MockAzure_ManagedIdentityPrivilegePathJSON: %v", err)
	}

	// 4. Subscription Level
	var doc4 []map[string]any
	if err := json.Unmarshal(MockAzure_SubscriptionLevelInheritedJSON(), &doc4); err != nil {
		t.Fatalf("failed parsing MockAzure_SubscriptionLevelInheritedJSON: %v", err)
	}

	// 5. Conditional Role Assignment
	var doc5 []map[string]any
	if err := json.Unmarshal(MockAzure_ConditionalRoleAssignmentJSON(), &doc5); err != nil {
		t.Fatalf("failed parsing MockAzure_ConditionalRoleAssignmentJSON: %v", err)
	}

	// 6. Role Definitions
	var doc6 []map[string]any
	if err := json.Unmarshal(MockAzure_StandardRoleDefinitionsJSON(), &doc6); err != nil {
		t.Fatalf("failed parsing MockAzure_StandardRoleDefinitionsJSON: %v", err)
	}
}
