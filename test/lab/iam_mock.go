package lab

// -------------------------------------------------------------------------
// Local IAM Mock Lab & Synthetic Policy Fixtures (Section 12)
// -------------------------------------------------------------------------

// 1. AWS Fixtures

// MockAWS_NormalUserRestrictedJSON returns a least-privilege read-only AWS policy.
func MockAWS_NormalUserRestrictedJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowS3ReadOnly",
				"Effect": "Allow",
				"Action": [
					"s3:GetObject",
					"s3:ListBucket"
				],
				"Resource": [
					"arn:aws:s3:::corporate-public-docs",
					"arn:aws:s3:::corporate-public-docs/*"
				]
			}
		]
	}`)
}

// MockAWS_UserExcessiveIAMJSON returns an IAM policy granting dangerous administrative actions.
func MockAWS_UserExcessiveIAMJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DirectIAMAttachUserPolicy",
				"Effect": "Allow",
				"Action": [
					"iam:AttachUserPolicy",
					"iam:PutUserPolicy"
				],
				"Resource": "*"
			}
		]
	}`)
}

// MockAWS_RoleDangerousTrustJSON returns a role trust policy with overly broad wildcard principal.
func MockAWS_RoleDangerousTrustJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "WildcardTrustPrincipal",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "sts:AssumeRole"
			}
		]
	}`)
}

// MockAWS_CrossAccountRoleAssumptionJSON returns a trust policy permitting external AWS account assumption.
func MockAWS_CrossAccountRoleAssumptionJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "CrossAccountAssumeRole",
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::999888777666:root"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`)
}

// MockAWS_PassRoleScenarioJSON returns a policy granting PassRole to compute services.
func MockAWS_PassRoleScenarioJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowPassRoleToAdmin",
				"Effect": "Allow",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::111222333444:role/PrivilegedEC2ExecutionRole"
			},
			{
				"Sid": "AllowEC2Run",
				"Effect": "Allow",
				"Action": "ec2:RunInstances",
				"Resource": "*"
			}
		]
	}`)
}

// MockAWS_PermissionBoundaryJSON returns an explicit permission boundary policy restricting admin actions.
func MockAWS_PermissionBoundaryJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "StrictBoundaryLimits",
				"Effect": "Allow",
				"Action": [
					"s3:*",
					"dynamodb:*"
				],
				"Resource": "*"
			}
		]
	}`)
}

// MockAWS_ExplicitDenyJSON returns a policy containing an explicit Deny statement overriding allows.
func MockAWS_ExplicitDenyJSON() []byte {
	return []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowEverythingInitially",
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			},
			{
				"Sid": "ExplicitDenyPrivilegeEscalation",
				"Effect": "Deny",
				"Action": [
					"iam:AttachUserPolicy",
					"iam:PutUserPolicy",
					"iam:CreatePolicyVersion",
					"sts:AssumeRole"
				],
				"Resource": "*"
			}
		]
	}`)
}

// 2. Google Cloud IAM Fixtures

// MockGCP_NormalServiceAccountPolicyJSON returns standard restricted viewer permissions.
func MockGCP_NormalServiceAccountPolicyJSON() []byte {
	return []byte(`{
		"bindings": [
			{
				"role": "roles/viewer",
				"members": [
					"serviceAccount:app-monitoring@project-alpha.iam.gserviceaccount.com"
				]
			}
		]
	}`)
}

// MockGCP_ServiceAccountImpersonationPolicyJSON returns impersonation token creator permissions.
func MockGCP_ServiceAccountImpersonationPolicyJSON() []byte {
	return []byte(`{
		"bindings": [
			{
				"role": "roles/iam.serviceAccountTokenCreator",
				"members": [
					"serviceAccount:low-priv-worker@project-alpha.iam.gserviceaccount.com"
				]
			}
		]
	}`)
}

// MockGCP_ExcessiveProjectPermissionsPolicyJSON returns project owner binding on target resource.
func MockGCP_ExcessiveProjectPermissionsPolicyJSON() []byte {
	return []byte(`{
		"bindings": [
			{
				"role": "roles/owner",
				"members": [
					"serviceAccount:deployment-sa@project-alpha.iam.gserviceaccount.com"
				]
			}
		]
	}`)
}

// MockGCP_CrossProjectTrustPolicyJSON returns cross-project service account binding.
func MockGCP_CrossProjectTrustPolicyJSON() []byte {
	return []byte(`{
		"bindings": [
			{
				"role": "roles/resourcemanager.organizationAdmin",
				"members": [
					"serviceAccount:external-sync@partner-project.iam.gserviceaccount.com"
				]
			}
		]
	}`)
}

// MockGCP_ConditionalBindingPolicyJSON returns a role binding constrained by a CEL date/time condition.
func MockGCP_ConditionalBindingPolicyJSON() []byte {
	return []byte(`{
		"bindings": [
			{
				"role": "roles/owner",
				"members": [
					"user:contractor@example.com"
				],
				"condition": {
					"title": "ExpiresOnDate",
					"description": "Temporary contractor access",
					"expression": "request.time < timestamp('2026-12-31T00:00:00Z')"
				}
			}
		]
	}`)
}

// 3. Azure RBAC Fixtures

// MockAzure_NormalUserRBACJSON returns reader role assignment at resource group scope.
func MockAzure_NormalUserRBACJSON() []byte {
	return []byte(`[
		{
			"id": "/subscriptions/sub-111/resourceGroups/rg-web/providers/Microsoft.Authorization/roleAssignments/ra-01",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
			"principalId": "user-reader-001",
			"principalType": "User",
			"scope": "/subscriptions/sub-111/resourceGroups/rg-web"
		}
	]`)
}

// MockAzure_ExcessiveRoleAssignmentJSON returns User Access Administrator role assignment.
func MockAzure_ExcessiveRoleAssignmentJSON() []byte {
	return []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleAssignments/ra-admin-01",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
			"principalId": "user-escalation-target-001",
			"principalType": "User",
			"scope": "/subscriptions/sub-111"
		}
	]`)
}

// MockAzure_ManagedIdentityPrivilegePathJSON returns a managed identity assignment with contributor role.
func MockAzure_ManagedIdentityPrivilegePathJSON() []byte {
	return []byte(`[
		{
			"id": "/subscriptions/sub-111/resourceGroups/rg-core/providers/Microsoft.Authorization/roleAssignments/ra-mi-01",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
			"principalId": "sp-workload-managed-identity",
			"principalType": "ServicePrincipal",
			"scope": "/subscriptions/sub-111"
		}
	]`)
}

// MockAzure_SubscriptionLevelInheritedJSON returns Owner assignment at subscription scope.
func MockAzure_SubscriptionLevelInheritedJSON() []byte {
	return []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleAssignments/ra-sub-owner",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"principalId": "user-sub-owner",
			"principalType": "User",
			"scope": "/subscriptions/sub-111"
		}
	]`)
}

// MockAzure_ConditionalRoleAssignmentJSON returns a role assignment with an ABAC condition string.
func MockAzure_ConditionalRoleAssignmentJSON() []byte {
	return []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleAssignments/ra-cond-01",
			"roleDefinitionId": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"principalId": "user-conditional",
			"principalType": "User",
			"scope": "/subscriptions/sub-111",
			"condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'restricted-container'"
		}
	]`)
}

// MockAzure_StandardRoleDefinitionsJSON returns standard Azure built-in role definitions.
func MockAzure_StandardRoleDefinitionsJSON() []byte {
	return []byte(`[
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
			"roleName": "Owner",
			"description": "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
			"permissions": [
				{
					"actions": ["*"],
					"notActions": [],
					"dataActions": [],
					"notDataActions": []
				}
			]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
			"roleName": "Contributor",
			"description": "Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC.",
			"permissions": [
				{
					"actions": ["*"],
					"notActions": [
						"Microsoft.Authorization/*/Delete",
						"Microsoft.Authorization/*/Write",
						"Microsoft.Authorization/elevateAccess/Action"
					],
					"dataActions": [],
					"notDataActions": []
				}
			]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
			"roleName": "Reader",
			"description": "View all resources, but cannot make changes.",
			"permissions": [
				{
					"actions": ["*/read"],
					"notActions": [],
					"dataActions": [],
					"notDataActions": []
				}
			]
		},
		{
			"id": "/subscriptions/sub-111/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
			"roleName": "User Access Administrator",
			"description": "Manage user access to Azure resources.",
			"permissions": [
				{
					"actions": [
						"Microsoft.Authorization/roleAssignments/*",
						"Microsoft.Authorization/roleDefinitions/*"
					],
					"notActions": [],
					"dataActions": [],
					"notDataActions": []
				}
			]
		}
	]`)
}
