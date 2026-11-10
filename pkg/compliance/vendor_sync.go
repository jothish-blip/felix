package compliance

import (
	"context"

	"felix/pkg/assessment"
)

// VendorSyncService provides a top-level alias to AuditorSyncEngine for compliance platform automation.
type VendorSyncService = AuditorSyncEngine

// NewVendorSyncService instantiates a VendorSyncService backed by a ComplianceStore and optional trusted key registry.
func NewVendorSyncService(store ComplianceStore, trustedKeys ...assessment.TrustedKeyRegistry) *VendorSyncService {
	return NewAuditorSyncEngine(store, trustedKeys...)
}

// QuickSyncAssessment synchronizes an assessment and optional attestation to an external compliance platform.
func QuickSyncAssessment(
	ctx context.Context,
	store ComplianceStore,
	platform CompliancePlatform,
	req *SyncAssessmentRequest,
	cfg ComplianceSyncConfig,
) (*SyncAssessmentResponse, error) {
	engine := NewAuditorSyncEngine(store, cfg.TrustedKeyRegistry)
	return engine.SyncAssessment(ctx, platform, req, cfg)
}
