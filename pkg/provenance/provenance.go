package provenance

import (
	"context"
	"os"
	"time"

	"felix/pkg/policy"
)

// StartOptions contains the contextual inputs available at the beginning of an assessment run.
type StartOptions struct {
	ExecutionID     string
	AssessmentID    string
	AssessmentRef   string
	FelixVersion    string
	BuildID         string
	WorkDir         string
	Config          any
	TargetIdentity  string
	ScopeMode       string
	ApprovedTargets []string
	BaselineRef     string
	EnabledEngines  []string
	Policy          *policy.ThresholdPolicy
}

// CaptureStart initializes the immutable baseline provenance at the beginning of an assessment execution.
func CaptureStart(ctx context.Context, opts StartOptions) *AssessmentProvenance {
	now := time.Now().UTC()
	vcs := ResolveVCSInfo(ctx, opts.WorkDir)

	cfgDigest, sanitizedCfg, _ := ComputeConfigDigest(opts.Config)

	var polIdentity, polDigest, polStatus string
	if opts.Policy != nil {
		polIdentity = opts.Policy.Name
		if polIdentity == "" {
			polIdentity = "default"
		}
		if opts.Policy.Version != "" {
			polIdentity += ":" + opts.Policy.Version
		}
		polDigest = ComputePolicyDigest(opts.Policy)
		polStatus = "CONFIGURED"
	} else {
		polStatus = "NONE"
	}

	felixVer := opts.FelixVersion
	if felixVer == "" {
		felixVer = "2.0.0"
	}

	return &AssessmentProvenance{
		ExecutionID:     opts.ExecutionID,
		AssessmentID:    opts.AssessmentID,
		AssessmentRef:   opts.AssessmentRef,
		FelixVersion:    felixVer,
		BuildID:         opts.BuildID,
		VCS:             vcs,
		StartedAt:       now,
		Status:          "RUNNING",
		ExitCode:        0,
		ConfigDigest:    cfgDigest,
		SanitizedConfig: sanitizedCfg,
		TargetIdentity:  opts.TargetIdentity,
		ScopeMode:       opts.ScopeMode,
		ApprovedTargets: opts.ApprovedTargets,
		PolicyIdentity:  polIdentity,
		PolicyDigest:    polDigest,
		PolicyStatus:    polStatus,
		BaselineRef:     opts.BaselineRef,
		EnabledEngines:  opts.EnabledEngines,
	}
}

// FinalizeOptions contains terminal execution metadata.
type FinalizeOptions struct {
	Status              string // COMPLETED, COMPLETED_WITH_ERRORS, FAILED, CANCELLED, INTERRUPTED
	FailureCategory     string // SUCCESS, SECURITY_VIOLATION, TOOL_FAILURE, INCOMPLETE
	ExitCode            int
	DurationMs          int64
	CoveredCategories   []string
	BaselineExecutionID string
	BaselineSnapshotID  string
	PolicyStatus        string // PASS, FAIL, NONE, ERROR
	Artifacts           []ArtifactProvenance
	IsPartial           bool
	RecoveryAction      string
	RecoveryReason      string
	RecoveredAt         *time.Time
}

// Finalize records the final outcome metadata when assessment execution finishes.
func (p *AssessmentProvenance) Finalize(opts FinalizeOptions) {
	if p == nil {
		return
	}

	now := time.Now().UTC()
	p.CompletedAt = &now
	if opts.DurationMs > 0 {
		p.DurationMs = opts.DurationMs
	} else if !p.StartedAt.IsZero() {
		p.DurationMs = now.Sub(p.StartedAt).Milliseconds()
		if p.DurationMs < 0 {
			p.DurationMs = 0
		}
	}

	if opts.Status != "" {
		p.Status = opts.Status
	}
	p.FailureCategory = opts.FailureCategory
	p.ExitCode = opts.ExitCode

	if len(opts.CoveredCategories) > 0 {
		p.CoveredCategories = opts.CoveredCategories
	}
	if opts.BaselineExecutionID != "" {
		p.BaselineExecutionID = opts.BaselineExecutionID
	}
	if opts.BaselineSnapshotID != "" {
		p.BaselineSnapshotID = opts.BaselineSnapshotID
	}
	if opts.PolicyStatus != "" {
		p.PolicyStatus = opts.PolicyStatus
	}

	p.IsPartial = opts.IsPartial || p.Status == "CANCELLED" || p.Status == "INTERRUPTED" || p.Status == "FAILED" || p.Status == "PARTIAL" || p.Status == "COMPLETED_WITH_ERRORS"
	p.RecoveryAction = opts.RecoveryAction
	p.RecoveryReason = opts.RecoveryReason
	p.RecoveredAt = opts.RecoveredAt

	// Populate digests and file sizes for successfully generated artifacts
	p.Artifacts = make([]ArtifactProvenance, 0, len(opts.Artifacts))
	for _, art := range opts.Artifacts {
		artCopy := art
		if artCopy.Generated && artCopy.Path != "" && artCopy.Digest == "" {
			if data, err := os.ReadFile(artCopy.Path); err == nil {
				artCopy.Digest = ComputeArtifactDigest(data)
				artCopy.SizeBytes = int64(len(data))
			}
		}
		p.Artifacts = append(p.Artifacts, artCopy)
	}
}

// IsComplete returns true only if the assessment concluded cleanly without interruption or partial failure.
func (p *AssessmentProvenance) IsComplete() bool {
	if p == nil {
		return false
	}
	return p.Status == "COMPLETED" && !p.IsPartial && p.CompletedAt != nil
}
