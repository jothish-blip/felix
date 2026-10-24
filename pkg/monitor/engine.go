package monitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/crawler"
	"felix/pkg/notify"
)

// MonitorStatus provides an overview of the monitoring health, baseline, and recent activity.
type MonitorStatus struct {
	TargetID         string            `json:"target_id"`
	HasBaseline      bool              `json:"has_baseline"`
	BaselineID       string            `json:"baseline_id,omitempty"`
	BaselineDate     *time.Time        `json:"baseline_date,omitempty"`
	BaselineRoutes   int               `json:"baseline_routes"`
	LatestSnapshotID string            `json:"latest_snapshot_id,omitempty"`
	LatestScanDate   *time.Time        `json:"latest_scan_date,omitempty"`
	LatestRoutes     int               `json:"latest_routes"`
	TotalSnapshots   int               `json:"total_snapshots"`
	TotalDelivered   int               `json:"total_delivered"`
	ActiveDriftCount int               `json:"active_drift_count"`
	DriftSummary     map[DriftClassification]int `json:"drift_summary,omitempty"`
	StateDirectory   string            `json:"state_directory"`
	MonitoringOn     bool              `json:"monitoring_enabled"`
	ConfiguredHooks  int               `json:"configured_webhooks"`
}

// MonitorEngine coordinates snapshot collection, storage, temporal comparison, and alerting.
type MonitorEngine struct {
	store         SnapshotStore
	deliveryStore *DeliveryStateStore
	notifier      *Notifier
	profile       *api.TargetProfile
	baseDir       string
}

// NewMonitorEngine initializes an engine configured with a target profile and storage location.
func NewMonitorEngine(profile *api.TargetProfile, stateDir string) (*MonitorEngine, error) {
	if strings.TrimSpace(stateDir) == "" {
		if profile != nil && profile.Monitoring != nil && profile.Monitoring.SnapshotDirectory != "" {
			stateDir = profile.Monitoring.SnapshotDirectory
		} else {
			stateDir = "./felix-state"
		}
	}

	retain := DefaultRetainSnapshots
	if profile != nil && profile.Monitoring != nil && profile.Monitoring.RetainSnapshots > 0 {
		retain = profile.Monitoring.RetainSnapshots
	}

	snapStore, err := NewFileSnapshotStore(stateDir, retain)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize snapshot store: %w", err)
	}

	targetID := "default_target"
	if profile != nil {
		if profile.Target.Name != "" {
			targetID = profile.Target.Name
		} else if len(profile.Target.BaseURLs) > 0 {
			targetID = profile.Target.BaseURLs[0]
		}
	}

	delivStore, err := NewDeliveryStateStore(stateDir, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize delivery state store: %w", err)
	}

	var monCfg *api.MonitoringConfig
	if profile != nil && profile.Monitoring != nil {
		monCfg = profile.Monitoring
	}

	notifier := NewNotifier(monCfg, delivStore)

	return &MonitorEngine{
		store:         snapStore,
		deliveryStore: delivStore,
		notifier:      notifier,
		profile:       profile,
		baseDir:       stateDir,
	}, nil
}

// CaptureSnapshot builds and durably saves a new surface snapshot from discovery artifacts.
func (me *MonitorEngine) CaptureSnapshot(
	ctx context.Context,
	candidates []crawler.RouteCandidate,
	recon *api.ReconciliationReport,
	prober *api.ProberReport,
	opts SnapshotBuildOptions,
) (*Snapshot, error) {
	snap := BuildSnapshot(candidates, recon, prober, opts)
	if err := me.store.SaveSnapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("failed to persist snapshot: %w", err)
	}
	return snap, nil
}

// RunDiff compares a snapshot against the target's active baseline and optionally delivers alerts.
func (me *MonitorEngine) RunDiff(ctx context.Context, currentSnap *Snapshot, sendAlerts bool) (*DriftReport, *DeliverySummary, error) {
	if currentSnap == nil {
		return nil, nil, errors.New("cannot run diff with nil snapshot")
	}

	baseline, err := me.store.GetBaseline(ctx, currentSnap.TargetID)
	if err != nil && !errors.Is(err, ErrBaselineNotFound) {
		return nil, nil, fmt.Errorf("failed to retrieve baseline: %w", err)
	}

	driftReport := CompareSnapshots(baseline, currentSnap)

	var deliverySummary *DeliverySummary
	if sendAlerts && me.notifier != nil {
		var delivErr error
		deliverySummary, delivErr = me.notifier.DeliverAlerts(ctx, driftReport)
		if delivErr != nil {
			driftReport.Warnings = append(driftReport.Warnings, fmt.Sprintf("Alert delivery warning: %v", delivErr))
		}
	}

	return driftReport, deliverySummary, nil
}

// GetStatus returns the monitoring status, baseline state, and delivery health for a target.
func (me *MonitorEngine) GetStatus(ctx context.Context, targetID string) (*MonitorStatus, error) {
	status := &MonitorStatus{
		TargetID:       targetID,
		StateDirectory: me.baseDir,
	}

	if me.profile != nil && me.profile.Monitoring != nil {
		status.MonitoringOn = me.profile.Monitoring.Enabled
		status.ConfiguredHooks = len(me.profile.Monitoring.Webhooks)
	}

	// 1. Check baseline
	baseSnap, err := me.store.GetBaseline(ctx, targetID)
	if err == nil && baseSnap != nil {
		status.HasBaseline = true
		status.BaselineID = baseSnap.ID
		status.BaselineDate = &baseSnap.CollectedAt
		status.BaselineRoutes = len(baseSnap.Routes)
	}

	// 2. Check snapshot history
	summaries, err := me.store.ListSnapshots(ctx, targetID)
	if err == nil {
		status.TotalSnapshots = len(summaries)
		if len(summaries) > 0 {
			latest := summaries[0]
			status.LatestSnapshotID = latest.ID
			status.LatestScanDate = &latest.CollectedAt
			status.LatestRoutes = latest.RouteCount
		}
	}

	// 3. Delivery count
	if me.deliveryStore != nil {
		status.TotalDelivered = me.deliveryStore.TotalDeliveredCount()
	}

	// 4. Compute active drift between latest and baseline if both exist
	if status.HasBaseline && status.LatestSnapshotID != "" {
		latestSnap, err := me.store.GetSnapshot(ctx, targetID, status.LatestSnapshotID)
		if err == nil && latestSnap != nil {
			drift := CompareSnapshots(baseSnap, latestSnap)
			status.ActiveDriftCount = drift.TotalEvents
			status.DriftSummary = drift.Summary
		}
	}

	return status, nil
}

// ResetBaseline replaces or establishes the baseline for a target with an audit reason.
func (me *MonitorEngine) ResetBaseline(ctx context.Context, targetID string, snap *Snapshot, reason string) error {
	if snap == nil {
		// Use latest snapshot
		latest, err := me.store.GetLatestSnapshot(ctx, targetID)
		if err != nil {
			return fmt.Errorf("cannot reset baseline: no snapshots found for target %q: %w", targetID, err)
		}
		snap = latest
	}

	return me.store.SetBaseline(ctx, snap, reason)
}

// TestWebhook sends a synthetic test notification through configured webhooks.
func (me *MonitorEngine) TestWebhook(ctx context.Context, webhookID, provider string) (*notify.DeliveryReceipt, error) {
	if me.notifier == nil {
		return nil, errors.New("notifier not configured")
	}
	return me.notifier.SendTestWebhook(ctx, webhookID, provider)
}
