package notify

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"felix/pkg/secrets"
)

const (
	DefaultDispatcherConcurrency = 5
	DefaultDeliveryLeaseDuration = 60 * time.Second
	DefaultInitialRetryDelay     = 2 * time.Second
	DefaultMaxRetryDelay         = 10 * time.Minute
)

// OutboxStore defines the persistence contract required by the OutboxDispatcher.
type OutboxStore interface {
	ClaimPendingNotifications(workerID string, limit int, leaseDuration time.Duration, now time.Time) ([]*Notification, error)
	MarkNotificationDelivered(id, workerID string, deliveredAt time.Time) error
	MarkNotificationFailed(id, workerID string, errStr string, nextRetryAt *time.Time, permanent bool) error
	ReclaimExpiredNotificationLeases(now time.Time) (int, error)
}

// DispatcherConfig configures the outbox dispatcher worker pool and retry behavior.
type DispatcherConfig struct {
	WorkerID          string
	Concurrency       int
	LeaseDuration     time.Duration
	InitialRetryDelay time.Duration
	MaxRetryDelay     time.Duration
}

// OutboxDispatcher coordinates claiming and delivery of queued outbox notifications.
type OutboxDispatcher struct {
	store    OutboxStore
	provider NotificationProvider
	cfg      DispatcherConfig

	mu       sync.Mutex
	activeWg sync.WaitGroup
	running  bool
	stopCh   chan struct{}
}

// NewOutboxDispatcher constructs an OutboxDispatcher.
func NewOutboxDispatcher(store OutboxStore, provider NotificationProvider, cfg DispatcherConfig) *OutboxDispatcher {
	if cfg.WorkerID == "" {
		cfg.WorkerID = fmt.Sprintf("worker_%d", time.Now().UnixNano())
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultDispatcherConcurrency
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = DefaultDeliveryLeaseDuration
	}
	if cfg.InitialRetryDelay <= 0 {
		cfg.InitialRetryDelay = DefaultInitialRetryDelay
	}
	if cfg.MaxRetryDelay <= 0 {
		cfg.MaxRetryDelay = DefaultMaxRetryDelay
	}

	return &OutboxDispatcher{
		store:    store,
		provider: provider,
		cfg:      cfg,
		stopCh:   make(chan struct{}),
	}
}

// DispatchBatch claims and delivers a single batch of pending notifications up to limit.
// Returns the number of successfully delivered notifications.
func (d *OutboxDispatcher) DispatchBatch(ctx context.Context, limit int) (int, error) {
	if d.store == nil || d.provider == nil {
		return 0, errors.New("outbox store and notification provider must be configured")
	}
	if limit <= 0 {
		limit = 10
	}

	now := time.Now().UTC()
	// 1. Reclaim any expired leases before claiming
	_, _ = d.store.ReclaimExpiredNotificationLeases(now)

	// 2. Claim pending notifications
	claimed, err := d.store.ClaimPendingNotifications(d.cfg.WorkerID, limit, d.cfg.LeaseDuration, now)
	if err != nil {
		return 0, fmt.Errorf("failed to claim pending notifications: %w", err)
	}

	if len(claimed) == 0 {
		return 0, nil
	}

	// 3. Process concurrently with bounded concurrency
	concurrency := d.cfg.Concurrency
	if concurrency > len(claimed) {
		concurrency = len(claimed)
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var deliveredCount int
	var countMu sync.Mutex

	for _, notif := range claimed {
		wg.Add(1)
		sem <- struct{}{}

		go func(n *Notification) {
			defer wg.Done()
			defer func() { <-sem }()

			delivered := d.deliverOne(ctx, n)
			if delivered {
				countMu.Lock()
				deliveredCount++
				countMu.Unlock()
			}
		}(notif)
	}

	wg.Wait()
	return deliveredCount, nil
}

// deliverOne attempts delivery of a single notification and updates store state.
func (d *OutboxDispatcher) deliverOne(ctx context.Context, n *Notification) bool {
	receipt, sendErr := d.provider.Send(ctx, n)
	if sendErr == nil {
		deliveredAt := time.Now().UTC()
		if receipt != nil && !receipt.DeliveredAt.IsZero() {
			deliveredAt = receipt.DeliveredAt
		}
		_ = d.store.MarkNotificationDelivered(n.ID, d.cfg.WorkerID, deliveredAt)
		return true
	}

	// Handle delivery error
	now := time.Now().UTC()
	errStr := secrets.RedactText(sendErr.Error())
	newAttemptCount := n.AttemptCount + 1

	var delivErr *DeliveryError
	isPermanent := false
	if errors.As(sendErr, &delivErr) {
		isPermanent = delivErr.IsPermanent()
	}

	if isPermanent || newAttemptCount >= n.MaxAttempts {
		// Terminal failure: mark FAILED permanently
		_ = d.store.MarkNotificationFailed(n.ID, d.cfg.WorkerID, errStr, nil, true)
		return false
	}

	// Transient failure: calculate bounded exponential backoff with jitter
	backoff := d.calculateBackoff(newAttemptCount)
	nextRetry := now.Add(backoff)
	_ = d.store.MarkNotificationFailed(n.ID, d.cfg.WorkerID, errStr, &nextRetry, false)
	return false
}

// calculateBackoff computes bounded exponential backoff with jitter.
func (d *OutboxDispatcher) calculateBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 10 {
		shift = 10
	}
	multiplier := 1 << shift
	backoff := d.cfg.InitialRetryDelay * time.Duration(multiplier)
	if backoff > d.cfg.MaxRetryDelay {
		backoff = d.cfg.MaxRetryDelay
	}

	// Add jitter (up to 25% of backoff)
	maxJitterMs := int64(backoff.Milliseconds()) / 4
	if maxJitterMs > 0 {
		if rnd, err := rand.Int(rand.Reader, big.NewInt(maxJitterMs)); err == nil {
			backoff += time.Duration(rnd.Int64()) * time.Millisecond
		}
	}

	return backoff
}

// Start begins a background polling loop for the outbox dispatcher.
func (d *OutboxDispatcher) Start(ctx context.Context, pollInterval time.Duration) {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.stopCh = make(chan struct{})
	d.mu.Unlock()

	if pollInterval <= 0 {
		pollInterval = 3 * time.Second
	}

	d.activeWg.Add(1)
	go func() {
		defer d.activeWg.Done()
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCh:
				return
			case <-ticker.C:
				_, _ = d.DispatchBatch(ctx, d.cfg.Concurrency*2)
			}
		}
	}()
}

// Stop gracefully shuts down the background dispatcher.
func (d *OutboxDispatcher) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	close(d.stopCh)
	d.mu.Unlock()

	d.activeWg.Wait()
}
