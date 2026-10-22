package notify

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"
)

// SendNotification attempts immediate, unretried synchronous delivery of a notification.
func SendNotification(ctx context.Context, provider NotificationProvider, notif *Notification) (*DeliveryReceipt, error) {
	if provider == nil {
		return nil, errors.New("notification provider cannot be nil")
	}
	if notif == nil {
		return nil, errors.New("notification cannot be nil")
	}
	receipt, err := provider.Send(ctx, notif)
	if err != nil {
		notif.LastError = err.Error()
		var delivErr *DeliveryError
		if errors.As(err, &delivErr) && delivErr.IsPermanent() {
			notif.DeliveryStatus = DeliveryStatusFailed
		} else {
			notif.DeliveryStatus = DeliveryStatusRetrying
		}
		return nil, err
	}
	notif.DeliveryStatus = DeliveryStatusDelivered
	return receipt, nil
}

// SendWithRetries delivers a notification synchronously with bounded retries and exponential backoff.
// Permanent errors (such as 4xx status codes or SSRF blocks) fail immediately without retrying.
// Transient errors (such as 429 rate limits, 5xx server errors, or network timeouts) back off exponentially.
func SendWithRetries(
	ctx context.Context,
	provider NotificationProvider,
	notif *Notification,
	maxRetries int,
	initialRetryDelay time.Duration,
) (*DeliveryReceipt, error) {
	if provider == nil {
		return nil, errors.New("notification provider cannot be nil")
	}
	if notif == nil {
		return nil, errors.New("notification cannot be nil")
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	if maxRetries > 10 {
		maxRetries = 10
	}
	if initialRetryDelay <= 0 {
		initialRetryDelay = 500 * time.Millisecond
	}

	var lastErr error
	attempts := maxRetries + 1

	for attempt := 1; attempt <= attempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, &DeliveryError{Permanent: false, Message: "context canceled or deadline exceeded", Err: ctx.Err()}
		default:
		}

		notif.AttemptCount = attempt
		receipt, err := provider.Send(ctx, notif)
		if err == nil {
			notif.DeliveryStatus = DeliveryStatusDelivered
			return receipt, nil
		}

		lastErr = err
		var delivErr *DeliveryError
		if errors.As(err, &delivErr) && delivErr.IsPermanent() {
			// Permanent error: abort retry loop immediately
			notif.DeliveryStatus = DeliveryStatusFailed
			notif.LastError = err.Error()
			return nil, err
		}

		if attempt == attempts {
			notif.DeliveryStatus = DeliveryStatusFailed
			notif.LastError = err.Error()
			break
		}

		notif.DeliveryStatus = DeliveryStatusRetrying
		notif.LastError = err.Error()

		// Calculate exponential backoff with jitter
		shift := attempt - 1
		if shift > 6 {
			shift = 6
		}
		backoff := initialRetryDelay * time.Duration(1<<shift)
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}

		// Add jitter up to 25% of backoff
		maxJitterMs := int64(backoff.Milliseconds()) / 4
		if maxJitterMs > 0 {
			if rnd, err := rand.Int(rand.Reader, big.NewInt(maxJitterMs)); err == nil {
				backoff += time.Duration(rnd.Int64()) * time.Millisecond
			}
		}

		select {
		case <-ctx.Done():
			return nil, &DeliveryError{Permanent: false, Message: "context canceled during retry backoff", Err: ctx.Err()}
		case <-time.After(backoff):
		}
	}

	return nil, lastErr
}
