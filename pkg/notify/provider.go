package notify

import (
	"context"
	"fmt"
	"time"

	"felix/pkg/secrets"
)

// DeliveryReceipt represents proof and metadata of successful delivery by a provider.
type DeliveryReceipt struct {
	ReceiptID    string    `json:"receipt_id"`
	DeliveredAt  time.Time `json:"delivered_at"`
	StatusCode   int       `json:"status_code"`
	ProviderName string    `json:"provider_name"`
}

// DeliveryError represents an error encountered during notification delivery,
// distinguishing permanent failures from transient (retryable) conditions.
type DeliveryError struct {
	Permanent  bool   `json:"permanent"`
	StatusCode int    `json:"status_code,omitempty"`
	Message    string `json:"message"`
	Err        error  `json:"-"`
}

func (e *DeliveryError) Error() string {
	msg := e.Message
	if msg == "" && e.Err != nil {
		msg = e.Err.Error()
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("delivery error (status %d, permanent=%v): %s", e.StatusCode, e.Permanent, secrets.RedactText(msg))
	}
	return fmt.Sprintf("delivery error (permanent=%v): %s", e.Permanent, secrets.RedactText(msg))
}

func (e *DeliveryError) Unwrap() error {
	return e.Err
}

// IsPermanent returns true if the delivery failure cannot be resolved by retrying.
func (e *DeliveryError) IsPermanent() bool {
	return e.Permanent
}

// NotificationProvider defines the abstraction for sending notifications across transports.
type NotificationProvider interface {
	// Name returns the provider identifier (e.g. "webhook").
	Name() string

	// ValidateConfig checks that the provider configuration is valid, safe, and actionable.
	ValidateConfig() error

	// Send attempts to deliver the notification to the target destination.
	// It must avoid holding database locks, redact sensitive headers or credentials in errors,
	// and return a DeliveryError indicating whether failure is permanent.
	Send(ctx context.Context, notif *Notification) (*DeliveryReceipt, error)
}
