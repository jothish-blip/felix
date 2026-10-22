package assessment

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func FuzzAssessmentNormalizeTargetURL(f *testing.F) {
	// Seed corpus: valid and boundary URLs
	f.Add("https://example.com")
	f.Add("http://example.com:8080/api/v1")
	f.Add("http://127.0.0.1:80/index.html")
	f.Add("http://[::1]:8080/test")
	f.Add("")
	f.Add("   ")
	f.Add("javascript:alert(1)")
	f.Add("file:///etc/passwd")
	f.Add("http://user:pass@example.com/protected")
	f.Add("http://example.com:notaport")

	f.Fuzz(func(t *testing.T, raw string) {
		norm, err := NormalizeTargetURL(raw)
		if err != nil {
			return
		}

		if strings.TrimSpace(norm) == "" {
			t.Fatalf("invariant violation: successful normalization returned empty string")
		}

		if !strings.HasPrefix(norm, "http://") && !strings.HasPrefix(norm, "https://") {
			t.Fatalf("invariant violation: normalized URL %q does not start with http:// or https://", norm)
		}

		parsed, parseErr := url.Parse(norm)
		if parseErr != nil {
			t.Fatalf("invariant violation: normalized URL %q failed net/url.Parse: %v", norm, parseErr)
		}

		if parsed.User != nil || strings.Contains(parsed.Host, "@") {
			t.Fatalf("invariant violation: normalized URL %q contains credentials", norm)
		}

		// Idempotency property
		norm2, err2 := NormalizeTargetURL(norm)
		if err2 != nil {
			t.Fatalf("invariant violation: NormalizeTargetURL not idempotent for %q: %v", norm, err2)
		}
		if norm2 != norm {
			t.Fatalf("invariant violation: NormalizeTargetURL changed on second pass: %q != %q", norm, norm2)
		}
	})
}

func FuzzValidateRecurrence(f *testing.F) {
	// Seed corpus: (recTypeStr, expr, intervalSec, tz)
	f.Add("once", "2026-10-22T10:00:00Z", int64(0), "UTC")
	f.Add("interval", "3600", int64(3600), "UTC")
	f.Add("interval", "", int64(60), "UTC")
	f.Add("daily", "02:30", int64(0), "UTC")
	f.Add("weekly", "Mon 02:30", int64(0), "UTC")
	f.Add("cron", "0 2 * * *", int64(0), "UTC")
	f.Add("cron", "*/15 * * * *", int64(0), "UTC")
	f.Add("cron", "0 0 1 1 *", int64(0), "UTC")
	f.Add("cron", "invalid cron", int64(0), "UTC")
	f.Add("invalid", "", int64(0), "")
	f.Add("cron", "* * * * * *", int64(0), "America/New_York")
	f.Add("daily", "25:70", int64(0), "UTC")

	now := time.Unix(1760000000, 0).UTC()

	f.Fuzz(func(t *testing.T, recTypeStr, expr string, intervalSec int64, tz string) {
		recType := RecurrenceType(recTypeStr)

		err := ValidateRecurrence(recType, expr, intervalSec, tz)
		if err != nil {
			return
		}

		// Invariant: If ValidateRecurrence succeeds, CalculateInitialNextDue must execute without panic
		nextDue, calcErr := CalculateInitialNextDue(recType, expr, intervalSec, tz, now)
		if calcErr == nil {
			// Invariant: nextDue must be in UTC
			if nextDue.Location() != time.UTC {
				t.Fatalf("CalculateInitialNextDue returned non-UTC time: %v", nextDue.Location())
			}
		}
	})
}
