package assessment

import (
	"testing"
	"time"
)

func TestRecurrence_Validation(t *testing.T) {
	tests := []struct {
		name        string
		recType     RecurrenceType
		expr        string
		intervalSec int64
		tz          string
		wantErr     bool
	}{
		{"valid once RFC3339", RecurrenceOnce, "2026-11-01T15:00:00Z", 0, "UTC", false},
		{"valid once local", RecurrenceOnce, "2026-11-01 15:00:00", 0, "America/New_York", false},
		{"invalid once empty", RecurrenceOnce, "", 0, "UTC", true},
		{"invalid once garbage", RecurrenceOnce, "not-a-date", 0, "UTC", true},

		{"valid interval seconds", RecurrenceInterval, "", 3600, "UTC", false},
		{"valid interval duration", RecurrenceInterval, "1h30m", 0, "UTC", false},
		{"valid interval @every", RecurrenceInterval, "@every 2h", 0, "UTC", false},
		{"valid interval days", RecurrenceInterval, "2d", 0, "UTC", false},
		{"invalid interval zero", RecurrenceInterval, "", 0, "UTC", true},
		{"invalid interval negative", RecurrenceInterval, "", -10, "UTC", true},
		{"invalid interval text", RecurrenceInterval, "invalid-duration", 0, "UTC", true},

		{"valid daily 24h", RecurrenceDaily, "02:30", 0, "UTC", false},
		{"valid daily AM", RecurrenceDaily, "2:30 AM", 0, "America/New_York", false},
		{"valid daily PM", RecurrenceDaily, "11:45 PM", 0, "UTC", false},
		{"invalid daily hour", RecurrenceDaily, "25:00", 0, "UTC", true},
		{"invalid daily minute", RecurrenceDaily, "12:65", 0, "UTC", true},
		{"invalid daily empty", RecurrenceDaily, "", 0, "UTC", true},

		{"valid weekly Mon", RecurrenceWeekly, "Mon 02:30", 0, "UTC", false},
		{"valid weekly Friday", RecurrenceWeekly, "Friday 18:00", 0, "America/Chicago", false},
		{"invalid weekly day", RecurrenceWeekly, "Funday 02:30", 0, "UTC", true},
		{"invalid weekly format", RecurrenceWeekly, "Mon", 0, "UTC", true},

		{"valid cron simple", RecurrenceCron, "0 2 * * *", 0, "UTC", false},
		{"valid cron complex", RecurrenceCron, "*/15 9-17 1-15 JAN-JUN MON-FRI", 0, "America/New_York", false},
		{"invalid cron field count", RecurrenceCron, "* * * *", 0, "UTC", true},
		{"invalid cron range", RecurrenceCron, "60 * * * *", 0, "UTC", true},
		{"invalid cron step", RecurrenceCron, "*/0 * * * *", 0, "UTC", true},

		{"invalid timezone", RecurrenceDaily, "02:30", 0, "NonExistent/Timezone", true},
		{"invalid recurrence type", "monthly", "1", 0, "UTC", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRecurrence(tc.recType, tc.expr, tc.intervalSec, tc.tz)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateRecurrence() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRecurrence_IntervalNextDue(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

	// 1 hour interval
	next, err := CalculateNextDue(RecurrenceInterval, "1h", 0, "UTC", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Date(2026, 10, 20, 11, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, next)
	}

	// 86400 seconds (1 day)
	next2, err := CalculateNextDue(RecurrenceInterval, "", 86400, "UTC", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected2 := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	if !next2.Equal(expected2) {
		t.Fatalf("expected %v, got %v", expected2, next2)
	}
}

func TestRecurrence_DailyNextDueAndTimezones(t *testing.T) {
	// Reference: 2026-10-20 01:00 UTC
	nowUTC := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)

	// Daily 02:30 in UTC: should be 2026-10-20 02:30 UTC
	next, err := CalculateNextDue(RecurrenceDaily, "02:30", 0, "UTC", nowUTC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exp := time.Date(2026, 10, 20, 2, 30, 0, 0, time.UTC)
	if !next.Equal(exp) {
		t.Fatalf("expected %v, got %v", exp, next)
	}

	// Daily 02:30 in America/New_York (UTC-4 in October):
	// 01:00 UTC on Oct 20 is 21:00 EDT on Oct 19.
	// So 02:30 EDT on Oct 20 is 06:30 UTC on Oct 20!
	nextNY, err := CalculateNextDue(RecurrenceDaily, "02:30", 0, "America/New_York", nowUTC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expNY := time.Date(2026, 10, 20, 6, 30, 0, 0, time.UTC)
	if !nextNY.Equal(expNY) {
		t.Fatalf("expected %v, got %v", expNY, nextNY)
	}
}

func TestRecurrence_WeeklyNextDue(t *testing.T) {
	// 2026-10-20 was a Tuesday
	tue := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

	// Next Wednesday 03:00 UTC (tomorrow)
	nextWed, err := CalculateNextDue(RecurrenceWeekly, "Wed 03:00", 0, "UTC", tue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expWed := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	if !nextWed.Equal(expWed) {
		t.Fatalf("expected %v, got %v", expWed, nextWed)
	}

	// Next Monday 09:00 UTC (6 days later)
	nextMon, err := CalculateNextDue(RecurrenceWeekly, "Mon 09:00", 0, "UTC", tue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expMon := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	if !nextMon.Equal(expMon) {
		t.Fatalf("expected %v, got %v", expMon, nextMon)
	}
}

func TestRecurrence_CronNextDue(t *testing.T) {
	ref := time.Date(2026, 10, 20, 10, 14, 0, 0, time.UTC)

	// Every 15 minutes: next should be 10:15
	next, err := CalculateNextDue(RecurrenceCron, "*/15 * * * *", 0, "UTC", ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exp := time.Date(2026, 10, 20, 10, 15, 0, 0, time.UTC)
	if !next.Equal(exp) {
		t.Fatalf("expected %v, got %v", exp, next)
	}
}

func TestRecurrence_CatchUpPolicy(t *testing.T) {
	// Schedule was due 3 hours ago
	due := time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC)
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

	// "once" catchup: should return runNow=true, and next future due = 11:00 UTC
	nextFuture, runNow := ApplyCatchUp(due, now, RecurrenceInterval, "1h", 0, "UTC", "once")
	if !runNow {
		t.Fatalf("expected runNow=true for 'once' catch-up policy")
	}
	if !nextFuture.After(now) {
		t.Fatalf("expected nextFuture (%v) to be strictly after now (%v)", nextFuture, now)
	}

	// "skip" catchup: should return runNow=false, and next future due = 11:00 UTC
	nextFutureSkip, runNowSkip := ApplyCatchUp(due, now, RecurrenceInterval, "1h", 0, "UTC", "skip")
	if runNowSkip {
		t.Fatalf("expected runNow=false for 'skip' catch-up policy")
	}
	if !nextFutureSkip.After(now) {
		t.Fatalf("expected nextFutureSkip (%v) to be strictly after now (%v)", nextFutureSkip, now)
	}
}
