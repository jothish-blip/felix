package assessment

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ValidateRecurrence validates that recurrence parameters are semantically valid and parseable.
func ValidateRecurrence(recType RecurrenceType, expr string, intervalSec int64, tz string) error {
	loc, err := LoadLocation(tz)
	if err != nil {
		return err
	}

	switch recType {
	case RecurrenceOnce:
		if strings.TrimSpace(expr) == "" {
			return fmt.Errorf("%w: once recurrence requires an execution timestamp in expr", ErrScheduleInvalid)
		}
		if _, err := parseTimestamp(expr, loc); err != nil {
			return fmt.Errorf("%w: invalid timestamp for once recurrence: %v", ErrScheduleInvalid, err)
		}
		return nil

	case RecurrenceInterval:
		sec, err := parseIntervalSeconds(expr, intervalSec)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrScheduleInvalid, err)
		}
		if sec <= 0 {
			return fmt.Errorf("%w: interval must be greater than zero", ErrScheduleInvalid)
		}
		return nil

	case RecurrenceDaily:
		if strings.TrimSpace(expr) == "" {
			return fmt.Errorf("%w: daily recurrence requires a time-of-day expression (e.g. '02:30')", ErrScheduleInvalid)
		}
		if _, _, _, err := parseTimeOfDay(expr); err != nil {
			return fmt.Errorf("%w: invalid time of day for daily recurrence: %v", ErrScheduleInvalid, err)
		}
		return nil

	case RecurrenceWeekly:
		if strings.TrimSpace(expr) == "" {
			return fmt.Errorf("%w: weekly recurrence requires a day and time expression (e.g. 'Mon 02:30')", ErrScheduleInvalid)
		}
		if _, _, _, _, err := parseWeeklyExpr(expr); err != nil {
			return fmt.Errorf("%w: invalid weekly recurrence expression: %v", ErrScheduleInvalid, err)
		}
		return nil

	case RecurrenceCron:
		if strings.TrimSpace(expr) == "" {
			return fmt.Errorf("%w: cron recurrence requires a 5-part cron expression", ErrScheduleInvalid)
		}
		if _, err := parseCronExpression(expr); err != nil {
			return fmt.Errorf("%w: invalid cron expression: %v", ErrScheduleInvalid, err)
		}
		return nil

	default:
		return fmt.Errorf("%w: unsupported recurrence type %q (supported: once, interval, daily, weekly, cron)", ErrScheduleInvalid, recType)
	}
}

// LoadLocation loads a time.Location by IANA name, defaulting to UTC if empty.
func LoadLocation(tz string) (*time.Location, error) {
	trimmed := strings.TrimSpace(tz)
	if trimmed == "" || strings.EqualFold(trimmed, "UTC") {
		return time.UTC, nil
	}
	if strings.EqualFold(trimmed, "Local") {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone %q: %w", trimmed, err)
	}
	return loc, nil
}

// CalculateInitialNextDue computes the first occurrence due at or after now.
func CalculateInitialNextDue(recType RecurrenceType, expr string, intervalSec int64, tz string, now time.Time) (time.Time, error) {
	loc, err := LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}

	switch recType {
	case RecurrenceOnce:
		t, err := parseTimestamp(expr, loc)
		if err != nil {
			return time.Time{}, err
		}
		return t.UTC(), nil

	case RecurrenceInterval:
		sec, err := parseIntervalSeconds(expr, intervalSec)
		if err != nil {
			return time.Time{}, err
		}
		return now.Add(time.Duration(sec) * time.Second).UTC(), nil

	case RecurrenceDaily:
		h, m, s, err := parseTimeOfDay(expr)
		if err != nil {
			return time.Time{}, err
		}
		nowLoc := now.In(loc)
		candidate := time.Date(nowLoc.Year(), nowLoc.Month(), nowLoc.Day(), h, m, s, 0, loc)
		if !candidate.After(nowLoc) {
			candidate = candidate.AddDate(0, 0, 1)
		}
		return candidate.UTC(), nil

	case RecurrenceWeekly:
		wd, h, m, s, err := parseWeeklyExpr(expr)
		if err != nil {
			return time.Time{}, err
		}
		nowLoc := now.In(loc)
		daysUntil := (int(wd) - int(nowLoc.Weekday()) + 7) % 7
		candidate := time.Date(nowLoc.Year(), nowLoc.Month(), nowLoc.Day(), h, m, s, 0, loc).AddDate(0, 0, daysUntil)
		if !candidate.After(nowLoc) {
			candidate = candidate.AddDate(0, 0, 7)
		}
		return candidate.UTC(), nil

	case RecurrenceCron:
		cron, err := parseCronExpression(expr)
		if err != nil {
			return time.Time{}, err
		}
		return cron.Next(now, loc)

	default:
		return time.Time{}, fmt.Errorf("%w: unsupported recurrence type %q", ErrScheduleInvalid, recType)
	}
}

// CalculateNextDue computes the next occurrence strictly after the reference time.
func CalculateNextDue(recType RecurrenceType, expr string, intervalSec int64, tz string, after time.Time) (time.Time, error) {
	loc, err := LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}

	switch recType {
	case RecurrenceOnce:
		// Once schedules have no subsequent occurrence
		return time.Time{}, nil

	case RecurrenceInterval:
		sec, err := parseIntervalSeconds(expr, intervalSec)
		if err != nil {
			return time.Time{}, err
		}
		return after.Add(time.Duration(sec) * time.Second).UTC(), nil

	case RecurrenceDaily:
		h, m, s, err := parseTimeOfDay(expr)
		if err != nil {
			return time.Time{}, err
		}
		afterLoc := after.In(loc)
		candidate := time.Date(afterLoc.Year(), afterLoc.Month(), afterLoc.Day(), h, m, s, 0, loc)
		if !candidate.After(afterLoc) {
			candidate = candidate.AddDate(0, 0, 1)
		}
		return candidate.UTC(), nil

	case RecurrenceWeekly:
		wd, h, m, s, err := parseWeeklyExpr(expr)
		if err != nil {
			return time.Time{}, err
		}
		afterLoc := after.In(loc)
		daysUntil := (int(wd) - int(afterLoc.Weekday()) + 7) % 7
		candidate := time.Date(afterLoc.Year(), afterLoc.Month(), afterLoc.Day(), h, m, s, 0, loc).AddDate(0, 0, daysUntil)
		if !candidate.After(afterLoc) {
			candidate = candidate.AddDate(0, 0, 7)
		}
		return candidate.UTC(), nil

	case RecurrenceCron:
		cron, err := parseCronExpression(expr)
		if err != nil {
			return time.Time{}, err
		}
		return cron.Next(after, loc)

	default:
		return time.Time{}, fmt.Errorf("%w: unsupported recurrence type %q", ErrScheduleInvalid, recType)
	}
}

// ApplyCatchUp applies the defined catch-up policy to a schedule whose next due time is in the past.
// Returns the next future due time, and whether a catch-up execution should be dispatched now.
func ApplyCatchUp(nextDue time.Time, now time.Time, recType RecurrenceType, expr string, intervalSec int64, tz string, policy string) (time.Time, bool) {
	if nextDue.After(now) {
		return nextDue, false
	}

	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "skip" {
		// Advance nextDue until it is strictly in the future without dispatching
		cur := nextDue
		for !cur.After(now) {
			next, err := CalculateNextDue(recType, expr, intervalSec, tz, cur)
			if err != nil || next.IsZero() || !next.After(cur) {
				return now.Add(1 * time.Hour), false
			}
			cur = next
		}
		return cur, false
	}

	// Default: "once" (bounded catch-up)
	// Dispatch at most once for missed periods, advancing nextDue to the next future occurrence
	cur := nextDue
	for !cur.After(now) {
		next, err := CalculateNextDue(recType, expr, intervalSec, tz, cur)
		if err != nil || next.IsZero() || !next.After(cur) {
			break
		}
		cur = next
	}
	return cur, true
}

// -----------------------------------------------------------------------------
// INTERNAL PARSING HELPERS
// -----------------------------------------------------------------------------

func parseTimestamp(expr string, loc *time.Location) (time.Time, error) {
	clean := strings.TrimSpace(expr)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, clean, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp %q", clean)
}

func parseIntervalSeconds(expr string, intervalSec int64) (int64, error) {
	if intervalSec > 0 {
		return intervalSec, nil
	}
	clean := strings.TrimSpace(expr)
	clean = strings.TrimPrefix(clean, "@every ")
	clean = strings.TrimSpace(clean)

	// Check if integer seconds
	if s, err := strconv.ParseInt(clean, 10, 64); err == nil && s > 0 {
		return s, nil
	}

	// Support day format e.g. "1d", "2d"
	if strings.HasSuffix(clean, "d") || strings.HasSuffix(clean, "D") {
		daysStr := clean[:len(clean)-1]
		if d, err := strconv.ParseInt(daysStr, 10, 64); err == nil && d > 0 {
			return d * 86400, nil
		}
	}

	d, err := time.ParseDuration(clean)
	if err != nil {
		return 0, fmt.Errorf("invalid interval duration %q: %w", clean, err)
	}
	sec := int64(d.Seconds())
	if sec <= 0 {
		return 0, fmt.Errorf("interval duration %q resolves to non-positive seconds", clean)
	}
	return sec, nil
}

func parseTimeOfDay(expr string) (int, int, int, error) {
	clean := strings.ToUpper(strings.TrimSpace(expr))

	// Handle 12-hour AM/PM formats
	isPM := strings.HasSuffix(clean, "PM")
	isAM := strings.HasSuffix(clean, "AM")
	if isPM || isAM {
		clean = strings.TrimSpace(clean[:len(clean)-2])
		parts := strings.Split(clean, ":")
		if len(parts) < 2 {
			return 0, 0, 0, fmt.Errorf("expected HH:MM AM/PM, got %q", expr)
		}
		h, err := strconv.Atoi(parts[0])
		if err != nil || h < 1 || h > 12 {
			return 0, 0, 0, fmt.Errorf("invalid hour %q", parts[0])
		}
		m, err := strconv.Atoi(parts[1])
		if err != nil || m < 0 || m > 59 {
			return 0, 0, 0, fmt.Errorf("invalid minute %q", parts[1])
		}
		s := 0
		if len(parts) >= 3 {
			s, _ = strconv.Atoi(parts[2])
		}
		if isPM && h < 12 {
			h += 12
		} else if isAM && h == 12 {
			h = 0
		}
		return h, m, s, nil
	}

	// Handle 24-hour format HH:MM or HH:MM:SS
	parts := strings.Split(clean, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, 0, 0, fmt.Errorf("expected HH:MM or HH:MM:SS in 24-hour time, got %q", expr)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, 0, 0, fmt.Errorf("invalid hour %d (must be 0-23)", h)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, 0, 0, fmt.Errorf("invalid minute %d (must be 0-59)", m)
	}
	s := 0
	if len(parts) == 3 {
		s, err = strconv.Atoi(parts[2])
		if err != nil || s < 0 || s > 59 {
			return 0, 0, 0, fmt.Errorf("invalid second %d (must be 0-59)", s)
		}
	}
	return h, m, s, nil
}

func parseWeeklyExpr(expr string) (time.Weekday, int, int, int, error) {
	fields := strings.Fields(expr)
	if len(fields) != 2 {
		return 0, 0, 0, 0, fmt.Errorf("expected format '<weekday> <time>' (e.g. 'Mon 02:30'), got %q", expr)
	}
	dayStr := strings.ToUpper(fields[0])
	timeStr := fields[1]

	var wd time.Weekday
	switch dayStr {
	case "SUN", "SUNDAY":
		wd = time.Sunday
	case "MON", "MONDAY":
		wd = time.Monday
	case "TUE", "TUESDAY":
		wd = time.Tuesday
	case "WED", "WEDNESDAY":
		wd = time.Wednesday
	case "THU", "THURSDAY":
		wd = time.Thursday
	case "FRI", "FRIDAY":
		wd = time.Friday
	case "SAT", "SATURDAY":
		wd = time.Saturday
	default:
		return 0, 0, 0, 0, fmt.Errorf("invalid weekday %q (must be Mon, Tue, Wed, Thu, Fri, Sat, Sun)", fields[0])
	}

	h, m, s, err := parseTimeOfDay(timeStr)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return wd, h, m, s, nil
}

// -----------------------------------------------------------------------------
// PURE CRON PARSER
// -----------------------------------------------------------------------------

type cronSchedule struct {
	minute     [60]bool
	hour       [24]bool
	dayOfMonth [32]bool
	month      [13]bool
	dayOfWeek  [8]bool // 0=Sun, 1=Mon ... 6=Sat, 7=Sun
}

func parseCronExpression(expr string) (*cronSchedule, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression must have 5 fields (minute, hour, dom, month, dow), got %d", len(fields))
	}

	cs := &cronSchedule{}

	if err := parseCronField(fields[0], 0, 59, cs.minute[:], nil); err != nil {
		return nil, fmt.Errorf("minute field error: %w", err)
	}
	if err := parseCronField(fields[1], 0, 23, cs.hour[:], nil); err != nil {
		return nil, fmt.Errorf("hour field error: %w", err)
	}
	if err := parseCronField(fields[2], 1, 31, cs.dayOfMonth[:], nil); err != nil {
		return nil, fmt.Errorf("day-of-month field error: %w", err)
	}
	monthNames := map[string]int{
		"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
		"JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
	}
	if err := parseCronField(fields[3], 1, 12, cs.month[:], monthNames); err != nil {
		return nil, fmt.Errorf("month field error: %w", err)
	}
	dowNames := map[string]int{
		"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
	}
	if err := parseCronField(fields[4], 0, 7, cs.dayOfWeek[:], dowNames); err != nil {
		return nil, fmt.Errorf("day-of-week field error: %w", err)
	}
	// Normalize 7 to 0 for Sunday
	if cs.dayOfWeek[7] {
		cs.dayOfWeek[0] = true
	}

	return cs, nil
}

func parseCronField(field string, min, max int, target []bool, names map[string]int) error {
	clean := strings.ToUpper(strings.TrimSpace(field))
	if clean == "" {
		return fmt.Errorf("empty field")
	}

	items := strings.Split(clean, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return fmt.Errorf("empty sub-expression")
		}

		step := 1
		rangeExpr := item
		if strings.Contains(item, "/") {
			parts := strings.Split(item, "/")
			if len(parts) != 2 {
				return fmt.Errorf("invalid step expression: %s", item)
			}
			rangeExpr = parts[0]
			s, err := strconv.Atoi(parts[1])
			if err != nil || s <= 0 {
				return fmt.Errorf("invalid step value: %s", parts[1])
			}
			step = s
		}

		var start, end int
		if rangeExpr == "*" {
			start = min
			end = max
		} else if strings.Contains(rangeExpr, "-") {
			parts := strings.Split(rangeExpr, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid range expression: %s", rangeExpr)
			}
			var err error
			start, err = resolveCronVal(parts[0], min, max, names)
			if err != nil {
				return err
			}
			end, err = resolveCronVal(parts[1], min, max, names)
			if err != nil {
				return err
			}
			if start > end {
				return fmt.Errorf("range start (%d) greater than end (%d)", start, end)
			}
		} else {
			val, err := resolveCronVal(rangeExpr, min, max, names)
			if err != nil {
				return err
			}
			start = val
			if strings.Contains(item, "/") {
				end = max
			} else {
				end = val
			}
		}

		for v := start; v <= end; v += step {
			if v >= min && v < len(target) {
				target[v] = true
			}
		}
	}
	return nil
}

func resolveCronVal(valStr string, min, max int, names map[string]int) (int, error) {
	valStr = strings.TrimSpace(valStr)
	if names != nil {
		if v, ok := names[valStr]; ok {
			return v, nil
		}
	}
	n, err := strconv.Atoi(valStr)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric token %q: %w", valStr, err)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("value %d out of bounds [%d, %d]", n, min, max)
	}
	return n, nil
}

// Next finds the earliest matching time strictly after the given reference timestamp.
func (cs *cronSchedule) Next(after time.Time, loc *time.Location) (time.Time, error) {
	t := after.In(loc).Truncate(time.Minute).Add(time.Minute)

	// Search up to 5 years (approx 2,628,000 minutes)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		// Month check
		if !cs.month[int(t.Month())] {
			// Advance to next month
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc)
			continue
		}

		// Day of month & day of week check
		domMatch := cs.dayOfMonth[t.Day()]
		dowMatch := cs.dayOfWeek[int(t.Weekday())]
		if !domMatch || !dowMatch {
			// Advance to next day
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
			continue
		}

		// Hour check
		if !cs.hour[t.Hour()] {
			// Advance to next hour
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, loc)
			continue
		}

		// Minute check
		if cs.minute[t.Minute()] {
			return t.UTC(), nil
		}
		t = t.Add(time.Minute)
	}

	return time.Time{}, fmt.Errorf("no matching cron occurrence found within 5-year scheduling horizon")
}
