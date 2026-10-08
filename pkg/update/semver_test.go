package update

import (
	"testing"
)

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		input       string
		shouldError bool
		major       int
		minor       int
		patch       int
	}{
		{"1.0.0", false, 1, 0, 0},
		{"v1.0.1", false, 1, 0, 1},
		{"2.15.8", false, 2, 15, 8},
		{"v0.1.0-rc1", false, 0, 1, 0},
		{"invalid", true, 0, 0, 0},
		{"1.0", true, 0, 0, 0},
		{"1.0.0.0", true, 0, 0, 0},
		{"", true, 0, 0, 0},
	}

	for _, tc := range tests {
		sv, err := ParseSemVer(tc.input)
		if tc.shouldError && err == nil {
			t.Errorf("expected error for %q, got nil", tc.input)
		}
		if !tc.shouldError && err != nil {
			t.Errorf("unexpected error for %q: %v", tc.input, err)
		}
		if !tc.shouldError {
			if sv.Major != tc.major || sv.Minor != tc.minor || sv.Patch != tc.patch {
				t.Errorf("parsed version mismatch for %q: got %d.%d.%d, expected %d.%d.%d",
					tc.input, sv.Major, sv.Minor, sv.Patch, tc.major, tc.minor, tc.patch)
			}
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.0.0", "1.0.0", 0},
		{"v1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
	}

	for _, tc := range tests {
		res, err := Compare(tc.v1, tc.v2)
		if err != nil {
			t.Fatalf("unexpected compare error (%s vs %s): %v", tc.v1, tc.v2, err)
		}
		if res != tc.expected {
			t.Errorf("Compare(%q, %q) = %d, expected %d", tc.v1, tc.v2, res, tc.expected)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer("1.0.1", "1.0.0") {
		t.Errorf("expected 1.0.1 to be newer than 1.0.0")
	}
	if IsNewer("1.0.0", "1.0.0") {
		t.Errorf("expected 1.0.0 to not be newer than 1.0.0")
	}
	if IsNewer("0.9.9", "1.0.0") {
		t.Errorf("expected 0.9.9 to not be newer than 1.0.0")
	}
	if IsNewer("invalid", "1.0.0") {
		t.Errorf("malformed version must not be newer")
	}
}
