package update

import (
	"testing"
)

func TestTargetKey(t *testing.T) {
	cases := []struct {
		goos, goarch string
		expected     string
		shouldError  bool
	}{
		{"windows", "amd64", "windows-amd64", false},
		{"linux", "amd64", "linux-amd64", false},
		{"linux", "arm64", "linux-arm64", false},
		{"darwin", "amd64", "darwin-amd64", false},
		{"darwin", "arm64", "darwin-arm64", false},
		{"windows", "386", "", true},
		{"freebsd", "amd64", "", true},
	}

	for _, tc := range cases {
		key, err := TargetKey(tc.goos, tc.goarch)
		if tc.shouldError && err == nil {
			t.Errorf("expected error for %s/%s, got nil", tc.goos, tc.goarch)
		}
		if !tc.shouldError && err != nil {
			t.Errorf("unexpected error for %s/%s: %v", tc.goos, tc.goarch, err)
		}
		if key != tc.expected {
			t.Errorf("TargetKey(%s, %s) = %q, expected %q", tc.goos, tc.goarch, key, tc.expected)
		}
	}
}

func TestArchiveName(t *testing.T) {
	cases := []struct {
		version, goos, goarch string
		expected              string
		shouldError           bool
	}{
		{"1.0.1", "windows", "amd64", "felix_1.0.1_windows_amd64.zip", false},
		{"v1.0.1", "linux", "amd64", "felix_1.0.1_linux_amd64.tar.gz", false},
		{"1.0.1", "linux", "arm64", "felix_1.0.1_linux_arm64.tar.gz", false},
		{"v1.0.1", "darwin", "amd64", "felix_1.0.1_darwin_amd64.tar.gz", false},
		{"1.0.1", "darwin", "arm64", "felix_1.0.1_darwin_arm64.tar.gz", false},
		{"1.0.1", "solaris", "amd64", "", true},
	}

	for _, tc := range cases {
		name, err := ArchiveName(tc.version, tc.goos, tc.goarch)
		if tc.shouldError && err == nil {
			t.Errorf("expected error for %s/%s, got nil", tc.goos, tc.goarch)
		}
		if !tc.shouldError && err != nil {
			t.Errorf("unexpected error for %s/%s: %v", tc.goos, tc.goarch, err)
		}
		if name != tc.expected {
			t.Errorf("ArchiveName(%s, %s, %s) = %q, expected %q", tc.version, tc.goos, tc.goarch, name, tc.expected)
		}
	}
}

func TestExecutableName(t *testing.T) {
	if ExecutableName("windows") != "felix.exe" {
		t.Errorf("expected windows executable to be felix.exe")
	}
	if ExecutableName("linux") != "felix" {
		t.Errorf("expected linux executable to be felix")
	}
	if ExecutableName("darwin") != "felix" {
		t.Errorf("expected darwin executable to be felix")
	}
}
