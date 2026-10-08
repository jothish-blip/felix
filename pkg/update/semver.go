package update

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var semverRegex = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

// SemVer represents a parsed semantic version.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease string
	Build      string
	Original   string
}

// ParseSemVer parses a semver string (e.g. "1.0.0", "v1.0.1", "1.0.0-rc1").
func ParseSemVer(s string) (SemVer, error) {
	s = strings.TrimSpace(s)
	matches := semverRegex.FindStringSubmatch(s)
	if matches == nil {
		return SemVer{}, fmt.Errorf("invalid semantic version format: %q", s)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid major version in %q: %w", s, err)
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid minor version in %q: %w", s, err)
	}
	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid patch version in %q: %w", s, err)
	}

	return SemVer{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		PreRelease: matches[4],
		Build:      matches[5],
		Original:   s,
	}, nil
}

// Compare compares two semantic version strings.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func Compare(v1, v2 string) (int, error) {
	sv1, err := ParseSemVer(v1)
	if err != nil {
		return 0, err
	}
	sv2, err := ParseSemVer(v2)
	if err != nil {
		return 0, err
	}

	if sv1.Major != sv2.Major {
		if sv1.Major < sv2.Major {
			return -1, nil
		}
		return 1, nil
	}
	if sv1.Minor != sv2.Minor {
		if sv1.Minor < sv2.Minor {
			return -1, nil
		}
		return 1, nil
	}
	if sv1.Patch != sv2.Patch {
		if sv1.Patch < sv2.Patch {
			return -1, nil
		}
		return 1, nil
	}

	// Normal releases have higher precedence than pre-releases
	if sv1.PreRelease == "" && sv2.PreRelease != "" {
		return 1, nil
	}
	if sv1.PreRelease != "" && sv2.PreRelease == "" {
		return -1, nil
	}
	if sv1.PreRelease != sv2.PreRelease {
		if sv1.PreRelease < sv2.PreRelease {
			return -1, nil
		}
		return 1, nil
	}

	return 0, nil
}

// IsNewer returns true if candidate version is strictly newer than current version.
func IsNewer(candidate, current string) bool {
	res, err := Compare(candidate, current)
	if err != nil {
		return false
	}
	return res > 0
}

// CleanVersion strips any leading 'v' prefix from a version string.
func CleanVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
