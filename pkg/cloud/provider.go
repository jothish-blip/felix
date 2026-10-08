package cloud

import (
	"net/url"
	"strings"
)

// Provider identifies a recognized Cloud or Backend-as-a-Service vendor.
type Provider string

const (
	ProviderSupabase Provider = "supabase"
	ProviderFirebase Provider = "firebase"
	ProviderAWS      Provider = "aws"
	ProviderGCP      Provider = "gcp"
)

// Service represents a discovered cloud endpoint or infrastructure resource.
type Service struct {
	Provider    Provider          `json:"provider"`
	URL         string            `json:"url"`
	Source      string            `json:"source"` // JavaScript, Source Map, HTML, Secret Engine
	Identifiers map[string]string `json:"identifiers,omitempty"` // e.g. project, bucket, region
}

// CanonicalID generates a stable deduplication key for the service.
func (s Service) CanonicalID() string {
	cleanURL := strings.ToLower(strings.TrimRight(s.URL, "/"))
	if parsed, err := url.Parse(cleanURL); err == nil {
		cleanURL = strings.ToLower(parsed.Scheme + "://" + parsed.Host + parsed.Path)
		cleanURL = strings.TrimRight(cleanURL, "/")
	}
	return string(s.Provider) + ":" + cleanURL
}
