package crawler

import (
	"errors"
	"mime"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// AssetType represents the category of a discovered web asset.
type AssetType string

const (
	AssetJavaScript AssetType = "javascript"
	AssetStylesheet AssetType = "stylesheet"
	AssetManifest   AssetType = "manifest"
	AssetSourceMap  AssetType = "source-map"
	AssetUnknown    AssetType = "unknown"
)

// Common crawler errors for asset handling.
var (
	ErrAssetTooLarge = errors.New("asset exceeds maximum allowed size")
	ErrOutOfScope    = errors.New("asset is out of scope")
)

// Asset provenance constants.
const (
	ProvenanceStatic  = "PROVENANCE_STATIC"
	ProvenanceBrowser = "PROVENANCE_BROWSER"
)

// Asset represents a discovered and optionally downloaded web asset.
type Asset struct {
	URL         string    `json:"url"`
	Type        AssetType `json:"type"`
	Content     []byte    `json:"-"`
	Size        int64     `json:"size"`
	StatusCode  int       `json:"status_code"`
	ContentType string    `json:"content_type"`
	IsSourceMap bool      `json:"is_source_map"`
	InScope     bool      `json:"in_scope"`
	Provenance  string    `json:"provenance,omitempty"`
	Inferred    bool      `json:"inferred,omitempty"`
	Error       error     `json:"error,omitempty"`
}

// Regex for extracting sourceMappingURL comments in JS or CSS.
// Matches //# sourceMappingURL=..., //@ sourceMappingURL=..., /*# sourceMappingURL=... */, etc.
var sourceMapRegex = regexp.MustCompile(`(?m)(?://|/\*)[#@]\s*sourceMappingURL=\s*(\S+?)(?:\s*\*\/|\s*$)`)

// ExtractSourceMapURL searches asset content for a sourceMappingURL reference.
func ExtractSourceMapURL(content []byte) string {
	matches := sourceMapRegex.FindSubmatch(content)
	if len(matches) > 1 {
		match := strings.TrimSpace(string(matches[1]))
		// Ignore inline data URIs for external file resolution
		if strings.HasPrefix(strings.ToLower(match), "data:") {
			return ""
		}
		return match
	}
	return ""
}

// ClassifyAsset categorizes an asset using its URL path and Content-Type header.
func ClassifyAsset(rawURL string, contentType string) AssetType {
	cleanPath := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		cleanPath = strings.ToLower(parsed.Path)
	} else {
		cleanPath = strings.ToLower(rawURL)
	}

	baseName := path.Base(cleanPath)

	// 1. Source maps: .map extension or .js.map / .css.map
	if strings.HasSuffix(cleanPath, ".map") {
		return AssetSourceMap
	}

	// 2. Web App Manifests: .webmanifest or manifest.json
	if strings.HasSuffix(cleanPath, ".webmanifest") || baseName == "manifest.json" {
		return AssetManifest
	}

	// 3. Stylesheets: .css extension
	if strings.HasSuffix(cleanPath, ".css") {
		return AssetStylesheet
	}

	// 4. JavaScript: .js, .mjs, .cjs
	if strings.HasSuffix(cleanPath, ".js") || strings.HasSuffix(cleanPath, ".mjs") || strings.HasSuffix(cleanPath, ".cjs") {
		return AssetJavaScript
	}

	// If URL extension was not conclusive, inspect Content-Type header
	if contentType != "" {
		mediaType, _, _ := mime.ParseMediaType(contentType)
		mediaType = strings.ToLower(strings.TrimSpace(mediaType))

		switch mediaType {
		case "application/javascript", "text/javascript", "application/x-javascript",
			"text/ecmascript", "application/ecmascript":
			return AssetJavaScript
		case "text/css":
			return AssetStylesheet
		case "application/manifest+json":
			return AssetManifest
		case "application/json":
			if strings.Contains(cleanPath, "manifest") {
				return AssetManifest
			}
		}
	}

	return AssetUnknown
}
