package apk

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ExtractedArtifact encapsulates an embedded configuration or resource file staged for intelligence analysis.
type ExtractedArtifact struct {
	RelPath  string            `json:"rel_path"`
	Type     string            `json:"type"` // "google-services", "json", "xml", "properties", "yaml", "javascript", "text"
	Size     int64             `json:"size"`
	Content  []byte            `json:"-"`
	KeyValue map[string]string `json:"key_value,omitempty"`
}

// GoogleServicesConfig represents the standard structure of google-services.json in Android packages.
type GoogleServicesConfig struct {
	ProjectInfo struct {
		ProjectNumber string `json:"project_number"`
		ProjectID     string `json:"project_id"`
		StorageBucket string `json:"storage_bucket"`
		FirebaseURL   string `json:"firebase_url"`
	} `json:"project_info"`
	Client []struct {
		ClientInfo struct {
			MobileSDKAppID    string `json:"mobilesdk_app_id"`
			AndroidClientInfo struct {
				PackageName string `json:"package_name"`
			} `json:"android_client_info"`
		} `json:"client_info"`
		OAuthClient []struct {
			ClientID   string `json:"client_id"`
			ClientType int    `json:"client_type"`
		} `json:"oauth_client"`
		APIKey []struct {
			CurrentKey string `json:"current_key"`
		} `json:"api_key"`
	} `json:"client"`
}

// isArtifactCandidate checks whether an archive entry path corresponds to a supported static intelligence target.
func isArtifactCandidate(cleanPath string) bool {
	base := strings.ToLower(path.Base(cleanPath))
	ext := strings.ToLower(path.Ext(cleanPath))

	// Android manifest and dex files are handled separately
	if cleanPath == "AndroidManifest.xml" || strings.HasSuffix(cleanPath, ".dex") {
		return false
	}

	// Exclude binary resources, native shared libraries, images, audio, video, fonts
	switch ext {
	case ".so", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".svg",
		".mp3", ".ogg", ".wav", ".mp4", ".ttf", ".otf", ".woff", ".woff2",
		".arsc", ".apk", ".jar", ".class":
		return false
	}

	// Known configuration files
	if base == "google-services.json" || base == "strings.xml" {
		return true
	}

	// Android string resource files (e.g. res/values/strings.xml, res/values-es/strings.xml)
	if strings.HasPrefix(cleanPath, "res/values") && strings.HasSuffix(cleanPath, ".xml") {
		return true
	}

	// Raw resources (e.g. res/raw/*)
	if strings.HasPrefix(cleanPath, "res/raw/") {
		return true
	}

	// Assets configurations and bundles
	if strings.HasPrefix(cleanPath, "assets/") {
		switch ext {
		case ".json", ".xml", ".properties", ".yaml", ".yml", ".ini", ".conf", ".config", ".env", ".js", ".bundle", ".txt", ".map":
			return true
		}
		if base == "index.android.bundle" || base == "main.jsbundle" {
			return true
		}
	}

	// Root-level configuration files
	if !strings.Contains(cleanPath, "/") {
		switch ext {
		case ".json", ".properties", ".yaml", ".yml", ".ini", ".conf", ".config", ".env", ".txt":
			return true
		}
	}

	return false
}

// detectArtifactType classifies the artifact format based on path and file magic/content.
func detectArtifactType(relPath string, data []byte) string {
	base := strings.ToLower(path.Base(relPath))
	ext := strings.ToLower(path.Ext(relPath))

	if base == "google-services.json" {
		return "google-services"
	}
	if ext == ".json" {
		return "json"
	}
	if ext == ".xml" {
		return "xml"
	}
	if ext == ".properties" || ext == ".ini" || ext == ".env" || ext == ".conf" || ext == ".config" {
		return "properties"
	}
	if ext == ".yaml" || ext == ".yml" {
		return "yaml"
	}
	if ext == ".js" || ext == ".bundle" || base == "index.android.bundle" || base == "main.jsbundle" {
		return "javascript"
	}

	// Inspect first few bytes for format detection
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 {
		if trimmed[0] == '{' || trimmed[0] == '[' {
			return "json"
		}
		if trimmed[0] == '<' {
			return "xml"
		}
	}

	return "text"
}

// DiscoverAndExtractArtifacts discovers and parses supported embedded configurations and resource files.
func DiscoverAndExtractArtifacts(ctx context.Context, ws *Workspace, limits Limits) ([]ExtractedArtifact, []string, error) {
	if ws == nil || ws.Dir == "" {
		return nil, nil, WrapError("discover_artifacts", "workspace is uninitialized", ErrInvalidInput)
	}

	maxFiles := limits.EffectiveMaxArtifactFiles()
	maxFileSize := limits.EffectiveMaxArtifactFileSize()
	maxTotalBytes := limits.EffectiveMaxArtifactTotalBytes()

	var (
		artifacts      []ExtractedArtifact
		limitations    []string
		totalBytesRead int64
	)

	// Strategy 1: Check if artifacts are already extracted to ws.Dir
	var extractedFiles []string
	_ = filepath.Walk(ws.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil
		}
		rel, rErr := filepath.Rel(ws.Dir, p)
		if rErr != nil {
			return nil
		}
		cleanRel := filepath.ToSlash(rel)
		if cleanRel != "AndroidManifest.xml" && !strings.HasSuffix(cleanRel, ".dex") {
			extractedFiles = append(extractedFiles, cleanRel)
		}
		return nil
	})

	if len(extractedFiles) > 0 {
		// Read directly from extracted workspace directory
		for _, relPath := range extractedFiles {
			if err := ctx.Err(); err != nil {
				return nil, limitations, WrapError("discover_artifacts", "operation cancelled during artifact extraction", err)
			}
			if len(artifacts) >= maxFiles {
				limitations = append(limitations, fmt.Sprintf("Reached artifact inspection limit of %d files; additional files omitted", maxFiles))
				break
			}
			if !isArtifactCandidate(relPath) {
				continue
			}

			targetPath, err := VerifyExtractionTarget(ws.Dir, relPath)
			if err != nil {
				limitations = append(limitations, fmt.Sprintf("Path validation skipped unsafe artifact %q: %v", relPath, err))
				continue
			}

			fi, err := os.Stat(targetPath)
			if err != nil {
				continue
			}
			if fi.Size() > maxFileSize {
				limitations = append(limitations, fmt.Sprintf("Artifact %q exceeds per-file limit (%d bytes > %d limit); omitted", relPath, fi.Size(), maxFileSize))
				continue
			}
			if totalBytesRead+fi.Size() > maxTotalBytes {
				limitations = append(limitations, fmt.Sprintf("Cumulative artifact size limit (%d bytes) reached; omitting %q", maxTotalBytes, relPath))
				break
			}

			data, err := os.ReadFile(targetPath)
			if err != nil {
				limitations = append(limitations, fmt.Sprintf("Failed reading artifact %q: %v", relPath, err))
				continue
			}
			totalBytesRead += int64(len(data))

			art := parseArtifactContent(relPath, data)
			artifacts = append(artifacts, art)
		}
		return artifacts, limitations, nil
	}

	// Strategy 2: If workspace was isolated with Extract=false, read artifact candidates from ws.APKPath
	if ws.APKPath != "" {
		apkFile, err := os.Open(ws.APKPath)
		if err != nil {
			return nil, limitations, WrapError("discover_artifacts", "failed opening APK for artifact streaming", err)
		}
		defer apkFile.Close()

		fi, err := apkFile.Stat()
		if err != nil {
			return nil, limitations, WrapError("discover_artifacts", "failed stating APK file", err)
		}

		zipReader, err := zip.NewReader(apkFile, fi.Size())
		if err != nil {
			return nil, limitations, WrapError("discover_artifacts", "failed opening ZIP archive reader", err)
		}

		for _, entry := range zipReader.File {
			if err := ctx.Err(); err != nil {
				return nil, limitations, WrapError("discover_artifacts", "operation cancelled during ZIP entry streaming", err)
			}
			if len(artifacts) >= maxFiles {
				limitations = append(limitations, fmt.Sprintf("Reached artifact inspection limit of %d files; additional entries omitted", maxFiles))
				break
			}

			cleanRel, err := SanitizeArchiveEntry(entry.Name, limits)
			if err != nil || !isArtifactCandidate(cleanRel) {
				continue
			}

			if int64(entry.UncompressedSize64) > maxFileSize {
				limitations = append(limitations, fmt.Sprintf("Archive entry %q uncompressed size exceeds limit; omitted", cleanRel))
				continue
			}
			if totalBytesRead+int64(entry.UncompressedSize64) > maxTotalBytes {
				limitations = append(limitations, fmt.Sprintf("Cumulative artifact size limit reached; omitting %q", cleanRel))
				break
			}

			entryReader, err := entry.Open()
			if err != nil {
				limitations = append(limitations, fmt.Sprintf("Failed opening entry %q: %v", cleanRel, err))
				continue
			}

			boundedReader := io.LimitReader(entryReader, maxFileSize+1)
			data, err := io.ReadAll(boundedReader)
			entryReader.Close()
			if err != nil {
				limitations = append(limitations, fmt.Sprintf("Decompression error reading entry %q: %v", cleanRel, err))
				continue
			}
			if int64(len(data)) > maxFileSize {
				limitations = append(limitations, fmt.Sprintf("Decompressed size for entry %q exceeded %d bytes limit", cleanRel, maxFileSize))
				continue
			}

			totalBytesRead += int64(len(data))
			art := parseArtifactContent(cleanRel, data)
			artifacts = append(artifacts, art)
		}
	}

	return artifacts, limitations, nil
}

// parseArtifactContent parses structured artifacts (JSON, XML, properties, YAML) into key-value pairs where applicable.
func parseArtifactContent(relPath string, data []byte) ExtractedArtifact {
	artType := detectArtifactType(relPath, data)
	art := ExtractedArtifact{
		RelPath:  relPath,
		Type:     artType,
		Size:     int64(len(data)),
		Content:  data,
		KeyValue: make(map[string]string),
	}

	switch artType {
	case "google-services", "json":
		extractJSONKeyValues(data, "", art.KeyValue, 0)
	case "xml":
		extractXMLStringResources(data, art.KeyValue)
	case "properties", "yaml":
		extractLineKeyValues(data, art.KeyValue)
	}

	return art
}

// extractJSONKeyValues flattens JSON keys recursively up to maxDepth.
func extractJSONKeyValues(data []byte, prefix string, result map[string]string, depth int) {
	if depth > 10 || len(result) >= 500 {
		return
	}

	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	flattenJSON(obj, prefix, result, depth)
}

func flattenJSON(val interface{}, prefix string, result map[string]string, depth int) {
	if depth > 10 || len(result) >= 500 {
		return
	}

	switch v := val.(type) {
	case map[string]interface{}:
		for k, item := range v {
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			flattenJSON(item, fullKey, result, depth+1)
		}
	case []interface{}:
		for i, item := range v {
			fullKey := fmt.Sprintf("%s[%d]", prefix, i)
			flattenJSON(item, fullKey, result, depth+1)
		}
	case string:
		if prefix != "" && strings.TrimSpace(v) != "" {
			result[prefix] = strings.TrimSpace(v)
		}
	case float64:
		if prefix != "" {
			result[prefix] = fmt.Sprintf("%.0f", v)
		}
	case bool:
		if prefix != "" {
			result[prefix] = fmt.Sprintf("%t", v)
		}
	}
}

// extractXMLStringResources parses Android <resources><string name="...">value</string></resources> using safe xml.Decoder.
func extractXMLStringResources(data []byte, result map[string]string) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	// Prevent entity expansion attacks
	decoder.Entity = map[string]string{}

	var currentName string
	var inStringElement bool
	var contentBuilder strings.Builder

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		if len(result) >= 500 {
			break
		}

		switch elem := tok.(type) {
		case xml.StartElement:
			if elem.Name.Local == "string" {
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						currentName = attr.Value
						inStringElement = true
						contentBuilder.Reset()
						break
					}
				}
			}
		case xml.CharData:
			if inStringElement {
				contentBuilder.Write(elem)
			}
		case xml.EndElement:
			if elem.Name.Local == "string" && inStringElement {
				if currentName != "" {
					result[currentName] = strings.TrimSpace(contentBuilder.String())
				}
				inStringElement = false
				currentName = ""
			}
		}
	}
}

// extractLineKeyValues extracts simple key-value pairs from properties, INI, and YAML files.
func extractLineKeyValues(data []byte, result map[string]string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		if len(result) >= 500 {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}

		sepIdx := strings.IndexAny(line, "=:")
		if sepIdx > 0 {
			key := strings.TrimSpace(line[:sepIdx])
			val := strings.TrimSpace(line[sepIdx+1:])
			// Strip surrounding quotes
			val = strings.Trim(val, "\"'`")
			if key != "" && val != "" {
				result[key] = val
			}
		}
	}
}
