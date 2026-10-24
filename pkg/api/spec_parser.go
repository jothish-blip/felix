package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxSpecificationFileSize = 10 * 1024 * 1024 // 10MB
	MaxReferenceDepth        = 20
)

var (
	rxValidHTTPMethods = map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"OPTIONS": true,
		"HEAD":    true,
		"TRACE":   true,
	}

	rxOpenAPIParam = regexp.MustCompile(`\{([^}]+)\}`)
	rxColonParam   = regexp.MustCompile(`/:([a-zA-Z0-9_]+)`)
	rxBracketParam = regexp.MustCompile(`/\[([a-zA-Z0-9_\.]+)\]`)
)

// SpecParser parses client-supplied OpenAPI 3.0/3.1 and Swagger 2.0 specifications from files or data.
type SpecParser struct {
	maxFileSize int64
	maxRefDepth int
}

// NewSpecParser creates a safe specification parser with bounded limits.
func NewSpecParser() *SpecParser {
	return &SpecParser{
		maxFileSize: MaxSpecificationFileSize,
		maxRefDepth: MaxReferenceDepth,
	}
}

// ParseSpecificationFile parses a specification file from disk (JSON or YAML).
func (sp *SpecParser) ParseSpecificationFile(filePath string) ([]DocumentedOperation, *SpecMetadata, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open specification file %s: %w", filePath, err)
	}

	if info.Size() > sp.maxFileSize {
		return nil, nil, fmt.Errorf("specification file %s exceeds size ceiling (%d bytes)", filePath, sp.maxFileSize)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read specification file %s: %w", filePath, err)
	}

	return sp.ParseSpecificationData(data, filePath)
}

// ParseSpecificationData parses raw JSON or YAML specification bytes.
func (sp *SpecParser) ParseSpecificationData(data []byte, sourceName string) ([]DocumentedOperation, *SpecMetadata, error) {
	if len(data) == 0 {
		return nil, &SpecMetadata{
			Source:   sourceName,
			Format:   "MALFORMED",
			Warnings: []string{"Empty specification data provided"},
		}, errors.New("empty specification data")
	}

	if int64(len(data)) > sp.maxFileSize {
		return nil, &SpecMetadata{
			Source:   sourceName,
			Format:   "MALFORMED",
			Warnings: []string{fmt.Sprintf("Data size (%d bytes) exceeds ceiling (%d bytes)", len(data), sp.maxFileSize)},
		}, fmt.Errorf("specification data exceeds limit of %d bytes", sp.maxFileSize)
	}

	var root map[string]any
	var warnings []string

	// Attempt JSON unmarshal first if input starts with JSON bracket/brace
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &root); err != nil {
			return nil, &SpecMetadata{
				Source:   sourceName,
				Format:   "MALFORMED",
				Warnings: []string{fmt.Sprintf("JSON parse error: %v", err)},
			}, fmt.Errorf("malformed JSON specification: %w", err)
		}
	} else {
		// Fallback to YAML unmarshal
		yamlRoot, yamlErr := parseYAMLDocument(string(data))
		if yamlErr != nil {
			return nil, &SpecMetadata{
				Source:   sourceName,
				Format:   "MALFORMED",
				Warnings: []string{fmt.Sprintf("YAML parse error: %v", yamlErr)},
			}, fmt.Errorf("malformed YAML specification: %w", yamlErr)
		}
		root = yamlRoot
	}

	if root == nil {
		return nil, &SpecMetadata{
			Source:   sourceName,
			Format:   "MALFORMED",
			Warnings: []string{"Failed to parse specification object root"},
		}, errors.New("malformed specification document")
	}

	// Determine specification version and format
	format := "UNSUPPORTED"
	version := ""
	if v, ok := root["openapi"].(string); ok {
		version = strings.TrimSpace(v)
		if strings.HasPrefix(version, "3.1") {
			format = "OPENAPI_3_1"
		} else if strings.HasPrefix(version, "3.") {
			format = "OPENAPI_3_0"
		}
	} else if v, ok := root["swagger"].(string); ok {
		version = strings.TrimSpace(v)
		if strings.HasPrefix(version, "2.") {
			format = "SWAGGER_2_0"
		}
	}

	if format == "UNSUPPORTED" {
		warnings = append(warnings, fmt.Sprintf("Unsupported or missing specification version header (openapi/swagger: %q)", version))
	}

	// Extract Title
	title := "API Specification"
	if infoObj, ok := root["info"].(map[string]any); ok {
		if t, ok := infoObj["title"].(string); ok && strings.TrimSpace(t) != "" {
			title = strings.TrimSpace(t)
		}
	}

	// Extract base paths and server origins
	var serverBases []string
	if serversList, ok := root["servers"].([]any); ok {
		for _, s := range serversList {
			if sMap, ok := s.(map[string]any); ok {
				if u, ok := sMap["url"].(string); ok && strings.TrimSpace(u) != "" {
					serverBases = append(serverBases, strings.TrimSpace(u))
				}
			}
		}
	} else if basePath, ok := root["basePath"].(string); ok && strings.TrimSpace(basePath) != "" {
		serverBases = append(serverBases, strings.TrimSpace(basePath))
	}

	// Extract Paths and Operations
	pathsMap, ok := root["paths"].(map[string]any)
	if !ok {
		meta := &SpecMetadata{
			Source:          sourceName,
			Title:           title,
			Version:         version,
			Format:          format,
			Servers:         serverBases,
			OperationsCount: 0,
			Warnings:        append(warnings, "Missing 'paths' object in specification"),
		}
		return nil, meta, nil
	}

	var operations []DocumentedOperation

	for rawPath, itemVal := range pathsMap {
		var pathItem map[string]any

		// Check if path item is a $ref
		if pMap, ok := itemVal.(map[string]any); ok {
			if refStr, hasRef := pMap["$ref"].(string); hasRef {
				visited := make(map[string]bool)
				resolved := sp.resolveLocalRef(root, refStr, visited, 0, &warnings)
				if resMap, ok := resolved.(map[string]any); ok {
					pathItem = resMap
				}
			} else {
				pathItem = pMap
			}
		}

		if pathItem == nil {
			continue
		}

		// Collect top-level path parameters
		var topParams []string
		if pList, ok := pathItem["parameters"].([]any); ok {
			for _, p := range pList {
				topParams = append(topParams, extractParamName(p, root, sp, &warnings))
			}
		}

		// Inspect HTTP Methods on path item
		for key, opVal := range pathItem {
			upperMethod := strings.ToUpper(strings.TrimSpace(key))
			if !rxValidHTTPMethods[upperMethod] {
				continue
			}

			opMap, ok := opVal.(map[string]any)
			if !ok {
				continue
			}

			// Operation parameters
			params := append([]string{}, topParams...)
			if pList, ok := opMap["parameters"].([]any); ok {
				for _, p := range pList {
					params = append(params, extractParamName(p, root, sp, &warnings))
				}
			}

			// Check requestBody properties
			var schemaProps []string
			if reqBody, ok := opMap["requestBody"].(map[string]any); ok {
				schemaProps = append(schemaProps, extractSchemaProps(reqBody, root, sp, &warnings)...)
			}

			opID := ""
			if id, ok := opMap["operationId"].(string); ok {
				opID = strings.TrimSpace(id)
			}
			summary := ""
			if s, ok := opMap["summary"].(string); ok {
				summary = strings.TrimSpace(s)
			}
			desc := ""
			if d, ok := opMap["description"].(string); ok {
				desc = strings.TrimSpace(d)
			}

			// Detect Sensitive Identifiers on this operation
			sensitiveHits := DetectSensitiveIdentifiers(rawPath, params, schemaProps, summary+" "+desc)

			canonical := CanonicalizeRoutePath(rawPath)

			op := DocumentedOperation{
				ID:            GenerateOperationID(upperMethod, canonical, sourceName),
				SpecSource:    sourceName,
				SpecTitle:     title,
				SpecVersion:   version,
				Method:        upperMethod,
				Path:          rawPath,
				CanonicalPath: canonical,
				OperationID:   opID,
				Summary:       summary,
				Description:   desc,
				Parameters:    params,
				SensitiveHits: sensitiveHits,
			}

			operations = append(operations, op)

			// If server bases exist with URL prefixes (e.g. /v1), also register operations with prefix
			for _, sb := range serverBases {
				prefix := extractBasePathPrefix(sb)
				if prefix != "" && !strings.HasPrefix(rawPath, prefix) {
					prefixedPath := prefix + "/" + strings.TrimPrefix(rawPath, "/")
					prefixedCanonical := CanonicalizeRoutePath(prefixedPath)
					prefixedOp := op
					prefixedOp.ID = GenerateOperationID(upperMethod, prefixedCanonical, sourceName)
					prefixedOp.CanonicalPath = prefixedCanonical
					operations = append(operations, prefixedOp)
				}
			}
		}
	}

	// Sort operations stably
	sort.Slice(operations, func(i, j int) bool {
		if operations[i].CanonicalPath != operations[j].CanonicalPath {
			return operations[i].CanonicalPath < operations[j].CanonicalPath
		}
		return operations[i].Method < operations[j].Method
	})

	metadata := &SpecMetadata{
		Source:          sourceName,
		Title:           title,
		Version:         version,
		Format:          format,
		Servers:         serverBases,
		OperationsCount: len(operations),
		Warnings:        warnings,
	}

	return operations, metadata, nil
}

// resolveLocalRef resolves local `#/components/...` references safely with cycle and depth detection.
// External references (http://, file://, ./...) are strictly blocked and recorded as warnings.
func (sp *SpecParser) resolveLocalRef(root map[string]any, refStr string, visited map[string]bool, depth int, warnings *[]string) any {
	if depth > sp.maxRefDepth {
		*warnings = append(*warnings, fmt.Sprintf("Maximum $ref resolution depth exceeded (%d) at %s", sp.maxRefDepth, refStr))
		return nil
	}

	// External $ref protection (P14.2-A Item 3)
	if !strings.HasPrefix(refStr, "#/") {
		*warnings = append(*warnings, fmt.Sprintf("External $ref %q blocked: external reference fetching is disabled for safety", refStr))
		return nil
	}

	// Cycle detection (P14.2-A Item 4)
	if visited[refStr] {
		*warnings = append(*warnings, fmt.Sprintf("Cyclic $ref detected at %s; resolution halted", refStr))
		return nil
	}
	visited[refStr] = true

	pointer := strings.TrimPrefix(refStr, "#/")
	parts := strings.Split(pointer, "/")
	var current any = root

	for _, rawPart := range parts {
		part := strings.ReplaceAll(strings.ReplaceAll(rawPart, "~1", "/"), "~0", "~")
		switch node := current.(type) {
		case map[string]any:
			val, exists := node[part]
			if !exists {
				*warnings = append(*warnings, fmt.Sprintf("Unresolvable $ref pointer segment %q in %s", part, refStr))
				return nil
			}
			current = val
		default:
			return nil
		}
	}

	// Follow nested $ref if resolved object itself is a reference
	if m, isMap := current.(map[string]any); isMap {
		if nextRef, hasRef := m["$ref"].(string); hasRef {
			return sp.resolveLocalRef(root, nextRef, visited, depth+1, warnings)
		}
	}

	return current
}

// extractParamName resolves parameter name and follows local $ref if needed.
func extractParamName(param any, root map[string]any, sp *SpecParser, warnings *[]string) string {
	pMap, ok := param.(map[string]any)
	if !ok {
		return ""
	}

	if refStr, hasRef := pMap["$ref"].(string); hasRef {
		resolved := sp.resolveLocalRef(root, refStr, make(map[string]bool), 0, warnings)
		if resMap, ok := resolved.(map[string]any); ok {
			pMap = resMap
		}
	}

	if name, ok := pMap["name"].(string); ok {
		return strings.TrimSpace(name)
	}
	return ""
}

// extractSchemaProps inspects requestBody schema definitions for property names.
func extractSchemaProps(reqBody map[string]any, root map[string]any, sp *SpecParser, warnings *[]string) []string {
	var props []string

	content, ok := reqBody["content"].(map[string]any)
	if !ok {
		return nil
	}

	for _, mediaTypeVal := range content {
		mediaTypeObj, ok := mediaTypeVal.(map[string]any)
		if !ok {
			continue
		}
		schemaVal, ok := mediaTypeObj["schema"].(map[string]any)
		if !ok {
			continue
		}

		if refStr, hasRef := schemaVal["$ref"].(string); hasRef {
			resolved := sp.resolveLocalRef(root, refStr, make(map[string]bool), 0, warnings)
			if resMap, ok := resolved.(map[string]any); ok {
				schemaVal = resMap
			}
		}

		if propMap, ok := schemaVal["properties"].(map[string]any); ok {
			for propName := range propMap {
				props = append(props, propName)
			}
		}
	}

	return props
}

// extractBasePathPrefix extracts relative path prefixes like "/v1" or "/api/v2" from server URLs.
func extractBasePathPrefix(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err == nil && u.Path != "" && u.Path != "/" {
		return strings.TrimRight(u.Path, "/")
	}
	if strings.HasPrefix(serverURL, "/") && serverURL != "/" {
		return strings.TrimRight(serverURL, "/")
	}
	return ""
}

// CanonicalizeRoutePath converts dynamic path parameter variants ({id}, :id, [id]) into a uniform `{param}`.
func CanonicalizeRoutePath(rawPath string) string {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "/"
	}

	// Separate query string if present
	pathPart := trimmed
	if idx := strings.IndexAny(trimmed, "?#"); idx != -1 {
		pathPart = trimmed[:idx]
	}

	// Collapse OpenAPI {id} -> {param}
	pathPart = rxOpenAPIParam.ReplaceAllString(pathPart, "{param}")

	// Collapse Express / Next colon param: /:id -> /{param}
	pathPart = rxColonParam.ReplaceAllString(pathPart, "/{param}")

	// Collapse Next.js bracket param: /[id] -> /{param}
	pathPart = rxBracketParam.ReplaceAllString(pathPart, "/{param}")

	// Collapse consecutive slashes
	for strings.Contains(pathPart, "//") {
		pathPart = strings.ReplaceAll(pathPart, "//", "/")
	}

	// Normalize trailing slash for non-root paths
	if len(pathPart) > 1 && strings.HasSuffix(pathPart, "/") {
		pathPart = strings.TrimSuffix(pathPart, "/")
	}

	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}

	return pathPart
}

// parseYAMLDocument parses basic YAML documents into map[string]any recursively.
func parseYAMLDocument(yamlText string) (map[string]any, error) {
	lines := strings.Split(yamlText, "\n")
	idx := 0
	val, err := parseYAMLBlock(lines, &idx, 0)
	if err != nil {
		return nil, err
	}
	if m, ok := val.(map[string]any); ok {
		return m, nil
	}
	return nil, errors.New("root of YAML document is not an object/mapping")
}

func parseYAMLBlock(lines []string, idx *int, currentIndent int) (any, error) {
	var currentMap map[string]any
	var currentList []any

	for *idx < len(lines) {
		rawLine := lines[*idx]
		trimmed := strings.TrimSpace(rawLine)

		// Ignore empty lines and comment lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			*idx++
			continue
		}

		indent := countLeadingSpaces(rawLine)
		if indent < currentIndent {
			// Indentation decreased; return from current block
			break
		}

		// Handle list item: - value
		if strings.HasPrefix(trimmed, "- ") {
			if currentMap != nil {
				// Mixed list and map at same indent is invalid
				break
			}
			if currentList == nil {
				currentList = []any{}
			}

			itemContent := strings.TrimSpace(trimmed[2:])
			*idx++

			if strings.Contains(itemContent, ":") && !strings.HasPrefix(itemContent, "{") && !strings.HasPrefix(itemContent, "\"") {
				// List item is an inline map entry
				subLines := []string{strings.Repeat(" ", indent+2) + itemContent}
				subIdx := 0
				subVal, _ := parseYAMLBlock(subLines, &subIdx, indent+2)
				currentList = append(currentList, subVal)
			} else if itemContent == "" {
				// Nested block under list item
				subVal, err := parseYAMLBlock(lines, idx, indent+2)
				if err != nil {
					return nil, err
				}
				currentList = append(currentList, subVal)
			} else {
				currentList = append(currentList, parseYAMLScalar(itemContent))
			}
			continue
		}

		// Handle map key-value: key: value
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx != -1 {
			if currentList != nil {
				break
			}
			if currentMap == nil {
				currentMap = make(map[string]any)
			}

			key := strings.TrimSpace(trimmed[:colonIdx])
			valStr := strings.TrimSpace(trimmed[colonIdx+1:])
			*idx++

			if valStr == "" {
				// Nested block under this key
				nestedVal, err := parseYAMLBlock(lines, idx, indent+1)
				if err != nil {
					return nil, err
				}
				currentMap[key] = nestedVal
			} else if strings.HasPrefix(valStr, "{") && strings.HasSuffix(valStr, "}") {
				// Inline JSON object
				var inlineMap map[string]any
				if err := json.Unmarshal([]byte(valStr), &inlineMap); err == nil {
					currentMap[key] = inlineMap
				} else {
					currentMap[key] = parseYAMLScalar(valStr)
				}
			} else if strings.HasPrefix(valStr, "[") && strings.HasSuffix(valStr, "]") {
				// Inline JSON list
				var inlineList []any
				if err := json.Unmarshal([]byte(valStr), &inlineList); err == nil {
					currentMap[key] = inlineList
				} else {
					currentMap[key] = parseYAMLScalar(valStr)
				}
			} else {
				currentMap[key] = parseYAMLScalar(valStr)
			}
			continue
		}

		*idx++
	}

	if currentList != nil {
		return currentList, nil
	}
	if currentMap != nil {
		return currentMap, nil
	}
	return nil, nil
}

func countLeadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		if r == ' ' {
			count++
		} else if r == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}

func parseYAMLScalar(s string) any {
	s = strings.TrimSpace(s)
	// Strip inline comment if not quoted
	if !strings.HasPrefix(s, "\"") && !strings.HasPrefix(s, "'") {
		if idx := strings.Index(s, " #"); idx != -1 {
			s = strings.TrimSpace(s[:idx])
		}
	}

	if s == "true" || s == "True" {
		return true
	}
	if s == "false" || s == "False" {
		return false
	}
	if s == "null" || s == "~" || s == "" {
		return nil
	}

	// Integer
	if iVal, err := strconv.ParseInt(s, 10, 64); err == nil {
		return iVal
	}
	// Float
	if fVal, err := strconv.ParseFloat(s, 64); err == nil {
		return fVal
	}

	// Stripped quotes
	if (strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"")) || (strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
		if len(s) >= 2 {
			return s[1 : len(s)-1]
		}
	}

	return s
}
