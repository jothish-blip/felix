package fuzzer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ParamLocation indicates the request segment where a parameter resides.
type ParamLocation string

const (
	LocQuery      ParamLocation = "QUERY"
	LocHeader     ParamLocation = "HEADER"
	LocForm       ParamLocation = "FORM"
	LocJSON       ParamLocation = "JSON"
	LocXML        ParamLocation = "XML"
	LocMultipart  ParamLocation = "MULTIPART"
	LocGraphQLVar ParamLocation = "GRAPHQL_VARIABLE"
)

// ValueContext classifies the semantic or structural context of a parameter value.
type ValueContext string

const (
	ContextNumeric      ValueContext = "numeric"
	ContextAlphanumeric ValueContext = "alphanumeric string"
	ContextEmail        ValueContext = "email"
	ContextUUID         ValueContext = "uuid"
	ContextFilePath     ValueContext = "file_path"
	ContextBase64       ValueContext = "base64"
	ContextUnknown      ValueContext = "unknown"
)

// Common validation regexes
var (
	uuidRegex   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	emailRegex  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	numRegex    = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
	alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	base64Regex = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

// Hop-by-hop and purely protocol headers to exclude from parameter fuzzing.
var defaultIgnoredHeaders = map[string]bool{
	"host":                      true,
	"content-length":            true,
	"connection":                true,
	"keep-alive":                true,
	"proxy-authenticate":        true,
	"proxy-authorization":       true,
	"te":                        true,
	"trailer":                   true,
	"transfer-encoding":         true,
	"upgrade":                   true,
	"accept-encoding":           true,
	"content-type":              true,
	"sec-websocket-key":         true,
	"sec-websocket-version":     true,
	"sec-websocket-extensions":  true,
}

// Parameter represents an extracted targetable input vector.
type Parameter struct {
	Path      string        `json:"path"`
	Name      string        `json:"name"`
	Location  ParamLocation `json:"location"`
	Value     string        `json:"value"`
	RawValue  any           `json:"raw_value,omitempty"`
	Context   ValueContext  `json:"context"`
	Sensitive bool          `json:"sensitive"`
	Index     int           `json:"index,omitempty"`
}

// RedactedValue returns a safe-to-log string representation.
func (p Parameter) RedactedValue() string {
	if p.Sensitive {
		return "[REDACTED]"
	}
	return p.Value
}

// ParameterExtractor handles robust input discovery, classification, and non-destructive mutation.
type ParameterExtractor struct {
	IncludeHeaders   bool
	IgnoredHeaders   map[string]bool
	SensitivePattern *regexp.Regexp
}

// NewParameterExtractor constructs a configured ParameterExtractor.
func NewParameterExtractor() *ParameterExtractor {
	return &ParameterExtractor{
		IncludeHeaders: true,
		IgnoredHeaders: defaultIgnoredHeaders,
		SensitivePattern: regexp.MustCompile(
			`(?i)(password|passwd|secret|token|api[-_]?key|auth|bearer|credential|session|jwt|credit[-_]?card|ssn)`,
		),
	}
}

// Extract analyzes an HTTP request and extracts all candidate parameter targets.
func (pe *ParameterExtractor) Extract(req *http.Request) ([]Parameter, error) {
	if req == nil {
		return nil, errors.New("cannot extract parameters from nil request")
	}

	var params []Parameter

	// 1. Query parameters
	if req.URL != nil && req.URL.RawQuery != "" {
		queryParams, err := pe.extractQueryParams(req.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to extract query parameters: %w", err)
		}
		params = append(params, queryParams...)
	}

	// 2. HTTP Headers
	if pe.IncludeHeaders && len(req.Header) > 0 {
		headerParams := pe.extractHeaders(req.Header)
		params = append(params, headerParams...)
	}

	// 3. Body parameters
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		// Restore body reader for downstream callers
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			contentType := req.Header.Get("Content-Type")
			bodyParams, err := pe.extractBodyParams(bodyBytes, contentType, req.URL)
			if err != nil {
				return nil, err
			}
			params = append(params, bodyParams...)
		}
	}

	// Sort parameters deterministically by path
	sort.Slice(params, func(i, j int) bool {
		return params[i].Path < params[j].Path
	})

	return params, nil
}

// extractQueryParams parses URL query parameters, preserving order and repeated keys.
func (pe *ParameterExtractor) extractQueryParams(u *url.URL) ([]Parameter, error) {
	var params []Parameter
	rawQuery := u.RawQuery

	for len(rawQuery) > 0 {
		var key string
		key, rawQuery, _ = strings.Cut(rawQuery, "&")
		if key == "" {
			continue
		}
		k, v, _ := strings.Cut(key, "=")
		decK, errK := url.QueryUnescape(k)
		if errK != nil {
			decK = k
		}
		decV, errV := url.QueryUnescape(v)
		if errV != nil {
			decV = v
		}

		params = append(params, Parameter{
			Name:      decK,
			Location:  LocQuery,
			Value:     decV,
			Context:   pe.ClassifyValue(decV),
			Sensitive: pe.isSensitive(decK),
		})
	}

	// Assign unambiguous paths, indexing repeated keys: query:id[0], query:id[1]
	keyCounts := make(map[string]int)
	for _, p := range params {
		keyCounts[p.Name]++
	}

	keyIndices := make(map[string]int)
	for i := range params {
		k := params[i].Name
		if keyCounts[k] > 1 {
			idx := keyIndices[k]
			params[i].Path = fmt.Sprintf("query:%s[%d]", k, idx)
			params[i].Index = idx
			keyIndices[k]++
		} else {
			params[i].Path = fmt.Sprintf("query:%s", k)
		}
	}

	return params, nil
}

// extractHeaders extracts candidate custom and non-protocol headers.
func (pe *ParameterExtractor) extractHeaders(headers http.Header) []Parameter {
	var params []Parameter
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		lowerK := strings.ToLower(k)
		if pe.IgnoredHeaders[lowerK] {
			continue
		}
		vals := headers[k]
		if len(vals) == 1 {
			params = append(params, Parameter{
				Path:      fmt.Sprintf("header:%s", k),
				Name:      k,
				Location:  LocHeader,
				Value:     vals[0],
				Context:   pe.ClassifyValue(vals[0]),
				Sensitive: pe.isSensitive(k),
			})
		} else {
			for i, v := range vals {
				params = append(params, Parameter{
					Path:      fmt.Sprintf("header:%s[%d]", k, i),
					Name:      k,
					Location:  LocHeader,
					Value:     v,
					Index:     i,
					Context:   pe.ClassifyValue(v),
					Sensitive: pe.isSensitive(k),
				})
			}
		}
	}
	return params
}

// extractBodyParams identifies format and delegates to format-specific extractors.
func (pe *ParameterExtractor) extractBodyParams(body []byte, contentType string, u *url.URL) ([]Parameter, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}

	mediaType := ""
	var mediaParams map[string]string
	if contentType != "" {
		var err error
		mediaType, mediaParams, err = mime.ParseMediaType(contentType)
		if err != nil {
			mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
		}
	}

	switch {
	case mediaType == "application/x-www-form-urlencoded" || (mediaType == "" && looksLikeForm(trimmed)):
		return pe.extractFormBody(trimmed)
	case mediaType == "multipart/form-data":
		boundary := ""
		if mediaParams != nil {
			boundary = mediaParams["boundary"]
		}
		if boundary == "" {
			return nil, errors.New("multipart/form-data missing boundary parameter")
		}
		return pe.extractMultipartBody(trimmed, boundary)
	case mediaType == "application/json" || mediaType == "text/json" || strings.HasSuffix(mediaType, "+json") || (mediaType == "" && (trimmed[0] == '{' || trimmed[0] == '[')):
		return pe.extractJSONBody(trimmed, u)
	case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml") || (mediaType == "" && trimmed[0] == '<'):
		return pe.extractXMLBody(trimmed)
	default:
		// Try heuristic detection if media type was unknown or generic text/plain
		if trimmed[0] == '{' || trimmed[0] == '[' {
			return pe.extractJSONBody(trimmed, u)
		}
		if trimmed[0] == '<' {
			return pe.extractXMLBody(trimmed)
		}
		if looksLikeForm(trimmed) {
			return pe.extractFormBody(trimmed)
		}
		return nil, nil
	}
}

// looksLikeForm evaluates whether body is urlencoded key-value pairs without json/xml characters.
func looksLikeForm(body []byte) bool {
	s := string(body)
	if strings.ContainsAny(s, "{}[];\"'<>") {
		return false
	}
	return strings.Contains(s, "=")
}

// extractFormBody parses urlencoded form inputs.
func (pe *ParameterExtractor) extractFormBody(body []byte) ([]Parameter, error) {
	var params []Parameter
	raw := string(body)

	for len(raw) > 0 {
		var part string
		part, raw, _ = strings.Cut(raw, "&")
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		decK, errK := url.QueryUnescape(k)
		if errK != nil {
			decK = k
		}
		decV, errV := url.QueryUnescape(v)
		if errV != nil {
			decV = v
		}

		params = append(params, Parameter{
			Name:      decK,
			Location:  LocForm,
			Value:     decV,
			Context:   pe.ClassifyValue(decV),
			Sensitive: pe.isSensitive(decK),
		})
	}

	keyCounts := make(map[string]int)
	for _, p := range params {
		keyCounts[p.Name]++
	}

	keyIndices := make(map[string]int)
	for i := range params {
		k := params[i].Name
		if keyCounts[k] > 1 {
			idx := keyIndices[k]
			params[i].Path = fmt.Sprintf("form:%s[%d]", k, idx)
			params[i].Index = idx
			keyIndices[k]++
		} else {
			params[i].Path = fmt.Sprintf("form:%s", k)
		}
	}

	return params, nil
}

// extractMultipartBody parses multipart/form-data fields and uploaded files.
func (pe *ParameterExtractor) extractMultipartBody(body []byte, boundary string) ([]Parameter, error) {
	var params []Parameter
	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed multipart payload: %w", err)
		}

		formName := part.FormName()
		fileName := part.FileName()
		data, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("error reading multipart field %q: %w", formName, err)
		}

		if fileName != "" {
			// File upload: extract filename and content
			params = append(params, Parameter{
				Path:      fmt.Sprintf("multipart:%s.filename", formName),
				Name:      fmt.Sprintf("%s.filename", formName),
				Location:  LocMultipart,
				Value:     fileName,
				Context:   pe.ClassifyValue(fileName),
				Sensitive: pe.isSensitive(formName),
			})
			params = append(params, Parameter{
				Path:      fmt.Sprintf("multipart:%s.content", formName),
				Name:      fmt.Sprintf("%s.content", formName),
				Location:  LocMultipart,
				Value:     string(data),
				Context:   pe.ClassifyValue(string(data)),
				Sensitive: pe.isSensitive(formName),
			})
		} else {
			// Regular text form field
			valStr := string(data)
			params = append(params, Parameter{
				Path:      fmt.Sprintf("multipart:%s", formName),
				Name:      formName,
				Location:  LocMultipart,
				Value:     valStr,
				Context:   pe.ClassifyValue(valStr),
				Sensitive: pe.isSensitive(formName),
			})
		}
	}

	return params, nil
}

// extractJSONBody recursively walks JSON and identifies GraphQL variables when applicable.
func (pe *ParameterExtractor) extractJSONBody(body []byte, u *url.URL) ([]Parameter, error) {
	var parsed any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("malformed JSON body: %w", err)
	}

	var params []Parameter

	// Detect GraphQL payload: either URL path contains /graphql or JSON contains a "query" string field
	isGraphQL := false
	if u != nil && strings.Contains(strings.ToLower(u.Path), "graphql") {
		isGraphQL = true
	}

	if obj, ok := parsed.(map[string]any); ok {
		if _, hasQuery := obj["query"]; hasQuery {
			isGraphQL = true
		}
		if isGraphQL {
			// Extract variables object as LocGraphQLVar
			if vars, hasVars := obj["variables"]; hasVars && vars != nil {
				pe.walkJSON(vars, "graphql:variables.", "variables", LocGraphQLVar, &params)
			}
			// Extract operationName if present
			if op, hasOp := obj["operationName"]; hasOp && op != nil {
				if opStr, isStr := op.(string); isStr {
					params = append(params, Parameter{
						Path:      "graphql:operationName",
						Name:      "operationName",
						Location:  LocGraphQLVar,
						Value:     opStr,
						RawValue:  op,
						Context:   pe.ClassifyValue(opStr),
						Sensitive: false,
					})
				}
			}
			// Extract query string as json:query
			if q, hasQ := obj["query"]; hasQ && q != nil {
				if qStr, isStr := q.(string); isStr {
					params = append(params, Parameter{
						Path:      "json:query",
						Name:      "query",
						Location:  LocJSON,
						Value:     qStr,
						RawValue:  q,
						Context:   pe.ClassifyValue(qStr),
						Sensitive: false,
					})
				}
			}
			// Extract other top-level keys if any
			for k, v := range obj {
				if k != "variables" && k != "operationName" && k != "query" {
					pe.walkJSON(v, "json:"+k, k, LocJSON, &params)
				}
			}
			return params, nil
		}
	}

	// Always extract standard JSON parameters across the whole payload
	pe.walkJSON(parsed, "json:", "", LocJSON, &params)

	return params, nil
}

// walkJSON recursively descends into JSON structures to locate targetable leaf parameters.
func (pe *ParameterExtractor) walkJSON(node any, prefix string, name string, loc ParamLocation, out *[]Parameter) {
	switch val := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var newPrefix string
			if prefix == "" {
				newPrefix = k
			} else if strings.HasSuffix(prefix, ":") || strings.HasSuffix(prefix, ".") {
				newPrefix = prefix + k
			} else {
				newPrefix = fmt.Sprintf("%s.%s", prefix, k)
			}
			pe.walkJSON(val[k], newPrefix, k, loc, out)
		}
	case []any:
		for i, item := range val {
			newPrefix := fmt.Sprintf("%s[%d]", prefix, i)
			pe.walkJSON(item, newPrefix, fmt.Sprintf("%s[%d]", name, i), loc, out)
		}
	default:
		// Leaf primitive node (string, json.Number, bool, nil)
		valStr := ""
		if val != nil {
			valStr = fmt.Sprintf("%v", val)
		}
		*out = append(*out, Parameter{
			Path:      prefix,
			Name:      name,
			Location:  loc,
			Value:     valStr,
			RawValue:  val,
			Context:   pe.ClassifyValue(valStr),
			Sensitive: pe.isSensitive(name),
		})
	}
}

// XMLNode represents a node in an XML DOM tree for traversal and mutation.
type XMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr
	Content  string
	Children []*XMLNode
}

// extractXMLBody parses XML element text and attributes.
func (pe *ParameterExtractor) extractXMLBody(body []byte) ([]Parameter, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var root *XMLNode
	var stack []*XMLNode

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed XML body: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			node := &XMLNode{
				XMLName: t.Name,
				Attrs:   t.Attr,
			}
			if len(stack) == 0 {
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				text := string(bytes.TrimSpace(t))
				if text != "" {
					stack[len(stack)-1].Content += text
				}
			}
		}
	}

	if root == nil {
		return nil, nil
	}

	var params []Parameter
	pe.walkXML(root, "xml:"+root.XMLName.Local, &params)
	return params, nil
}

// walkXML recursively walks XML elements and attributes.
func (pe *ParameterExtractor) walkXML(node *XMLNode, prefix string, out *[]Parameter) {
	// 1. Attributes
	for _, attr := range node.Attrs {
		attrPath := fmt.Sprintf("%s@%s", prefix, attr.Name.Local)
		*out = append(*out, Parameter{
			Path:      attrPath,
			Name:      attr.Name.Local,
			Location:  LocXML,
			Value:     attr.Value,
			Context:   pe.ClassifyValue(attr.Value),
			Sensitive: pe.isSensitive(attr.Name.Local),
		})
	}

	// 2. Leaf content
	if len(node.Children) == 0 {
		*out = append(*out, Parameter{
			Path:      prefix,
			Name:      node.XMLName.Local,
			Location:  LocXML,
			Value:     node.Content,
			Context:   pe.ClassifyValue(node.Content),
			Sensitive: pe.isSensitive(node.XMLName.Local),
		})
		return
	}

	// 3. Children with disambiguated paths
	childCounts := make(map[string]int)
	for _, child := range node.Children {
		childCounts[child.XMLName.Local]++
	}

	childIndices := make(map[string]int)
	for _, child := range node.Children {
		name := child.XMLName.Local
		var childPrefix string
		if childCounts[name] > 1 {
			idx := childIndices[name]
			childPrefix = fmt.Sprintf("%s.%s[%d]", prefix, name, idx)
			childIndices[name]++
		} else {
			childPrefix = fmt.Sprintf("%s.%s", prefix, name)
		}
		pe.walkXML(child, childPrefix, out)
	}
}

// ClassifyValue classifies a parameter value conservatively into one of the designated categories.
func (pe *ParameterExtractor) ClassifyValue(val string) ValueContext {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return ContextUnknown
	}

	// 1. UUID Check
	if uuidRegex.MatchString(trimmed) {
		return ContextUUID
	}

	// 2. Email Check
	if emailRegex.MatchString(trimmed) {
		return ContextEmail
	}

	// 3. Numeric Check (Integer or Floating Point)
	if numRegex.MatchString(trimmed) {
		return ContextNumeric
	}

	// 4. File Path Check
	if isFilePath(trimmed) {
		return ContextFilePath
	}

	// 5. Base64 Check (Must be >= 8 bytes, valid base64 chars, and decode without error)
	if len(trimmed) >= 8 && len(trimmed)%4 == 0 && base64Regex.MatchString(trimmed) {
		if dec, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(dec) > 0 {
			// Require mixed character sets or symbols to distinguish from plain alphanumeric words
			hasUpper := false
			hasLower := false
			hasDigit := false
			hasSymbol := strings.ContainsAny(trimmed, "+/=")
			for _, r := range trimmed {
				if r >= 'A' && r <= 'Z' {
					hasUpper = true
				} else if r >= 'a' && r <= 'z' {
					hasLower = true
				} else if r >= '0' && r <= '9' {
					hasDigit = true
				}
			}
			if (hasUpper && hasLower && hasDigit) || hasSymbol {
				return ContextBase64
			}
		}
	}

	// 6. Alphanumeric String Check
	if alphanumericRegex.MatchString(trimmed) {
		return ContextAlphanumeric
	}

	// Fallback conservative classification
	return ContextUnknown
}

// isFilePath evaluates standard filesystem path indicators.
func isFilePath(s string) bool {
	// Absolute Unix path
	if strings.HasPrefix(s, "/") && strings.Count(s, "/") >= 2 {
		return true
	}
	// Relative path
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, `.\`) || strings.HasPrefix(s, `..\`) {
		return true
	}
	// Windows absolute drive path
	if len(s) >= 3 && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	// Has standard file extension
	ext := filepath.Ext(s)
	if ext != "" {
		switch strings.ToLower(ext) {
		case ".txt", ".ini", ".conf", ".cfg", ".log", ".json", ".xml", ".html", ".htm",
			".php", ".jsp", ".py", ".rb", ".js", ".pdf", ".png", ".jpg", ".sh", ".bat", ".exe":
			return true
		}
	}
	return false
}

// isSensitive matches field names against known credential and token patterns.
func (pe *ParameterExtractor) isSensitive(name string) bool {
	if pe.SensitivePattern == nil {
		return false
	}
	return pe.SensitivePattern.MatchString(name)
}

// GenerateMutation creates a deep-cloned HTTP request with EXACTLY ONE targeted parameter replaced,
// guaranteeing 100% preservation of all non-target fields, headers, and nested structures.
func (pe *ParameterExtractor) GenerateMutation(orig *http.Request, target Parameter, payload string) (*http.Request, error) {
	if orig == nil {
		return nil, errors.New("cannot mutate nil request")
	}

	// Clone the base request structure
	clone := orig.Clone(orig.Context())

	// Deep clone URL
	if orig.URL != nil {
		clone.URL = new(url.URL)
		*clone.URL = *orig.URL
	}

	// Deep clone Headers
	clone.Header = make(http.Header)
	for k, vv := range orig.Header {
		newVV := make([]string, len(vv))
		copy(newVV, vv)
		clone.Header[k] = newVV
	}

	// 1. Target is a Query Parameter
	if target.Location == LocQuery {
		newQuery, err := pe.mutateQuery(orig.URL.RawQuery, target, payload)
		if err != nil {
			return nil, err
		}
		clone.URL.RawQuery = newQuery
		// If body existed in original, clone body bytes
		if orig.Body != nil {
			bodyBytes, _ := io.ReadAll(orig.Body)
			orig.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return clone, nil
	}

	// 2. Target is an HTTP Header
	if target.Location == LocHeader {
		pe.mutateHeader(clone.Header, target, payload)
		if orig.Body != nil {
			bodyBytes, _ := io.ReadAll(orig.Body)
			orig.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return clone, nil
	}

	// For body mutations, read original body
	var bodyBytes []byte
	if orig.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(orig.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body for mutation: %w", err)
		}
		orig.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	var mutatedBody []byte
	var mutatedContentType string

	switch target.Location {
	case LocForm:
		mutated, err := pe.mutateForm(bodyBytes, target, payload)
		if err != nil {
			return nil, err
		}
		mutatedBody = mutated

	case LocMultipart:
		contentType := orig.Header.Get("Content-Type")
		_, mediaParams, _ := mime.ParseMediaType(contentType)
		boundary := ""
		if mediaParams != nil {
			boundary = mediaParams["boundary"]
		}
		mutated, newContentType, err := pe.mutateMultipart(bodyBytes, boundary, target, payload)
		if err != nil {
			return nil, err
		}
		mutatedBody = mutated
		mutatedContentType = newContentType

	case LocJSON:
		mutated, err := pe.mutateJSON(bodyBytes, target, payload)
		if err != nil {
			return nil, err
		}
		mutatedBody = mutated

	case LocGraphQLVar:
		mutated, err := pe.mutateGraphQLVar(bodyBytes, target, payload)
		if err != nil {
			return nil, err
		}
		mutatedBody = mutated

	case LocXML:
		mutated, err := pe.mutateXML(bodyBytes, target, payload)
		if err != nil {
			return nil, err
		}
		mutatedBody = mutated

	default:
		return nil, fmt.Errorf("unsupported parameter location for mutation: %s", target.Location)
	}

	// Set mutated body and adjust headers
	clone.Body = io.NopCloser(bytes.NewReader(mutatedBody))
	clone.ContentLength = int64(len(mutatedBody))
	clone.Header.Set("Content-Length", strconv.Itoa(len(mutatedBody)))
	if mutatedContentType != "" {
		clone.Header.Set("Content-Type", mutatedContentType)
	}

	return clone, nil
}

// isRawPreEncoded checks if a payload is an already percent-encoded byte sequence (e.g. %2e%2e%2f)
// that should not be double-escaped, while ensuring raw payloads containing spaces, brackets, or angle brackets
// are safely query-escaped.
func isRawPreEncoded(s string) bool {
	if strings.ContainsAny(s, " <>\"'`{}") {
		return false
	}
	return strings.Contains(s, "%2e") || strings.Contains(s, "%2E") ||
		strings.Contains(s, "%2f") || strings.Contains(s, "%2F") ||
		strings.Contains(s, "%5c") || strings.Contains(s, "%5C") ||
		strings.Contains(s, "%25")
}

// mutateQuery swaps the target query parameter at its exact index.
func (pe *ParameterExtractor) mutateQuery(rawQuery string, target Parameter, payload string) (string, error) {
	type pair struct {
		key string
		val string
	}
	var pairs []pair
	rem := rawQuery
	for len(rem) > 0 {
		var part string
		part, rem, _ = strings.Cut(rem, "&")
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		decK, _ := url.QueryUnescape(k)
		decV, _ := url.QueryUnescape(v)
		pairs = append(pairs, pair{key: decK, val: decV})
	}

	keyIndex := 0
	targetPairIndex := -1
	found := false
	for i := range pairs {
		if pairs[i].key == target.Name {
			if keyIndex == target.Index {
				pairs[i].val = payload
				targetPairIndex = i
				found = true
				break
			}
			keyIndex++
		}
	}

	if !found {
		return "", fmt.Errorf("target query parameter %q (index %d) not found in query string", target.Name, target.Index)
	}

	var buf strings.Builder
	for i, p := range pairs {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(url.QueryEscape(p.key))
		buf.WriteByte('=')
		if i == targetPairIndex && isRawPreEncoded(p.val) {
			// Preserve pre-encoded injection payloads (e.g. %2e%2e%2f) without double-escaping
			buf.WriteString(p.val)
		} else {
			buf.WriteString(url.QueryEscape(p.val))
		}
	}
	return buf.String(), nil
}

// mutateHeader updates the specific header value or array item.
func (pe *ParameterExtractor) mutateHeader(headers http.Header, target Parameter, payload string) {
	for k, vv := range headers {
		if strings.EqualFold(k, target.Name) {
			if len(vv) > 1 && target.Index < len(vv) {
				vv[target.Index] = payload
			} else {
				headers[k] = []string{payload}
			}
			return
		}
	}
	headers.Set(target.Name, payload)
}

// mutateForm swaps the target form field value.
func (pe *ParameterExtractor) mutateForm(body []byte, target Parameter, payload string) ([]byte, error) {
	type pair struct {
		key string
		val string
	}
	var pairs []pair
	rem := string(body)
	for len(rem) > 0 {
		var part string
		part, rem, _ = strings.Cut(rem, "&")
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		decK, _ := url.QueryUnescape(k)
		decV, _ := url.QueryUnescape(v)
		pairs = append(pairs, pair{key: decK, val: decV})
	}

	keyIndex := 0
	found := false
	for i := range pairs {
		if pairs[i].key == target.Name {
			if keyIndex == target.Index {
				pairs[i].val = payload
				found = true
				break
			}
			keyIndex++
		}
	}

	if !found {
		return nil, fmt.Errorf("target form field %q (index %d) not found in form body", target.Name, target.Index)
	}

	var buf strings.Builder
	for i, p := range pairs {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(url.QueryEscape(p.key))
		buf.WriteByte('=')
		buf.WriteString(url.QueryEscape(p.val))
	}
	return []byte(buf.String()), nil
}

// mutateMultipart replaces target part content or filename, preserving all other parts.
func (pe *ParameterExtractor) mutateMultipart(body []byte, boundary string, target Parameter, payload string) ([]byte, string, error) {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("error reading multipart part: %w", err)
		}

		formName := part.FormName()
		fileName := part.FileName()
		data, err := io.ReadAll(part)
		if err != nil {
			return nil, "", fmt.Errorf("error reading part %q: %w", formName, err)
		}

		if fileName != "" {
			newFileName := fileName
			newData := data

			if target.Path == fmt.Sprintf("multipart:%s.filename", formName) {
				newFileName = payload
			} else if target.Path == fmt.Sprintf("multipart:%s.content", formName) {
				newData = []byte(payload)
			}

			// Preserve existing header fields if any
			h := make(textproto.MIMEHeader)
			for k, v := range part.Header {
				h[k] = v
			}
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, formName, newFileName))

			partWriter, err := writer.CreatePart(h)
			if err != nil {
				return nil, "", err
			}
			partWriter.Write(newData)
		} else {
			newData := data
			if target.Path == fmt.Sprintf("multipart:%s", formName) {
				newData = []byte(payload)
			}
			writer.WriteField(formName, string(newData))
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), writer.FormDataContentType(), nil
}

// mutateJSON deep-walks the JSON document and mutates the leaf identified by target.Path.
func (pe *ParameterExtractor) mutateJSON(body []byte, target Parameter, payload string) ([]byte, error) {
	var root any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("malformed JSON in mutation target: %w", err)
	}

	// Remove leading "json:" or "graphql:"
	path := target.Path
	if strings.HasPrefix(path, "json:") {
		path = strings.TrimPrefix(path, "json:")
	} else if strings.HasPrefix(path, "graphql:") {
		path = strings.TrimPrefix(path, "graphql:")
	}

	if path == "" {
		return json.Marshal(payload)
	}

	tokens := parsePathTokens(path)
	if err := updateJSONPath(&root, tokens, payload); err != nil {
		return nil, err
	}

	return json.Marshal(root)
}

// mutateGraphQLVar updates the specific variable within the "variables" JSON object.
func (pe *ParameterExtractor) mutateGraphQLVar(body []byte, target Parameter, payload string) ([]byte, error) {
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("malformed GraphQL JSON payload: %w", err)
	}

	if target.Path == "graphql:operationName" {
		root["operationName"] = payload
		return json.Marshal(root)
	}

	path := target.Path
	if strings.HasPrefix(path, "graphql:variables.") {
		path = strings.TrimPrefix(path, "graphql:variables.")
	} else if strings.HasPrefix(path, "graphql:") {
		path = strings.TrimPrefix(path, "graphql:")
	}

	vars, ok := root["variables"].(map[string]any)
	if !ok || vars == nil {
		vars = make(map[string]any)
		root["variables"] = vars
	}

	tokens := parsePathTokens(path)
	var anyVars any = vars
	if err := updateJSONPath(&anyVars, tokens, payload); err != nil {
		return nil, err
	}
	root["variables"] = anyVars

	return json.Marshal(root)
}

// pathToken represents a segment in a structured path (object key or array index).
type pathToken struct {
	key     string
	isArray bool
	index   int
}

// parsePathTokens splits paths like "user.profile.emails[0].address" into structured tokens.
func parsePathTokens(path string) []pathToken {
	var tokens []pathToken
	segments := strings.Split(path, ".")

	for _, seg := range segments {
		if !strings.Contains(seg, "[") {
			tokens = append(tokens, pathToken{key: seg})
			continue
		}

		// Handle array indexing: e.g. "emails[0]" or "[0]"
		key := seg[:strings.Index(seg, "[")]
		if key != "" {
			tokens = append(tokens, pathToken{key: key})
		}

		rem := seg[strings.Index(seg, "["):]
		for strings.HasPrefix(rem, "[") {
			end := strings.Index(rem, "]")
			if end == -1 {
				break
			}
			idxStr := rem[1:end]
			idx, _ := strconv.Atoi(idxStr)
			tokens = append(tokens, pathToken{isArray: true, index: idx})
			rem = rem[end+1:]
		}
	}

	return tokens
}

// updateJSONPath recursively updates a value in a nested map/slice structure.
func updateJSONPath(current *any, tokens []pathToken, payload string) error {
	if len(tokens) == 0 {
		*current = payload
		return nil
	}

	tok := tokens[0]
	rest := tokens[1:]

	if tok.isArray {
		slice, ok := (*current).([]any)
		if !ok {
			return fmt.Errorf("expected array at token index %d", tok.index)
		}
		if tok.index < 0 || tok.index >= len(slice) {
			return fmt.Errorf("array index %d out of bounds (len %d)", tok.index, len(slice))
		}
		if len(rest) == 0 {
			slice[tok.index] = payload
			return nil
		}
		elem := slice[tok.index]
		if err := updateJSONPath(&elem, rest, payload); err != nil {
			return err
		}
		slice[tok.index] = elem
		return nil
	}

	// Object key token
	obj, ok := (*current).(map[string]any)
	if !ok {
		return fmt.Errorf("expected object at key %q", tok.key)
	}

	if len(rest) == 0 {
		obj[tok.key] = payload
		return nil
	}

	val, exists := obj[tok.key]
	if !exists {
		return fmt.Errorf("key %q not found in JSON object", tok.key)
	}
	if err := updateJSONPath(&val, rest, payload); err != nil {
		return err
	}
	obj[tok.key] = val
	return nil
}

// mutateXML modifies an element content or attribute in an XML DOM structure.
func (pe *ParameterExtractor) mutateXML(body []byte, target Parameter, payload string) ([]byte, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var root *XMLNode
	var stack []*XMLNode

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed XML body: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			node := &XMLNode{
				XMLName: t.Name,
				Attrs:   t.Attr,
			}
			if len(stack) == 0 {
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				text := string(bytes.TrimSpace(t))
				if text != "" {
					stack[len(stack)-1].Content += text
				}
			}
		}
	}

	if root == nil {
		return nil, errors.New("empty or invalid XML root")
	}

	found := pe.mutateXMLNode(root, "xml:"+root.XMLName.Local, target.Path, payload)
	if !found {
		return nil, fmt.Errorf("target XML path %q not found in XML tree", target.Path)
	}

	return pe.renderXML(root), nil
}

// mutateXMLNode walks the node tree to locate and replace the targeted element text or attribute.
func (pe *ParameterExtractor) mutateXMLNode(node *XMLNode, prefix string, targetPath string, payload string) bool {
	// 1. Check attributes
	for i := range node.Attrs {
		attrPath := fmt.Sprintf("%s@%s", prefix, node.Attrs[i].Name.Local)
		if attrPath == targetPath {
			node.Attrs[i].Value = payload
			return true
		}
	}

	// 2. Leaf content
	if len(node.Children) == 0 {
		if prefix == targetPath {
			node.Content = payload
			return true
		}
		return false
	}

	// 3. Children
	childCounts := make(map[string]int)
	for _, child := range node.Children {
		childCounts[child.XMLName.Local]++
	}

	childIndices := make(map[string]int)
	for _, child := range node.Children {
		name := child.XMLName.Local
		var childPrefix string
		if childCounts[name] > 1 {
			idx := childIndices[name]
			childPrefix = fmt.Sprintf("%s.%s[%d]", prefix, name, idx)
			childIndices[name]++
		} else {
			childPrefix = fmt.Sprintf("%s.%s", prefix, name)
		}
		if pe.mutateXMLNode(child, childPrefix, targetPath, payload) {
			return true
		}
	}

	return false
}

// renderXML formats the XML DOM tree back into canonical XML bytes.
func (pe *ParameterExtractor) renderXML(node *XMLNode) []byte {
	var buf bytes.Buffer
	pe.writeXMLNode(&buf, node)
	return buf.Bytes()
}

func (pe *ParameterExtractor) writeXMLNode(buf *bytes.Buffer, node *XMLNode) {
	buf.WriteString("<")
	buf.WriteString(node.XMLName.Local)
	for _, attr := range node.Attrs {
		buf.WriteString(fmt.Sprintf(` %s="%s"`, attr.Name.Local, xmlEscape(attr.Value)))
	}

	if len(node.Children) == 0 && node.Content == "" {
		buf.WriteString("/>")
		return
	}

	buf.WriteString(">")
	if len(node.Children) > 0 {
		for _, child := range node.Children {
			pe.writeXMLNode(buf, child)
		}
	} else {
		buf.WriteString(xmlEscape(node.Content))
	}
	buf.WriteString(fmt.Sprintf("</%s>", node.XMLName.Local))
}

// xmlEscape handles special XML entities.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
