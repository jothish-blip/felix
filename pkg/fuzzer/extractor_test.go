package fuzzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func TestExtract_NilRequest(t *testing.T) {
	pe := NewParameterExtractor()
	_, err := pe.Extract(nil)
	if err == nil {
		t.Fatal("expected error when extracting from nil request, got nil")
	}
}

func TestExtract_QueryParams(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = false // isolate query testing

	// Query with single keys, repeated keys, and URL-encoded values
	rawURL := "http://example.com/search?q=hello%20world&id=100&id=200&tag=security&empty=&uuid=123e4567-e89b-12d3-a456-426614174000"
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	expectedPaths := []string{
		"query:empty",
		"query:id[0]",
		"query:id[1]",
		"query:q",
		"query:tag",
		"query:uuid",
	}

	if len(params) != len(expectedPaths) {
		t.Fatalf("expected %d params, got %d", len(expectedPaths), len(params))
	}

	for i, expPath := range expectedPaths {
		if params[i].Path != expPath {
			t.Errorf("param[%d] path mismatch: expected %q, got %q", i, expPath, params[i].Path)
		}
	}

	// Verify specific values and classifications
	for _, p := range params {
		switch p.Path {
		case "query:q":
			if p.Value != "hello world" {
				t.Errorf("query:q value expected 'hello world', got %q", p.Value)
			}
		case "query:id[0]":
			if p.Value != "100" || p.Context != ContextNumeric {
				t.Errorf("query:id[0] expected '100' numeric, got %q (%s)", p.Value, p.Context)
			}
		case "query:id[1]":
			if p.Value != "200" || p.Context != ContextNumeric {
				t.Errorf("query:id[1] expected '200' numeric, got %q (%s)", p.Value, p.Context)
			}
		case "query:uuid":
			if p.Context != ContextUUID {
				t.Errorf("query:uuid expected uuid context, got %s", p.Context)
			}
		case "query:empty":
			if p.Value != "" || p.Context != ContextUnknown {
				t.Errorf("query:empty expected empty unknown, got %q (%s)", p.Value, p.Context)
			}
		}
	}
}

func TestExtract_Headers(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = true

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/api", nil)
	req.Header.Set("X-Api-Key", "secret-token-1234")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.Header.Set("User-Agent", "FELIX-Agent/3.0")
	req.Header.Set("Authorization", "Bearer dGVzdGluZ19iYXNlNjQ=")
	// Ignored protocol headers
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", "example.com")

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	foundHeaders := make(map[string]Parameter)
	for _, p := range params {
		if p.Location == LocHeader {
			foundHeaders[p.Name] = p
		}
	}

	// Verify protocol headers are excluded
	for _, ignored := range []string{"Host", "Content-Length", "Connection"} {
		if _, exists := foundHeaders[ignored]; exists {
			t.Errorf("protocol header %q should have been ignored", ignored)
		}
	}

	// Verify custom headers are extracted
	if p, ok := foundHeaders["X-Api-Key"]; !ok {
		t.Error("missing header X-Api-Key")
	} else {
		if !p.Sensitive {
			t.Error("X-Api-Key should be marked Sensitive")
		}
		if p.RedactedValue() != "[REDACTED]" {
			t.Errorf("X-Api-Key RedactedValue expected '[REDACTED]', got %q", p.RedactedValue())
		}
	}

	if p, ok := foundHeaders["Authorization"]; !ok {
		t.Error("missing header Authorization")
	} else if !p.Sensitive {
		t.Error("Authorization header should be marked Sensitive")
	}
}

func TestExtract_JSONBody(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = false

	jsonBody := `{
		"user": {
			"id": 42,
			"username": "admin",
			"email": "admin@example.com",
			"active": true,
			"profile": {
				"avatar_path": "/uploads/images/avatar.png",
				"bio": "Security Auditor"
			}
		},
		"roles": ["admin", "auditor"],
		"session_token": "dGVzdF9zZWNyZXRfdG9rZW4="
	}`

	req, _ := http.NewRequest(http.MethodPost, "http://example.com/api/users", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	paramMap := make(map[string]Parameter)
	for _, p := range params {
		paramMap[p.Path] = p
	}

	expectedContexts := map[string]ValueContext{
		"json:user.id":                  ContextNumeric,
		"json:user.username":            ContextAlphanumeric,
		"json:user.email":               ContextEmail,
		"json:user.profile.avatar_path": ContextFilePath,
		"json:roles[0]":                 ContextAlphanumeric,
		"json:roles[1]":                 ContextAlphanumeric,
		"json:session_token":            ContextBase64,
	}

	for path, expCtx := range expectedContexts {
		p, exists := paramMap[path]
		if !exists {
			t.Errorf("missing expected JSON parameter path: %q", path)
			continue
		}
		if p.Context != expCtx {
			t.Errorf("path %q: expected context %q, got %q", path, expCtx, p.Context)
		}
	}

	// Verify sensitivity
	if p, ok := paramMap["json:session_token"]; ok {
		if !p.Sensitive {
			t.Errorf("session_token should be marked Sensitive")
		}
	}
}

func TestExtract_GraphQLVariables(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = false

	graphqlPayload := `{
		"operationName": "GetPaste",
		"query": "query GetPaste($id: Int!, $filter: PasteFilter) { paste(id: $id, filter: $filter) { id title } }",
		"variables": {
			"id": 105,
			"filter": {
				"public": false,
				"owner": "DVGAUser"
			}
		}
	}`

	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:5013/graphql", strings.NewReader(graphqlPayload))
	req.Header.Set("Content-Type", "application/json")

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	var gqlParams []Parameter
	for _, p := range params {
		if p.Location == LocGraphQLVar {
			gqlParams = append(gqlParams, p)
		}
	}

	if len(gqlParams) == 0 {
		t.Fatal("expected GraphQL variable parameters, got 0")
	}

	gqlMap := make(map[string]Parameter)
	for _, p := range gqlParams {
		gqlMap[p.Path] = p
	}

	if p, ok := gqlMap["graphql:variables.id"]; !ok {
		t.Error("missing graphql:variables.id")
	} else if p.Value != "105" || p.Context != ContextNumeric {
		t.Errorf("graphql:variables.id expected '105' (numeric), got %q (%s)", p.Value, p.Context)
	}

	if p, ok := gqlMap["graphql:variables.filter.owner"]; !ok {
		t.Error("missing graphql:variables.filter.owner")
	} else if p.Value != "DVGAUser" || p.Context != ContextAlphanumeric {
		t.Errorf("graphql:variables.filter.owner expected 'DVGAUser' (alphanumeric), got %q (%s)", p.Value, p.Context)
	}
}

func TestExtract_FormUrlencoded(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = false

	formBody := "account=jim%40juice-sh.op&operator=OR&injection=1%3D1&tag=audit&tag=vapt"
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/WebGoat/SqlInjection/assignment5a", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	expectedPaths := []string{
		"form:account",
		"form:injection",
		"form:operator",
		"form:tag[0]",
		"form:tag[1]",
	}

	paramMap := make(map[string]Parameter)
	for _, p := range params {
		paramMap[p.Path] = p
	}

	for _, exp := range expectedPaths {
		if _, ok := paramMap[exp]; !ok {
			t.Errorf("missing expected form parameter path: %q", exp)
		}
	}

	if p, ok := paramMap["form:account"]; ok {
		if p.Value != "jim@juice-sh.op" || p.Context != ContextEmail {
			t.Errorf("form:account expected 'jim@juice-sh.op' (email), got %q (%s)", p.Value, p.Context)
		}
	}
}

func TestExtract_MultipartFormData(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = false

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	writer.WriteField("title", "Bug Bounty Report")
	writer.WriteField("severity", "High")

	fileWriter, err := writer.CreateFormFile("attachment", "vuln_poc.pdf")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	fileWriter.Write([]byte("%PDF-1.4 Mock PDF Content"))
	writer.Close()

	req, _ := http.NewRequest(http.MethodPost, "http://example.com/upload", &b)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	paramMap := make(map[string]Parameter)
	for _, p := range params {
		paramMap[p.Path] = p
	}

	if p, ok := paramMap["multipart:title"]; !ok {
		t.Error("missing multipart:title")
	} else if p.Value != "Bug Bounty Report" {
		t.Errorf("multipart:title value mismatch: %q", p.Value)
	}

	if p, ok := paramMap["multipart:attachment.filename"]; !ok {
		t.Error("missing multipart:attachment.filename")
	} else if p.Value != "vuln_poc.pdf" || p.Context != ContextFilePath {
		t.Errorf("multipart:attachment.filename expected 'vuln_poc.pdf' (file_path), got %q (%s)", p.Value, p.Context)
	}

	if p, ok := paramMap["multipart:attachment.content"]; !ok {
		t.Error("missing multipart:attachment.content")
	} else if !strings.Contains(p.Value, "%PDF-1.4") {
		t.Errorf("multipart:attachment.content missing PDF header: %q", p.Value)
	}
}

func TestExtract_XMLBody(t *testing.T) {
	pe := NewParameterExtractor()
	pe.IncludeHeaders = false

	xmlBody := `<root id="101" env="production">
		<user status="active">
			<name>John Doe</name>
			<email>john.doe@enterprise.com</email>
			<config key="timeout">30</config>
			<config key="retries">3</config>
		</user>
	</root>`

	req, _ := http.NewRequest(http.MethodPost, "http://example.com/api/xml", strings.NewReader(xmlBody))
	req.Header.Set("Content-Type", "application/xml")

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	paramMap := make(map[string]Parameter)
	for _, p := range params {
		paramMap[p.Path] = p
	}

	expectedPaths := []string{
		"xml:root@env",
		"xml:root@id",
		"xml:root.user@status",
		"xml:root.user.name",
		"xml:root.user.email",
		"xml:root.user.config[0]@key",
		"xml:root.user.config[0]",
		"xml:root.user.config[1]@key",
		"xml:root.user.config[1]",
	}

	for _, exp := range expectedPaths {
		if _, ok := paramMap[exp]; !ok {
			t.Errorf("missing expected XML parameter path: %q", exp)
		}
	}

	if p, ok := paramMap["xml:root.user.email"]; ok {
		if p.Value != "john.doe@enterprise.com" || p.Context != ContextEmail {
			t.Errorf("xml email expected 'john.doe@enterprise.com' (email), got %q (%s)", p.Value, p.Context)
		}
	}
	if p, ok := paramMap["xml:root@id"]; ok {
		if p.Value != "101" || p.Context != ContextNumeric {
			t.Errorf("xml root@id expected '101' (numeric), got %q (%s)", p.Value, p.Context)
		}
	}
}

func TestClassifyValue_Exhaustive(t *testing.T) {
	pe := NewParameterExtractor()

	tests := []struct {
		input    string
		expected ValueContext
	}{
		{"12345", ContextNumeric},
		{"-99", ContextNumeric},
		{"3.14159", ContextNumeric},
		{"0", ContextNumeric},
		{"admin", ContextAlphanumeric},
		{"user_account_99", ContextAlphanumeric},
		{"test@example.com", ContextEmail},
		{"firstname.lastname+tag@sub.domain.org", ContextEmail},
		{"123e4567-e89b-12d3-a456-426614174000", ContextUUID},
		{"C02G8416-XXXX-XXXX-XXXX-XXXXXXXXXXXX", ContextUnknown}, // invalid hex
		{"/etc/passwd", ContextFilePath},
		{"/var/log/nginx/access.log", ContextFilePath},
		{`C:\Windows\System32\drivers\etc\hosts`, ContextFilePath},
		{"../../config.json", ContextFilePath},
		{"./local/script.sh", ContextFilePath},
		{"aGVsbG8gd29ybGQ=", ContextBase64},          // "hello world"
		{"dGVzdGluZ19iYXNlNjQ=", ContextBase64},      // "testing_base64"
		{"", ContextUnknown},
		{"!@#$%^&*()_+", ContextUnknown},
		{"Hello World with Spaces", ContextUnknown},
	}

	for _, tt := range tests {
		got := pe.ClassifyValue(tt.input)
		if got != tt.expected {
			t.Errorf("ClassifyValue(%q): expected %q, got %q", tt.input, tt.expected, got)
		}
	}
}

func TestExtract_MalformedInputs_NoPanics(t *testing.T) {
	pe := NewParameterExtractor()

	malformedCases := []struct {
		name        string
		contentType string
		body        string
	}{
		{"Malformed JSON", "application/json", `{"key": "val", broken: true`},
		{"Malformed XML", "application/xml", `<root><unclosed>text</root>`},
		{"Malformed Multipart", "multipart/form-data; boundary=myboundary", `--myboundary\nContent-Disposition: form-data`},
	}

	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://example.com/test", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)

			// Must not panic, must return non-nil error
			params, err := pe.Extract(req)
			if err == nil {
				t.Errorf("%s: expected error on malformed body, got nil (params: %v)", tc.name, params)
			}
		})
	}
}

func TestGenerateMutation_QueryIsolationAndPreservation(t *testing.T) {
	pe := NewParameterExtractor()
	rawURL := "http://example.com/search?category=books&page=1&sort=asc"
	origReq, _ := http.NewRequest(http.MethodGet, rawURL, nil)

	params, err := pe.Extract(origReq)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	var targetParam Parameter
	for _, p := range params {
		if p.Path == "query:page" {
			targetParam = p
			break
		}
	}
	if targetParam.Path == "" {
		t.Fatal("could not find target query:page")
	}

	payload := "1' OR '1'='1"
	mutatedReq, err := pe.GenerateMutation(origReq, targetParam, payload)
	if err != nil {
		t.Fatalf("GenerateMutation failed: %v", err)
	}

	// 1. Verify target parameter was mutated
	q := mutatedReq.URL.Query()
	if q.Get("page") != payload {
		t.Errorf("target param 'page' expected %q, got %q", payload, q.Get("page"))
	}

	// 2. Verify non-target parameters remain 100% intact
	if q.Get("category") != "books" {
		t.Errorf("non-target 'category' was corrupted: got %q", q.Get("category"))
	}
	if q.Get("sort") != "asc" {
		t.Errorf("non-target 'sort' was corrupted: got %q", q.Get("sort"))
	}

	// 3. Verify original request was not modified in-place
	origQ := origReq.URL.Query()
	if origQ.Get("page") != "1" {
		t.Errorf("original request was mutated in-place: page is now %q", origQ.Get("page"))
	}
}

func TestGenerateMutation_JSONIsolationAndPreservation(t *testing.T) {
	pe := NewParameterExtractor()
	jsonBody := `{
		"account": {
			"id": 1001,
			"details": {
				"plan": "premium",
				"status": "active"
			}
		},
		"tags": ["prod", "finance"],
		"version": 2
	}`

	origReq, _ := http.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(jsonBody))
	origReq.Header.Set("Content-Type", "application/json")

	params, err := pe.Extract(origReq)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	var targetParam Parameter
	for _, p := range params {
		if p.Path == "json:account.details.plan" {
			targetParam = p
			break
		}
	}
	if targetParam.Path == "" {
		t.Fatal("could not find target json:account.details.plan")
	}

	payload := "' OR 1=1--"
	mutatedReq, err := pe.GenerateMutation(origReq, targetParam, payload)
	if err != nil {
		t.Fatalf("GenerateMutation failed: %v", err)
	}

	mutatedBytes, _ := io.ReadAll(mutatedReq.Body)
	var mutatedObj map[string]any
	if err := json.Unmarshal(mutatedBytes, &mutatedObj); err != nil {
		t.Fatalf("mutated JSON is malformed: %v", err)
	}

	// 1. Verify target mutation
	account := mutatedObj["account"].(map[string]any)
	details := account["details"].(map[string]any)
	if details["plan"] != payload {
		t.Errorf("target plan expected %q, got %v", payload, details["plan"])
	}

	// 2. Verify non-target nested preservation
	if details["status"] != "active" {
		t.Errorf("non-target status corrupted: got %v", details["status"])
	}
	if fmt.Sprintf("%v", account["id"]) != "1001" {
		t.Errorf("non-target account.id corrupted: got %v", account["id"])
	}
	tags := mutatedObj["tags"].([]any)
	if len(tags) != 2 || tags[0] != "prod" || tags[1] != "finance" {
		t.Errorf("non-target tags array corrupted: %v", tags)
	}

	// 3. Verify original body is untouched
	origBytes, _ := io.ReadAll(origReq.Body)
	var origObj map[string]any
	json.Unmarshal(origBytes, &origObj)
	origPlan := origObj["account"].(map[string]any)["details"].(map[string]any)["plan"]
	if origPlan != "premium" {
		t.Errorf("original plan was mutated in-place: %v", origPlan)
	}
}

func TestGenerateMutation_GraphQLVariableIsolation(t *testing.T) {
	pe := NewParameterExtractor()
	gqlBody := `{
		"query": "query GetUser($id: Int!, $type: String) { user(id: $id, type: $type) { name } }",
		"variables": {
			"id": 55,
			"type": "regular"
		}
	}`

	origReq, _ := http.NewRequest(http.MethodPost, "http://example.com/graphql", strings.NewReader(gqlBody))
	origReq.Header.Set("Content-Type", "application/json")

	params, err := pe.Extract(origReq)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	var targetParam Parameter
	for _, p := range params {
		if p.Path == "graphql:variables.id" {
			targetParam = p
			break
		}
	}
	if targetParam.Path == "" {
		t.Fatal("could not find target graphql:variables.id")
	}

	payload := "55 OR 1=1"
	mutatedReq, err := pe.GenerateMutation(origReq, targetParam, payload)
	if err != nil {
		t.Fatalf("GenerateMutation failed: %v", err)
	}

	mutatedBytes, _ := io.ReadAll(mutatedReq.Body)
	var mutatedObj map[string]any
	json.Unmarshal(mutatedBytes, &mutatedObj)

	// Check variable was mutated
	vars := mutatedObj["variables"].(map[string]any)
	if vars["id"] != payload {
		t.Errorf("target variable id expected %q, got %v", payload, vars["id"])
	}
	// Check other variable preserved
	if vars["type"] != "regular" {
		t.Errorf("non-target variable type corrupted: got %v", vars["type"])
	}
	// Check query string preserved
	if !strings.Contains(mutatedObj["query"].(string), "GetUser") {
		t.Errorf("query string was corrupted: %v", mutatedObj["query"])
	}
}

func TestGenerateMutation_XMLPreservation(t *testing.T) {
	pe := NewParameterExtractor()
	xmlBody := `<catalog id="cat1"><item sku="SKU99"><price>49.99</price><stock>10</stock></item></catalog>`

	origReq, _ := http.NewRequest(http.MethodPost, "http://example.com/api/xml", strings.NewReader(xmlBody))
	origReq.Header.Set("Content-Type", "application/xml")

	params, err := pe.Extract(origReq)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	var targetParam Parameter
	for _, p := range params {
		if p.Path == "xml:catalog.item.price" {
			targetParam = p
			break
		}
	}
	if targetParam.Path == "" {
		t.Fatal("could not find target xml:catalog.item.price")
	}

	payload := "0.01' UNION SELECT 1--"
	mutatedReq, err := pe.GenerateMutation(origReq, targetParam, payload)
	if err != nil {
		t.Fatalf("GenerateMutation failed: %v", err)
	}

	mutatedBytes, _ := io.ReadAll(mutatedReq.Body)
	mutatedStr := string(mutatedBytes)

	if !strings.Contains(mutatedStr, "<price>0.01&#39; UNION SELECT 1--</price>") &&
		!strings.Contains(mutatedStr, "<price>0.01' UNION SELECT 1--</price>") {
		t.Errorf("target XML price element not mutated correctly: %s", mutatedStr)
	}
	if !strings.Contains(mutatedStr, `<item sku="SKU99">`) {
		t.Errorf("non-target XML attribute sku corrupted: %s", mutatedStr)
	}
	if !strings.Contains(mutatedStr, "<stock>10</stock>") {
		t.Errorf("non-target XML stock element corrupted: %s", mutatedStr)
	}
}

func TestGenerateMutation_MultipartPreservation(t *testing.T) {
	pe := NewParameterExtractor()
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	writer.WriteField("username", "alice")
	writer.WriteField("role", "member")
	filePart, _ := writer.CreateFormFile("document", "contract.pdf")
	filePart.Write([]byte("Initial contract content"))
	writer.Close()

	origReq, _ := http.NewRequest(http.MethodPost, "http://example.com/upload", &b)
	origReq.Header.Set("Content-Type", writer.FormDataContentType())

	params, err := pe.Extract(origReq)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	var targetParam Parameter
	for _, p := range params {
		if p.Path == "multipart:role" {
			targetParam = p
			break
		}
	}
	if targetParam.Path == "" {
		t.Fatal("could not find target multipart:role")
	}

	payload := "admin"
	mutatedReq, err := pe.GenerateMutation(origReq, targetParam, payload)
	if err != nil {
		t.Fatalf("GenerateMutation failed: %v", err)
	}

	// Re-parse mutated multipart body
	mutatedParams, err := pe.Extract(mutatedReq)
	if err != nil {
		t.Fatalf("Extract mutated multipart failed: %v", err)
	}

	mMap := make(map[string]Parameter)
	for _, p := range mutatedParams {
		mMap[p.Path] = p
	}

	if mMap["multipart:role"].Value != "admin" {
		t.Errorf("target multipart:role expected 'admin', got %q", mMap["multipart:role"].Value)
	}
	if mMap["multipart:username"].Value != "alice" {
		t.Errorf("non-target multipart:username corrupted: got %q", mMap["multipart:username"].Value)
	}
	if mMap["multipart:document.filename"].Value != "contract.pdf" {
		t.Errorf("non-target multipart filename corrupted: got %q", mMap["multipart:document.filename"].Value)
	}
	if !strings.Contains(mMap["multipart:document.content"].Value, "Initial contract content") {
		t.Errorf("non-target multipart file content corrupted")
	}
}
