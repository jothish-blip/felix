package apk

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/report"
)

// encodeULEB128 encodes an unsigned integer into Little-Endian Base 128 bytes.
func encodeULEB128(val uint32) []byte {
	var out []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if val == 0 {
			break
		}
	}
	return out
}

// buildSyntheticDEX constructs a valid Dalvik Executable binary containing the specified string pool.
func buildSyntheticDEX(stringsList []string, version string) []byte {
	if version == "" {
		version = "035"
	}

	header := make([]byte, DEXHeaderSize)
	copy(header[0:4], []byte("dex\n"))
	copy(header[4:7], []byte(version))
	header[7] = 0

	// Endian tag
	binary.LittleEndian.PutUint32(header[0x28:0x2C], EndianConstant)
	// Header size
	binary.LittleEndian.PutUint32(header[0x24:0x28], DEXHeaderSize)

	stringCount := uint32(len(stringsList))
	stringIDsOff := uint32(DEXHeaderSize)
	binary.LittleEndian.PutUint32(header[0x38:0x3C], stringCount)
	binary.LittleEndian.PutUint32(header[0x3C:0x40], stringIDsOff)

	stringTableSize := stringCount * 4
	dataOffset := stringIDsOff + stringTableSize

	var stringTable bytes.Buffer
	var stringData bytes.Buffer

	for _, s := range stringsList {
		currentDataOff := dataOffset + uint32(stringData.Len())
		var offBytes [4]byte
		binary.LittleEndian.PutUint32(offBytes[:], currentDataOff)
		stringTable.Write(offBytes[:])

		// ULEB128 utf-16 len
		stringData.Write(encodeULEB128(uint32(len(s))))
		// MUTF-8 data
		stringData.WriteString(s)
		// Null terminator
		stringData.WriteByte(0x00)
	}

	totalSize := uint32(DEXHeaderSize) + stringTableSize + uint32(stringData.Len())
	binary.LittleEndian.PutUint32(header[0x20:0x24], totalSize)

	var dex bytes.Buffer
	dex.Write(header)
	dex.Write(stringTable.Bytes())
	dex.Write(stringData.Bytes())

	return dex.Bytes()
}

// ----------------------------------------------------------------------------
// DEX Parser Tests
// ----------------------------------------------------------------------------

func TestDEXParser_ValidVersions(t *testing.T) {
	versions := []string{"035", "037", "038", "039"}
	testStrings := []string{
		"Lcom/example/app/MainActivity;",
		"https://api.example.com/v1/auth",
		"AIzaSyD-1234567890abcdef1234567890abcdef",
		"AKIAIOSFODNN7EXAMPLE",
	}

	for _, v := range versions {
		t.Run("version_"+v, func(t *testing.T) {
			dexBytes := buildSyntheticDEX(testStrings, v)
			ctx := context.Background()
			limits := DefaultLimits()

			dexFile, err := ParseDEX(ctx, "classes.dex", dexBytes, limits)
			if err != nil {
				t.Fatalf("unexpected error parsing DEX v%s: %v", v, err)
			}
			if dexFile.Version != v {
				t.Errorf("expected version %s, got %s", v, dexFile.Version)
			}
			if dexFile.StringCount != len(testStrings) {
				t.Errorf("expected %d strings, got %d", len(testStrings), dexFile.StringCount)
			}
			if dexFile.Endian != "little-endian" {
				t.Errorf("expected little-endian, got %s", dexFile.Endian)
			}
		})
	}
}

func TestDEXParser_TruncatedAndMalformed(t *testing.T) {
	ctx := context.Background()
	limits := DefaultLimits()

	// 1. Data too small (< 112 bytes)
	_, err := ParseDEX(ctx, "classes.dex", []byte("dex\n035\x00short"), limits)
	if err == nil || !strings.Contains(err.Error(), "smaller than required header") {
		t.Errorf("expected truncated header error, got %v", err)
	}

	// 2. Invalid magic prefix
	badMagic := buildSyntheticDEX([]string{"hello"}, "035")
	copy(badMagic[0:4], []byte("bad\n"))
	_, err = ParseDEX(ctx, "classes.dex", badMagic, limits)
	if err == nil || !strings.Contains(err.Error(), "invalid DEX magic prefix") {
		t.Errorf("expected invalid magic error, got %v", err)
	}

	// 3. Unsupported version
	unsupportedVer := buildSyntheticDEX([]string{"hello"}, "040")
	_, err = ParseDEX(ctx, "classes.dex", unsupportedVer, limits)
	if err == nil || !strings.Contains(err.Error(), "unsupported DEX version") {
		t.Errorf("expected unsupported version error, got %v", err)
	}

	// 4. Declared file_size > actual bytes
	oversizedDecl := buildSyntheticDEX([]string{"hello"}, "035")
	binary.LittleEndian.PutUint32(oversizedDecl[0x20:0x24], uint32(len(oversizedDecl)+500))
	_, err = ParseDEX(ctx, "classes.dex", oversizedDecl, limits)
	if err == nil || !strings.Contains(err.Error(), "declared file_size") {
		t.Errorf("expected declared file_size exceeded error, got %v", err)
	}

	// 5. String IDs table offset out of bounds
	badTableOff := buildSyntheticDEX([]string{"hello"}, "035")
	binary.LittleEndian.PutUint32(badTableOff[0x3C:0x40], 0x100000)
	_, err = ParseDEX(ctx, "classes.dex", badTableOff, limits)
	if err == nil || !strings.Contains(err.Error(), "string_ids table") {
		t.Errorf("expected string_ids table bounds error, got %v", err)
	}

	// 6. Unterminated string data (missing null byte)
	unterminated := buildSyntheticDEX([]string{"my_string"}, "035")
	// Corrupt terminating null byte (last byte in file)
	unterminated[len(unterminated)-1] = 'A'
	_, err = ParseDEX(ctx, "classes.dex", unterminated, limits)
	if err == nil || !strings.Contains(err.Error(), "missing null terminator") {
		t.Errorf("expected unterminated string error, got %v", err)
	}
}

func TestDEXParser_LimitsAndCancellation(t *testing.T) {
	ctx := context.Background()

	// 1. Max strings limit
	smallLimits := DefaultLimits()
	smallLimits.MaxDEXStrings = 2
	dexBytes := buildSyntheticDEX([]string{"one", "two", "three", "four"}, "035")
	_, err := ParseDEX(ctx, "classes.dex", dexBytes, smallLimits)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("expected MaxDEXStrings limit exceeded error, got %v", err)
	}

	// 2. Cancellation
	cancellingCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ParseDEX(cancellingCtx, "classes.dex", dexBytes, DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("expected context cancelled error, got %v", err)
	}
}

// ----------------------------------------------------------------------------
// Embedded Configuration & Resource Analysis Tests
// ----------------------------------------------------------------------------

func TestArtifact_GoogleServicesJSON(t *testing.T) {
	rawJSON := `{
		"project_info": {
			"project_number": "123456789012",
			"project_id": "test-security-project",
			"storage_bucket": "test-security-project.appspot.com",
			"firebase_url": "https://test-security-project.firebaseio.com"
		},
		"client": [
			{
				"client_info": {
					"mobilesdk_app_id": "1:123456789012:android:abcdef0123456789",
					"android_client_info": {
						"package_name": "com.felix.testapp"
					}
				},
				"oauth_client": [
					{
						"client_id": "123456789012-abcdef123456789.apps.googleusercontent.com",
						"client_type": 3
					}
				],
				"api_key": [
					{
						"current_key": "AIzaSyC1234567890abcdef1234567890abcdef"
					}
				]
			}
		]
	}`

	tempDir := t.TempDir()
	ws, err := NewWorkspace(tempDir)
	if err != nil {
		t.Fatalf("failed creating workspace: %v", err)
	}
	defer ws.Close()

	// Write google-services.json to workspace
	gsPath := filepath.Join(ws.Dir, "google-services.json")
	if err := os.WriteFile(gsPath, []byte(rawJSON), 0600); err != nil {
		t.Fatalf("failed writing google-services.json: %v", err)
	}

	ctx := context.Background()
	limits := DefaultLimits()

	res, err := AnalyzeArtifacts(ctx, ws, limits)
	if err != nil {
		t.Fatalf("unexpected AnalyzeArtifacts error: %v", err)
	}

	// Verify Firebase service indicator
	var foundFirebase bool
	var foundGoogleKey bool
	for _, f := range res.Findings {
		if f.RuleID == "APK-ART-SERVICE-FIREBASE" {
			foundFirebase = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("Firebase service indicator must be INFO, got %s", f.Severity)
			}
			if !strings.Contains(f.Evidence, "test-security-project") {
				t.Errorf("Firebase observation missing project id: %s", f.Evidence)
			}
		}
		if f.RuleID == "APK-ART-SECRET-GOOGLE-KEY" {
			foundGoogleKey = true
			if f.Severity != report.SeverityMedium {
				t.Errorf("Google API key should be MEDIUM, got %s", f.Severity)
			}
			// Strict check: raw key MUST NOT be present in observation or details
			if strings.Contains(f.Evidence, "AIzaSyC1234567890abcdef1234567890abcdef") {
				t.Errorf("RAW SECRET LEAKED IN EVIDENCE: %s", f.Evidence)
			}
			if strings.Contains(f.EvidenceDetails.Details["redacted_value"], "AIzaSyC1234567890abcdef1234567890abcdef") {
				t.Errorf("RAW SECRET LEAKED IN DETAILS: %v", f.EvidenceDetails.Details)
			}
		}

		// Ensure public identifiers were NOT classified as secret exposures
		if strings.HasPrefix(f.RuleID, "APK-ART-SECRET-") {
			if strings.Contains(f.Title, "project_id") || strings.Contains(f.Title, "mobilesdk_app_id") || strings.Contains(f.Title, "client_id") {
				t.Errorf("Public identifier improperly marked as secret: %s", f.Title)
			}
		}
	}

	if !foundFirebase {
		t.Error("expected Firebase service indicator finding")
	}
	if !foundGoogleKey {
		t.Error("expected Google API key candidate finding")
	}
}

func TestArtifact_StringsXMLAndProperties(t *testing.T) {
	tempDir := t.TempDir()
	ws, err := NewWorkspace(tempDir)
	if err != nil {
		t.Fatalf("failed creating workspace: %v", err)
	}
	defer ws.Close()

	// 1. res/values/strings.xml
	resValuesDir := filepath.Join(ws.Dir, "res", "values")
	if err := os.MkdirAll(resValuesDir, 0700); err != nil {
		t.Fatalf("failed creating res/values: %v", err)
	}
	stringsXML := `<?xml version="1.0" encoding="utf-8"?>
	<resources>
		<string name="app_name">TestApp</string>
		<string name="server_endpoint">https://api.testservice.com/api/v1/mobile</string>
		<string name="graphql_url">https://api.testservice.com/graphql</string>
		<string name="aws_access_key">AKIAIOSFODNN7EXAMPLE</string>
	</resources>`
	if err := os.WriteFile(filepath.Join(resValuesDir, "strings.xml"), []byte(stringsXML), 0600); err != nil {
		t.Fatalf("failed writing strings.xml: %v", err)
	}

	// 2. assets/config.properties with database URI containing credentials
	assetsDir := filepath.Join(ws.Dir, "assets")
	if err := os.MkdirAll(assetsDir, 0700); err != nil {
		t.Fatalf("failed creating assets: %v", err)
	}
	propsContent := `
	# Database configuration
	mongodb.uri=mongodb://admin:SuperSecretPass123!@mongo.internal.net:27017/prod_db
	api.timeout=30
	redis.url=redis://:RedisToken999@cache.internal.net:6379
	`
	if err := os.WriteFile(filepath.Join(assetsDir, "config.properties"), []byte(propsContent), 0600); err != nil {
		t.Fatalf("failed writing config.properties: %v", err)
	}

	ctx := context.Background()
	limits := DefaultLimits()

	res, err := AnalyzeArtifacts(ctx, ws, limits)
	if err != nil {
		t.Fatalf("unexpected AnalyzeArtifacts error: %v", err)
	}

	var foundAWS bool
	var foundMongoCreds bool
	var foundMongoService bool
	var foundGraphQL bool
	var foundEndpoint bool

	for _, f := range res.Findings {
		if f.RuleID == "APK-ART-SECRET-AWS-KEY" {
			foundAWS = true
			if strings.Contains(f.Evidence, "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("Raw AWS key leaked in evidence: %s", f.Evidence)
			}
		}
		if f.RuleID == "APK-ART-SECRET-DB-URI" {
			foundMongoCreds = true
			if f.Severity != report.SeverityCritical {
				t.Errorf("Exposed DB URI must be CRITICAL severity, got %s", f.Severity)
			}
			// Verify credentials strictly redacted
			if strings.Contains(f.Evidence, "SuperSecretPass123!") || strings.Contains(f.Evidence, "RedisToken999") {
				t.Errorf("RAW DATABASE PASSWORD LEAKED: %s", f.Evidence)
			}
			if strings.Contains(f.EvidenceDetails.Details["sanitized_uri"], "SuperSecretPass123!") {
				t.Errorf("RAW PASSWORD IN SANITIZED URI: %v", f.EvidenceDetails.Details)
			}
		}
		if f.RuleID == "APK-ART-SERVICE-MONGODB" {
			foundMongoService = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("DB service indicator must be INFO, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-ART-GRAPHQL" {
			foundGraphQL = true
		}
		if f.RuleID == "APK-ART-API-ENDPOINT" || f.RuleID == "APK-ART-API-BASE-URL" {
			foundEndpoint = true
		}
	}

	if !foundAWS {
		t.Error("expected AWS Access Key finding")
	}
	if !foundMongoCreds {
		t.Error("expected Database URI with credentials finding")
	}
	if !foundMongoService {
		t.Error("expected MongoDB Service finding")
	}
	if !foundGraphQL {
		t.Error("expected GraphQL finding")
	}
	if !foundEndpoint {
		t.Error("expected API endpoint / base URL finding")
	}
}

func TestArtifact_SecretTypesAndMandatoryRedaction(t *testing.T) {
	mockStripe := "sk_live_" + "51Abcdefghijklmnopqrstuvwx"
	mockGitHub := "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	mockSlack := "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
	mockOpenAI := "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"

	dexStrings := []string{
		mockStripe,
		mockGitHub,
		mockSlack,
		mockOpenAI,
		"-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgtestkey123456789012\n-----END PRIVATE KEY-----",
		"https://my-bucket.s3.amazonaws.com/uploads/",
		"https://api.service.com/api/v2/payments/charge",
		"query GetUserData { user { id name email } }",
	}

	dexBytes := buildSyntheticDEX(dexStrings, "035")

	tempDir := t.TempDir()
	ws, err := NewWorkspace(tempDir)
	if err != nil {
		t.Fatalf("failed creating workspace: %v", err)
	}
	defer ws.Close()

	if err := os.WriteFile(filepath.Join(ws.Dir, "classes.dex"), dexBytes, 0600); err != nil {
		t.Fatalf("failed writing classes.dex: %v", err)
	}
	ws.DexFiles = []string{"classes.dex"}

	ctx := context.Background()
	res, err := AnalyzeArtifacts(ctx, ws, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rawSecrets := []string{
		mockStripe,
		mockGitHub,
		mockSlack,
		mockOpenAI,
		"testkey123456789012",
	}

	// Verify that NO raw secret is present anywhere in any finding
	for _, f := range res.Findings {
		for _, raw := range rawSecrets {
			if strings.Contains(f.Evidence, raw) {
				t.Fatalf("RAW SECRET %q LEAKED IN FINDING EVIDENCE: %s", raw, f.Evidence)
			}
			if strings.Contains(f.Title, raw) {
				t.Fatalf("RAW SECRET %q LEAKED IN FINDING TITLE: %s", raw, f.Title)
			}
			if strings.Contains(f.Description, raw) {
				t.Fatalf("RAW SECRET %q LEAKED IN FINDING DESCRIPTION: %s", raw, f.Description)
			}
			for dk, dv := range f.EvidenceDetails.Details {
				if strings.Contains(dv, raw) {
					t.Fatalf("RAW SECRET %q LEAKED IN DETAIL %s: %s", raw, dk, dv)
				}
			}
		}
	}

	// Verify summary counts
	if res.Summary.SecretsCount < 5 {
		t.Errorf("expected at least 5 secrets, got %d", res.Summary.SecretsCount)
	}
	if res.Summary.ServicesCount < 1 {
		t.Errorf("expected at least 1 service (AWS S3), got %d", res.Summary.ServicesCount)
	}
	if res.Summary.GraphQLCount < 1 {
		t.Errorf("expected at least 1 GraphQL indicator, got %d", res.Summary.GraphQLCount)
	}
	if res.Summary.EndpointsCount < 1 {
		t.Errorf("expected at least 1 endpoint, got %d", res.Summary.EndpointsCount)
	}
}

func TestArtifact_MultidexHandling(t *testing.T) {
	// Construct classes.dex and classes2.dex
	dex1Strings := []string{
		"Lcom/example/app/ActivityOne;",
		"https://api.gateway.com/v1/auth",
	}
	dex2Strings := []string{
		"Lcom/example/app/ActivityTwo;",
		"https://analytics.service.com/v1/log",
		"AIzaSyD9876543210zyxwvutsrqponmlkjihgfe",
	}

	dex1 := buildSyntheticDEX(dex1Strings, "035")
	dex2 := buildSyntheticDEX(dex2Strings, "035")

	tempDir := t.TempDir()
	ws, err := NewWorkspace(tempDir)
	if err != nil {
		t.Fatalf("failed creating workspace: %v", err)
	}
	defer ws.Close()

	if err := os.WriteFile(filepath.Join(ws.Dir, "classes.dex"), dex1, 0600); err != nil {
		t.Fatalf("failed writing classes.dex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ws.Dir, "classes2.dex"), dex2, 0600); err != nil {
		t.Fatalf("failed writing classes2.dex: %v", err)
	}
	ws.DexFiles = []string{"classes.dex", "classes2.dex"}

	res, err := AnalyzeArtifacts(context.Background(), ws, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.DexFilesAnalyzed) != 2 {
		t.Errorf("expected 2 DEX files analyzed, got %d", len(res.DexFilesAnalyzed))
	}
	if res.Summary.SecretsCount != 1 {
		t.Errorf("expected 1 secret (Google API key in classes2.dex), got %d", res.Summary.SecretsCount)
	}
}

func TestArtifact_EndToEndSyntheticAPK(t *testing.T) {
	// Create a complete valid synthetic APK archive on disk
	dexBytes := buildSyntheticDEX([]string{
		"Lcom/example/app/MainActivity;",
		"https://api.mycorp.com/v1/users",
		"AKIA1111222233334444",
	}, "035")

	apkPath := filepath.Join(t.TempDir(), "app-release.apk")
	apkFile, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed creating test apk file: %v", err)
	}

	zw := zip.NewWriter(apkFile)

	// AndroidManifest.xml
	mw, _ := zw.Create("AndroidManifest.xml")
	mw.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>`))

	// classes.dex
	dw, _ := zw.Create("classes.dex")
	dw.Write(dexBytes)

	// google-services.json
	gw, _ := zw.Create("google-services.json")
	gw.Write([]byte(`{"project_info":{"project_id":"corp-mobile","storage_bucket":"corp.appspot.com"}}`))

	zw.Close()
	apkFile.Close()

	// Perform full Intake with extraction
	ctx := context.Background()
	intakeRes, err := Intake(ctx, apkPath, IntakeOptions{Extract: true})
	if err != nil {
		t.Fatalf("Intake failed: %v", err)
	}
	defer intakeRes.Workspace.Close()

	// Run AnalyzeArtifacts
	artifactRes, err := AnalyzeArtifacts(ctx, intakeRes.Workspace, DefaultLimits())
	if err != nil {
		t.Fatalf("AnalyzeArtifacts failed: %v", err)
	}

	if len(artifactRes.DexFilesAnalyzed) != 1 {
		t.Errorf("expected 1 DEX file analyzed, got %d", len(artifactRes.DexFilesAnalyzed))
	}
	if len(artifactRes.ConfigsAnalyzed) != 1 {
		t.Errorf("expected 1 config analyzed (google-services.json), got %d", len(artifactRes.ConfigsAnalyzed))
	}
	if artifactRes.Summary.SecretsCount != 1 {
		t.Errorf("expected 1 secret (AKIA...), got %d", artifactRes.Summary.SecretsCount)
	}
	if artifactRes.Summary.ServicesCount != 1 {
		t.Errorf("expected 1 service (Firebase), got %d", artifactRes.Summary.ServicesCount)
	}
	if artifactRes.Summary.EndpointsCount < 1 {
		t.Errorf("expected at least 1 endpoint (/api/v1/users), got %d", artifactRes.Summary.EndpointsCount)
	}
}
