package apk

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"felix/pkg/report"
)

// ============================================================================
// AXML TEST FIXTURE BUILDER
// ============================================================================

type testAXMLBuilder struct {
	strings []string
	strMap  map[string]uint32
	resIDs  []uint32
}

func newAXMLBuilder() *testAXMLBuilder {
	return &testAXMLBuilder{
		strMap: make(map[string]uint32),
	}
}

func (b *testAXMLBuilder) addString(s string) uint32 {
	if idx, ok := b.strMap[s]; ok {
		return idx
	}
	idx := uint32(len(b.strings))
	b.strings = append(b.strings, s)
	b.strMap[s] = idx
	return idx
}

// buildAXML generates a valid, standard-compliant binary XML byte slice.
func (b *testAXMLBuilder) buildAXML(packageName string, debuggable, cleartext *bool, exportedCompName string, exportedVal *bool) []byte {
	// Pre-seed common strings
	androidNsIdx := b.addString(AndroidNamespace)
	androidPrefixIdx := b.addString("android")
	manifestIdx := b.addString("manifest")
	packageIdx := b.addString("package")
	pkgNameIdx := b.addString(packageName)
	appIdx := b.addString("application")
	debuggableIdx := b.addString("debuggable")
	cleartextIdx := b.addString("usesCleartextTraffic")
	actIdx := b.addString("activity")
	nameIdx := b.addString("name")
	compNameIdx := b.addString(exportedCompName)
	exportedIdx := b.addString("exported")

	// Resource IDs corresponding to attributes in resource map
	b.resIDs = []uint32{
		0x01010003, // name
		0x01010010, // exported
		0x01010011, // debuggable
	}

	// 1. Build String Pool Chunk (UTF-16LE)
	var strPoolBody bytes.Buffer
	stringCount := uint32(len(b.strings))
	styleCount := uint32(0)
	flags := uint32(0) // UTF-16LE

	// Calculate offsets
	offsets := make([]uint32, stringCount)
	var strBytes bytes.Buffer
	for i, s := range b.strings {
		offsets[i] = uint32(strBytes.Len())
		runes := utf16.Encode([]rune(s))
		u16len := uint16(len(runes))
		_ = binary.Write(&strBytes, binary.LittleEndian, u16len)
		for _, r := range runes {
			_ = binary.Write(&strBytes, binary.LittleEndian, r)
		}
		_ = binary.Write(&strBytes, binary.LittleEndian, uint16(0)) // null terminator
	}

	headerSize := uint16(28)
	stringsStart := uint32(int(headerSize) + len(offsets)*4)
	chunkSize := stringsStart + uint32(strBytes.Len())

	_ = binary.Write(&strPoolBody, binary.LittleEndian, uint16(axmlChunkStringPool))
	_ = binary.Write(&strPoolBody, binary.LittleEndian, headerSize)
	_ = binary.Write(&strPoolBody, binary.LittleEndian, chunkSize)
	_ = binary.Write(&strPoolBody, binary.LittleEndian, stringCount)
	_ = binary.Write(&strPoolBody, binary.LittleEndian, styleCount)
	_ = binary.Write(&strPoolBody, binary.LittleEndian, flags)
	_ = binary.Write(&strPoolBody, binary.LittleEndian, stringsStart)
	_ = binary.Write(&strPoolBody, binary.LittleEndian, uint32(0)) // stylesStart

	for _, off := range offsets {
		_ = binary.Write(&strPoolBody, binary.LittleEndian, off)
	}
	strPoolBody.Write(strBytes.Bytes())

	// 2. Build Resource Map Chunk
	var resMapBody bytes.Buffer
	resMapHeaderSize := uint16(8)
	resMapChunkSize := uint32(int(resMapHeaderSize) + len(b.resIDs)*4)
	_ = binary.Write(&resMapBody, binary.LittleEndian, uint16(axmlChunkResourceMap))
	_ = binary.Write(&resMapBody, binary.LittleEndian, resMapHeaderSize)
	_ = binary.Write(&resMapBody, binary.LittleEndian, resMapChunkSize)
	for _, id := range b.resIDs {
		_ = binary.Write(&resMapBody, binary.LittleEndian, id)
	}

	// 3. Namespace Start Chunk
	var nsStartBody bytes.Buffer
	_ = binary.Write(&nsStartBody, binary.LittleEndian, uint16(axmlChunkStartNamespace))
	_ = binary.Write(&nsStartBody, binary.LittleEndian, uint16(16))
	_ = binary.Write(&nsStartBody, binary.LittleEndian, uint32(24))
	_ = binary.Write(&nsStartBody, binary.LittleEndian, uint32(1)) // lineNumber
	_ = binary.Write(&nsStartBody, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&nsStartBody, binary.LittleEndian, androidPrefixIdx)
	_ = binary.Write(&nsStartBody, binary.LittleEndian, androidNsIdx)

	// 4. Start Element <manifest>
	var manifestStart bytes.Buffer
	// Attribute: package=packageName
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(axmlChunkStartElement))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(16))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint32(36+20)) // 36 header + 20 attr
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint32(1))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint32(0xFFFFFFFF)) // ns
	_ = binary.Write(&manifestStart, binary.LittleEndian, manifestIdx)        // name
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(36))        // attrStart
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(20))        // attrSize
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(1))         // attrCount
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(0))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(0))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(0))
	// Attribute: package
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&manifestStart, binary.LittleEndian, packageIdx)
	_ = binary.Write(&manifestStart, binary.LittleEndian, pkgNameIdx)
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint16(8))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint8(0))
	_ = binary.Write(&manifestStart, binary.LittleEndian, uint8(axmlTypeString))
	_ = binary.Write(&manifestStart, binary.LittleEndian, pkgNameIdx)

	// 5. Start Element <application>
	var appStart bytes.Buffer
	appAttrCount := uint16(0)
	var appAttrs bytes.Buffer

	if debuggable != nil {
		appAttrCount++
		boolVal := uint32(0)
		if *debuggable {
			boolVal = 1
		}
		_ = binary.Write(&appAttrs, binary.LittleEndian, androidNsIdx)
		_ = binary.Write(&appAttrs, binary.LittleEndian, debuggableIdx)
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint32(0xFFFFFFFF))
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint16(8))
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint8(0))
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint8(axmlTypeIntBoolean))
		_ = binary.Write(&appAttrs, binary.LittleEndian, boolVal)
	}
	if cleartext != nil {
		appAttrCount++
		boolVal := uint32(0)
		if *cleartext {
			boolVal = 1
		}
		_ = binary.Write(&appAttrs, binary.LittleEndian, androidNsIdx)
		_ = binary.Write(&appAttrs, binary.LittleEndian, cleartextIdx)
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint32(0xFFFFFFFF))
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint16(8))
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint8(0))
		_ = binary.Write(&appAttrs, binary.LittleEndian, uint8(axmlTypeIntBoolean))
		_ = binary.Write(&appAttrs, binary.LittleEndian, boolVal)
	}

	appChunkSize := uint32(36 + int(appAttrCount)*20)
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(axmlChunkStartElement))
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(16))
	_ = binary.Write(&appStart, binary.LittleEndian, appChunkSize)
	_ = binary.Write(&appStart, binary.LittleEndian, uint32(2))
	_ = binary.Write(&appStart, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&appStart, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&appStart, binary.LittleEndian, appIdx)
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(36))
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(20))
	_ = binary.Write(&appStart, binary.LittleEndian, appAttrCount)
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(0))
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(0))
	_ = binary.Write(&appStart, binary.LittleEndian, uint16(0))
	appStart.Write(appAttrs.Bytes())

	// 6. Start Element <activity>
	var actStart bytes.Buffer
	if exportedCompName != "" {
		actAttrCount := uint16(1)
		var actAttrs bytes.Buffer

		// android:name
		_ = binary.Write(&actAttrs, binary.LittleEndian, androidNsIdx)
		_ = binary.Write(&actAttrs, binary.LittleEndian, nameIdx)
		_ = binary.Write(&actAttrs, binary.LittleEndian, compNameIdx)
		_ = binary.Write(&actAttrs, binary.LittleEndian, uint16(8))
		_ = binary.Write(&actAttrs, binary.LittleEndian, uint8(0))
		_ = binary.Write(&actAttrs, binary.LittleEndian, uint8(axmlTypeString))
		_ = binary.Write(&actAttrs, binary.LittleEndian, compNameIdx)

		if exportedVal != nil {
			actAttrCount++
			bVal := uint32(0)
			if *exportedVal {
				bVal = 1
			}
			_ = binary.Write(&actAttrs, binary.LittleEndian, androidNsIdx)
			_ = binary.Write(&actAttrs, binary.LittleEndian, exportedIdx)
			_ = binary.Write(&actAttrs, binary.LittleEndian, uint32(0xFFFFFFFF))
			_ = binary.Write(&actAttrs, binary.LittleEndian, uint16(8))
			_ = binary.Write(&actAttrs, binary.LittleEndian, uint8(0))
			_ = binary.Write(&actAttrs, binary.LittleEndian, uint8(axmlTypeIntBoolean))
			_ = binary.Write(&actAttrs, binary.LittleEndian, bVal)
		}

		actChunkSize := uint32(36 + int(actAttrCount)*20)
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(axmlChunkStartElement))
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(16))
		_ = binary.Write(&actStart, binary.LittleEndian, actChunkSize)
		_ = binary.Write(&actStart, binary.LittleEndian, uint32(3))
		_ = binary.Write(&actStart, binary.LittleEndian, uint32(0xFFFFFFFF))
		_ = binary.Write(&actStart, binary.LittleEndian, uint32(0xFFFFFFFF))
		_ = binary.Write(&actStart, binary.LittleEndian, actIdx)
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(36))
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(20))
		_ = binary.Write(&actStart, binary.LittleEndian, actAttrCount)
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(0))
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(0))
		_ = binary.Write(&actStart, binary.LittleEndian, uint16(0))
		actStart.Write(actAttrs.Bytes())
	}

	// 7. End Elements
	var endChunks bytes.Buffer
	if exportedCompName != "" {
		_ = binary.Write(&endChunks, binary.LittleEndian, uint16(axmlChunkEndElement))
		_ = binary.Write(&endChunks, binary.LittleEndian, uint16(16))
		_ = binary.Write(&endChunks, binary.LittleEndian, uint32(24))
		_ = binary.Write(&endChunks, binary.LittleEndian, uint32(3))
		_ = binary.Write(&endChunks, binary.LittleEndian, uint32(0xFFFFFFFF))
		_ = binary.Write(&endChunks, binary.LittleEndian, uint32(0xFFFFFFFF))
		_ = binary.Write(&endChunks, binary.LittleEndian, actIdx)
	}

	// End <application>
	_ = binary.Write(&endChunks, binary.LittleEndian, uint16(axmlChunkEndElement))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint16(16))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(24))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(2))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&endChunks, binary.LittleEndian, appIdx)

	// End <manifest>
	_ = binary.Write(&endChunks, binary.LittleEndian, uint16(axmlChunkEndElement))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint16(16))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(24))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(1))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&endChunks, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&endChunks, binary.LittleEndian, manifestIdx)

	// End Namespace
	var nsEndBody bytes.Buffer
	_ = binary.Write(&nsEndBody, binary.LittleEndian, uint16(axmlChunkEndNamespace))
	_ = binary.Write(&nsEndBody, binary.LittleEndian, uint16(16))
	_ = binary.Write(&nsEndBody, binary.LittleEndian, uint32(24))
	_ = binary.Write(&nsEndBody, binary.LittleEndian, uint32(4))
	_ = binary.Write(&nsEndBody, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&nsEndBody, binary.LittleEndian, androidPrefixIdx)
	_ = binary.Write(&nsEndBody, binary.LittleEndian, androidNsIdx)

	// Total Assembly
	var fullXML bytes.Buffer
	bodyChunks := bytes.Join([][]byte{
		strPoolBody.Bytes(),
		resMapBody.Bytes(),
		nsStartBody.Bytes(),
		manifestStart.Bytes(),
		appStart.Bytes(),
		actStart.Bytes(),
		endChunks.Bytes(),
		nsEndBody.Bytes(),
	}, nil)

	totalChunkSize := uint32(8 + len(bodyChunks))
	_ = binary.Write(&fullXML, binary.LittleEndian, uint16(axmlChunkXML))
	_ = binary.Write(&fullXML, binary.LittleEndian, uint16(8))
	_ = binary.Write(&fullXML, binary.LittleEndian, totalChunkSize)
	fullXML.Write(bodyChunks)

	return fullXML.Bytes()
}

// ============================================================================
// 1. FORMAT DETECTION & PARSING TESTS
// ============================================================================

func TestManifest_FormatDetection(t *testing.T) {
	b := newAXMLBuilder()
	axmlBytes := b.buildAXML("com.test.app", nil, nil, "", nil)

	if format := DetectManifestFormat(axmlBytes); format != FormatAXML {
		t.Errorf("expected FormatAXML, got %q", format)
	}

	xmlText := []byte("<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.test\"/>")
	if format := DetectManifestFormat(xmlText); format != FormatXML {
		t.Errorf("expected FormatXML, got %q", format)
	}

	unknownData := []byte("INVALID_MANIFEST_BYTES_12345")
	if format := DetectManifestFormat(unknownData); format != FormatUnknown {
		t.Errorf("expected FormatUnknown, got %q", format)
	}
}

func TestManifest_ParseAXML_Valid(t *testing.T) {
	b := newAXMLBuilder()
	dbg := true
	exp := true
	axmlBytes := b.buildAXML("com.felix.axml", &dbg, nil, ".MainActivity", &exp)

	root, err := ParseAXML(axmlBytes, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected AXML parse error: %v", err)
	}

	if root.Name != "manifest" {
		t.Errorf("expected root element manifest, got %q", root.Name)
	}

	doc := ExtractManifestDocument(root, FormatAXML)
	if doc.PackageName != "com.felix.axml" {
		t.Errorf("expected package com.felix.axml, got %q", doc.PackageName)
	}
	if doc.Application.Debuggable == nil || !*doc.Application.Debuggable {
		t.Errorf("expected Application.Debuggable=true")
	}
	if len(doc.Application.Activities) != 1 {
		t.Fatalf("expected 1 activity, got %d", len(doc.Application.Activities))
	}
	act := doc.Application.Activities[0]
	if act.ResolvedName != "com.felix.axml.MainActivity" {
		t.Errorf("expected resolved activity name com.felix.axml.MainActivity, got %q", act.ResolvedName)
	}
	if act.Exported == nil || !*act.Exported {
		t.Errorf("expected activity Exported=true")
	}
}

func TestManifest_ParseTextualXML_Valid(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.felix.textual"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <application android:debuggable="true" android:allowBackup="false">
        <activity android:name=".DetailActivity" android:exported="false"/>
    </application>
</manifest>`)

	root, err := ParseTextualManifest(xmlData, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected textual XML parse error: %v", err)
	}

	doc := ExtractManifestDocument(root, FormatXML)
	if doc.PackageName != "com.felix.textual" {
		t.Errorf("expected package com.felix.textual, got %q", doc.PackageName)
	}
	if doc.MinSDK != 21 || doc.TargetSDK != 33 {
		t.Errorf("expected MinSDK=21, TargetSDK=33, got %d, %d", doc.MinSDK, doc.TargetSDK)
	}
	if doc.Application.Debuggable == nil || !*doc.Application.Debuggable {
		t.Errorf("expected Debuggable=true")
	}
	if doc.Application.AllowBackup == nil || *doc.Application.AllowBackup {
		t.Errorf("expected AllowBackup=false")
	}
	if len(doc.Application.Activities) != 1 {
		t.Fatalf("expected 1 activity, got %d", len(doc.Application.Activities))
	}
	if doc.Application.Activities[0].Exported == nil || *doc.Application.Activities[0].Exported {
		t.Errorf("expected activity Exported=false")
	}
}

func TestManifest_ProhibitDOCTYPE_EntityExpansion(t *testing.T) {
	xxePayload := []byte(`<?xml version="1.0"?>
<!DOCTYPE manifest [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<manifest package="com.evil">
    <application android:label="&xxe;"/>
</manifest>`)

	_, err := ParseTextualManifest(xxePayload, DefaultLimits())
	if err == nil {
		t.Fatalf("expected security error for DOCTYPE declaration, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestManifest_ParseAXML_TruncatedHeader(t *testing.T) {
	shortData := []byte{0x03, 0x00, 0x08, 0x00} // only 4 bytes
	_, err := ParseAXML(shortData, DefaultLimits())
	if err == nil {
		t.Fatalf("expected error for truncated AXML header, got nil")
	}
	if !errors.Is(err, ErrMalformedArchive) {
		t.Errorf("expected ErrMalformedArchive, got %v", err)
	}
}

func TestManifest_ParseAXML_CorruptedStringPool(t *testing.T) {
	b := newAXMLBuilder()
	data := b.buildAXML("com.test", nil, nil, "", nil)

	// Corrupt string pool chunk size at offset 12
	data[12] = 0xFF
	data[13] = 0xFF

	_, err := ParseAXML(data, DefaultLimits())
	if err == nil {
		t.Fatalf("expected error for corrupted string pool, got nil")
	}
	if !errors.Is(err, ErrMalformedArchive) {
		t.Errorf("expected ErrMalformedArchive, got %v", err)
	}
}

// ============================================================================
// 2. DEBUGGABILITY ANALYSIS TESTS
// ============================================================================

func TestAnalyze_DebuggableExplicitTrue(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.debug">
    <application android:debuggable="true"/>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-DEBUGGABLE" {
			found = true
			if f.Severity != report.SeverityHigh {
				t.Errorf("expected High severity for debuggable=true, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected APK-MAN-DEBUGGABLE finding for debuggable=true")
	}
}

func TestAnalyze_DebuggableExplicitFalse(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.release">
    <application android:debuggable="false"/>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-DEBUGGABLE" && f.Severity == report.SeverityHigh {
			t.Errorf("unexpected High finding for debuggable=false")
		}
	}
}

func TestAnalyze_DebuggableOmitted(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.omitted">
    <application/>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-DEBUGGABLE" {
			t.Errorf("omitted debuggable must not produce high severity finding, got %+v", f)
		}
	}
}

// ============================================================================
// 3. EXPORTED COMPONENTS & PERMISSION TESTS
// ============================================================================

func TestAnalyze_ExportedComponents_AllFiveTypes(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.components">
    <uses-sdk android:targetSdkVersion="30"/>
    <application>
        <activity android:name=".PublicActivity" android:exported="true"/>
        <activity-alias android:name=".PublicAlias" android:targetActivity=".PublicActivity" android:exported="true"/>
        <service android:name=".SyncService" android:exported="true"/>
        <receiver android:name=".PushReceiver" android:exported="true"/>
        <provider android:name=".DataProvider" android:authorities="com.test.provider" android:exported="true"/>
    </application>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundProvider := false
	foundService := false
	foundReceiver := false
	foundActivity := false

	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-EXPORTED-PROVIDER" {
			foundProvider = true
			if f.Severity != report.SeverityHigh {
				t.Errorf("expected High severity for exported provider without permissions, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-MAN-EXPORTED-COMPONENT" && f.Endpoint == "com.test.components.SyncService" {
			foundService = true
			if f.Severity != report.SeverityMedium {
				t.Errorf("expected Medium severity for exported service, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-MAN-EXPORTED-COMPONENT" && f.Endpoint == "com.test.components.PushReceiver" {
			foundReceiver = true
		}
		if f.RuleID == "APK-MAN-EXPORTED-COMPONENT" && f.Endpoint == "com.test.components.PublicActivity" {
			foundActivity = true
		}
	}

	if !foundProvider {
		t.Errorf("missing exported provider finding")
	}
	if !foundService {
		t.Errorf("missing exported service finding")
	}
	if !foundReceiver {
		t.Errorf("missing exported receiver finding")
	}
	if !foundActivity {
		t.Errorf("missing exported activity finding")
	}
}

func TestAnalyze_MainLauncherActivity_ClassifiedInfo(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.launcher">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundLauncher := false
	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-LAUNCHER-EXPORTED" {
			foundLauncher = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("expected launcher activity to be INFO severity, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-MAN-EXPORTED-COMPONENT" && f.Endpoint == "com.test.launcher.MainActivity" {
			t.Errorf("launcher activity must not be classified as vulnerable component")
		}
	}
	if !foundLauncher {
		t.Errorf("expected APK-MAN-LAUNCHER-EXPORTED observation")
	}
}

func TestAnalyze_ExportedComponent_ProtectedByPermission(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.perm">
    <application>
        <service android:name=".SecureService" android:exported="true" android:permission="com.test.perm.AUTHORIZED"/>
    </application>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundProtected := false
	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-EXPORTED-PROTECTED" {
			foundProtected = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("expected protected exported component to be INFO, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-MAN-EXPORTED-COMPONENT" {
			t.Errorf("protected component should not be flagged as unprotected")
		}
	}
	if !foundProtected {
		t.Errorf("expected APK-MAN-EXPORTED-PROTECTED finding")
	}
}

// ============================================================================
// 4. DEEP LINKS & INTENT FILTERS
// ============================================================================

func TestAnalyze_DeepLinks_CustomSchemeAndCleartextHTTP(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.links">
    <application>
        <activity android:name=".LinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="mycustomscheme" android:host="profile"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="http" android:host="insecure.example.com" android:pathPattern=".*"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCustom := false
	foundCleartext := false
	foundBroad := false

	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-DEEPLINK-CUSTOM-SCHEME" {
			foundCustom = true
		}
		if f.RuleID == "APK-MAN-DEEPLINK-CLEARTEXT" {
			foundCleartext = true
		}
		if f.RuleID == "APK-MAN-DEEPLINK-BROAD-PATH" {
			foundBroad = true
		}
	}

	if !foundCustom {
		t.Errorf("missing custom scheme finding")
	}
	if !foundCleartext {
		t.Errorf("missing cleartext http deep link finding")
	}
	if !foundBroad {
		t.Errorf("missing broad wildcard pathPattern finding")
	}
}

// ============================================================================
// 5. NETWORK SECURITY CONFIGURATION
// ============================================================================

func TestAnalyze_NetworkSecurity_CleartextAndUserCertificates(t *testing.T) {
	// Create mock workspace with network_security_config.xml
	tmpDir := t.TempDir()
	ws, err := NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	resXmlDir := filepath.Join(ws.Dir, "res", "xml")
	if err := os.MkdirAll(resXmlDir, 0700); err != nil {
		t.Fatal(err)
	}

	netXmlContent := []byte(`<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>`)

	if err := os.WriteFile(filepath.Join(resXmlDir, "network_security_config.xml"), netXmlContent, 0600); err != nil {
		t.Fatal(err)
	}

	manifestData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.netsec">
    <uses-sdk android:targetSdkVersion="29"/>
    <application
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config"/>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), manifestData, ws, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCleartext := false
	foundBaseCleartext := false
	foundUserCerts := false
	foundDebugCerts := false

	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-CLEARTEXT-ENABLED" {
			foundCleartext = true
			if f.Severity != report.SeverityMedium {
				t.Errorf("expected Medium severity on targetSDK 29 for cleartext, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-MAN-NETSEC-BASE-CLEARTEXT" {
			foundBaseCleartext = true
		}
		if f.RuleID == "APK-MAN-NETSEC-USER-CERTS" {
			foundUserCerts = true
			if f.Severity != report.SeverityHigh {
				t.Errorf("expected High severity for user certs in production, got %s", f.Severity)
			}
		}
		if f.RuleID == "APK-MAN-NETSEC-DEBUG-CERTS" {
			foundDebugCerts = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("expected Info severity for debug user certs, got %s", f.Severity)
			}
		}
	}

	if !foundCleartext {
		t.Errorf("missing cleartext traffic finding")
	}
	if !foundBaseCleartext {
		t.Errorf("missing base cleartext config finding")
	}
	if !foundUserCerts {
		t.Errorf("missing user certs in production finding")
	}
	if !foundDebugCerts {
		t.Errorf("missing debug user certs finding")
	}
}

// ============================================================================
// 6. BACKUP CONFIGURATION
// ============================================================================

func TestAnalyze_BackupEnabled(t *testing.T) {
	xmlData := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.backup">
    <application android:allowBackup="true"/>
</manifest>`)

	res, err := ParseAndAnalyzeManifest(context.Background(), xmlData, nil, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundBackup := false
	for _, f := range res.Findings {
		if f.RuleID == "APK-MAN-BACKUP-ENABLED" {
			foundBackup = true
			if f.Severity != report.SeverityLow {
				t.Errorf("expected Low severity for allowBackup=true, got %s", f.Severity)
			}
		}
	}
	if !foundBackup {
		t.Errorf("missing APK-MAN-BACKUP-ENABLED finding")
	}
}
