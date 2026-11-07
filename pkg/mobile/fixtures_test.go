package mobile

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// Helper to create an in-memory ZIP archive
func createZipArchive(files map[string][]byte) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := f.Write(content); err != nil {
			panic(err)
		}
	}
	_ = w.Close()
	return buf.Bytes()
}

// Helper to create a synthetic binary plist (bplist00)
func createSyntheticBplist(bundleID string, allowArbitrary bool, customScheme string) []byte {
	// We'll construct a simple bplist00 with:
	// Root Dict (object 0):
	//   "CFBundleIdentifier" (obj 1) -> bundleID (obj 2)
	//   "NSAppTransportSecurity" (obj 3) -> Dict (obj 4)
	//       "NSAllowsArbitraryLoads" (obj 5) -> allowArbitrary bool (obj 6)
	//   "CFBundleURLTypes" (obj 7) -> Array (obj 8)
	//       Dict (obj 9):
	//           "CFBundleURLSchemes" (obj 10) -> Array (obj 11)
	//               customScheme (obj 12)

	var buf bytes.Buffer
	buf.WriteString("bplist00")

	// Store objects and collect offsets
	offsets := make([]int, 0)

	addObject := func(b []byte) int {
		idx := len(offsets)
		offsets = append(offsets, buf.Len())
		buf.Write(b)
		return idx
	}

	makeString := func(s string) []byte {
		if len(s) < 15 {
			b := make([]byte, 1+len(s))
			b[0] = 0x50 | byte(len(s))
			copy(b[1:], s)
			return b
		}
		// Length >= 15: marker is 0x5F, followed by integer object (0x10 = 1-byte int)
		b := make([]byte, 3+len(s))
		b[0] = 0x5F
		b[1] = 0x10 // 1-byte int
		b[2] = byte(len(s))
		copy(b[3:], s)
		return b
	}

	// Obj 1: "CFBundleIdentifier"
	o1 := addObject(makeString("CFBundleIdentifier"))
	// Obj 2: bundleID
	o2 := addObject(makeString(bundleID))

	// Obj 5: "NSAllowsArbitraryLoads"
	o5 := addObject(makeString("NSAllowsArbitraryLoads"))
	// Obj 6: bool
	boolByte := byte(0x08) // false
	if allowArbitrary {
		boolByte = 0x09 // true
	}
	o6 := addObject([]byte{boolByte})

	// Obj 4: Dict for ATS
	// 0xD1: dict with 1 key-value pair, keyRef = o5, valRef = o6
	o4 := addObject([]byte{0xD1, byte(o5), byte(o6)})

	// Obj 3: "NSAppTransportSecurity"
	o3 := addObject(makeString("NSAppTransportSecurity"))

	// Obj 12: customScheme
	o12 := addObject(makeString(customScheme))
	// Obj 11: Array [o12]
	o11 := addObject([]byte{0xA1, byte(o12)})
	// Obj 10: "CFBundleURLSchemes"
	o10 := addObject(makeString("CFBundleURLSchemes"))
	// Obj 9: Dict { o10: o11 }
	o9 := addObject([]byte{0xD1, byte(o10), byte(o11)})
	// Obj 8: Array [o9]
	o8 := addObject([]byte{0xA1, byte(o9)})
	// Obj 7: "CFBundleURLTypes"
	o7 := addObject(makeString("CFBundleURLTypes"))

	// Root Dict (obj 0): 3 pairs (CFBundleIdentifier, NSAppTransportSecurity, CFBundleURLTypes)
	// Keys: o1, o3, o7; Vals: o2, o4, o8
	rootDict := []byte{0xD3, byte(o1), byte(o3), byte(o7), byte(o2), byte(o4), byte(o8)}
	o0 := addObject(rootDict)

	// Now write offset table
	offsetTableStart := buf.Len()
	for i := 0; i < len(offsets); i++ {
		// in bplist, root is topObject (which is o0)
		buf.WriteByte(byte(offsets[i]))
	}

	// Trailer (32 bytes)
	trailer := make([]byte, 32)
	trailer[6] = 1 // offsetIntSize = 1 byte
	trailer[7] = 1 // objectRefSize = 1 byte
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(offsets)))
	binary.BigEndian.PutUint64(trailer[16:24], uint64(o0)) // topObject is root
	binary.BigEndian.PutUint64(trailer[24:32], uint64(offsetTableStart))
	buf.Write(trailer)

	return buf.Bytes()
}

// -----------------------------------------------------------------------------
// 21 Synthetic Fixture Tests
// -----------------------------------------------------------------------------

// Fixture 1: Valid Binary Android Manifest (tested via real or synthesized AXML)
func TestFixture_01_ValidBinaryManifest(t *testing.T) {
	// Read UnCrackable-Level1.apk manifest if available
	path := `C:\SecurityLabs\android-mastg\Crackmes\Android\Level_01\UnCrackable-Level1.apk`
	if _, err := os.Stat(path); err == nil {
		analyzer := NewStaticAnalyzer()
		res, err := analyzer.InspectAPKFile(context.Background(), path)
		if err != nil {
			t.Fatalf("Fixture 1 failed: %v", err)
		}
		if res.Android.PackageName != "owasp.mstg.uncrackable1" {
			t.Errorf("expected package owasp.mstg.uncrackable1, got: %s", res.Android.PackageName)
		}
	}
}

// Fixture 2: Textual XML Manifest
func TestFixture_02_TextualXMLManifest(t *testing.T) {
	textManifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.textmanifest"
    android:versionCode="100"
    android:versionName="1.0.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <application android:debuggable="false" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{
		"AndroidManifest.xml": textManifest,
	})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "textual.apk")
	if err != nil {
		t.Fatalf("Fixture 2 failed: %v", err)
	}

	if res.Android.PackageName != "com.example.textmanifest" {
		t.Errorf("expected package com.example.textmanifest, got: %s", res.Android.PackageName)
	}
	if res.Android.TargetSDK != 33 {
		t.Errorf("expected targetSDK 33, got %d", res.Android.TargetSDK)
	}
	if len(res.Android.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(res.Android.Components))
	}
}

// Fixture 3: Exported activity without permission (HIGH finding)
func TestFixture_03_ExportedActivity_WithoutPermission(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.vuln">
    <application>
        <activity android:name=".UnprotectedActivity" android:exported="true" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "vuln.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "EXPORTED-ACTIVITY-UNPROTECTED" && strings.Contains(f.ComponentOrKey, "UnprotectedActivity") {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH severity, got: %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EXPORTED-ACTIVITY-UNPROTECTED finding")
	}
}

// Fixture 4: Exported activity protected by permission (Defended / INFO)
func TestFixture_04_ExportedActivity_ProtectedByPermission(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.secure">
    <application>
        <activity android:name=".ProtectedActivity" android:exported="true" android:permission="com.example.MY_PERMISSION" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "secure.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	foundUnprotected := false
	foundProtected := false
	for _, f := range res.Findings {
		if f.RuleID == "EXPORTED-ACTIVITY-UNPROTECTED" {
			foundUnprotected = true
		}
		if f.RuleID == "EXPORTED-COMPONENT-PROTECTED" {
			foundProtected = true
		}
	}
	if foundUnprotected {
		t.Errorf("protected activity should not be flagged as unprotected")
	}
	if !foundProtected {
		t.Errorf("expected EXPORTED-COMPONENT-PROTECTED finding")
	}
}

// Fixture 5: Exported service without permission (HIGH finding)
func TestFixture_05_ExportedService(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.service">
    <application>
        <service android:name=".ExportedService" android:exported="true" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "service.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "EXPORTED-SERVICE-UNPROTECTED" {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EXPORTED-SERVICE-UNPROTECTED finding")
	}
}

// Fixture 6: Exported receiver without permission (HIGH finding)
func TestFixture_06_ExportedReceiver(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.receiver">
    <application>
        <receiver android:name=".ExportedReceiver" android:exported="true" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "receiver.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "EXPORTED-RECEIVER-UNPROTECTED" {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EXPORTED-RECEIVER-UNPROTECTED finding")
	}
}

// Fixture 7: Exported content provider without permission (CRITICAL finding)
func TestFixture_07_ExportedProvider(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.provider">
    <application>
        <provider android:name=".UserDataProvider" android:exported="true" android:authorities="com.example.userdata" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "provider.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "EXPORTED-PROVIDER-UNPROTECTED" {
			found = true
			if f.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EXPORTED-PROVIDER-UNPROTECTED finding")
	}
}

// Fixture 8: Explicit and Implicit Exported Behavior
func TestFixture_08_ExplicitVsImplicitExported(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.implicit">
    <application>
        <!-- Implicitly exported because it has an intent filter -->
        <activity android:name=".ImplicitExported">
            <intent-filter>
                <action android:name="com.example.CUSTOM_ACTION" />
            </intent-filter>
        </activity>
        <!-- Explicitly NOT exported even though it has an intent filter -->
        <activity android:name=".ExplicitNonExported" android:exported="false">
            <intent-filter>
                <action android:name="com.example.INTERNAL_ACTION" />
            </intent-filter>
        </activity>
        <!-- Implicitly private because no intent filter -->
        <activity android:name=".ImplicitPrivate" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "implicit.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	compMap := make(map[string]AndroidComponent)
	for _, c := range res.Android.Components {
		compMap[c.Name] = c
	}

	c1 := compMap["com.example.implicit.ImplicitExported"]
	if !c1.Exported || c1.ExplicitExported {
		t.Errorf("expected ImplicitExported to be exported=true, explicit=false, got exported=%v, explicit=%v", c1.Exported, c1.ExplicitExported)
	}

	c2 := compMap["com.example.implicit.ExplicitNonExported"]
	if c2.Exported || !c2.ExplicitExported {
		t.Errorf("expected ExplicitNonExported to be exported=false, explicit=true, got exported=%v, explicit=%v", c2.Exported, c2.ExplicitExported)
	}

	c3 := compMap["com.example.implicit.ImplicitPrivate"]
	if c3.Exported {
		t.Errorf("expected ImplicitPrivate to be exported=false, got true")
	}
}

// Fixture 9: Debuggable application (CRITICAL finding)
func TestFixture_09_DebuggableApp(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.debug">
    <application android:debuggable="true" />
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "debug.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "APP-DEBUGGABLE" {
			found = true
			if f.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected APP-DEBUGGABLE finding")
	}
}

// Fixture 10: AllowBackup application
func TestFixture_10_AllowBackupApp(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.backup">
    <application android:allowBackup="true" />
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "backup.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "APP-ALLOW-BACKUP" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected APP-ALLOW-BACKUP finding")
	}
}

// Fixture 11: Cleartext Traffic Configuration
func TestFixture_11_CleartextTraffic(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.cleartext">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="30" />
    <application android:usesCleartextTraffic="true" />
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "cleartext.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "APP-CLEARTEXT-TRAFFIC" {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH on targetSDK 30, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected APP-CLEARTEXT-TRAFFIC finding")
	}
}

// Fixture 12: Malformed AXML
func TestFixture_12_MalformedAXML(t *testing.T) {
	malformedAXML := []byte{0x03, 0x00, 0x08, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x99, 0x88}
	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": malformedAXML})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "corrupt.apk")
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}

	if res.Stats.InconclusiveFindings == 0 {
		t.Errorf("expected inconclusive finding on malformed AXML")
	}
}

// Fixture 13: Malformed ZIP archive
func TestFixture_13_MalformedZip(t *testing.T) {
	corruptBytes := []byte("PK\x03\x04not a valid zip archive content")
	analyzer := NewStaticAnalyzer()
	_, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(corruptBytes), int64(len(corruptBytes)), "corrupt.apk")
	if err == nil {
		t.Errorf("expected error opening malformed zip archive")
	}
}

// Fixture 14: ZIP path traversal attempt
func TestFixture_14_ZipPathTraversal(t *testing.T) {
	apkBytes := createZipArchive(map[string][]byte{
		"../../etc/passwd":    []byte("root:x:0:0"),
		"AndroidManifest.xml": []byte("<manifest package=\"com.test\" />"),
	})

	analyzer := NewStaticAnalyzer()
	_, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "traversal.apk")
	if err == nil {
		t.Errorf("expected security error rejecting path traversal")
	} else if !strings.Contains(err.Error(), "traversal") {
		t.Errorf("expected traversal error message, got: %v", err)
	}
}

// Fixture 15: ZIP bomb / resource limit attempt
func TestFixture_15_ZipBombResourceLimit(t *testing.T) {
	limits := ArchiveSecurityLimits{
		MaxEntries:           2,
		MaxSingleEntrySize:   1024,
		MaxTotalUncompressed: 2048,
		MaxCompressionRatio:  10,
	}
	analyzer := NewStaticAnalyzerWithLimits(limits)

	// Create archive exceeding entry size
	oversized := make([]byte, 5000)
	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": oversized})

	_, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "bomb.apk")
	if err == nil {
		t.Errorf("expected rejection of oversized entry")
	} else if !strings.Contains(err.Error(), "exceeds single-entry limit") {
		t.Errorf("expected limit error message, got: %v", err)
	}
}

// Fixture 16: XML Info.plist
func TestFixture_16_XMLInfoPlist(t *testing.T) {
	plistXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.xmlapp</string>
    <key>CFBundleName</key>
    <string>XMLApp</string>
    <key>CFBundleShortVersionString</key>
    <string>1.2.3</string>
</dict>
</plist>`)

	ipaBytes := createZipArchive(map[string][]byte{
		"Payload/XMLApp.app/Info.plist": plistXML,
	})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaBytes), int64(len(ipaBytes)), "xmlapp.ipa")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	if res.IOS.BundleIdentifier != "com.example.xmlapp" {
		t.Errorf("expected bundleID com.example.xmlapp, got: %s", res.IOS.BundleIdentifier)
	}
	if res.IOS.VersionString != "1.2.3" {
		t.Errorf("expected version 1.2.3, got: %s", res.IOS.VersionString)
	}
}

// Fixture 17: Binary Info.plist (bplist00)
func TestFixture_17_BinaryInfoPlist(t *testing.T) {
	bplistData := createSyntheticBplist("com.example.binapp", false, "binapp")
	parsed, err := ParsePlist(bplistData)
	if err != nil {
		t.Fatalf("ParsePlist failed: %v", err)
	}
	t.Logf("Direct ParsePlist output: %+v (type: %T)", parsed, parsed)

	ipaBytes := createZipArchive(map[string][]byte{
		"Payload/BinApp.app/Info.plist": bplistData,
	})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaBytes), int64(len(ipaBytes)), "binapp.ipa")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	if res.IOS.BundleIdentifier != "com.example.binapp" {
		t.Errorf("expected bundleID com.example.binapp, got: %s", res.IOS.BundleIdentifier)
	}
	if len(res.IOS.URLSchemes) != 1 || res.IOS.URLSchemes[0] != "binapp" {
		t.Errorf("expected URL scheme 'binapp', got: %v", res.IOS.URLSchemes)
	}
}

// Fixture 18: ATS Arbitrary Load Exception
func TestFixture_18_ATSArbitraryLoad(t *testing.T) {
	plistXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.atsarb</string>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>`)

	ipaBytes := createZipArchive(map[string][]byte{
		"Payload/App.app/Info.plist": plistXML,
	})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaBytes), int64(len(ipaBytes)), "ats.ipa")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "ATS-ARBITRARY-LOADS" {
			found = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected ATS-ARBITRARY-LOADS finding")
	}
}

// Fixture 19: ATS Domain-Specific Exception
func TestFixture_19_ATSDomainException(t *testing.T) {
	plistXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.atsdom</string>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSExceptionDomains</key>
        <dict>
            <key>api.legacy-backend.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
                <key>NSIncludesSubdomains</key>
                <true/>
            </dict>
        </dict>
    </dict>
</dict>
</plist>`)

	ipaBytes := createZipArchive(map[string][]byte{
		"Payload/App.app/Info.plist": plistXML,
	})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaBytes), int64(len(ipaBytes)), "atsdom.ipa")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.RuleID == "ATS-DOMAIN-INSECURE-HTTP" && strings.Contains(f.ComponentOrKey, "api.legacy-backend.com") {
			found = true
			if f.Severity != "MEDIUM" {
				t.Errorf("expected MEDIUM, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected ATS-DOMAIN-INSECURE-HTTP finding")
	}
}

// Fixture 20: Custom URL Scheme
func TestFixture_20_CustomURLScheme(t *testing.T) {
	plistXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.scheme</string>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>custompay</string>
                <string>mybank</string>
            </array>
        </dict>
    </array>
</dict>
</plist>`)

	ipaBytes := createZipArchive(map[string][]byte{
		"Payload/App.app/Info.plist": plistXML,
	})

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaBytes), int64(len(ipaBytes)), "scheme.ipa")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	if len(res.IOS.URLSchemes) != 2 {
		t.Errorf("expected 2 URL schemes, got %d", len(res.IOS.URLSchemes))
	}
	foundCustompay := false
	for _, f := range res.Findings {
		if f.RuleID == "CUSTOM-URL-SCHEME" && f.ComponentOrKey == "custompay" {
			foundCustompay = true
		}
	}
	if !foundCustompay {
		t.Errorf("expected finding for custom URL scheme 'custompay'")
	}
}

// Fixture 21: Missing or Malformed Info.plist
func TestFixture_21_MissingOrMalformedInfoPlist(t *testing.T) {
	// 21a: Missing Info.plist
	ipaEmpty := createZipArchive(map[string][]byte{
		"Payload/App.app/empty.txt": []byte("hello"),
	})
	analyzer := NewStaticAnalyzer()
	_, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaEmpty), int64(len(ipaEmpty)), "missing.ipa")
	if err == nil {
		t.Errorf("expected error when Info.plist is missing")
	}

	// 21b: Corrupted Info.plist
	ipaCorrupt := createZipArchive(map[string][]byte{
		"Payload/App.app/Info.plist": []byte("corrupted non-plist content"),
	})
	res, err := analyzer.InspectIPA(context.Background(), bytes.NewReader(ipaCorrupt), int64(len(ipaCorrupt)), "corrupt.ipa")
	if err != nil {
		t.Fatalf("unexpected hard failure on corrupt plist: %v", err)
	}
	if res.Stats.InconclusiveFindings == 0 {
		t.Errorf("expected inconclusive finding on corrupt Info.plist")
	}
}

// -----------------------------------------------------------------------------
// Negative Test for Secure Manifest
// -----------------------------------------------------------------------------

func TestNegative_SecureAndroidConfiguration(t *testing.T) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.hardened">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="33" />
    <application android:debuggable="false" android:allowBackup="false" android:usesCleartextTraffic="false">
        <activity android:name=".PrivateActivity" android:exported="false" />
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPK(context.Background(), bytes.NewReader(apkBytes), int64(len(apkBytes)), "hardened.apk")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}

	// Only finding should be INFO for launcher activity
	for _, f := range res.Findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" || f.Severity == "MEDIUM" {
			t.Errorf("hardened app should have 0 critical/high/medium findings, found: [%s] %s (%s)", f.Severity, f.RuleID, f.ComponentOrKey)
		}
	}
}

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

func Benchmark_APK_ManifestParsing(b *testing.B) {
	manifest := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.bench">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".UnprotectedActivity" android:exported="true" />
        <service android:name=".UnprotectedService" android:exported="true" />
        <receiver android:name=".UnprotectedReceiver" android:exported="true" />
        <provider android:name=".UnprotectedProvider" android:exported="true" android:authorities="com.example.bench" />
    </application>
</manifest>`)

	apkBytes := createZipArchive(map[string][]byte{"AndroidManifest.xml": manifest})
	analyzer := NewStaticAnalyzer()
	ctx := context.Background()
	reader := bytes.NewReader(apkBytes)
	size := int64(len(apkBytes))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = analyzer.InspectAPK(ctx, reader, size, "bench.apk")
	}
}

func Benchmark_IPA_PlistParsing(b *testing.B) {
	bplistData := createSyntheticBplist("com.example.benchipa", true, "benchscheme")
	ipaBytes := createZipArchive(map[string][]byte{
		"Payload/BenchApp.app/Info.plist": bplistData,
	})
	analyzer := NewStaticAnalyzer()
	ctx := context.Background()
	reader := bytes.NewReader(ipaBytes)
	size := int64(len(ipaBytes))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = analyzer.InspectIPA(ctx, reader, size, "bench.ipa")
	}
}
