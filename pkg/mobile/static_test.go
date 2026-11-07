package mobile

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestLive_InsecureBankv2_APK(t *testing.T) {
	path := `C:\SecurityLabs\android-insecurebankv2\InsecureBankv2.apk`
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Live target missing at %s", path)
	}

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPKFile(context.Background(), path)
	if err != nil {
		t.Fatalf("failed analyzing InsecureBankv2.apk: %v", err)
	}

	if res.Android == nil {
		t.Fatalf("expected parsed Android metadata")
	}

	t.Logf("PackageName: %s", res.Android.PackageName)
	t.Logf("Version: %s (%d)", res.Android.VersionName, res.Android.VersionCode)
	t.Logf("MinSDK: %d, TargetSDK: %d", res.Android.MinSDK, res.Android.TargetSDK)
	t.Logf("Debuggable: %v, AllowBackup: %v", res.Android.Debuggable, res.Android.AllowBackup)
	t.Logf("Total Components: %d", len(res.Android.Components))

	for _, c := range res.Android.Components {
		t.Logf(" - [%s] %s (Exported: %v, Perm: %q, HasLauncher: %v)", c.Type, c.Name, c.Exported, c.Permission, c.HasLauncherIntent)
	}

	t.Logf("Total Findings: %d", len(res.Findings))
	for _, f := range res.Findings {
		t.Logf(" * [%s] %s (%s): %s", f.Severity, f.RuleID, f.Classification, f.ComponentOrKey)
	}

	// Aggressive test case from spec:
	// "Identify exported activity com.android.insecurebankv2.PostLogin with exported=true and lack of permission check; flag as HIGH severity."
	foundPostLogin := false
	for _, f := range res.Findings {
		if strings.Contains(f.ComponentOrKey, "PostLogin") && f.RuleID == "EXPORTED-ACTIVITY-UNPROTECTED" {
			foundPostLogin = true
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH severity for PostLogin exported finding, got: %s", f.Severity)
			}
			if f.Classification != ClassificationConfirmed {
				t.Errorf("expected CONFIRMED classification for PostLogin finding, got: %s", f.Classification)
			}
			break
		}
	}
	if !foundPostLogin {
		t.Fatalf("aggressive test case failed: com.android.insecurebankv2.PostLogin unprotected exported activity not flagged as HIGH")
	}
}


func TestLive_UnCrackable_Level1_APK(t *testing.T) {
	path := `C:\SecurityLabs\android-mastg\Crackmes\Android\Level_01\UnCrackable-Level1.apk`
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Live target missing at %s", path)
	}

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectAPKFile(context.Background(), path)
	if err != nil {
		t.Fatalf("failed analyzing UnCrackable-Level1.apk: %v", err)
	}

	if res.Android == nil {
		t.Fatalf("expected parsed Android metadata")
	}

	t.Logf("PackageName: %s", res.Android.PackageName)
	t.Logf("Version: %s (%d)", res.Android.VersionName, res.Android.VersionCode)
	t.Logf("MinSDK: %d, TargetSDK: %d", res.Android.MinSDK, res.Android.TargetSDK)
	t.Logf("Total Components: %d", len(res.Android.Components))
	t.Logf("Total Findings: %d", len(res.Findings))

	for _, f := range res.Findings {
		t.Logf(" * [%s] %s (%s): %s", f.Severity, f.RuleID, f.Classification, f.ComponentOrKey)
	}
}

func TestLive_UnCrackable_Level1_IPA(t *testing.T) {
	path := `C:\SecurityLabs\android-mastg\Crackmes\iOS\Level_01\UnCrackable-Level1.ipa`
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Live target missing at %s", path)
	}

	analyzer := NewStaticAnalyzer()
	res, err := analyzer.InspectIPAFile(context.Background(), path)
	if err != nil {
		t.Fatalf("failed analyzing UnCrackable-Level1.ipa: %v", err)
	}

	if res.IOS == nil {
		t.Fatalf("expected parsed iOS metadata")
	}

	t.Logf("BundleID: %s", res.IOS.BundleIdentifier)
	t.Logf("BundleName: %s", res.IOS.BundleName)
	t.Logf("Version: %s (%s)", res.IOS.VersionString, res.IOS.BuildNumber)
	t.Logf("MinOSVersion: %s", res.IOS.MinimumOSVersion)
	t.Logf("Total Findings: %d", len(res.Findings))

	for _, f := range res.Findings {
		t.Logf(" * [%s] %s (%s): %s", f.Severity, f.RuleID, f.Classification, f.ComponentOrKey)
	}
}
