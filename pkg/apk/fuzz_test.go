package apk

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func FuzzAXMLParser(f *testing.F) {
	// Seed 1: valid generated AXML
	b := newAXMLBuilder()
	tBool := true
	fBool := false
	validAXML := b.buildAXML("com.example.fuzzapp", &tBool, &fBool, "MainActivity", &tBool)
	f.Add(validAXML)

	// Boundary / malformed seeds
	f.Add([]byte{})
	f.Add([]byte{0x03, 0x00, 0x08, 0x00})                         // short header
	f.Add([]byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}) // 0 size
	f.Add([]byte{0x03, 0x00, 0x08, 0x00, 0xff, 0xff, 0xff, 0x7f}) // huge declared size
	f.Add([]byte{0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00}) // invalid root chunk type
	f.Add(bytes.Repeat([]byte{0x01, 0x00, 0x10, 0x00}, 50))
	f.Add([]byte("PK\x03\x04not-axml-at-all"))

	limits := DefaultLimits()

	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := ParseAXML(data, limits)
		if err != nil {
			return
		}

		// Invariant 1: If parsing succeeded, root element must not be nil
		if root == nil {
			t.Fatalf("ParseAXML succeeded but returned nil root")
		}

		// Invariant 2: ExtractManifestDocument must process root without panic
		doc := ExtractManifestDocument(root, "binary")
		if doc == nil {
			t.Fatalf("ExtractManifestDocument returned nil document")
		}
	})
}

func FuzzTextualManifestParser(f *testing.F) {
	// Seed 1: valid minimal manifest
	f.Add([]byte(`<manifest package="com.example.app"><application android:debuggable="true"/></manifest>`))
	// Seed 2: valid full manifest with components
	f.Add([]byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
		<application android:allowBackup="false" android:usesCleartextTraffic="true">
			<activity android:name=".MainActivity" android:exported="true"/>
		</application>
	</manifest>`))
	// Seed 3: XXE attack attempts
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><manifest>&test;</manifest>`))
	f.Add([]byte(`<!doctype manifest [<!entity lol "lol">]><manifest>&lol;</manifest>`))
	// Seed 4: malformed XML
	f.Add([]byte("<manifest>"))
	f.Add([]byte(""))
	f.Add([]byte("   "))
	f.Add([]byte("<manifest><application><activity></manifest>"))
	f.Add([]byte(strings.Repeat("<tag>", 100)))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff})

	limits := DefaultLimits()

	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := ParseTextualManifest(data, limits)
		if err != nil {
			// Expected outcome for malformed XML or hostile DTDs
			return
		}

		// Invariant 1: Prohibited DOCTYPE or ENTITY must never succeed
		upper := bytes.ToUpper(data)
		if bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<!ENTITY")) {
			t.Fatalf("security violation: ParseTextualManifest accepted DTD/ENTITY input: %s", string(data))
		}

		// Invariant 2: If parsing succeeded, root must not be nil
		if root == nil {
			t.Fatalf("ParseTextualManifest succeeded but returned nil root")
		}

		// Invariant 3: ExtractManifestDocument must execute without panic
		doc := ExtractManifestDocument(root, "xml")
		if doc == nil {
			t.Fatalf("ExtractManifestDocument returned nil for parsed manifest")
		}
	})
}

func FuzzDEXParser(f *testing.F) {
	// Seed 1: DEX magic header
	dexMagic035 := []byte("dex\n035\x00" + strings.Repeat("\x00", 104))
	f.Add(dexMagic035)
	dexMagic039 := []byte("dex\n039\x00" + strings.Repeat("\x00", 104))
	f.Add(dexMagic039)
	f.Add([]byte{})
	f.Add([]byte("dex\n"))
	f.Add([]byte("not a dex file"))
	f.Add(bytes.Repeat([]byte{0xff}, 120))

	limits := DefaultLimits()
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, data []byte) {
		dex, err := ParseDEX(ctx, "classes.dex", data, limits)
		if err != nil {
			return
		}
		// Invariant: If parsing succeeded, dex must not be nil
		if dex == nil {
			t.Fatalf("ParseDEX succeeded but returned nil DEXFile")
		}
	})
}
