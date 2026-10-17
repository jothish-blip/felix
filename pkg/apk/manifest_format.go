package apk

import (
	"bytes"
)

const (
	// FormatAXML designates compiled Android binary XML.
	FormatAXML = "AXML"

	// FormatXML designates textual UTF-8 XML.
	FormatXML = "XML"

	// FormatUnknown designates unrecognized manifest content.
	FormatUnknown = "UNKNOWN"
)

var (
	// axmlHeaderMagic is the 4-byte signature for compiled Android binary XML (CHUNK_AXML_FILE = 0x00080003).
	axmlHeaderMagic = []byte{0x03, 0x00, 0x08, 0x00}
)

// DetectManifestFormat inspects the raw manifest bytes and determines whether
// the input is compiled Android binary XML (AXML), standard textual XML, or unknown.
func DetectManifestFormat(data []byte) string {
	if len(data) < 4 {
		return FormatUnknown
	}

	// 1. Check for compiled Android binary XML header (0x00080003)
	if bytes.Equal(data[:4], axmlHeaderMagic) {
		return FormatAXML
	}

	// 2. Check for standard textual XML
	content := data
	if bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}) { // Strip UTF-8 BOM
		content = content[3:]
	}
	trimmed := bytes.TrimSpace(content)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.Contains(content, []byte("<manifest")) {
		return FormatXML
	}

	return FormatUnknown
}
