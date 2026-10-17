package apk

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// NetworkSecurityConfigInfo encapsulates security properties parsed from network_security_config.xml.
type NetworkSecurityConfigInfo struct {
	DeclaredResource       string
	ResolvedPath           string
	ConfigFound            bool
	BaseCleartextPermitted *bool
	UserTrustAnchors       bool
	DebugUserTrustAnchors  bool
	Domains                []DomainConfigInfo
	PinSets                []PinSetInfo
	ParseError             string
}

// DomainConfigInfo captures domain-specific network security overrides.
type DomainConfigInfo struct {
	Domain              string
	IncludeSubdomains   bool
	CleartextPermitted  *bool
	UserTrustAnchors    bool
	HasPinSet           bool
}

// PinSetInfo models certificate pinning declarations.
type PinSetInfo struct {
	Expiration string
	Pins       []string
}

// ParseNetworkSecurityConfig locates and parses the XML resource referenced by android:networkSecurityConfig.
// It enforces workspace containment and strict XML entity expansion defenses.
func ParseNetworkSecurityConfig(ws *Workspace, resourceRef string, limits Limits) (*NetworkSecurityConfigInfo, error) {
	if resourceRef == "" {
		return nil, nil
	}

	info := &NetworkSecurityConfigInfo{
		DeclaredResource: resourceRef,
	}

	if ws == nil || ws.Dir == "" {
		info.ParseError = "no workspace available to resolve referenced network security resource"
		return info, nil
	}

	// Resolve resource reference (e.g. "@xml/network_security_config" -> "res/xml/network_security_config.xml")
	relPath := resolveNetworkSecurityResourcePath(resourceRef)
	if relPath == "" || strings.HasPrefix(strings.ToLower(strings.TrimPrefix(resourceRef, "@")), "0x") {
		// Fallback for compiled hex resource references (@0x7F...): check standard candidate filenames
		candidates := []string{
			"res/xml/network_security_config.xml",
			"res/xml/network-security-config.xml",
			"res/xml/network_security.xml",
		}
		for _, cand := range candidates {
			tp, err := VerifyExtractionTarget(ws.Dir, cand)
			if err == nil {
				if fi, err := os.Stat(tp); err == nil && !fi.IsDir() && fi.Size() > 0 {
					relPath = cand
					break
				}
			}
		}
	}
	if relPath == "" {
		info.ParseError = fmt.Sprintf("unrecognized networkSecurityConfig resource syntax: %q", resourceRef)
		return info, nil
	}

	targetPath, err := VerifyExtractionTarget(ws.Dir, relPath)
	if err != nil {
		info.ParseError = fmt.Sprintf("network security resource escapes workspace: %v", err)
		return info, err
	}

	fi, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Resource not extracted or not present in standalone manifest-only intake
			info.ResolvedPath = relPath
			info.ConfigFound = false
			return info, nil
		}
		info.ParseError = fmt.Sprintf("failed accessing network security resource: %v", err)
		return info, nil
	}

	if fi.IsDir() || fi.Size() == 0 {
		info.ParseError = fmt.Sprintf("invalid network security resource file (dir or empty): %s", targetPath)
		return info, nil
	}

	maxSize := int64(1 * 1024 * 1024) // 1 MiB limit for network config
	if fi.Size() > maxSize {
		info.ParseError = fmt.Sprintf("network security resource size (%d) exceeds limit (%d)", fi.Size(), maxSize)
		return info, nil
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		info.ParseError = fmt.Sprintf("failed reading network security config: %v", err)
		return info, nil
	}

	info.ConfigFound = true
	info.ResolvedPath = relPath

	// Prohibit DOCTYPE / ENTITY
	upper := bytes.ToUpper(data)
	if bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<!ENTITY")) {
		info.ParseError = "prohibited DOCTYPE or ENTITY in network security configuration"
		return info, nil
	}

	// Parse XML safely
	if err := parseNetworkSecurityXML(data, info); err != nil {
		info.ParseError = fmt.Sprintf("failed parsing network security config XML: %v", err)
		return info, nil
	}

	return info, nil
}

func resolveNetworkSecurityResourcePath(resourceRef string) string {
	res := strings.TrimSpace(resourceRef)
	res = strings.TrimPrefix(res, "@")
	parts := strings.Split(res, "/")
	if len(parts) == 2 {
		folder := parts[0]
		file := parts[1]
		if folder == "xml" {
			return filepath.ToSlash(filepath.Join("res", "xml", file+".xml"))
		}
		return filepath.ToSlash(filepath.Join("res", folder, file+".xml"))
	}
	if len(parts) == 1 && parts[0] != "" {
		return filepath.ToSlash(filepath.Join("res", "xml", parts[0]+".xml"))
	}
	return ""
}

func parseNetworkSecurityXML(data []byte, info *NetworkSecurityConfigInfo) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Entity = map[string]string{}

	var (
		inDomainConfig  bool
		inDebugOverride bool
		inTrustAnchors  bool
		inPinSet        bool
		currentDomain   *DomainConfigInfo
		currentPinSet   *PinSetInfo
	)

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch t := token.(type) {
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			switch name {
			case "base-config":
				for _, a := range t.Attr {
					if strings.EqualFold(a.Name.Local, "cleartextTrafficPermitted") {
						info.BaseCleartextPermitted = ParseBoolPtr(a.Value, true)
					}
				}

			case "domain-config":
				inDomainConfig = true
				currentDomain = &DomainConfigInfo{}
				for _, a := range t.Attr {
					if strings.EqualFold(a.Name.Local, "cleartextTrafficPermitted") {
						currentDomain.CleartextPermitted = ParseBoolPtr(a.Value, true)
					}
				}

			case "domain":
				if inDomainConfig && currentDomain != nil {
					for _, a := range t.Attr {
						if strings.EqualFold(a.Name.Local, "includeSubdomains") {
							b := ParseBoolPtr(a.Value, true)
							if b != nil {
								currentDomain.IncludeSubdomains = *b
							}
						}
					}
					// Read text inside <domain>
					var domainText string
					if err := decoder.DecodeElement(&domainText, &t); err == nil {
						currentDomain.Domain = strings.TrimSpace(domainText)
					}
				}

			case "debug-overrides":
				inDebugOverride = true

			case "trust-anchors":
				inTrustAnchors = true

			case "certificates":
				if inTrustAnchors {
					for _, a := range t.Attr {
						if strings.EqualFold(a.Name.Local, "src") {
							val := strings.ToLower(strings.TrimSpace(a.Value))
							if val == "user" {
								if inDebugOverride {
									info.DebugUserTrustAnchors = true
								} else {
									info.UserTrustAnchors = true
									if inDomainConfig && currentDomain != nil {
										currentDomain.UserTrustAnchors = true
									}
								}
							}
						}
					}
				}

			case "pin-set":
				inPinSet = true
				currentPinSet = &PinSetInfo{}
				for _, a := range t.Attr {
					if strings.EqualFold(a.Name.Local, "expiration") {
						currentPinSet.Expiration = a.Value
					}
				}
				if inDomainConfig && currentDomain != nil {
					currentDomain.HasPinSet = true
				}

			case "pin":
				if inPinSet && currentPinSet != nil {
					var pinDigest string
					if err := decoder.DecodeElement(&pinDigest, &t); err == nil {
						currentPinSet.Pins = append(currentPinSet.Pins, strings.TrimSpace(pinDigest))
					}
				}
			}

		case xml.EndElement:
			name := strings.ToLower(t.Name.Local)
			switch name {
			case "domain-config":
				if currentDomain != nil {
					info.Domains = append(info.Domains, *currentDomain)
					currentDomain = nil
				}
				inDomainConfig = false
			case "debug-overrides":
				inDebugOverride = false
			case "trust-anchors":
				inTrustAnchors = false
			case "pin-set":
				if currentPinSet != nil {
					info.PinSets = append(info.PinSets, *currentPinSet)
					currentPinSet = nil
				}
				inPinSet = false
			}
		}
	}

	return nil
}
