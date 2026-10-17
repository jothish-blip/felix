package apk

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const (
	maxXMLNestingDepth = 50
	maxXMLElementCount = 10000
)

// ParseTextualManifest parses standard textual XML manifest bytes into a RawElement tree.
// It strictly rejects DTD/entity declarations to prevent XML entity expansion attacks (Billion Laughs / SSRF).
func ParseTextualManifest(data []byte, limits Limits) (*RawElement, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: manifest data is empty", ErrInvalidInput)
	}
	if limits.MaxEntrySize > 0 && int64(len(data)) > limits.MaxEntrySize {
		return nil, fmt.Errorf("%w: manifest size (%d bytes) exceeds maximum limit (%d bytes)",
			ErrLimitExceeded, len(data), limits.MaxEntrySize)
	}

	// Security Defense: Prohibit DOCTYPE and ENTITY declarations outright
	upper := bytes.ToUpper(data)
	if bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<!ENTITY")) {
		return nil, fmt.Errorf("%w: prohibited DOCTYPE or ENTITY declaration in manifest (entity expansion defense)",
			ErrSecurityViolation)
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	// Ensure external entities are never resolved
	decoder.Entity = map[string]string{}

	var (
		stack      []*RawElement
		root       *RawElement
		elemCount  int
		namespaces = make(map[string]string) // prefix -> uri
	)

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("%w: XML parsing error: %v", ErrMalformedArchive, err)
		}

		switch t := token.(type) {
		case xml.StartElement:
			elemCount++
			if elemCount > maxXMLElementCount {
				return nil, fmt.Errorf("%w: XML element count exceeded limit %d", ErrLimitExceeded, maxXMLElementCount)
			}
			if len(stack) >= maxXMLNestingDepth {
				return nil, fmt.Errorf("%w: XML nesting depth exceeded limit %d", ErrLimitExceeded, maxXMLNestingDepth)
			}

			// Scan for xmlns declarations
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" {
					namespaces[a.Name.Local] = a.Value
				} else if a.Name.Local == "xmlns" && a.Name.Space == "" {
					namespaces[""] = a.Value
				}
			}

			// Build raw attributes
			var attrs []RawAttribute
			for _, a := range t.Attr {
				ns := a.Name.Space
				name := a.Name.Local

				// If namespace is a prefix rather than full URI, resolve it
				if uri, ok := namespaces[ns]; ok && uri != "" {
					ns = uri
				} else if ns == "android" {
					ns = AndroidNamespace
				}

				// If name has "android:" prefix embedded
				if strings.HasPrefix(name, "android:") {
					name = strings.TrimPrefix(name, "android:")
					ns = AndroidNamespace
				}

				attrs = append(attrs, RawAttribute{
					Namespace: ns,
					Name:      name,
					Value:     a.Value,
				})
			}

			elemNs := t.Name.Space
			if uri, ok := namespaces[elemNs]; ok && uri != "" {
				elemNs = uri
			}

			elem := &RawElement{
				Namespace: elemNs,
				Name:      t.Name.Local,
				Attrs:     attrs,
			}

			if root == nil {
				root = elem
			} else if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, elem)
			}

			stack = append(stack, elem)

		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}

	if root == nil {
		return nil, fmt.Errorf("%w: empty or invalid manifest XML", ErrNotAnAPK)
	}

	return root, nil
}
