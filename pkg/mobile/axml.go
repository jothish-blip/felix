package mobile

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// AXML Chunk Types
const (
	chunkResNull           uint16 = 0x0000
	chunkResStringPool     uint16 = 0x0001
	chunkResTable          uint16 = 0x0002
	chunkResXML            uint16 = 0x0003
	chunkResXMLStartNS     uint16 = 0x0100
	chunkResXMLEndNS       uint16 = 0x0101
	chunkResXMLStartElem   uint16 = 0x0102
	chunkResXMLEndElem     uint16 = 0x0103
	chunkResXMLCDATA       uint16 = 0x0104
	chunkResXMLResourceMap uint16 = 0x0180
)

// AXML Attribute Data Types
const (
	typeNull      uint8 = 0x00
	typeReference uint8 = 0x01
	typeAttribute uint8 = 0x02
	typeString    uint8 = 0x03
	typeFloat     uint8 = 0x04
	typeDimension uint8 = 0x05
	typeFraction  uint8 = 0x06
	typeIntDec    uint8 = 0x10
	typeIntHex    uint8 = 0x11
	typeBoolean   uint8 = 0x12
)

// Well-known Android resource IDs in the framework resource map
var knownResourceIDs = map[uint32]string{
	0x01010002: "debuggable",
	0x01010003: "name",
	0x01010006: "permission",
	0x0101000e: "enabled",
	0x01010010: "exported",
	0x01010012: "authorities",
	0x01010016: "grantUriPermissions",
	0x01010017: "readPermission",
	0x01010018: "writePermission",
	0x01010020: "versionCode",
	0x0101002b: "versionName",
	0x0101020c: "minSdkVersion",
	0x01010270: "targetSdkVersion",
	0x01010271: "maxSdkVersion",
	0x0101027f: "allowBackup",
	0x010104ec: "usesCleartextTraffic",
	0x01010524: "networkSecurityConfig",
	0x01010028: "scheme",
	0x01010029: "host",
	0x0101002a: "port",
	0x0101002c: "path",
}

// XMLElement represents a parsed XML element from binary or textual XML.
type XMLElement struct {
	Tag        string
	Attributes map[string]string
	Children   []*XMLElement
}

// GetAttr returns an attribute value by name (checking both exact and suffix match).
func (e *XMLElement) GetAttr(name string) (string, bool) {
	if val, ok := e.Attributes[name]; ok {
		return val, true
	}
	// Try prefixed e.g. "android:name" or bare "name"
	targetSuffix := ":" + name
	for k, v := range e.Attributes {
		if strings.HasSuffix(k, targetSuffix) || k == name {
			return v, true
		}
	}
	return "", false
}

// FindChildren returns all direct child elements matching the given tag.
func (e *XMLElement) FindChildren(tag string) []*XMLElement {
	var res []*XMLElement
	targetSuffix := ":" + tag
	for _, child := range e.Children {
		if child.Tag == tag || strings.HasSuffix(child.Tag, targetSuffix) {
			res = append(res, child)
		}
	}
	return res
}

// FindChild returns the first direct child element matching the given tag.
func (e *XMLElement) FindChild(tag string) *XMLElement {
	matches := e.FindChildren(tag)
	if len(matches) > 0 {
		return matches[0]
	}
	return nil
}

// ParseAndroidManifest attempts to parse raw manifest bytes, supporting binary XML (AXML) and textual XML.
func ParseAndroidManifest(data []byte) (*XMLElement, error) {
	if len(data) < 8 {
		return nil, errors.New("manifest data too short")
	}

	// Check if data is binary XML (RES_XML_TYPE = 0x0003, header size = 8)
	chunkType := binary.LittleEndian.Uint16(data[0:2])
	headerSize := binary.LittleEndian.Uint16(data[2:4])

	if chunkType == chunkResXML && headerSize == 8 {
		return parseBinaryXML(data)
	}

	// Fallback to textual XML parser
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<manifest")) {
		return parseTextualXML(trimmed)
	}

	return nil, fmt.Errorf("unrecognized manifest format (magic: 0x%04x, header: 0x%04x)", chunkType, headerSize)
}

// parseTextualXML parses ordinary XML manifests.
func parseTextualXML(data []byte) (*XMLElement, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var root *XMLElement
	var stack []*XMLElement

	for {
		tok, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("textual XML parse error: %w", err)
		}

		switch elem := tok.(type) {
		case xml.StartElement:
			node := &XMLElement{
				Tag:        elem.Name.Local,
				Attributes: make(map[string]string),
				Children:   nil,
			}
			for _, attr := range elem.Attr {
				attrName := attr.Name.Local
				if attr.Name.Space != "" {
					attrName = attr.Name.Space + ":" + attr.Name.Local
				}
				node.Attributes[attrName] = attr.Value
				// Also store bare name for easy lookup
				if _, exists := node.Attributes[attr.Name.Local]; !exists {
					node.Attributes[attr.Name.Local] = attr.Value
				}
			}

			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			} else {
				root = node
			}
			stack = append(stack, node)

		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}

	if root == nil {
		return nil, errors.New("no root XML element found in textual manifest")
	}
	return root, nil
}

// parseBinaryXML decodes an Android Binary XML (AXML) stream into an XMLElement tree.
func parseBinaryXML(data []byte) (*XMLElement, error) {
	if len(data) < 8 {
		return nil, errors.New("binary XML too short")
	}

	fileSize := binary.LittleEndian.Uint32(data[4:8])
	if int(fileSize) > len(data) {
		return nil, fmt.Errorf("binary XML declared size %d exceeds available data %d", fileSize, len(data))
	}

	var stringPool []string
	var resourceIDs []uint32

	var root *XMLElement
	var stack []*XMLElement

	offset := 8
	maxOffset := len(data)

	for offset < maxOffset {
		if offset+8 > maxOffset {
			break
		}

		cType := binary.LittleEndian.Uint16(data[offset : offset+2])
		cHeaderSize := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		cSize := binary.LittleEndian.Uint32(data[offset+4 : offset+8])

		if cSize < 8 || int(cSize) > maxOffset-offset {
			return nil, fmt.Errorf("malformed chunk at offset %d: size %d invalid", offset, cSize)
		}

		chunkEnd := offset + int(cSize)

		switch cType {
		case chunkResStringPool:
			pool, err := parseStringPool(data[offset:chunkEnd])
			if err != nil {
				return nil, fmt.Errorf("string pool error: %w", err)
			}
			stringPool = pool

		case chunkResXMLResourceMap:
			rIDs, err := parseResourceMap(data[offset:chunkEnd])
			if err != nil {
				return nil, fmt.Errorf("resource map error: %w", err)
			}
			resourceIDs = rIDs

		case chunkResXMLStartNS, chunkResXMLEndNS:
			// Namespaces are tracked or skipped

		case chunkResXMLStartElem:
			elem, err := parseStartElement(data[offset:chunkEnd], stringPool, resourceIDs)
			if err != nil {
				return nil, fmt.Errorf("element parse error at offset %d: %w", offset, err)
			}

			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, elem)
			} else {
				root = elem
			}
			stack = append(stack, elem)

		case chunkResXMLEndElem:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case chunkResXMLCDATA:
			// CDATA ignored
		}

		offset = chunkEnd
		_ = cHeaderSize
	}

	if root == nil {
		return nil, errors.New("no root element found in binary XML")
	}

	return root, nil
}

// parseStringPool extracts all strings from the RES_STRING_POOL_TYPE chunk.
func parseStringPool(data []byte) ([]string, error) {
	if len(data) < 28 {
		return nil, errors.New("string pool chunk too short")
	}

	stringCount := binary.LittleEndian.Uint32(data[8:12])
	styleCount := binary.LittleEndian.Uint32(data[12:16])
	flags := binary.LittleEndian.Uint32(data[16:20])
	stringsStart := binary.LittleEndian.Uint32(data[20:24])
	_ = styleCount

	isUTF8 := (flags & (1 << 8)) != 0

	if int(stringsStart) > len(data) {
		return nil, errors.New("stringsStart out of bounds")
	}

	offsetTableOffset := 28
	if offsetTableOffset+int(stringCount)*4 > len(data) {
		return nil, errors.New("string offset table exceeds chunk size")
	}

	offsets := make([]uint32, stringCount)
	for i := 0; i < int(stringCount); i++ {
		offsets[i] = binary.LittleEndian.Uint32(data[offsetTableOffset+i*4 : offsetTableOffset+(i+1)*4])
	}

	stringsData := data[stringsStart:]
	result := make([]string, stringCount)

	for i := 0; i < int(stringCount); i++ {
		strOffset := int(offsets[i])
		if strOffset >= len(stringsData) {
			result[i] = ""
			continue
		}

		if isUTF8 {
			str, err := decodeAXMLStringUTF8(stringsData[strOffset:])
			if err != nil {
				result[i] = ""
			} else {
				result[i] = str
			}
		} else {
			str, err := decodeAXMLStringUTF16(stringsData[strOffset:])
			if err != nil {
				result[i] = ""
			} else {
				result[i] = str
			}
		}
	}

	return result, nil
}

// decodeAXMLStringUTF8 decodes a UTF-8 string entry from the string pool.
func decodeAXMLStringUTF8(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("buffer too short")
	}
	idx := 0

	// 1. Skip UTF-16 length (1 or 2 bytes)
	if b[idx]&0x80 != 0 {
		idx += 2
	} else {
		idx += 1
	}
	if idx >= len(b) {
		return "", errors.New("buffer truncated in utf16 length")
	}

	// 2. Read UTF-8 byte length (1 or 2 bytes)
	var utf8Len int
	if b[idx]&0x80 != 0 {
		if idx+1 >= len(b) {
			return "", errors.New("buffer truncated in utf8 length")
		}
		utf8Len = (int(b[idx]&0x7F) << 8) | int(b[idx+1])
		idx += 2
	} else {
		utf8Len = int(b[idx])
		idx += 1
	}

	if idx+utf8Len > len(b) {
		// Truncated, take what is available
		utf8Len = len(b) - idx
	}

	return string(b[idx : idx+utf8Len]), nil
}

// decodeAXMLStringUTF16 decodes a UTF-16LE string entry from the string pool.
func decodeAXMLStringUTF16(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("buffer too short for utf16")
	}
	idx := 0

	// 1. Read UTF-16 length in 2-byte units (1 or 2 uint16s)
	u0 := binary.LittleEndian.Uint16(b[idx : idx+2])
	idx += 2
	var charCount int
	if u0&0x8000 != 0 {
		if idx+2 > len(b) {
			return "", errors.New("buffer truncated in utf16 length")
		}
		u1 := binary.LittleEndian.Uint16(b[idx : idx+2])
		idx += 2
		charCount = (int(u0&0x7FFF) << 16) | int(u1)
	} else {
		charCount = int(u0)
	}

	byteLen := charCount * 2
	if idx+byteLen > len(b) {
		byteLen = (len(b) - idx) &^ 1 // round down to even
		charCount = byteLen / 2
	}

	u16s := make([]uint16, charCount)
	for i := 0; i < charCount; i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[idx+i*2 : idx+(i+1)*2])
	}

	return string(utf16.Decode(u16s)), nil
}

// parseResourceMap extracts resource IDs from RES_XML_RESOURCE_MAP_TYPE chunk.
func parseResourceMap(data []byte) ([]uint32, error) {
	if len(data) < 8 {
		return nil, errors.New("resource map chunk too short")
	}
	chunkSize := binary.LittleEndian.Uint32(data[4:8])
	count := (chunkSize - 8) / 4
	if 8+int(count)*4 > len(data) {
		count = uint32((len(data) - 8) / 4)
	}

	ids := make([]uint32, count)
	for i := 0; i < int(count); i++ {
		ids[i] = binary.LittleEndian.Uint32(data[8+i*4 : 8+(i+1)*4])
	}
	return ids, nil
}

// parseStartElement decodes a start element chunk and its attributes.
func parseStartElement(data []byte, stringPool []string, resourceIDs []uint32) (*XMLElement, error) {
	if len(data) < 36 {
		return nil, errors.New("start element chunk too short")
	}

	nameIndex := binary.LittleEndian.Uint32(data[20:24])
	attrStart := binary.LittleEndian.Uint16(data[24:26])
	attrSize := binary.LittleEndian.Uint16(data[26:28])
	attrCount := binary.LittleEndian.Uint16(data[28:30])

	tagName := ""
	if int(nameIndex) < len(stringPool) {
		tagName = stringPool[nameIndex]
	} else {
		tagName = fmt.Sprintf("elem_0x%x", nameIndex)
	}

	elem := &XMLElement{
		Tag:        tagName,
		Attributes: make(map[string]string),
	}

	// Attr offset relative to chunk header
	attrOffset := int(attrStart)
	if attrOffset < 36 {
		attrOffset = 36 // default if 0 or offset from header
	}

	for i := 0; i < int(attrCount); i++ {
		recOffset := attrOffset + i*int(attrSize)
		if recOffset+20 > len(data) {
			break
		}

		nsIdx := binary.LittleEndian.Uint32(data[recOffset : recOffset+4])
		attrNameIdx := binary.LittleEndian.Uint32(data[recOffset+4 : recOffset+8])
		rawValIdx := binary.LittleEndian.Uint32(data[recOffset+8 : recOffset+12])
		dataType := data[recOffset+15]
		dataVal := binary.LittleEndian.Uint32(data[recOffset+16 : recOffset+20])

		_ = nsIdx

		// Determine attribute name
		attrName := ""
		if int(attrNameIdx) < len(stringPool) {
			attrName = stringPool[attrNameIdx]
		}
		if attrName == "" && int(attrNameIdx) < len(resourceIDs) {
			resID := resourceIDs[attrNameIdx]
			if knownName, ok := knownResourceIDs[resID]; ok {
				attrName = knownName
			}
		}
		if attrName == "" {
			attrName = fmt.Sprintf("attr_0x%x", attrNameIdx)
		}

		// Determine attribute value
		attrValue := ""
		if rawValIdx != 0xFFFFFFFF && int(rawValIdx) < len(stringPool) && stringPool[rawValIdx] != "" {
			attrValue = stringPool[rawValIdx]
		} else {
			switch dataType {
			case typeString:
				if int(dataVal) < len(stringPool) {
					attrValue = stringPool[dataVal]
				}
			case typeBoolean:
				if dataVal != 0 {
					attrValue = "true"
				} else {
					attrValue = "false"
				}
			case typeIntDec:
				attrValue = strconv.Itoa(int(int32(dataVal)))
			case typeIntHex:
				attrValue = fmt.Sprintf("0x%x", dataVal)
			case typeReference:
				attrValue = fmt.Sprintf("@0x%08x", dataVal)
			default:
				if int(dataVal) < len(stringPool) && stringPool[dataVal] != "" {
					attrValue = stringPool[dataVal]
				} else {
					attrValue = strconv.FormatUint(uint64(dataVal), 10)
				}
			}
		}

		// Store with both android: and bare name for seamless query
		elem.Attributes[attrName] = attrValue
		if !strings.HasPrefix(attrName, "android:") {
			elem.Attributes["android:"+attrName] = attrValue
		}
	}

	return elem, nil
}
