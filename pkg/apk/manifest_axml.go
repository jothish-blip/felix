package apk

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"unicode/utf16"
)

// AXML chunk types
const (
	axmlChunkXML            = 0x0003
	axmlChunkStringPool     = 0x0001
	axmlChunkResourceMap    = 0x0180
	axmlChunkStartNamespace = 0x0100
	axmlChunkEndNamespace   = 0x0101
	axmlChunkStartElement   = 0x0102
	axmlChunkEndElement     = 0x0103
	axmlChunkCData          = 0x0104
)

// AXML typed value data types
const (
	axmlTypeNull       = 0x00
	axmlTypeReference  = 0x01
	axmlTypeAttribute  = 0x02
	axmlTypeString     = 0x03
	axmlTypeFloat      = 0x04
	axmlTypeDimension  = 0x05
	axmlTypeFraction   = 0x06
	axmlTypeIntDec     = 0x10
	axmlTypeIntHex     = 0x11
	axmlTypeIntBoolean = 0x12
)

const (
	maxAXMLNestingDepth = 50
	maxAXMLElementCount = 10000
	maxAXMLStringCount  = 50000
)

type axmlStringPool struct {
	strings []string
}

func (sp *axmlStringPool) getString(idx uint32) string {
	if sp == nil || idx == 0xFFFFFFFF || int(idx) >= len(sp.strings) {
		return ""
	}
	return sp.strings[idx]
}

// ParseAXML parses compiled Android binary XML bytes into a RawElement tree.
func ParseAXML(data []byte, limits Limits) (*RawElement, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: AXML data too short (%d bytes)", ErrMalformedArchive, len(data))
	}
	if limits.MaxEntrySize > 0 && int64(len(data)) > limits.MaxEntrySize {
		return nil, fmt.Errorf("%w: AXML size (%d) exceeds limit (%d)", ErrLimitExceeded, len(data), limits.MaxEntrySize)
	}

	chunkType := binary.LittleEndian.Uint16(data[0:2])
	headerSize := binary.LittleEndian.Uint16(data[2:4])
	chunkSize := binary.LittleEndian.Uint32(data[4:8])

	if chunkType != axmlChunkXML {
		return nil, fmt.Errorf("%w: invalid AXML root chunk type 0x%04X (expected 0x0003)", ErrNotAnAPK, chunkType)
	}
	if headerSize < 8 || int(headerSize) > len(data) {
		return nil, fmt.Errorf("%w: invalid AXML root header size %d", ErrMalformedArchive, headerSize)
	}
	if int(chunkSize) > len(data) {
		return nil, fmt.Errorf("%w: declared AXML chunk size %d exceeds data length %d", ErrMalformedArchive, chunkSize, len(data))
	}

	offset := int(headerSize)
	end := int(chunkSize)

	var (
		stringPool  *axmlStringPool
		resourceMap []uint32
		nsPrefixMap = make(map[string]string) // prefix -> uri
		nsUriMap    = make(map[string]string) // uri -> prefix
		stack       []*RawElement
		root        *RawElement
		elemCount   int
	)

	for offset < end {
		if offset+8 > end {
			return nil, fmt.Errorf("%w: truncated chunk at offset %d", ErrMalformedArchive, offset)
		}

		cType := binary.LittleEndian.Uint16(data[offset : offset+2])
		cHeaderSize := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		cSize := binary.LittleEndian.Uint32(data[offset+4 : offset+8])

		if cSize < 8 || offset+int(cSize) > end {
			return nil, fmt.Errorf("%w: invalid chunk size %d at offset %d (exceeds bounds %d)",
				ErrMalformedArchive, cSize, offset, end)
		}

		chunkData := data[offset : offset+int(cSize)]

		switch cType {
		case axmlChunkStringPool:
			sp, err := parseAXMLStringPool(chunkData)
			if err != nil {
				return nil, err
			}
			stringPool = sp

		case axmlChunkResourceMap:
			rm, err := parseAXMLResourceMap(chunkData, cHeaderSize)
			if err != nil {
				return nil, err
			}
			resourceMap = rm

		case axmlChunkStartNamespace:
			if len(chunkData) >= 16 && stringPool != nil {
				prefixIdx := binary.LittleEndian.Uint32(chunkData[8:12])
				uriIdx := binary.LittleEndian.Uint32(chunkData[12:16])
				prefix := stringPool.getString(prefixIdx)
				uri := stringPool.getString(uriIdx)
				if uri != "" {
					nsPrefixMap[prefix] = uri
					nsUriMap[uri] = prefix
				}
			}

		case axmlChunkEndNamespace:
			// Pop namespace mapping if tracking scopes, or retain global mapping

		case axmlChunkStartElement:
			if stringPool == nil {
				return nil, fmt.Errorf("%w: element encountered before string pool", ErrMalformedArchive)
			}
			elemCount++
			if elemCount > maxAXMLElementCount {
				return nil, fmt.Errorf("%w: element count exceeded limit %d", ErrLimitExceeded, maxAXMLElementCount)
			}
			if len(stack) >= maxAXMLNestingDepth {
				return nil, fmt.Errorf("%w: nesting depth exceeded limit %d", ErrLimitExceeded, maxAXMLNestingDepth)
			}

			elem, err := parseAXMLStartElement(chunkData, stringPool, resourceMap, nsPrefixMap)
			if err != nil {
				return nil, err
			}

			if root == nil {
				root = elem
			} else if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, elem)
			}
			stack = append(stack, elem)

		case axmlChunkEndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case axmlChunkCData:
			// Discard or capture CDATA
		}

		offset += int(cSize)
	}

	if root == nil {
		return nil, fmt.Errorf("%w: no root element found in AXML manifest", ErrNotAnAPK)
	}

	return root, nil
}

func parseAXMLStringPool(data []byte) (*axmlStringPool, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("%w: string pool chunk too small (%d bytes)", ErrMalformedArchive, len(data))
	}

	stringCount := binary.LittleEndian.Uint32(data[8:12])
	flags := binary.LittleEndian.Uint32(data[16:20])
	stringsStart := binary.LittleEndian.Uint32(data[20:24])

	if stringCount > maxAXMLStringCount {
		return nil, fmt.Errorf("%w: string pool count %d exceeds maximum limit %d", ErrLimitExceeded, stringCount, maxAXMLStringCount)
	}
	if int(stringsStart) > len(data) {
		return nil, fmt.Errorf("%w: invalid string pool stringsStart offset %d", ErrMalformedArchive, stringsStart)
	}

	isUTF8 := (flags & 0x0100) != 0

	// Read string offsets
	offsetsOffset := 28
	if offsetsOffset+int(stringCount)*4 > len(data) {
		return nil, fmt.Errorf("%w: string offsets array extends beyond chunk bounds", ErrMalformedArchive)
	}

	offsets := make([]uint32, stringCount)
	for i := uint32(0); i < stringCount; i++ {
		offsets[i] = binary.LittleEndian.Uint32(data[offsetsOffset+int(i)*4 : offsetsOffset+int(i)*4+4])
	}

	stringsSlice := make([]string, stringCount)
	stringBlock := data[stringsStart:]

	for i, off := range offsets {
		if int(off) >= len(stringBlock) {
			stringsSlice[i] = ""
			continue
		}

		strData := stringBlock[off:]
		if isUTF8 {
			// In UTF-8 string pool:
			// 1. Length in UTF-16 chars (1 or 2 bytes)
			// 2. Length in UTF-8 bytes (1 or 2 bytes)
			// 3. String bytes (null-terminated)
			pos := 0
			if pos >= len(strData) {
				continue
			}
			// Skip UTF-16 length
			if strData[pos]&0x80 != 0 {
				pos += 2
			} else {
				pos++
			}
			if pos >= len(strData) {
				continue
			}
			// Read UTF-8 byte length
			var u8len int
			if strData[pos]&0x80 != 0 {
				if pos+1 >= len(strData) {
					continue
				}
				u8len = int(strData[pos]&0x7F)<<8 | int(strData[pos+1])
				pos += 2
			} else {
				u8len = int(strData[pos])
				pos++
			}

			if pos+u8len <= len(strData) {
				stringsSlice[i] = string(strData[pos : pos+u8len])
			}
		} else {
			// In UTF-16LE string pool:
			// 1. Length in 16-bit words (2 or 4 bytes)
			// 2. 16-bit word characters (null-terminated)
			pos := 0
			if pos+2 > len(strData) {
				continue
			}
			u16len := int(binary.LittleEndian.Uint16(strData[pos : pos+2]))
			pos += 2
			if u16len&0x8000 != 0 {
				if pos+2 > len(strData) {
					continue
				}
				u16len = (u16len&0x7FFF)<<16 | int(binary.LittleEndian.Uint16(strData[pos:pos+2]))
				pos += 2
			}

			byteLen := u16len * 2
			if pos+byteLen <= len(strData) {
				u16s := make([]uint16, u16len)
				for j := 0; j < u16len; j++ {
					u16s[j] = binary.LittleEndian.Uint16(strData[pos+j*2 : pos+j*2+2])
				}
				stringsSlice[i] = string(utf16.Decode(u16s))
			}
		}
	}

	return &axmlStringPool{strings: stringsSlice}, nil
}

func parseAXMLResourceMap(data []byte, headerSize uint16) ([]uint32, error) {
	if int(headerSize) > len(data) {
		return nil, fmt.Errorf("%w: resource map headerSize exceeds chunk", ErrMalformedArchive)
	}
	resBytes := data[headerSize:]
	count := len(resBytes) / 4
	resMap := make([]uint32, count)
	for i := 0; i < count; i++ {
		resMap[i] = binary.LittleEndian.Uint32(resBytes[i*4 : i*4+4])
	}
	return resMap, nil
}

func parseAXMLStartElement(data []byte, pool *axmlStringPool, resMap []uint32, nsMap map[string]string) (*RawElement, error) {
	if len(data) < 36 {
		return nil, fmt.Errorf("%w: start element chunk too small (%d bytes)", ErrMalformedArchive, len(data))
	}

	lineNum := binary.LittleEndian.Uint32(data[8:12])
	nsIdx := binary.LittleEndian.Uint32(data[16:20])
	nameIdx := binary.LittleEndian.Uint32(data[20:24])

	attrStart := binary.LittleEndian.Uint16(data[24:26])
	attrSize := binary.LittleEndian.Uint16(data[26:28])
	attrCount := binary.LittleEndian.Uint16(data[28:30])

	elemName := pool.getString(nameIdx)
	elemNs := pool.getString(nsIdx)

	elem := &RawElement{
		Namespace: elemNs,
		Name:      elemName,
		Line:      int(lineNum),
	}

	if attrCount > 256 {
		return nil, fmt.Errorf("%w: attribute count %d exceeds limit", ErrLimitExceeded, attrCount)
	}

	pos := int(attrStart)
	for i := uint16(0); i < attrCount; i++ {
		if pos+int(attrSize) > len(data) || attrSize < 20 {
			break
		}

		aNsIdx := binary.LittleEndian.Uint32(data[pos : pos+4])
		aNameIdx := binary.LittleEndian.Uint32(data[pos+4 : pos+8])
		aRawValIdx := binary.LittleEndian.Uint32(data[pos+8 : pos+12])

		typedDataType := data[pos+15]
		typedData := binary.LittleEndian.Uint32(data[pos+16 : pos+20])

		aNs := pool.getString(aNsIdx)
		aName := pool.getString(aNameIdx)

		// If aName is empty, try resolving from ResourceMap
		if aName == "" && int(aNameIdx) < len(resMap) {
			aName = resolveKnownResourceID(resMap[aNameIdx])
		}

		// Resolve attribute value based on typed data
		var aVal string
		switch typedDataType {
		case axmlTypeIntBoolean:
			if typedData != 0 {
				aVal = "true"
			} else {
				aVal = "false"
			}
		case axmlTypeIntDec:
			aVal = strconv.Itoa(int(int32(typedData)))
		case axmlTypeIntHex:
			aVal = fmt.Sprintf("0x%X", typedData)
		case axmlTypeString:
			aVal = pool.getString(typedData)
		case axmlTypeReference:
			if aRawValIdx != 0xFFFFFFFF {
				aVal = pool.getString(aRawValIdx)
			}
			if aVal == "" {
				aVal = fmt.Sprintf("@0x%08X", typedData)
			}
		default:
			if aRawValIdx != 0xFFFFFFFF {
				aVal = pool.getString(aRawValIdx)
			}
		}

		elem.Attrs = append(elem.Attrs, RawAttribute{
			Namespace: aNs,
			Name:      aName,
			Value:     aVal,
		})

		pos += int(attrSize)
	}

	return elem, nil
}

// resolveKnownResourceID maps standard Android framework attribute IDs to attribute names.
func resolveKnownResourceID(resID uint32) string {
	switch resID {
	case 0x01010003:
		return "name"
	case 0x01010006:
		return "permission"
	case 0x0101000E:
		return "enabled"
	case 0x01010010:
		return "exported"
	case 0x01010011:
		return "debuggable"
	case 0x01010017:
		return "readPermission"
	case 0x01010018:
		return "writePermission"
	case 0x01010019:
		return "authorities"
	case 0x0101001B:
		return "grantUriPermissions"
	case 0x0101001E:
		return "allowBackup"
	case 0x01010020:
		return "targetSdkVersion"
	case 0x0101020C:
		return "minSdkVersion"
	case 0x0101021B:
		return "scheme"
	case 0x01010028:
		return "host"
	case 0x01010029:
		return "port"
	case 0x0101002A:
		return "path"
	case 0x0101002B:
		return "pathPrefix"
	case 0x0101002C:
		return "pathPattern"
	case 0x01010026:
		return "mimeType"
	case 0x01010486:
		return "autoVerify"
	case 0x01010503:
		return "directBootAware"
	case 0x01010528:
		return "networkSecurityConfig"
	case 0x0101057A:
		return "compileSdkVersion"
	default:
		return fmt.Sprintf("attr_0x%08X", resID)
	}
}
