package mobile

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ParsePlist detects whether data is XML or binary plist (bplist00) and decodes it into a Go value (usually map[string]any).
func ParsePlist(data []byte) (any, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 8 {
		return nil, errors.New("plist data too short")
	}

	if bytes.HasPrefix(trimmed, []byte("bplist00")) {
		return parseBinaryPlist(trimmed)
	}

	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.Contains(trimmed[:min(len(trimmed), 256)], []byte("<plist")) {
		return parseXMLPlist(trimmed)
	}

	return nil, fmt.Errorf("unsupported plist format (prefix: %q)", string(trimmed[:min(len(trimmed), 16)]))
}

// -----------------------------------------------------------------------------
// XML Plist Parser
// -----------------------------------------------------------------------------

func parseXMLPlist(data []byte) (any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))

	// Find root <plist>
	for {
		tok, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("failed locating plist root: %w", err)
		}
		if start, ok := tok.(xml.StartElement); ok {
			if start.Name.Local == "plist" {
				break
			}
		}
	}

	// Read top-level value
	val, err := parseXMLPlistValue(decoder)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func parseXMLPlistValue(d *xml.Decoder) (any, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}

		switch elem := tok.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "dict":
				return parseXMLPlistDict(d)
			case "array":
				return parseXMLPlistArray(d)
			case "string":
				var s string
				if err := d.DecodeElement(&s, &elem); err != nil {
					return "", err
				}
				return s, nil
			case "integer":
				var s string
				if err := d.DecodeElement(&s, &elem); err != nil {
					return int64(0), err
				}
				i, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
				return i, nil
			case "real":
				var s string
				if err := d.DecodeElement(&s, &elem); err != nil {
					return float64(0), err
				}
				f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
				return f, nil
			case "true":
				_ = d.Skip()
				return true, nil
			case "false":
				_ = d.Skip()
				return false, nil
			case "data", "date":
				var s string
				_ = d.DecodeElement(&s, &elem)
				return s, nil
			default:
				_ = d.Skip()
			}
		case xml.EndElement:
			return nil, nil
		}
	}
}

func parseXMLPlistDict(d *xml.Decoder) (map[string]any, error) {
	res := make(map[string]any)
	var currentKey string

	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		switch elem := tok.(type) {
		case xml.StartElement:
			if elem.Name.Local == "key" {
				var k string
				if err := d.DecodeElement(&k, &elem); err != nil {
					return nil, err
				}
				currentKey = strings.TrimSpace(k)
			} else {
				val, err := parseXMLPlistValueFromElement(d, elem)
				if err != nil {
					return nil, err
				}
				if currentKey != "" {
					res[currentKey] = val
					currentKey = ""
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "dict" {
				return res, nil
			}
		}
	}
	return res, nil
}

func parseXMLPlistArray(d *xml.Decoder) ([]any, error) {
	var res []any

	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		switch elem := tok.(type) {
		case xml.StartElement:
			val, err := parseXMLPlistValueFromElement(d, elem)
			if err != nil {
				return nil, err
			}
			res = append(res, val)
		case xml.EndElement:
			if elem.Name.Local == "array" {
				return res, nil
			}
		}
	}
	return res, nil
}

func parseXMLPlistValueFromElement(d *xml.Decoder, elem xml.StartElement) (any, error) {
	switch elem.Name.Local {
	case "dict":
		return parseXMLPlistDict(d)
	case "array":
		return parseXMLPlistArray(d)
	case "string":
		var s string
		if err := d.DecodeElement(&s, &elem); err != nil {
			return "", err
		}
		return s, nil
	case "integer":
		var s string
		if err := d.DecodeElement(&s, &elem); err != nil {
			return int64(0), err
		}
		i, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return i, nil
	case "real":
		var s string
		if err := d.DecodeElement(&s, &elem); err != nil {
			return float64(0), err
		}
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, nil
	case "true":
		_ = d.Skip()
		return true, nil
	case "false":
		_ = d.Skip()
		return false, nil
	case "data", "date":
		var s string
		_ = d.DecodeElement(&s, &elem)
		return s, nil
	default:
		_ = d.Skip()
		return nil, nil
	}
}

// -----------------------------------------------------------------------------
// Binary Plist (bplist00) Parser
// -----------------------------------------------------------------------------

type bplistReader struct {
	data              []byte
	offsetIntSize     int
	objectRefSize     int
	numObjects        int
	topObject         int
	offsetTableOffset int
	offsetTable       []int
}

func parseBinaryPlist(data []byte) (any, error) {
	if len(data) < 32+8 {
		return nil, errors.New("binary plist too short")
	}

	// 1. Read 32-byte trailer at end of file
	trailer := data[len(data)-32:]
	offsetIntSize := int(trailer[6])
	objectRefSize := int(trailer[7])
	numObjects := int(binary.BigEndian.Uint64(trailer[8:16]))
	topObject := int(binary.BigEndian.Uint64(trailer[16:24]))
	offsetTableOffset := int(binary.BigEndian.Uint64(trailer[24:32]))

	if offsetIntSize < 1 || offsetIntSize > 8 {
		return nil, fmt.Errorf("invalid offsetIntSize: %d", offsetIntSize)
	}
	if objectRefSize < 1 || objectRefSize > 8 {
		return nil, fmt.Errorf("invalid objectRefSize: %d", objectRefSize)
	}
	if numObjects < 1 || numObjects > 1000000 {
		return nil, fmt.Errorf("invalid numObjects: %d", numObjects)
	}
	if offsetTableOffset < 8 || offsetTableOffset > len(data)-32 {
		return nil, fmt.Errorf("invalid offsetTableOffset: %d", offsetTableOffset)
	}
	if offsetTableOffset+numObjects*offsetIntSize > len(data)-32 {
		return nil, errors.New("offset table exceeds file boundary")
	}

	bp := &bplistReader{
		data:              data,
		offsetIntSize:     offsetIntSize,
		objectRefSize:     objectRefSize,
		numObjects:        numObjects,
		topObject:         topObject,
		offsetTableOffset: offsetTableOffset,
		offsetTable:       make([]int, numObjects),
	}

	// 2. Read offset table
	for i := 0; i < numObjects; i++ {
		offEntry := offsetTableOffset + i*offsetIntSize
		off := bp.readIntBytes(offEntry, offsetIntSize)
		if off < 8 || int(off) >= len(data)-32 {
			return nil, fmt.Errorf("object %d offset out of bounds: %d", i, off)
		}
		bp.offsetTable[i] = int(off)
	}

	// 3. Resolve top object recursively with depth guard
	return bp.readObject(topObject, 0)
}

func (bp *bplistReader) readIntBytes(offset int, byteCount int) int64 {
	var val int64
	for i := 0; i < byteCount; i++ {
		val = (val << 8) | int64(bp.data[offset+i])
	}
	return val
}

func (bp *bplistReader) readObject(objIdx int, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("bplist recursion depth exceeded limit 64")
	}
	if objIdx < 0 || objIdx >= bp.numObjects {
		return nil, fmt.Errorf("bplist object index %d out of bounds (total: %d)", objIdx, bp.numObjects)
	}

	offset := bp.offsetTable[objIdx]
	if offset >= len(bp.data) {
		return nil, errors.New("object offset beyond data bounds")
	}

	marker := bp.data[offset]
	objType := marker & 0xF0
	objInfo := marker & 0x0F

	switch objType {
	case 0x00: // Simple types: null, bool
		switch objInfo {
		case 0x00:
			return nil, nil
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		default:
			return nil, nil
		}

	case 0x10: // Integer
		size := 1 << objInfo
		if offset+1+size > len(bp.data) {
			return nil, errors.New("integer object truncated")
		}
		return bp.readIntBytes(offset+1, size), nil

	case 0x20: // Real / Float
		size := 1 << objInfo
		if size == 4 && offset+1+4 <= len(bp.data) {
			bits := binary.BigEndian.Uint32(bp.data[offset+1 : offset+1+4])
			return float64(math.Float32frombits(bits)), nil
		} else if size == 8 && offset+1+8 <= len(bp.data) {
			bits := binary.BigEndian.Uint64(bp.data[offset+1 : offset+1+8])
			return math.Float64frombits(bits), nil
		}
		return float64(0), nil

	case 0x30: // Date
		if offset+9 <= len(bp.data) {
			bits := binary.BigEndian.Uint64(bp.data[offset+1 : offset+9])
			return math.Float64frombits(bits), nil
		}
		return float64(0), nil

	case 0x40: // Data
		length, headerLen, err := bp.readObjectLength(offset, objInfo)
		if err != nil {
			return nil, err
		}
		dataStart := offset + headerLen
		if dataStart+length > len(bp.data) {
			return nil, errors.New("data object truncated")
		}
		return bp.data[dataStart : dataStart+length], nil

	case 0x50: // ASCII string
		length, headerLen, err := bp.readObjectLength(offset, objInfo)
		if err != nil {
			return nil, err
		}
		strStart := offset + headerLen
		if strStart+length > len(bp.data) {
			return nil, errors.New("ASCII string truncated")
		}
		return string(bp.data[strStart : strStart+length]), nil

	case 0x60: // UTF-16BE string
		charCount, headerLen, err := bp.readObjectLength(offset, objInfo)
		if err != nil {
			return nil, err
		}
		strStart := offset + headerLen
		byteLen := charCount * 2
		if strStart+byteLen > len(bp.data) {
			return nil, errors.New("UTF-16 string truncated")
		}
		u16s := make([]uint16, charCount)
		for i := 0; i < charCount; i++ {
			u16s[i] = binary.BigEndian.Uint16(bp.data[strStart+i*2 : strStart+(i+1)*2])
		}
		return string(utf16.Decode(u16s)), nil

	case 0x80: // UID
		return bp.readIntBytes(offset+1, int(objInfo)+1), nil

	case 0xA0: // Array
		count, headerLen, err := bp.readObjectLength(offset, objInfo)
		if err != nil {
			return nil, err
		}
		refsStart := offset + headerLen
		if refsStart+count*bp.objectRefSize > len(bp.data) {
			return nil, errors.New("array object refs truncated")
		}
		arr := make([]any, count)
		for i := 0; i < count; i++ {
			ref := int(bp.readIntBytes(refsStart+i*bp.objectRefSize, bp.objectRefSize))
			elem, err := bp.readObject(ref, depth+1)
			if err != nil {
				return nil, err
			}
			arr[i] = elem
		}
		return arr, nil

	case 0xD0: // Dictionary
		count, headerLen, err := bp.readObjectLength(offset, objInfo)
		if err != nil {
			return nil, err
		}
		refsStart := offset + headerLen
		totalRefsLen := count * 2 * bp.objectRefSize
		if refsStart+totalRefsLen > len(bp.data) {
			return nil, errors.New("dictionary object refs truncated")
		}

		keyRefsStart := refsStart
		valRefsStart := refsStart + count*bp.objectRefSize

		dict := make(map[string]any, count)
		for i := 0; i < count; i++ {
			keyRef := int(bp.readIntBytes(keyRefsStart+i*bp.objectRefSize, bp.objectRefSize))
			valRef := int(bp.readIntBytes(valRefsStart+i*bp.objectRefSize, bp.objectRefSize))

			kObj, err := bp.readObject(keyRef, depth+1)
			if err != nil {
				return nil, err
			}
			vObj, err := bp.readObject(valRef, depth+1)
			if err != nil {
				return nil, err
			}

			keyStr := fmt.Sprintf("%v", kObj)
			dict[keyStr] = vObj
		}
		return dict, nil

	default:
		return nil, fmt.Errorf("unsupported bplist object type: 0x%02x", objType)
	}
}

func (bp *bplistReader) readObjectLength(offset int, objInfo uint8) (int, int, error) {
	if objInfo < 0x0F {
		return int(objInfo), 1, nil
	}

	// 0x0F marker means length is stored in subsequent int object
	if offset+1 >= len(bp.data) {
		return 0, 0, errors.New("length object marker truncated")
	}
	intMarker := bp.data[offset+1]
	if (intMarker & 0xF0) != 0x10 {
		return 0, 0, fmt.Errorf("expected int marker following 0x0F, got 0x%02x", intMarker)
	}
	intSize := 1 << (intMarker & 0x0F)
	if offset+2+intSize > len(bp.data) {
		return 0, 0, errors.New("extended length bytes truncated")
	}
	lenVal := int(bp.readIntBytes(offset+2, intSize))
	return lenVal, 2 + intSize, nil
}
