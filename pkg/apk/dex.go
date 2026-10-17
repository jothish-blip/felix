package apk

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	// DEXHeaderSize is the canonical 112-byte size of standard Android DEX headers.
	DEXHeaderSize = 112

	// EndianConstant identifies little-endian byte ordering in Dalvik executables.
	EndianConstant uint32 = 0x12345678

	// ReverseEndianConstant identifies big-endian byte ordering in Dalvik executables.
	ReverseEndianConstant uint32 = 0x78563412

	// MaxDEXStringLength caps individual string lengths extracted from the string pool.
	MaxDEXStringLength = 65536

	// MaxCumulativeDEXStringBytes bounds total heap allocation for strings per DEX file (30 MiB).
	MaxCumulativeDEXStringBytes int64 = 30 * 1024 * 1024
)

// DEXHeader represents the fixed-format 112-byte Dalvik Executable header.
type DEXHeader struct {
	Magic         [8]byte
	Checksum      uint32
	Signature     [20]byte
	FileSize      uint32
	HeaderSize    uint32
	EndianTag     uint32
	LinkSize      uint32
	LinkOff       uint32
	MapOff        uint32
	StringIDsSize uint32
	StringIDsOff  uint32
	TypeIDsSize   uint32
	TypeIDsOff    uint32
	ProtoIDsSize  uint32
	ProtoIDsOff   uint32
	FieldIDsSize  uint32
	FieldIDsOff   uint32
	MethodIDsSize uint32
	MethodIDsOff  uint32
	ClassDefsSize uint32
	ClassDefsOff  uint32
	DataSize      uint32
	DataOff       uint32
}

// DEXFile encapsulates the parsed metadata, string pool, and class descriptors from a DEX archive entry.
type DEXFile struct {
	FileName    string   `json:"file_name"`
	Version     string   `json:"version"`
	Endian      string   `json:"endian"`
	FileSize    uint32   `json:"file_size"`
	StringCount int      `json:"string_count"`
	ClassCount  int      `json:"class_count"`
	Strings     []string `json:"-"`
	Classes     []string `json:"classes,omitempty"`
}

// decodeULEB128 reads an unsigned Little-Endian Base 128 integer from data starting at offset.
// It enforces bounds checking and caps the sequence at 5 bytes to prevent infinite loops or bit overflow.
func decodeULEB128(data []byte, offset int) (uint32, int, error) {
	var result uint32
	var shift uint
	for i := 0; i < 5; i++ {
		idx := offset + i
		if idx >= len(data) {
			return 0, 0, fmt.Errorf("%w: unexpected EOF while decoding ULEB128 at offset 0x%x", ErrMalformedDEX, idx)
		}
		b := data[idx]
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("%w: invalid ULEB128 sequence exceeds 5 bytes at offset 0x%x", ErrMalformedDEX, offset)
}

// ParseDEX parses and validates raw Dalvik Executable bytecode bytes without executing them.
// All section bounds, table counts, string data offsets, and memory limits are strictly verified.
func ParseDEX(ctx context.Context, fileName string, data []byte, limits Limits) (*DEXFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, WrapError("parse_dex", "operation cancelled before DEX parsing", err)
	}

	if len(data) < DEXHeaderSize {
		return nil, fmt.Errorf("%w: DEX byte length (%d) is smaller than required header (%d)",
			ErrMalformedDEX, len(data), DEXHeaderSize)
	}

	// 1. Verify Magic
	magic := data[0:8]
	if string(magic[0:4]) != "dex\n" {
		return nil, fmt.Errorf("%w: file %q has invalid DEX magic prefix %q",
			ErrMalformedDEX, fileName, string(magic[0:4]))
	}
	if magic[7] != 0 {
		return nil, fmt.Errorf("%w: file %q magic missing null terminator", ErrMalformedDEX, fileName)
	}

	version := string(magic[4:7])
	switch version {
	case "035", "036", "037", "038", "039":
		// Officially supported Dalvik/ART DEX versions
	default:
		return nil, fmt.Errorf("%w: file %q declares unsupported DEX version %q",
			ErrUnsupportedDEX, fileName, version)
	}

	// 2. Determine Endianness
	rawEndianTag := binary.LittleEndian.Uint32(data[0x28:0x2C])
	var order binary.ByteOrder
	var endianStr string
	if rawEndianTag == EndianConstant {
		order = binary.LittleEndian
		endianStr = "little-endian"
	} else if rawEndianTag == ReverseEndianConstant {
		order = binary.BigEndian
		endianStr = "big-endian"
	} else {
		return nil, fmt.Errorf("%w: file %q has invalid endian tag 0x%08x", ErrMalformedDEX, fileName, rawEndianTag)
	}

	// 3. Header Fields Validation
	headerSize := order.Uint32(data[0x24:0x28])
	if headerSize != DEXHeaderSize {
		return nil, fmt.Errorf("%w: file %q declares invalid header size %d (expected %d)",
			ErrMalformedDEX, fileName, headerSize, DEXHeaderSize)
	}

	fileSize := order.Uint32(data[0x20:0x24])
	if fileSize > uint32(len(data)) {
		return nil, fmt.Errorf("%w: file %q declared file_size (%d) exceeds available bytes (%d)",
			ErrMalformedDEX, fileName, fileSize, len(data))
	}

	// 4. Validate String IDs Table Bounds
	stringIDsSize := order.Uint32(data[0x38:0x3C])
	stringIDsOff := order.Uint32(data[0x3C:0x40])

	maxStrings := limits.EffectiveMaxDEXStrings()
	if int(stringIDsSize) > maxStrings {
		return nil, fmt.Errorf("%w: file %q string_ids_size (%d) exceeds limit (%d)",
			ErrLimitExceeded, fileName, stringIDsSize, maxStrings)
	}

	stringTableBytes := uint64(stringIDsSize) * 4
	if uint64(stringIDsOff)+stringTableBytes > uint64(len(data)) {
		return nil, fmt.Errorf("%w: file %q string_ids table [0x%x, 0x%x) exceeds file bounds (%d)",
			ErrMalformedDEX, fileName, stringIDsOff, uint64(stringIDsOff)+stringTableBytes, len(data))
	}

	// 5. Parse String Pool with Memory and Boundary Guards
	stringsList := make([]string, 0, stringIDsSize)
	var cumulativeStringBytes int64

	for i := uint32(0); i < stringIDsSize; i++ {
		if i%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, WrapError("parse_dex_strings", "operation cancelled during string table parsing", err)
			}
		}

		offsetLoc := int(stringIDsOff) + int(i*4)
		strDataOff := order.Uint32(data[offsetLoc : offsetLoc+4])

		if uint64(strDataOff) >= uint64(len(data)) {
			return nil, fmt.Errorf("%w: file %q string[%d] offset 0x%x out of bounds (%d)",
				ErrMalformedDEX, fileName, i, strDataOff, len(data))
		}

		// Decode ULEB128 character count
		_, ulebBytes, err := decodeULEB128(data, int(strDataOff))
		if err != nil {
			return nil, fmt.Errorf("%w: file %q string[%d] at 0x%x: %v", ErrMalformedDEX, fileName, i, strDataOff, err)
		}

		strStart := int(strDataOff) + ulebBytes
		if strStart > len(data) {
			return nil, fmt.Errorf("%w: file %q string[%d] start 0x%x exceeds file bounds", ErrMalformedDEX, fileName, i, strStart)
		}

		// Locate null terminator for MUTF-8
		nullPos := bytes.IndexByte(data[strStart:], 0x00)
		if nullPos == -1 {
			return nil, fmt.Errorf("%w: file %q string[%d] at 0x%x missing null terminator", ErrMalformedDEX, fileName, i, strStart)
		}

		if nullPos > MaxDEXStringLength {
			nullPos = MaxDEXStringLength
		}

		strBytes := data[strStart : strStart+nullPos]
		cumulativeStringBytes += int64(len(strBytes))
		if cumulativeStringBytes > MaxCumulativeDEXStringBytes {
			return nil, fmt.Errorf("%w: file %q cumulative string memory exceeds %d bytes",
				ErrLimitExceeded, fileName, MaxCumulativeDEXStringBytes)
		}

		// Convert MUTF-8 embedded nulls (\xC0\x80) to clean UTF-8
		cleaned := string(bytes.ReplaceAll(strBytes, []byte{0xC0, 0x80}, []byte{0x00}))
		stringsList = append(stringsList, cleaned)
	}

	// 6. Parse Class Definitions (Optional Structural Metadata)
	classDefsSize := order.Uint32(data[0x60:0x64])
	classDefsOff := order.Uint32(data[0x64:0x68])
	typeIDsSize := order.Uint32(data[0x40:0x44])
	typeIDsOff := order.Uint32(data[0x44:0x48])

	var classes []string
	if classDefsSize > 0 && typeIDsSize > 0 {
		typeTableBytes := uint64(typeIDsSize) * 4
		classTableBytes := uint64(classDefsSize) * 32

		if uint64(typeIDsOff)+typeTableBytes <= uint64(len(data)) &&
			uint64(classDefsOff)+classTableBytes <= uint64(len(data)) {
			classes = make([]string, 0, classDefsSize)
			for i := uint32(0); i < classDefsSize; i++ {
				cLoc := int(classDefsOff) + int(i*32)
				classIdx := order.Uint32(data[cLoc : cLoc+4])
				if classIdx < typeIDsSize {
					tLoc := int(typeIDsOff) + int(classIdx*4)
					descIdx := order.Uint32(data[tLoc : tLoc+4])
					if descIdx < uint32(len(stringsList)) {
						rawDesc := stringsList[descIdx]
						// Convert Dalvik class descriptor Lcom/example/MyClass; -> com.example.MyClass
						if strings.HasPrefix(rawDesc, "L") && strings.HasSuffix(rawDesc, ";") {
							cls := strings.TrimSuffix(strings.TrimPrefix(rawDesc, "L"), ";")
							cls = strings.ReplaceAll(cls, "/", ".")
							classes = append(classes, cls)
						} else {
							classes = append(classes, rawDesc)
						}
					}
				}
			}
		}
	}

	return &DEXFile{
		FileName:    fileName,
		Version:     version,
		Endian:      endianStr,
		FileSize:    fileSize,
		StringCount: len(stringsList),
		ClassCount:  len(classes),
		Strings:     stringsList,
		Classes:     classes,
	}, nil
}

// ParseDEXReader reads and parses a DEX file from an io.ReaderAt within specified limits.
func ParseDEXReader(ctx context.Context, fileName string, r io.ReaderAt, size int64, limits Limits) (*DEXFile, error) {
	if size > limits.MaxEntrySize {
		return nil, fmt.Errorf("%w: DEX entry %q size %d exceeds MaxEntrySize %d",
			ErrLimitExceeded, fileName, size, limits.MaxEntrySize)
	}

	buf := make([]byte, size)
	if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: failed reading DEX entry %q: %v", ErrMalformedDEX, fileName, err)
	}

	return ParseDEX(ctx, fileName, buf, limits)
}
