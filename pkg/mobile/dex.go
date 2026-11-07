package mobile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
)

// DEX Constants & Limits
const (
	DEXMagicPrefix       = "dex\n"
	DEXEndianConstant    = 0x12345678
	DEXReverseEndian     = 0x78563412
	DEXHeaderSize        = 0x70 // 112 bytes
	DEXMaxFileSize       = 100 * 1024 * 1024 // 100 MB max DEX size limit
	DEXMaxStringsCount   = 500000
	DEXMaxTypesCount     = 100000
	DEXMaxProtosCount    = 100000
	DEXMaxFieldsCount    = 200000
	DEXMaxMethodsCount   = 300000
	DEXMaxClassesCount   = 100000
	DEXNOINDEX           = 0xFFFFFFFF
)

// SupportedDEXVersions identifies recognized Dalvik bytecode versions.
var SupportedDEXVersions = map[string]bool{
	"035": true,
	"036": true,
	"037": true,
	"038": true,
	"039": true,
}

// DEXHeader represents the 112-byte fixed header of a .dex file.
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

	Version       string `json:"version"`
	IsLittleEndian bool   `json:"is_little_endian"`
}

// MethodReference tracks where a string or constant is referenced in bytecode.
type MethodReference struct {
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	Signature  string `json:"signature,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
}

// StringItem encapsulates an extracted string with its references and metadata.
type StringItem struct {
	Index      int               `json:"index"`
	Value      string            `json:"value"`
	References []MethodReference `json:"references,omitempty"`
}

// MethodItem encapsulates an extracted method definition.
type MethodItem struct {
	Index      int    `json:"index"`
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	Proto      string `json:"proto"`
}

// ClassItem encapsulates an extracted class definition.
type ClassItem struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Superclass  string   `json:"superclass,omitempty"`
	SourceFile  string   `json:"source_file,omitempty"`
	AccessFlags uint32   `json:"access_flags"`
	Methods     []string `json:"methods,omitempty"`
}

// FieldItem encapsulates an extracted field definition.
type FieldItem struct {
	Index     int    `json:"index"`
	ClassName string `json:"class_name"`
	TypeName  string `json:"type_name"`
	FieldName string `json:"field_name"`
}

// EncodedArrayPayload represents an array payload extracted from a fill-array-data table.
type EncodedArrayPayload struct {
	ElementWidth uint16 `json:"element_width"`
	ElementCount uint32 `json:"element_count"`
	Data         []byte `json:"data"`
}

// StaticFieldArrayAssignment records an array payload assigned to a field via iput/sput.
type StaticFieldArrayAssignment struct {
	ClassName string              `json:"class_name"`
	FieldName string              `json:"field_name"`
	FieldType string              `json:"field_type"`
	Payload   EncodedArrayPayload `json:"payload"`
}

// FieldAccessItem records a field access (read/write) observed in bytecode.
type FieldAccessItem struct {
	ClassName  string `json:"class_name"`
	FieldName  string `json:"field_name"`
	MethodName string `json:"method_name"`
	Register   byte   `json:"register"`
	IsWrite    bool   `json:"is_write"`
}

// MethodInvocationItem records a method invocation observed in Dalvik bytecode.
type MethodInvocationItem struct {
	CallerClassName  string `json:"caller_class_name"`
	CallerMethodName string `json:"caller_method_name"`
	TargetClassName  string `json:"target_class_name"`
	TargetMethodName string `json:"target_method_name"`
	TargetProto      string `json:"target_proto"`
	ArgRegisters     []byte `json:"arg_registers,omitempty"`
}

// MethodCodeMeta records method register allocations and parameter sizing.
type MethodCodeMeta struct {
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	RegsSize   uint16 `json:"regs_size"`
	InsSize    uint16 `json:"ins_size"`
	IsStatic   bool   `json:"is_static"`
}

// DEXFile represents a fully parsed Dalvik Executable file.
type DEXFile struct {
	Header         DEXHeader                    `json:"header"`
	SHA256         string                       `json:"sha256"`
	SizeBytes      int64                        `json:"size_bytes"`
	Strings        []StringItem                 `json:"strings"`
	Types          []string                     `json:"types"`
	Methods        []MethodItem                 `json:"methods"`
	Classes        []ClassItem                  `json:"classes"`
	Fields         []FieldItem                  `json:"fields"`
	FieldArrays    []StaticFieldArrayAssignment `json:"field_arrays,omitempty"`
	FieldReads     []FieldAccessItem            `json:"field_reads,omitempty"`
	Invocations    []MethodInvocationItem       `json:"invocations,omitempty"`
	ArrayPayloads  []EncodedArrayPayload        `json:"array_payloads,omitempty"`
	MethodMetadata map[string]MethodCodeMeta    `json:"method_metadata,omitempty"`
	StringRefTable [][]MethodReference         `json:"-"`
	RawData        []byte                       `json:"-"`
}

// ExtractedDEX wraps a DEX file extracted from an APK archive.
type ExtractedDEX struct {
	EntryName string   `json:"entry_name"`
	Size      int64    `json:"size"`
	SHA256    string   `json:"sha256"`
	DEX       *DEXFile `json:"dex"`
	Error     string   `json:"error,omitempty"`
}

// ParseDEX parses raw DEX bytes with strict bounds checking and zero external dependencies.
func ParseDEX(data []byte) (*DEXFile, error) {
	if len(data) < DEXHeaderSize {
		return nil, fmt.Errorf("DEX data too short: %d bytes (minimum header size: %d)", len(data), DEXHeaderSize)
	}

	if int64(len(data)) > DEXMaxFileSize {
		return nil, fmt.Errorf("DEX file size %d exceeds safety limit of %d bytes", len(data), DEXMaxFileSize)
	}

	// 1. Verify Magic: "dex\n" followed by 3 version characters and null byte
	if !bytes.HasPrefix(data, []byte(DEXMagicPrefix)) {
		return nil, fmt.Errorf("invalid DEX magic: %q (expected %q prefix)", data[:min(8, len(data))], DEXMagicPrefix)
	}

	version := string(data[4:7])
	if data[7] != 0 {
		return nil, fmt.Errorf("invalid DEX magic null-terminator at byte 7: 0x%02x", data[7])
	}
	if !SupportedDEXVersions[version] {
		return nil, fmt.Errorf("unsupported DEX version %q (supported: 035, 036, 037, 038, 039)", version)
	}

	// 2. Parse Header
	header := DEXHeader{
		Version: version,
	}
	copy(header.Magic[:], data[0:8])

	// Endianness determination
	rawEndian := binary.LittleEndian.Uint32(data[40:44])
	var bo binary.ByteOrder
	switch rawEndian {
	case DEXEndianConstant:
		bo = binary.LittleEndian
		header.IsLittleEndian = true
	case DEXReverseEndian:
		bo = binary.BigEndian
		header.IsLittleEndian = false
	default:
		return nil, fmt.Errorf("invalid DEX endian tag: 0x%08x", rawEndian)
	}
	header.EndianTag = rawEndian

	header.Checksum = bo.Uint32(data[8:12])
	copy(header.Signature[:], data[12:32])
	header.FileSize = bo.Uint32(data[32:36])
	header.HeaderSize = bo.Uint32(data[36:40])
	header.LinkSize = bo.Uint32(data[44:48])
	header.LinkOff = bo.Uint32(data[48:52])
	header.MapOff = bo.Uint32(data[52:56])
	header.StringIDsSize = bo.Uint32(data[56:60])
	header.StringIDsOff = bo.Uint32(data[60:64])
	header.TypeIDsSize = bo.Uint32(data[64:68])
	header.TypeIDsOff = bo.Uint32(data[68:72])
	header.ProtoIDsSize = bo.Uint32(data[72:76])
	header.ProtoIDsOff = bo.Uint32(data[76:80])
	header.FieldIDsSize = bo.Uint32(data[80:84])
	header.FieldIDsOff = bo.Uint32(data[84:88])
	header.MethodIDsSize = bo.Uint32(data[88:92])
	header.MethodIDsOff = bo.Uint32(data[92:96])
	header.ClassDefsSize = bo.Uint32(data[96:100])
	header.ClassDefsOff = bo.Uint32(data[100:104])
	header.DataSize = bo.Uint32(data[104:108])
	header.DataOff = bo.Uint32(data[108:112])

	// Validate header sizes and bounds
	if header.HeaderSize != DEXHeaderSize {
		return nil, fmt.Errorf("unexpected DEX header size %d (expected %d)", header.HeaderSize, DEXHeaderSize)
	}
	if header.FileSize != uint32(len(data)) {
		// Log or tolerate minor padding discrepancies if file size is at least header size
		if header.FileSize > uint32(len(data)) {
			return nil, fmt.Errorf("truncated DEX file: declared size %d, actual size %d", header.FileSize, len(data))
		}
	}

	// Boundary guards
	if header.StringIDsSize > DEXMaxStringsCount {
		return nil, fmt.Errorf("DEX string count %d exceeds maximum limit %d", header.StringIDsSize, DEXMaxStringsCount)
	}
	if header.TypeIDsSize > DEXMaxTypesCount {
		return nil, fmt.Errorf("DEX type count %d exceeds maximum limit %d", header.TypeIDsSize, DEXMaxTypesCount)
	}
	if header.MethodIDsSize > DEXMaxMethodsCount {
		return nil, fmt.Errorf("DEX method count %d exceeds maximum limit %d", header.MethodIDsSize, DEXMaxMethodsCount)
	}
	if header.ClassDefsSize > DEXMaxClassesCount {
		return nil, fmt.Errorf("DEX class count %d exceeds maximum limit %d", header.ClassDefsSize, DEXMaxClassesCount)
	}

	dataLen := uint32(len(data))
	if header.StringIDsOff+header.StringIDsSize*4 > dataLen {
		return nil, errors.New("string_ids table extends beyond DEX file bounds")
	}
	if header.TypeIDsOff+header.TypeIDsSize*4 > dataLen {
		return nil, errors.New("type_ids table extends beyond DEX file bounds")
	}
	if header.ProtoIDsOff+header.ProtoIDsSize*12 > dataLen {
		return nil, errors.New("proto_ids table extends beyond DEX file bounds")
	}
	if header.FieldIDsOff+header.FieldIDsSize*8 > dataLen {
		return nil, errors.New("field_ids table extends beyond DEX file bounds")
	}
	if header.MethodIDsOff+header.MethodIDsSize*8 > dataLen {
		return nil, errors.New("method_ids table extends beyond DEX file bounds")
	}
	if header.ClassDefsOff+header.ClassDefsSize*32 > dataLen {
		return nil, errors.New("class_defs table extends beyond DEX file bounds")
	}

	sum := sha256.Sum256(data)
	dexFile := &DEXFile{
		Header:         header,
		SHA256:         hex.EncodeToString(sum[:]),
		SizeBytes:      int64(len(data)),
		Strings:        make([]StringItem, 0, header.StringIDsSize),
		Types:          make([]string, 0, header.TypeIDsSize),
		Methods:        make([]MethodItem, 0, header.MethodIDsSize),
		Classes:        make([]ClassItem, 0, header.ClassDefsSize),
		Fields:         make([]FieldItem, 0, header.FieldIDsSize),
		FieldArrays:    make([]StaticFieldArrayAssignment, 0),
		FieldReads:     make([]FieldAccessItem, 0),
		Invocations:    make([]MethodInvocationItem, 0),
		ArrayPayloads:  make([]EncodedArrayPayload, 0),
		MethodMetadata: make(map[string]MethodCodeMeta),
		StringRefTable: make([][]MethodReference, header.StringIDsSize),
		RawData:        data,
	}

	// 3. Parse String Pool
	rawStrings := make([]string, header.StringIDsSize)
	for i := uint32(0); i < header.StringIDsSize; i++ {
		off := bo.Uint32(data[header.StringIDsOff+i*4 : header.StringIDsOff+i*4+4])
		s, err := readDEXString(data, int(off))
		if err != nil {
			rawStrings[i] = fmt.Sprintf("<error: %v>", err)
		} else {
			rawStrings[i] = s
		}
	}

	// 4. Parse Type IDs
	for i := uint32(0); i < header.TypeIDsSize; i++ {
		strIdx := bo.Uint32(data[header.TypeIDsOff+i*4 : header.TypeIDsOff+i*4+4])
		if strIdx < uint32(len(rawStrings)) {
			dexFile.Types = append(dexFile.Types, rawStrings[strIdx])
		} else {
			dexFile.Types = append(dexFile.Types, fmt.Sprintf("<invalid_type_%d>", strIdx))
		}
	}

	// 5. Parse Proto IDs (helper for methods)
	type protoItem struct {
		shorty     string
		returnType string
		params     []string
	}
	protos := make([]protoItem, header.ProtoIDsSize)
	for i := uint32(0); i < header.ProtoIDsSize; i++ {
		pOff := header.ProtoIDsOff + i*12
		shortyIdx := bo.Uint32(data[pOff : pOff+4])
		returnTypeIdx := bo.Uint32(data[pOff+4 : pOff+8])
		paramsOff := bo.Uint32(data[pOff+8 : pOff+12])

		var shorty, retType string
		if shortyIdx < uint32(len(rawStrings)) {
			shorty = rawStrings[shortyIdx]
		}
		if returnTypeIdx < uint32(len(dexFile.Types)) {
			retType = dexFile.Types[returnTypeIdx]
		}

		var params []string
		if paramsOff > 0 && paramsOff+4 <= dataLen {
			paramCount := bo.Uint32(data[paramsOff : paramsOff+4])
			if paramsOff+4+paramCount*2 <= dataLen && paramCount < 256 {
				for p := uint32(0); p < paramCount; p++ {
					tIdx := bo.Uint16(data[paramsOff+4+p*2 : paramsOff+4+p*2+2])
					if int(tIdx) < len(dexFile.Types) {
						params = append(params, dexFile.Types[tIdx])
					}
				}
			}
		}

		protos[i] = protoItem{
			shorty:     shorty,
			returnType: retType,
			params:     params,
		}
	}

	// 6. Parse Method IDs
	for i := uint32(0); i < header.MethodIDsSize; i++ {
		mOff := header.MethodIDsOff + i*8
		classIdx := bo.Uint16(data[mOff : mOff+2])
		protoIdx := bo.Uint16(data[mOff+2 : mOff+4])
		nameIdx := bo.Uint32(data[mOff+4 : mOff+8])

		var className, methodName, protoStr string
		if int(classIdx) < len(dexFile.Types) {
			className = CleanClassName(dexFile.Types[classIdx])
		}
		if int(nameIdx) < len(rawStrings) {
			methodName = rawStrings[nameIdx]
		}
		if int(protoIdx) < len(protos) {
			p := protos[protoIdx]
			protoStr = fmt.Sprintf("(%s)%s", strings.Join(p.params, ","), p.returnType)
		}

		dexFile.Methods = append(dexFile.Methods, MethodItem{
			Index:      int(i),
			ClassName:  className,
			MethodName: methodName,
			Proto:      protoStr,
		})
	}

	// 6b. Parse Field IDs
	for i := uint32(0); i < header.FieldIDsSize; i++ {
		fOff := header.FieldIDsOff + i*8
		classIdx := bo.Uint16(data[fOff : fOff+2])
		typeIdx := bo.Uint16(data[fOff+2 : fOff+4])
		nameIdx := bo.Uint32(data[fOff+4 : fOff+8])

		var className, typeName, fieldName string
		if int(classIdx) < len(dexFile.Types) {
			className = CleanClassName(dexFile.Types[classIdx])
		}
		if int(typeIdx) < len(dexFile.Types) {
			typeName = dexFile.Types[typeIdx]
		}
		if int(nameIdx) < len(rawStrings) {
			fieldName = rawStrings[nameIdx]
		}

		dexFile.Fields = append(dexFile.Fields, FieldItem{
			Index:     int(i),
			ClassName: className,
			TypeName:  typeName,
			FieldName: fieldName,
		})
	}

	// 7. Parse Class Defs & Bytecode String References
	for i := uint32(0); i < header.ClassDefsSize; i++ {
		cOff := header.ClassDefsOff + i*32
		classIdx := bo.Uint32(data[cOff : cOff+4])
		accessFlags := bo.Uint32(data[cOff+4 : cOff+8])
		superIdx := bo.Uint32(data[cOff+8 : cOff+12])
		sourceFileIdx := bo.Uint32(data[cOff+16 : cOff+20])
		classDataOff := bo.Uint32(data[cOff+24 : cOff+28])

		var className, superclass, sourceFile string
		if classIdx < uint32(len(dexFile.Types)) {
			className = CleanClassName(dexFile.Types[classIdx])
		}
		if superIdx != DEXNOINDEX && superIdx < uint32(len(dexFile.Types)) {
			superclass = CleanClassName(dexFile.Types[superIdx])
		}
		if sourceFileIdx != DEXNOINDEX && sourceFileIdx < uint32(len(rawStrings)) {
			sourceFile = rawStrings[sourceFileIdx]
		}

		classItem := ClassItem{
			Index:       int(i),
			Name:        className,
			Superclass:  superclass,
			SourceFile:  sourceFile,
			AccessFlags: accessFlags,
			Methods:     make([]string, 0),
		}

		// Parse Class Data if present
		if classDataOff > 0 && classDataOff < dataLen {
			dexFile.parseClassData(int(classDataOff), className, sourceFile, bo, &classItem)
		}

		dexFile.Classes = append(dexFile.Classes, classItem)
	}

	// 8. Assemble final StringItem list with bytecode provenance
	for i, s := range rawStrings {
		item := StringItem{
			Index:      i,
			Value:      s,
			References: dexFile.StringRefTable[i],
		}
		dexFile.Strings = append(dexFile.Strings, item)
	}

	return dexFile, nil
}

// parseClassData decodes fields, direct/virtual methods, and scans bytecode instructions for string constants.
func (d *DEXFile) parseClassData(offset int, className, sourceFile string, bo binary.ByteOrder, classItem *ClassItem) {
	data := d.RawData
	dataLen := len(data)

	// ULEB128 counts: static_fields, instance_fields, direct_methods, virtual_methods
	staticFieldsSize, n, err := readULEB128(data, offset)
	if err != nil {
		return
	}
	offset += n

	instanceFieldsSize, n, err := readULEB128(data, offset)
	if err != nil {
		return
	}
	offset += n

	directMethodsSize, n, err := readULEB128(data, offset)
	if err != nil {
		return
	}
	offset += n

	virtualMethodsSize, n, err := readULEB128(data, offset)
	if err != nil {
		return
	}
	offset += n

	// Skip fields
	totalFields := int(staticFieldsSize + instanceFieldsSize)
	for f := 0; f < totalFields; f++ {
		_, n, err := readULEB128(data, offset)
		if err != nil {
			return
		}
		offset += n
		_, n, err = readULEB128(data, offset)
		if err != nil {
			return
		}
		offset += n
	}

	// Parse Methods (Direct + Virtual)
	totalMethods := int(directMethodsSize + virtualMethodsSize)
	runningMethodIdx := 0

	for m := 0; m < totalMethods; m++ {
		if offset >= dataLen {
			break
		}
		// Reset running method index between direct and virtual lists
		if m == int(directMethodsSize) {
			runningMethodIdx = 0
		}

		diff, n, err := readULEB128(data, offset)
		if err != nil {
			break
		}
		offset += n
		runningMethodIdx += int(diff)

		// access_flags
		accessFlags, n, err := readULEB128(data, offset)
		if err != nil {
			break
		}
		offset += n

		// code_off
		codeOff, n, err := readULEB128(data, offset)
		if err != nil {
			break
		}
		offset += n

		var methodName, protoStr string
		if runningMethodIdx < len(d.Methods) {
			methodName = d.Methods[runningMethodIdx].MethodName
			protoStr = d.Methods[runningMethodIdx].Proto
		} else {
			methodName = fmt.Sprintf("method_%d", runningMethodIdx)
		}
		classItem.Methods = append(classItem.Methods, methodName)

		// Scan Dalvik bytecode if code_off > 0
		if codeOff > 0 && int(codeOff)+16 <= dataLen {
			isStatic := (accessFlags & 0x0008) != 0
			d.scanCodeItem(int(codeOff), className, methodName, protoStr, sourceFile, bo, isStatic)
		}
	}
}

// ExtractFillArrayDataPayload decodes a fill-array-data payload from a DEX code item.
// Format:
//   ident: uint16 (0x0300)
//   element_width: uint16 (1, 2, 4, 8)
//   size: uint32 (element count)
//   data: size * element_width bytes (padded to 2-byte boundary)
func ExtractFillArrayDataPayload(data []byte, codeOff, pc int, offsetRel int32, bo binary.ByteOrder) (*EncodedArrayPayload, error) {
	targetPC := int32(pc) + offsetRel
	if targetPC < 0 {
		return nil, fmt.Errorf("invalid negative target code unit offset: %d", targetPC)
	}

	payloadOff := codeOff + 16 + int(targetPC)*2
	if payloadOff < 0 || payloadOff+8 > len(data) {
		return nil, fmt.Errorf("fill-array-data payload offset %d out of bounds (len=%d)", payloadOff, len(data))
	}

	ident := bo.Uint16(data[payloadOff : payloadOff+2])
	if ident != 0x0300 {
		return nil, fmt.Errorf("invalid fill-array-data payload ident: 0x%04x (expected 0x0300)", ident)
	}

	elemWidth := bo.Uint16(data[payloadOff+2 : payloadOff+4])
	if elemWidth != 1 && elemWidth != 2 && elemWidth != 4 && elemWidth != 8 {
		return nil, fmt.Errorf("invalid fill-array-data element width: %d (expected 1, 2, 4, or 8)", elemWidth)
	}

	elemCount := bo.Uint32(data[payloadOff+4 : payloadOff+8])
	totalBytes := uint64(elemWidth) * uint64(elemCount)
	const maxPayloadBytes = 10 * 1024 * 1024 // 10MB safety cap
	if totalBytes > maxPayloadBytes {
		return nil, fmt.Errorf("oversized fill-array-data payload: %d bytes (exceeds 10MB limit)", totalBytes)
	}

	if uint64(payloadOff)+8+totalBytes > uint64(len(data)) {
		return nil, fmt.Errorf("fill-array-data payload data extends beyond file bounds (offset %d + %d > %d)", payloadOff+8, totalBytes, len(data))
	}

	rawPayload := make([]byte, totalBytes)
	copy(rawPayload, data[payloadOff+8:payloadOff+8+int(totalBytes)])

	return &EncodedArrayPayload{
		ElementWidth: elemWidth,
		ElementCount: elemCount,
		Data:         rawPayload,
	}, nil
}

// scanCodeItem inspects code instructions to record string constants and track array data-flow.
func (d *DEXFile) scanCodeItem(codeOff int, className, methodName, protoStr, sourceFile string, bo binary.ByteOrder, isStatic bool) {
	data := d.RawData
	dataLen := len(data)

	// code_item layout:
	// registers_size uint16 (0)
	// ins_size       uint16 (2)
	// outs_size      uint16 (4)
	// tries_size     uint16 (6)
	// debug_info_off uint32 (8)
	// insns_size     uint32 (12)
	regsSize := bo.Uint16(data[codeOff : codeOff+2])
	insSize := bo.Uint16(data[codeOff+2 : codeOff+4])
	if d.MethodMetadata != nil {
		d.MethodMetadata[className+"#"+methodName] = MethodCodeMeta{
			ClassName:  className,
			MethodName: methodName,
			RegsSize:   regsSize,
			InsSize:    insSize,
			IsStatic:   isStatic,
		}
	}

	insnsSize := bo.Uint32(data[codeOff+12 : codeOff+16])
	insnsByteLen := int(insnsSize) * 2

	if insnsByteLen <= 0 || codeOff+16+insnsByteLen > dataLen {
		return
	}

	insnsData := data[codeOff+16 : codeOff+16+insnsByteLen]
	ref := MethodReference{
		ClassName:  className,
		MethodName: methodName,
		Signature:  protoStr,
		SourceFile: sourceFile,
	}

	regArrayPayloads := make(map[byte]EncodedArrayPayload)

	// Scan 16-bit code units
	pc := 0
	numUnits := int(insnsSize)
	for pc < numUnits {
		unit := bo.Uint16(insnsData[pc*2 : pc*2+2])
		opcode := byte(unit & 0xFF)

		switch opcode {
		case 0x1A: // const-string vAA, string@BBBB (Format 21c, 2 units)
			if pc+1 < numUnits {
				stringIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				d.recordStringRef(stringIdx, ref)
			}
			pc += 2
		case 0x1B: // const-string/jumbo vAA, string@BBBBBBBB (Format 31c, 3 units)
			if pc+2 < numUnits {
				low := uint32(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				high := uint32(bo.Uint16(insnsData[(pc+2)*2 : (pc+2)*2+2]))
				stringIdx := int(low | (high << 16))
				d.recordStringRef(stringIdx, ref)
			}
			pc += 3
		case 0x26: // fill-array-data vAA, +BBBBBBBB (Format 31t, 3 units)
			if pc+2 < numUnits {
				vAA := byte(unit >> 8)
				offsetRel := int32(bo.Uint32(insnsData[(pc+1)*2 : (pc+1)*2+4]))
				payload, err := ExtractFillArrayDataPayload(data, codeOff, pc, offsetRel, bo)
				if err == nil && payload != nil {
					regArrayPayloads[vAA] = *payload
					d.ArrayPayloads = append(d.ArrayPayloads, *payload)
				}
			}
			pc += 3
		case 0x5B: // iput-object vA, vB, field@CCCC (Format 22c, 2 units)
			if pc+1 < numUnits {
				vA := byte(unit >> 8) & 0x0F
				fieldIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				if payload, found := regArrayPayloads[vA]; found && fieldIdx < len(d.Fields) {
					f := d.Fields[fieldIdx]
					d.recordFieldArray(StaticFieldArrayAssignment{
						ClassName: f.ClassName,
						FieldName: f.FieldName,
						FieldType: f.TypeName,
						Payload:   payload,
					})
				}
			}
			pc += 2
		case 0x69: // sput-object vAA, field@BBBB (Format 21c, 2 units)
			if pc+1 < numUnits {
				vAA := byte(unit >> 8)
				fieldIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				if payload, found := regArrayPayloads[vAA]; found && fieldIdx < len(d.Fields) {
					f := d.Fields[fieldIdx]
					d.recordFieldArray(StaticFieldArrayAssignment{
						ClassName: f.ClassName,
						FieldName: f.FieldName,
						FieldType: f.TypeName,
						Payload:   payload,
					})
				}
			}
			pc += 2
		case 0x54: // iget-object vA, vB, field@CCCC (Format 22c, 2 units)
			if pc+1 < numUnits {
				vA := byte(unit >> 8) & 0x0F
				fieldIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				if fieldIdx < len(d.Fields) {
					f := d.Fields[fieldIdx]
					fnLower := strings.ToLower(f.FieldName)
					if f.TypeName == "[B" || strings.Contains(fnLower, "iv") || strings.Contains(fnLower, "key") {
						d.recordFieldRead(f.ClassName, f.FieldName, methodName, vA)
					}
				}
			}
			pc += 2
		case 0x62: // sget-object vAA, field@BBBB (Format 21c, 2 units)
			if pc+1 < numUnits {
				vAA := byte(unit >> 8)
				fieldIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				if fieldIdx < len(d.Fields) {
					f := d.Fields[fieldIdx]
					fnLower := strings.ToLower(f.FieldName)
					if f.TypeName == "[B" || strings.Contains(fnLower, "iv") || strings.Contains(fnLower, "key") {
						d.recordFieldRead(f.ClassName, f.FieldName, methodName, vAA)
					}
				}
			}
			pc += 2
		case 0x6E, 0x6F, 0x70, 0x71, 0x72: // invoke-kind (Format 35c, 3 units)
			if pc+2 < numUnits {
				count := byte(unit >> 12)
				methIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				regsUnit := bo.Uint16(insnsData[(pc+2)*2 : (pc+2)*2+2])
				vC := byte(regsUnit & 0x0F)
				vD := byte((regsUnit >> 4) & 0x0F)
				vE := byte((regsUnit >> 8) & 0x0F)
				vF := byte((regsUnit >> 12) & 0x0F)
				vG := byte(unit >> 8) & 0x0F
				allRegs := [5]byte{vC, vD, vE, vF, vG}
				if count > 5 {
					count = 5
				}
				args := append([]byte(nil), allRegs[:count]...)

				if methIdx < len(d.Methods) {
					targetMeth := d.Methods[methIdx]
					tClass := targetMeth.ClassName
					if tClass == className || strings.Contains(tClass, "Cipher") || strings.Contains(tClass, "IvParameterSpec") || strings.Contains(targetMeth.Proto, "IvParameterSpec") {
						d.recordInvocation(className, methodName, targetMeth.ClassName, targetMeth.MethodName, targetMeth.Proto, args)
					}
				}
			}
			pc += 3
		case 0x74, 0x75, 0x76, 0x77, 0x78: // invoke-kind/range (Format 3rc, 3 units)
			if pc+2 < numUnits {
				count := byte(unit >> 8)
				methIdx := int(bo.Uint16(insnsData[(pc+1)*2 : (pc+1)*2+2]))
				startReg := bo.Uint16(insnsData[(pc+2)*2 : (pc+2)*2+2])
				var args []byte
				for i := 0; i < int(count); i++ {
					args = append(args, byte(startReg+uint16(i)))
				}

				if methIdx < len(d.Methods) {
					targetMeth := d.Methods[methIdx]
					tClass := targetMeth.ClassName
					if tClass == className || strings.Contains(tClass, "Cipher") || strings.Contains(tClass, "IvParameterSpec") || strings.Contains(targetMeth.Proto, "IvParameterSpec") {
						d.recordInvocation(className, methodName, targetMeth.ClassName, targetMeth.MethodName, targetMeth.Proto, args)
					}
				}
			}
			pc += 3
		default:
			// Move ahead safely by 1 code unit
			pc++
		}
	}
}

func (d *DEXFile) recordFieldRead(className, fieldName, methodName string, reg byte) {
	for _, existing := range d.FieldReads {
		if existing.ClassName == className && existing.FieldName == fieldName && existing.MethodName == methodName && existing.Register == reg {
			return
		}
	}
	d.FieldReads = append(d.FieldReads, FieldAccessItem{
		ClassName:  className,
		FieldName:  fieldName,
		MethodName: methodName,
		Register:   reg,
		IsWrite:    false,
	})
}

func (d *DEXFile) recordInvocation(callerClass, callerMethod, targetClass, targetMethod, targetProto string, args []byte) {
	for _, existing := range d.Invocations {
		if existing.CallerClassName == callerClass && existing.CallerMethodName == callerMethod &&
			existing.TargetClassName == targetClass && existing.TargetMethodName == targetMethod &&
			bytes.Equal(existing.ArgRegisters, args) {
			return
		}
	}
	d.Invocations = append(d.Invocations, MethodInvocationItem{
		CallerClassName:  callerClass,
		CallerMethodName: callerMethod,
		TargetClassName:  targetClass,
		TargetMethodName: targetMethod,
		TargetProto:      targetProto,
		ArgRegisters:     args,
	})
}

func (d *DEXFile) recordFieldArray(assignment StaticFieldArrayAssignment) {
	for _, existing := range d.FieldArrays {
		if existing.ClassName == assignment.ClassName && existing.FieldName == assignment.FieldName {
			return
		}
	}
	d.FieldArrays = append(d.FieldArrays, assignment)
}

func (d *DEXFile) recordStringRef(stringIdx int, ref MethodReference) {
	if stringIdx < 0 || stringIdx >= len(d.StringRefTable) {
		return
	}
	existing := d.StringRefTable[stringIdx]
	if len(existing) >= 5 {
		return
	}
	for _, e := range existing {
		if e.ClassName == ref.ClassName && e.MethodName == ref.MethodName {
			return // duplicate reference in same method
		}
	}
	d.StringRefTable[stringIdx] = append(existing, ref)
}

// ExtractDEXFilesFromAPK searches and parses all `classes*.dex` files in an APK archive.
func ExtractDEXFilesFromAPK(ctx context.Context, r io.ReaderAt, size int64, limits *ArchiveSecurityLimits) ([]*ExtractedDEX, error) {
	if limits == nil {
		def := DefaultArchiveLimits()
		limits = &def
	}

	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed opening APK zip archive: %w", err)
	}

	safeReader, err := NewSafeZipReader(zipReader, limits)
	if err != nil {
		return nil, fmt.Errorf("APK archive security violation: %w", err)
	}

	// Match classes.dex, classes2.dex, classes3.dex, etc.
	dexNameRegex := regexp.MustCompile(`(?i)^classes\d*\.dex$`)
	var dexEntries []*zip.File

	for _, f := range zipReader.File {
		base := filepath.Base(f.Name)
		if dexNameRegex.MatchString(base) && !strings.Contains(f.Name, "/") && !strings.Contains(f.Name, "\\") {
			dexEntries = append(dexEntries, f)
		}
	}

	if len(dexEntries) == 0 {
		return nil, errors.New("no DEX entries (classes*.dex) found in APK archive")
	}

	results := make([]*ExtractedDEX, 0, len(dexEntries))

	for _, entry := range dexEntries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		dexData, err := safeReader.ReadTargetEntry(ctx, entry)
		if err != nil {
			results = append(results, &ExtractedDEX{
				EntryName: entry.Name,
				Size:      int64(entry.UncompressedSize64),
				Error:     fmt.Sprintf("extraction failed: %v", err),
			})
			continue
		}

		h := sha256.Sum256(dexData)
		hashStr := hex.EncodeToString(h[:])

		parsedDEX, err := ParseDEX(dexData)
		if err != nil {
			results = append(results, &ExtractedDEX{
				EntryName: entry.Name,
				Size:      int64(len(dexData)),
				SHA256:    hashStr,
				Error:     fmt.Sprintf("parse failed: %v", err),
			})
			continue
		}

		results = append(results, &ExtractedDEX{
			EntryName: entry.Name,
			Size:      int64(len(dexData)),
			SHA256:    hashStr,
			DEX:       parsedDEX,
		})
	}

	return results, nil
}

// -----------------------------------------------------------------------------
// Helpers: ULEB128 & MUTF-8 String Parsing
// -----------------------------------------------------------------------------

func readULEB128(data []byte, offset int) (uint32, int, error) {
	var result uint32
	var shift uint
	bytesRead := 0

	for {
		if offset+bytesRead >= len(data) {
			return 0, 0, errors.New("unexpected EOF reading ULEB128")
		}
		b := data[offset+bytesRead]
		bytesRead++
		result |= uint32(b&0x7F) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, 0, errors.New("ULEB128 overflow (exceeds 32-bit integer)")
		}
	}
	return result, bytesRead, nil
}

func readDEXString(data []byte, offset int) (string, error) {
	if offset < 0 || offset >= len(data) {
		return "", errors.New("string offset out of bounds")
	}

	// Read ULEB128 utf16_size
	utf16Size, n, err := readULEB128(data, offset)
	if err != nil {
		return "", fmt.Errorf("failed reading string length ULEB128: %w", err)
	}
	offset += n

	if utf16Size > 65536 {
		return "", fmt.Errorf("string utf16 size %d exceeds safety limit", utf16Size)
	}

	// Locate null terminator
	start := offset
	end := start
	for end < len(data) && data[end] != 0 {
		end++
	}
	if end >= len(data) {
		return "", errors.New("unterminated MUTF-8 string (missing null byte)")
	}

	return decodeMUTF8(data[start:end]), nil
}

// decodeMUTF8 decodes Dalvik Modified UTF-8 into standard Go UTF-8 string.
func decodeMUTF8(b []byte) string {
	var runes []rune
	i := 0
	n := len(b)

	for i < n {
		c := b[i]
		if c < 0x80 {
			runes = append(runes, rune(c))
			i++
		} else if (c & 0xE0) == 0xC0 {
			if i+1 < n {
				r := rune(c&0x1F)<<6 | rune(b[i+1]&0x3F)
				runes = append(runes, r)
				i += 2
			} else {
				runes = append(runes, rune(c))
				i++
			}
		} else if (c & 0xF0) == 0xE0 {
			if i+2 < n {
				r := rune(c&0x0F)<<12 | rune(b[i+1]&0x3F)<<6 | rune(b[i+2]&0x3F)
				runes = append(runes, r)
				i += 3
			} else {
				runes = append(runes, rune(c))
				i++
			}
		} else {
			runes = append(runes, rune(c))
			i++
		}
	}

	// Decode surrogate pairs if present
	var out []rune
	for j := 0; j < len(runes); j++ {
		r := runes[j]
		if utf16.IsSurrogate(r) && j+1 < len(runes) && utf16.IsSurrogate(runes[j+1]) {
			combined := utf16.DecodeRune(r, runes[j+1])
			out = append(out, combined)
			j++
		} else {
			out = append(out, r)
		}
	}

	return string(out)
}

// CleanClassName transforms DEX type descriptors like "Lcom/android/App;" into "com.android.App".
func CleanClassName(desc string) string {
	if strings.HasPrefix(desc, "L") && strings.HasSuffix(desc, ";") {
		desc = desc[1 : len(desc)-1]
		return strings.ReplaceAll(desc, "/", ".")
	}
	return desc
}
