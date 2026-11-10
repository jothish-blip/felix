package remediation

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// BuildUnifiedDiff constructs a standard, developer-ready unified diff string.
func BuildUnifiedDiff(targetFile string, originalLines []string, replacementLines []string, startLine int, endLine int, contextLines int) (*RemediationDiff, error) {
	cleanFile := filepath.ToSlash(filepath.Clean(strings.TrimSpace(targetFile)))
	if cleanFile == "" {
		return nil, fmt.Errorf("target file cannot be empty")
	}

	if contextLines <= 0 {
		contextLines = 3
	}

	totalOriginal := len(originalLines)
	if startLine < 1 {
		startLine = 1
	}
	if endLine > totalOriginal {
		endLine = totalOriginal
	}
	if startLine > endLine+1 {
		return nil, fmt.Errorf("invalid line range: start=%d, end=%d (total=%d)", startLine, endLine, totalOriginal)
	}

	// Context range calculation (0-indexed)
	ctxBeforeStart := startLine - 1 - contextLines
	if ctxBeforeStart < 0 {
		ctxBeforeStart = 0
	}
	ctxBeforeEnd := startLine - 1
	if ctxBeforeEnd < 0 {
		ctxBeforeEnd = 0
	}

	vulnStart := startLine - 1
	vulnEnd := endLine
	if vulnEnd > totalOriginal {
		vulnEnd = totalOriginal
	}

	ctxAfterStart := endLine
	if ctxAfterStart > totalOriginal {
		ctxAfterStart = totalOriginal
	}
	ctxAfterEnd := endLine + contextLines
	if ctxAfterEnd > totalOriginal {
		ctxAfterEnd = totalOriginal
	}

	// Gather lines
	beforeCtx := []string{}
	if ctxBeforeStart < ctxBeforeEnd && ctxBeforeEnd <= totalOriginal {
		beforeCtx = originalLines[ctxBeforeStart:ctxBeforeEnd]
	}

	removed := []string{}
	if vulnStart < vulnEnd && vulnEnd <= totalOriginal {
		removed = originalLines[vulnStart:vulnEnd]
	}

	afterCtx := []string{}
	if ctxAfterStart < ctxAfterEnd && ctxAfterEnd <= totalOriginal {
		afterCtx = originalLines[ctxAfterStart:ctxAfterEnd]
	}

	oldStart := ctxBeforeStart + 1
	oldCount := len(beforeCtx) + len(removed) + len(afterCtx)
	newStart := ctxBeforeStart + 1
	newCount := len(beforeCtx) + len(replacementLines) + len(afterCtx)

	var hunkLines []string
	for _, l := range beforeCtx {
		hunkLines = append(hunkLines, " "+l)
	}
	for _, l := range removed {
		hunkLines = append(hunkLines, "-"+l)
	}
	for _, l := range replacementLines {
		hunkLines = append(hunkLines, "+"+l)
	}
	for _, l := range afterCtx {
		hunkLines = append(hunkLines, " "+l)
	}

	hunkHeader := fmt.Sprintf("@@ -%d,%d +%d,%d @@", oldStart, oldCount, newStart, newCount)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- a/%s\n", cleanFile))
	sb.WriteString(fmt.Sprintf("+++ b/%s\n", cleanFile))
	sb.WriteString(hunkHeader + "\n")
	for _, hl := range hunkLines {
		sb.WriteString(hl + "\n")
	}

	// Assemble patched full source in-memory
	var patchedFull []string
	if ctxBeforeStart > 0 {
		patchedFull = append(patchedFull, originalLines[:ctxBeforeStart]...)
	}
	patchedFull = append(patchedFull, beforeCtx...)
	patchedFull = append(patchedFull, replacementLines...)
	patchedFull = append(patchedFull, afterCtx...)
	if ctxAfterEnd < totalOriginal {
		patchedFull = append(patchedFull, originalLines[ctxAfterEnd:]...)
	}

	hunk := DiffHunk{
		OldStart: oldStart,
		OldCount: oldCount,
		NewStart: newStart,
		NewCount: newCount,
		Heading:  hunkHeader,
		Lines:    hunkLines,
	}

	return &RemediationDiff{
		TargetFile:         cleanFile,
		OriginalSource:     strings.Join(originalLines, "\n"),
		PatchedSource:      strings.Join(patchedFull, "\n"),
		UnifiedDiff:        sb.String(),
		Hunks:              []DiffHunk{hunk},
		AddedLinesCount:    len(replacementLines),
		RemovedLinesCount:  len(removed),
		IsReferencePattern: false,
	}, nil
}

// ValidateDiffSyntax parses and verifies that unified diff text complies with standard diff syntax.
func ValidateDiffSyntax(diffText string) (bool, []string) {
	var errs []string
	normalized := strings.ReplaceAll(diffText, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // trim trailing empty line from split
	}

	if len(lines) < 3 {
		return false, []string{"diff text is too short to be a valid unified diff"}
	}

	if !strings.HasPrefix(lines[0], "--- ") {
		errs = append(errs, fmt.Sprintf("line 1: expected '--- a/...', got %q", lines[0]))
	}
	if !strings.HasPrefix(lines[1], "+++ ") {
		errs = append(errs, fmt.Sprintf("line 2: expected '+++ b/...', got %q", lines[1]))
	}

	hunkFound := false
	var expectedOldCount, expectedNewCount int
	var actualOldCount, actualNewCount int
	inHunk := false

	for i := 2; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "@@ ") {
			if inHunk {
				// Validate previous hunk count
				if actualOldCount != expectedOldCount {
					errs = append(errs, fmt.Sprintf("hunk line count mismatch: expected old count %d, got %d", expectedOldCount, actualOldCount))
				}
				if actualNewCount != expectedNewCount {
					errs = append(errs, fmt.Sprintf("hunk line count mismatch: expected new count %d, got %d", expectedNewCount, actualNewCount))
				}
			}

			hunkFound = true
			inHunk = true
			actualOldCount = 0
			actualNewCount = 0

			// Parse @@ -oldStart,oldCount +newStart,newCount @@
			parts := strings.Split(line, " ")
			if len(parts) < 4 || !strings.HasPrefix(parts[1], "-") || !strings.HasPrefix(parts[2], "+") {
				errs = append(errs, fmt.Sprintf("line %d: malformed hunk header %q", i+1, line))
				continue
			}

			oldParts := strings.Split(strings.TrimPrefix(parts[1], "-"), ",")
			if len(oldParts) == 2 {
				expectedOldCount, _ = strconv.Atoi(oldParts[1])
			} else {
				expectedOldCount = 1
			}

			newParts := strings.Split(strings.TrimPrefix(parts[2], "+"), ",")
			if len(newParts) == 2 {
				expectedNewCount, _ = strconv.Atoi(newParts[1])
			} else {
				expectedNewCount = 1
			}
			continue
		}

		if inHunk {
			if len(line) == 0 {
				errs = append(errs, fmt.Sprintf("line %d: empty line inside diff hunk must start with ' ', '+', or '-'", i+1))
				continue
			}
			prefix := line[0]
			switch prefix {
			case ' ':
				actualOldCount++
				actualNewCount++
			case '-':
				actualOldCount++
			case '+':
				actualNewCount++
			case '\\':
				// e.g. \ No newline at end of file
			default:
				errs = append(errs, fmt.Sprintf("line %d: invalid line prefix %q inside diff hunk", i+1, prefix))
			}
		}
	}

	if inHunk {
		if actualOldCount != expectedOldCount {
			errs = append(errs, fmt.Sprintf("trailing hunk line count mismatch: expected old count %d, got %d", expectedOldCount, actualOldCount))
		}
		if actualNewCount != expectedNewCount {
			errs = append(errs, fmt.Sprintf("trailing hunk line count mismatch: expected new count %d, got %d", expectedNewCount, actualNewCount))
		}
	}

	if !hunkFound {
		errs = append(errs, "no hunk header (@@ ... @@) found in diff")
	}

	return len(errs) == 0, errs
}

// ApplyPatchToMemory applies a unified diff to the original source in-memory without modifying any disk files.
func ApplyPatchToMemory(originalSource string, diff *RemediationDiff) (string, error) {
	if diff == nil {
		return "", fmt.Errorf("diff cannot be nil")
	}

	if diff.IsReferencePattern {
		return "", fmt.Errorf("reference pattern diffs cannot be applied to target source: target source unavailable")
	}

	normalized := strings.ReplaceAll(originalSource, "\r\n", "\n")
	origLines := strings.Split(normalized, "\n")

	lineOffset := 0
	for _, hunk := range diff.Hunks {
		oldStartIdx := (hunk.OldStart - 1) + lineOffset
		if oldStartIdx < 0 || oldStartIdx > len(origLines) {
			return "", fmt.Errorf("hunk old_start %d (offset %d) is out of bounds for source of %d lines", hunk.OldStart, lineOffset, len(origLines))
		}

		// Reconstruct old lines and new lines from hunk
		var expectedOldLines []string
		var replacementLines []string
		for _, hl := range hunk.Lines {
			if len(hl) == 0 {
				continue
			}
			switch hl[0] {
			case ' ':
				expectedOldLines = append(expectedOldLines, hl[1:])
				replacementLines = append(replacementLines, hl[1:])
			case '-':
				expectedOldLines = append(expectedOldLines, hl[1:])
			case '+':
				replacementLines = append(replacementLines, hl[1:])
			}
		}

		// Verify that original lines at target match expectedOldLines
		oldEndIdx := oldStartIdx + len(expectedOldLines)
		if oldEndIdx > len(origLines) {
			return "", fmt.Errorf("hunk old block extends beyond end of source (%d > %d)", oldEndIdx, len(origLines))
		}

		for j, expLine := range expectedOldLines {
			actualLine := origLines[oldStartIdx+j]
			if actualLine != expLine {
				return "", fmt.Errorf("context mismatch at line %d: expected %q, got %q", oldStartIdx+j+1, expLine, actualLine)
			}
		}

		// Replace old block with replacementLines
		var newLines []string
		newLines = append(newLines, origLines[:oldStartIdx]...)
		newLines = append(newLines, replacementLines...)
		if oldEndIdx < len(origLines) {
			newLines = append(newLines, origLines[oldEndIdx:]...)
		}
		origLines = newLines
		lineOffset += (len(replacementLines) - len(expectedOldLines))
	}

	return strings.Join(origLines, "\n"), nil
}

// DetectConflicts checks if multiple remediation items target overlapping line ranges in the same file.
func DetectConflicts(items []*RemediationItem) []string {
	var conflicts []string
	byFile := make(map[string][]*RemediationItem)
	for _, it := range items {
		if it == nil || it.TargetFile == "" || it.Diff == nil || it.Diff.IsReferencePattern {
			continue
		}
		byFile[it.TargetFile] = append(byFile[it.TargetFile], it)
	}

	for file, fileItems := range byFile {
		if len(fileItems) < 2 {
			continue
		}
		for i := 0; i < len(fileItems); i++ {
			for j := i + 1; j < len(fileItems); j++ {
				a := fileItems[i]
				b := fileItems[j]

				// Overlap condition: max(startA, startB) <= min(endA, endB)
				startMax := a.StartLine
				if b.StartLine > startMax {
					startMax = b.StartLine
				}
				endMin := a.EndLine
				if b.EndLine < endMin {
					endMin = b.EndLine
				}

				if startMax <= endMin {
					conflicts = append(conflicts, fmt.Sprintf("file %s: item %s (lines %d-%d) conflicts with item %s (lines %d-%d)", file, a.ID, a.StartLine, a.EndLine, b.ID, b.StartLine, b.EndLine))
				}
			}
		}
	}
	return conflicts
}
