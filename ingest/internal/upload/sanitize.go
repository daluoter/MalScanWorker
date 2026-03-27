package upload

import (
	"path"
	"strings"
)

// SanitizeFilename sanitizes an uploaded filename to prevent path traversal
// and other attacks. Matches Python _sanitize_filename behavior exactly.
func SanitizeFilename(filename string) string {
	// Replace Windows path separators with Unix ones
	filename = strings.ReplaceAll(filename, "\\", "/")

	// Extract basename (use path.Base, NOT filepath.Base — path.Base
	// always uses forward-slash semantics regardless of OS)
	filename = path.Base(filename)

	// Remove null bytes
	filename = strings.ReplaceAll(filename, "\x00", "")

	// Truncate to 255 characters
	if len(filename) > 255 {
		filename = filename[:255]
	}

	// path.Base returns "." for empty input and "/" for root — treat as empty
	if filename == "." || filename == "/" {
		filename = ""
	}

	// Fallback for empty or whitespace-only names
	if strings.TrimSpace(filename) == "" {
		filename = "unnamed"
	}

	return filename
}
