package upload_test

import (
	"strings"
	"testing"

	"github.com/daluoter/malscan-ingest/internal/upload"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "normal filename passes through",
			input: "normal.exe",
			want:  "normal.exe",
		},
		{
			name:  "strips path traversal",
			input: "../../etc/passwd",
			want:  "passwd",
		},
		{
			name:  "strips Windows path to basename",
			input: "C:\\Users\\test\\malware.exe",
			want:  "malware.exe",
		},
		{
			name:  "removes null bytes",
			input: "file\x00name.txt",
			want:  "filename.txt",
		},
		{
			name:  "truncates to 255 characters",
			input: strings.Repeat("a", 300),
			want:  strings.Repeat("a", 255),
		},
		{
			name:  "empty string becomes unnamed",
			input: "",
			want:  "unnamed",
		},
		{
			name:  "whitespace-only becomes unnamed",
			input: "   ",
			want:  "unnamed",
		},
		{
			name:  "slash-only becomes unnamed",
			input: "/",
			want:  "unnamed",
		},
		{
			name:  "Unix path extracts basename",
			input: "dir/file.txt",
			want:  "file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := upload.SanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
