package upload_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daluoter/malscan-ingest/internal/upload"
)

func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		code       string
		message    string
		details    map[string]any
		wantStatus int
		wantCode   string
		wantMsg    string
		hasDetails bool
	}{
		{
			name:       "FILE_TOO_LARGE with details",
			status:     http.StatusBadRequest,
			code:       upload.CodeFileTooLarge,
			message:    "File size exceeds limit",
			details:    map[string]any{"max_size_bytes": float64(104857600)},
			wantStatus: http.StatusBadRequest,
			wantCode:   "FILE_TOO_LARGE",
			wantMsg:    "File size exceeds limit",
			hasDetails: true,
		},
		{
			name:       "NO_FILE without details",
			status:     http.StatusUnprocessableEntity,
			code:       upload.CodeNoFile,
			message:    "No file field in form data",
			details:    nil,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "NO_FILE",
			wantMsg:    "No file field in form data",
			hasDetails: false,
		},
		{
			name:       "INTERNAL_ERROR without details",
			status:     http.StatusInternalServerError,
			code:       upload.CodeInternalError,
			message:    "something broke",
			details:    nil,
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL_ERROR",
			wantMsg:    "something broke",
			hasDetails: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			upload.WriteError(w, tt.status, tt.code, tt.message, tt.details)

			// Check HTTP status code
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			// Check Content-Type header
			ct := w.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}

			// Parse JSON body
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response body: %v", err)
			}

			// Check envelope structure: {"error": {"code": ..., "message": ...}}
			errObj, ok := resp["error"].(map[string]any)
			if !ok {
				t.Fatalf("response missing 'error' envelope, got: %v", resp)
			}

			if errObj["code"] != tt.wantCode {
				t.Errorf("error.code = %q, want %q", errObj["code"], tt.wantCode)
			}

			if errObj["message"] != tt.wantMsg {
				t.Errorf("error.message = %q, want %q", errObj["message"], tt.wantMsg)
			}

			// Check details presence/absence
			_, detailsPresent := errObj["details"]
			if tt.hasDetails && !detailsPresent {
				t.Error("expected 'details' key in error, but it was absent")
			}
			if !tt.hasDetails && detailsPresent {
				t.Error("expected no 'details' key in error, but it was present")
			}
		})
	}
}
