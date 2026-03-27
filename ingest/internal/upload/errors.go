package upload

import (
	"encoding/json"
	"net/http"
)

// Error code constants matching the Python ApiError codes.
const (
	CodeFileTooLarge     = "FILE_TOO_LARGE"
	CodeNoFile           = "NO_FILE"
	CodeInvalidRequest   = "INVALID_REQUEST"
	CodeInternalError    = "INTERNAL_ERROR"
	CodeStorageError     = "STORAGE_ERROR"
	CodeQueueUnavailable = "QUEUE_UNAVAILABLE"
)

// ApiError represents a single error with code, message, and optional details.
type ApiError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// ApiErrorResponse wraps an error in the standard envelope.
type ApiErrorResponse struct {
	Error ApiError `json:"error"`
}

// WriteError writes a JSON error response matching the Python ApiErrorResponse schema.
func WriteError(w http.ResponseWriter, status int, code string, message string, details map[string]any) {
	resp := ApiErrorResponse{
		Error: ApiError{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
