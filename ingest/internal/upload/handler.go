package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"

	"github.com/daluoter/malscan-ingest/internal/queue"
	"github.com/daluoter/malscan-ingest/internal/store"
)

// ObjectUploader abstracts MinIO PutObject for testing.
// *minio.Client satisfies this interface natively.
type ObjectUploader interface {
	PutObject(ctx context.Context, bucketName string, objectName string,
		reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
}

// UploadResponse matches backend/src/malscan/schemas/requests.py UploadResponse exactly.
type UploadResponse struct {
	JobID     string `json:"job_id"`
	FileID    string `json:"file_id"`
	SHA256    string `json:"sha256"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// FileStore abstracts database operations for testing.
type FileStore interface {
	CreateFileAndJob(ctx context.Context, sha256 string, size int64, filename string,
		contentType string, parentJobID *uuid.UUID, depth int) (store.FileRecord, store.JobRecord, error)
	ValidateParentJob(ctx context.Context, parentJobID uuid.UUID) (int, error)
	MarkJobFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error
}

// JobPublisher abstracts RabbitMQ publishing for testing.
type JobPublisher interface {
	Publish(ctx context.Context, msg queue.JobMessage) error
}

// Handler handles multipart file uploads with streaming, SHA256 hashing,
// size validation, dedup, MinIO storage, database records, and MQ publishing.
type Handler struct {
	storage   ObjectUploader
	store     FileStore
	publisher JobPublisher
	bucket    string
	maxSize   int64 // per-file limit (from config.MaxFileSize)
	logger    *slog.Logger
}

// NewHandler creates an upload handler with the given dependencies.
func NewHandler(storage ObjectUploader, st FileStore, publisher JobPublisher,
	bucket string, maxSize int64, logger *slog.Logger) *Handler {
	return &Handler{
		storage:   storage,
		store:     st,
		publisher: publisher,
		bucket:    bucket,
		maxSize:   maxSize,
		logger:    logger,
	}
}

// ServeHTTP handles POST /api/v1/files — streams multipart upload,
// hashes with SHA256, validates size, dedup-checks, stores in MinIO,
// creates DB records, and publishes to the job queue.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Parse multipart stream — NOT r.ParseMultipartForm (CONTEXT.md decision)
	reader, err := r.MultipartReader()
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			WriteError(w, http.StatusBadRequest, CodeFileTooLarge, "Request body too large", nil)
			return
		}
		WriteError(w, http.StatusBadRequest, CodeInvalidRequest, "Invalid multipart request: "+err.Error(), nil)
		return
	}

	// 2. Loop through parts: capture "file" and "parent_job_id"
	var filename string
	var contentType string
	var filePart io.Reader
	var parentJobIDStr string

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				WriteError(w, http.StatusBadRequest, CodeFileTooLarge, "Request body too large", nil)
				return
			}
			WriteError(w, http.StatusBadRequest, CodeInvalidRequest, "Error reading multipart: "+err.Error(), nil)
			return
		}
		switch part.FormName() {
		case "file":
			filename = SanitizeFilename(part.FileName())
			contentType = part.Header.Get("Content-Type")
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			filePart = part
		case "parent_job_id":
			data, readErr := io.ReadAll(part)
			if readErr != nil {
				WriteError(w, http.StatusBadRequest, CodeInvalidRequest, "Error reading parent_job_id: "+readErr.Error(), nil)
				return
			}
			parentJobIDStr = string(data)
		}
		if filePart != nil {
			break // stop reading parts once we have the file
		}
	}

	if filePart == nil {
		WriteError(w, http.StatusUnprocessableEntity, CodeNoFile, "No file field in form data or field is not a file", nil)
		return
	}

	// 3. Create temp file for streaming
	tempFile, err := os.CreateTemp("", "ingest-*")
	if err != nil {
		WriteError(w, http.StatusInternalServerError, CodeInternalError, "Failed to create temp file: "+err.Error(), nil)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// 4. Stream: read 1MB chunks, hash with SHA256, validate size
	hasher := sha256.New()
	teeReader := io.TeeReader(filePart, hasher)

	buf := make([]byte, 1024*1024) // 1MB chunks matching Python CHUNK_SIZE
	var fileSize int64

	for {
		n, readErr := teeReader.Read(buf)
		if n > 0 {
			fileSize += int64(n)
			if fileSize > h.maxSize {
				WriteError(w, http.StatusBadRequest, CodeFileTooLarge, "File size exceeds limit", map[string]any{
					"max_size_bytes":    h.maxSize,
					"actual_size_bytes": fileSize,
				})
				return
			}
			if _, writeErr := tempFile.Write(buf[:n]); writeErr != nil {
				WriteError(w, http.StatusInternalServerError, CodeInternalError, "Failed to write temp file: "+writeErr.Error(), nil)
				return
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(readErr, &maxBytesErr) {
				WriteError(w, http.StatusBadRequest, CodeFileTooLarge, "Request body too large", map[string]any{
					"max_size_bytes": h.maxSize,
				})
				return
			}
			WriteError(w, http.StatusInternalServerError, CodeInternalError, "Error reading upload: "+readErr.Error(), nil)
			return
		}
	}

	// 5. Compute SHA256 hash
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	// 6. Parse and validate parent_job_id if present
	var parentJobID *uuid.UUID
	var depth int
	if parentJobIDStr != "" {
		parsed, parseErr := uuid.Parse(parentJobIDStr)
		if parseErr != nil {
			WriteError(w, http.StatusBadRequest, CodeInvalidRequest, "Invalid parent_job_id: not a valid UUID", nil)
			return
		}
		parentDepth, valErr := h.store.ValidateParentJob(r.Context(), parsed)
		if valErr != nil {
			if errors.Is(valErr, store.ErrNotFound) {
				WriteError(w, http.StatusBadRequest, CodeInvalidRequest, "Parent job not found", nil)
				return
			}
			if errors.Is(valErr, store.ErrDepthExceeded) {
				WriteError(w, http.StatusBadRequest, CodeInvalidRequest, "Maximum recursion depth exceeded", nil)
				return
			}
			WriteError(w, http.StatusInternalServerError, CodeInternalError, "Failed to validate parent job: "+valErr.Error(), nil)
			return
		}
		parentJobID = &parsed
		depth = parentDepth + 1
	}

	// 7. Create file and job records in DB
	fileRec, jobRec, err := h.store.CreateFileAndJob(r.Context(), sha256Hash, fileSize, filename, contentType, parentJobID, depth)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, CodeInternalError, "Failed to create records: "+err.Error(), nil)
		return
	}

	// 8. Upload to MinIO only if file is new (dedup)
	if fileRec.IsNew {
		if _, seekErr := tempFile.Seek(0, io.SeekStart); seekErr != nil {
			WriteError(w, http.StatusInternalServerError, CodeInternalError, "Failed to seek temp file: "+seekErr.Error(), nil)
			return
		}
		_, err = h.storage.PutObject(r.Context(), h.bucket, sha256Hash, tempFile, fileSize,
			minio.PutObjectOptions{ContentType: contentType})
		if err != nil {
			WriteError(w, http.StatusInternalServerError, CodeStorageError, "Failed to store file: "+err.Error(), nil)
			return
		}
	} else {
		h.logger.Info("file_exists", "sha256", sha256Hash, "file_id", fileRec.ID.String())
	}

	// 9. Publish job to RabbitMQ
	err = h.publisher.Publish(r.Context(), queue.JobMessage{
		JobID:            jobRec.ID.String(),
		FileID:           fileRec.ID.String(),
		StorageKey:       sha256Hash,
		SHA256:           sha256Hash,
		OriginalFilename: filename,
	})
	if err != nil {
		// Mark the job as failed since we couldn't queue it
		if markErr := h.store.MarkJobFailed(r.Context(), jobRec.ID, "publish failed: "+err.Error()); markErr != nil {
			h.logger.Error("failed to mark job as failed", "job_id", jobRec.ID.String(), "error", markErr)
		}
		WriteError(w, http.StatusServiceUnavailable, CodeQueuePublishFailed, "Failed to submit job to processing queue. Please try again.", nil)
		return
	}

	// 10. Success response
	h.logger.Info("file_uploaded", "sha256", sha256Hash, "size", fileSize, "filename", filename,
		"job_id", jobRec.ID.String(), "file_id", fileRec.ID.String(), "is_new", fileRec.IsNew)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := UploadResponse{
		JobID:     jobRec.ID.String(),
		FileID:    fileRec.ID.String(),
		SHA256:    sha256Hash,
		Status:    jobRec.Status,
		CreatedAt: jobRec.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999+00:00"),
	}
	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		h.logger.Error("failed to encode response", "error", encErr)
	}
}
