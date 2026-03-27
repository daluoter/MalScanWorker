package upload_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"

	"github.com/daluoter/malscan-ingest/internal/queue"
	"github.com/daluoter/malscan-ingest/internal/store"
	"github.com/daluoter/malscan-ingest/internal/upload"
)

// mockUploader implements upload.ObjectUploader for testing.
type mockUploader struct {
	putErr     error
	lastBucket string
	lastKey    string
	lastData   []byte
	lastCT     string
	putCalled  bool
}

func (m *mockUploader) PutObject(_ context.Context, bucket, key string, reader io.Reader, _ int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	m.putCalled = true
	m.lastBucket = bucket
	m.lastKey = key
	m.lastData, _ = io.ReadAll(reader)
	m.lastCT = opts.ContentType
	return minio.UploadInfo{}, m.putErr
}

// mockFileStore implements upload.FileStore for testing.
type mockFileStore struct {
	fileRec         store.FileRecord
	jobRec          store.JobRecord
	createErr       error
	validateDepth   int
	validateErr     error
	markFailedErr   error
	markFailedCalls int
}

func newDefaultMockFileStore() *mockFileStore {
	fileID := uuid.New()
	jobID := uuid.New()
	return &mockFileStore{
		fileRec: store.FileRecord{
			ID:        fileID,
			SHA256:    "", // will be overwritten by handler
			IsNew:     true,
			CreatedAt: time.Now().UTC(),
		},
		jobRec: store.JobRecord{
			ID:        jobID,
			FileID:    fileID,
			Status:    "queued",
			CreatedAt: time.Now().UTC(),
		},
	}
}

func (m *mockFileStore) CreateFileAndJob(_ context.Context, _ string, _ int64, _ string,
	_ string, _ *uuid.UUID, _ int) (store.FileRecord, store.JobRecord, error) {
	return m.fileRec, m.jobRec, m.createErr
}

func (m *mockFileStore) ValidateParentJob(_ context.Context, _ uuid.UUID) (int, error) {
	return m.validateDepth, m.validateErr
}

func (m *mockFileStore) MarkJobFailed(_ context.Context, _ uuid.UUID, _ string) error {
	m.markFailedCalls++
	return m.markFailedErr
}

// mockJobPublisher implements upload.JobPublisher for testing.
type mockJobPublisher struct {
	publishErr error
	lastMsg    queue.JobMessage
	published  bool
}

func (m *mockJobPublisher) Publish(_ context.Context, msg queue.JobMessage) error {
	m.lastMsg = msg
	m.published = true
	return m.publishErr
}

// newMultipartRequest creates a multipart HTTP request with a single file field.
func newMultipartRequest(t *testing.T, fieldName, filename, contentType string, body []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Create a part with custom content-type header if specified
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldName, filename))
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := pw.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// newMultipartRequestWithParent creates a multipart request with file and parent_job_id fields.
func newMultipartRequestWithParent(t *testing.T, filename, contentType string, body []byte, parentJobID string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Write parent_job_id text field FIRST (before file, since handler stops at file)
	if parentJobID != "" {
		fw, err := mw.CreateFormField("parent_job_id")
		if err != nil {
			t.Fatalf("create parent_job_id field: %v", err)
		}
		if _, err := fw.Write([]byte(parentJobID)); err != nil {
			t.Fatalf("write parent_job_id: %v", err)
		}
	}

	// Write file part
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, filename))
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := pw.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestHandler_ValidUpload(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	fileContent := []byte("helloworld")
	expectedHash := sha256.Sum256(fileContent)
	expectedKey := hex.EncodeToString(expectedHash[:])

	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", fileContent)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if resp["sha256"] != expectedKey {
		t.Errorf("sha256 = %q, want %q", resp["sha256"], expectedKey)
	}
	if resp["job_id"] != mockStore.jobRec.ID.String() {
		t.Errorf("job_id = %q, want %q", resp["job_id"], mockStore.jobRec.ID.String())
	}
	if resp["file_id"] != mockStore.fileRec.ID.String() {
		t.Errorf("file_id = %q, want %q", resp["file_id"], mockStore.fileRec.ID.String())
	}
	if resp["status"] != "queued" {
		t.Errorf("status = %q, want %q", resp["status"], "queued")
	}

	// Verify mock received correct data
	if mock.lastBucket != "test-bucket" {
		t.Errorf("mock bucket = %q, want %q", mock.lastBucket, "test-bucket")
	}
	if mock.lastKey != expectedKey {
		t.Errorf("mock key = %q, want %q", mock.lastKey, expectedKey)
	}
	if !bytes.Equal(mock.lastData, fileContent) {
		t.Errorf("mock data = %q, want %q", mock.lastData, fileContent)
	}

	// Verify publisher was called
	if !mockPub.published {
		t.Error("publisher was not called")
	}
	if mockPub.lastMsg.JobID != mockStore.jobRec.ID.String() {
		t.Errorf("published job_id = %q, want %q", mockPub.lastMsg.JobID, mockStore.jobRec.ID.String())
	}
}

func TestHandler_CustomContentType(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "readme.txt", "text/plain", []byte("hello"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if mock.lastCT != "text/plain" {
		t.Errorf("content-type = %q, want %q", mock.lastCT, "text/plain")
	}
}

func TestHandler_DefaultContentType(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	// Empty content-type in multipart header
	req := newMultipartRequest(t, "file", "data.bin", "", []byte("bytes"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if mock.lastCT != "application/octet-stream" {
		t.Errorf("content-type = %q, want %q", mock.lastCT, "application/octet-stream")
	}
}

func TestHandler_FileTooLarge(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 5, slog.Default()) // 5-byte limit

	req := newMultipartRequest(t, "file", "big.exe", "application/octet-stream", []byte("0123456789"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "FILE_TOO_LARGE" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "FILE_TOO_LARGE")
	}
}

func TestHandler_NoFileField(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	// Use field name "other" instead of "file"
	req := newMultipartRequest(t, "other", "test.exe", "application/octet-stream", []byte("data"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnprocessableEntity, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "NO_FILE" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "NO_FILE")
	}
}

func TestHandler_MinIOError(t *testing.T) {
	mock := &mockUploader{putErr: fmt.Errorf("connection refused")}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", []byte("data"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "STORAGE_ERROR" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "STORAGE_ERROR")
	}
}

func TestHandler_FilenameSanitization(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "../../evil.exe", "application/octet-stream", []byte("data"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	// Filename is no longer in the response (it's in DB now), but we verify upload succeeds
	if resp["sha256"] == nil {
		t.Error("expected sha256 in response")
	}
}

// === New tests for Phase 3 pipeline ===

func TestHandler_DedupSkipMinIO(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockStore.fileRec.IsNew = false // dedup hit
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", []byte("data"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// PutObject should NOT have been called
	if mock.putCalled {
		t.Error("PutObject was called, but file already exists (IsNew=false)")
	}

	// Publisher should still be called
	if !mockPub.published {
		t.Error("publisher was not called for dedup file")
	}
}

func TestHandler_MQPublishFailure(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{publishErr: fmt.Errorf("connection lost")}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", []byte("data"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusServiceUnavailable, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "QUEUE_UNAVAILABLE" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "QUEUE_UNAVAILABLE")
	}

	// MarkJobFailed should have been called
	if mockStore.markFailedCalls != 1 {
		t.Errorf("markFailedCalls = %d, want 1", mockStore.markFailedCalls)
	}
}

func TestHandler_InvalidParentJobID(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequestWithParent(t, "test.exe", "application/octet-stream", []byte("data"), "not-a-uuid")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "INVALID_REQUEST")
	}
}

func TestHandler_ParentJobNotFound(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockStore.validateErr = fmt.Errorf("parent job %s: %w", uuid.New(), store.ErrNotFound)
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	parentID := uuid.New().String()
	req := newMultipartRequestWithParent(t, "test.exe", "application/octet-stream", []byte("data"), parentID)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "INVALID_REQUEST")
	}
}

func TestHandler_ParentJobDepthExceeded(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockStore.validateErr = fmt.Errorf("maximum recursion depth (3): %w", store.ErrDepthExceeded)
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	parentID := uuid.New().String()
	req := newMultipartRequestWithParent(t, "test.exe", "application/octet-stream", []byte("data"), parentID)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "INVALID_REQUEST")
	}
}

func TestHandler_CreateRecordError(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockStore.createErr = fmt.Errorf("db connection lost")
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", []byte("data"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "INTERNAL_ERROR")
	}
}
