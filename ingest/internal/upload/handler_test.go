package upload_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
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
	statErr        error
	putErr         error
	lastStatBucket string
	lastStatKey    string
	lastBucket     string
	lastKey        string
	lastData       []byte
	lastSize       int64
	lastCT         string
	statCalled     bool
	statCalls      int
	putCalled      bool
	putCalls       int
	events         *[]string
}

func (m *mockUploader) StatObject(_ context.Context, bucket, key string, _ minio.StatObjectOptions) (minio.ObjectInfo, error) {
	m.statCalled = true
	m.statCalls++
	m.lastStatBucket = bucket
	m.lastStatKey = key
	if m.events != nil {
		*m.events = append(*m.events, "stat")
	}
	return minio.ObjectInfo{}, m.statErr
}

func (m *mockUploader) PutObject(_ context.Context, bucket, key string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	m.putCalled = true
	m.putCalls++
	m.lastBucket = bucket
	m.lastKey = key
	m.lastSize = size
	m.lastData, _ = io.ReadAll(reader)
	m.lastCT = opts.ContentType
	if m.events != nil {
		*m.events = append(*m.events, "put")
	}
	return minio.UploadInfo{}, m.putErr
}

// mockFileStore implements upload.FileStore for testing.
type mockFileStore struct {
	fileRec          store.FileRecord
	jobRec           store.JobRecord
	createErr        error
	validateDepth    int
	validateErr      error
	markFailedErr    error
	markFailedCalls  int
	markFailedJobID  uuid.UUID
	markFailedReason string
	markFailed       func(context.Context, uuid.UUID, string)
	createCalls      int
	events           *[]string
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
	m.createCalls++
	if m.events != nil {
		*m.events = append(*m.events, "create")
	}
	return m.fileRec, m.jobRec, m.createErr
}

func (m *mockFileStore) ValidateParentJob(_ context.Context, _ uuid.UUID) (int, error) {
	return m.validateDepth, m.validateErr
}

func (m *mockFileStore) MarkJobFailed(ctx context.Context, jobID uuid.UUID, reason string) error {
	m.markFailedCalls++
	m.markFailedJobID = jobID
	m.markFailedReason = reason
	if m.events != nil {
		*m.events = append(*m.events, "mark_failed")
	}
	if m.markFailed != nil {
		m.markFailed(ctx, jobID, reason)
	}
	return m.markFailedErr
}

// mockJobPublisher implements upload.JobPublisher for testing.
type mockJobPublisher struct {
	publishErr error
	lastMsg    queue.JobMessage
	published  bool
	events     *[]string
}

func (m *mockJobPublisher) Publish(_ context.Context, msg queue.JobMessage) error {
	m.lastMsg = msg
	m.published = true
	if m.events != nil {
		*m.events = append(*m.events, "publish")
	}
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

const lifecycleUploadContent = "sha256-addressed lifecycle test content"

func runLifecycleUpload(t *testing.T, isNew bool, statErr, putErr error) (*httptest.ResponseRecorder, *mockUploader, *mockFileStore, *mockJobPublisher, []string) {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	events := []string{}
	uploader := &mockUploader{statErr: statErr, putErr: putErr, events: &events}
	fileStore := newDefaultMockFileStore()
	fileStore.fileRec.IsNew = isNew
	fileStore.events = &events
	publisher := &mockJobPublisher{events: &events}
	h := upload.NewHandler(uploader, fileStore, publisher, "test-bucket", 100*1024*1024, slog.Default())

	req := newMultipartRequest(t, "file", "lifecycle.bin", "application/x-lifecycle-test", []byte(lifecycleUploadContent))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temporary upload files remain after request: %v", entries)
	}
	return w, uploader, fileStore, publisher, events
}

func assertEventOrder(t *testing.T, got, want []string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("invocation order = %v, want %v", got, want)
	}
}

func assertStorageErrorResponse(t *testing.T, w *httptest.ResponseRecorder, storageErr error) {
	t.Helper()
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("response schema = %v, want only the error envelope", resp)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok || errObj["code"] != "STORAGE_ERROR" {
		t.Fatalf("error.code = %v, want STORAGE_ERROR", resp["error"])
	}
	if got, want := errObj["message"], "Failed to store file: "+storageErr.Error(); got != want {
		t.Errorf("error.message = %v, want original storage message %q", got, want)
	}
	if len(errObj) != 2 {
		t.Errorf("error schema = %v, want only code and message", errObj)
	}
}

func assertJobFailureMarked(t *testing.T, fileStore *mockFileStore, wantReason string) {
	t.Helper()
	if fileStore.markFailedCalls != 1 {
		t.Fatalf("MarkJobFailed calls = %d, want exactly 1", fileStore.markFailedCalls)
	}
	if fileStore.markFailedJobID != fileStore.jobRec.ID {
		t.Errorf("MarkJobFailed job ID = %s, want created job ID %s", fileStore.markFailedJobID, fileStore.jobRec.ID)
	}
	if fileStore.markFailedReason != wantReason {
		t.Errorf("MarkJobFailed reason = %q, want %q", fileStore.markFailedReason, wantReason)
	}
}

type cleanupContextValueKey struct{}

const cleanupContextTestTimeout = 5 * time.Second

func assertCleanupContextAtCall(t *testing.T, ctx context.Context, wantValue string) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Errorf("MarkJobFailed context err = %v, want nil while cleanup runs", err)
	}
	select {
	case <-ctx.Done():
		t.Error("MarkJobFailed context Done is already closed while cleanup runs")
	default:
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("MarkJobFailed context has no bounded deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > cleanupContextTestTimeout {
		t.Errorf("MarkJobFailed context deadline is %s away, want within %s", remaining, cleanupContextTestTimeout)
	}
	if got := ctx.Value(cleanupContextValueKey{}); got != wantValue {
		t.Errorf("MarkJobFailed context value = %v, want %q", got, wantValue)
	}
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

	// Unmarshal into typed UploadResponse (not map[string]any)
	var resp upload.UploadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse UploadResponse: %v", err)
	}

	if resp.SHA256 != expectedKey {
		t.Errorf("sha256 = %q, want %q", resp.SHA256, expectedKey)
	}
	if resp.JobID != mockStore.jobRec.ID.String() {
		t.Errorf("job_id = %q, want %q", resp.JobID, mockStore.jobRec.ID.String())
	}
	if resp.FileID != mockStore.fileRec.ID.String() {
		t.Errorf("file_id = %q, want %q", resp.FileID, mockStore.fileRec.ID.String())
	}
	if resp.Status != "queued" {
		t.Errorf("status = %q, want %q", resp.Status, "queued")
	}
	if resp.CreatedAt == "" {
		t.Error("created_at is empty")
	}

	// Verify created_at is parseable as ISO 8601 with timezone
	_, parseErr := time.Parse("2006-01-02T15:04:05.999999+00:00", resp.CreatedAt)
	if parseErr != nil {
		// Try RFC3339 fallback for compatibility
		_, parseErr = time.Parse(time.RFC3339, resp.CreatedAt)
		if parseErr != nil {
			t.Errorf("created_at %q is not valid ISO 8601: %v", resp.CreatedAt, parseErr)
		}
	}

	// Verify JSON field names match Python UploadResponse exactly
	var rawResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rawResp); err != nil {
		t.Fatalf("parse raw response: %v", err)
	}
	for _, field := range []string{"job_id", "file_id", "sha256", "status", "created_at"} {
		if _, ok := rawResp[field]; !ok {
			t.Errorf("response missing expected field %q", field)
		}
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

func TestHandler_NewFileSkipsStatAndPublishesAfterPut(t *testing.T) {
	w, uploader, fileStore, publisher, events := runLifecycleUpload(t, true, nil, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if uploader.statCalls != 0 {
		t.Errorf("StatObject calls = %d, want 0 for a new file", uploader.statCalls)
	}
	if uploader.putCalls != 1 || !publisher.published {
		t.Errorf("PutObject calls = %d and published = %t, want one PutObject then one publish", uploader.putCalls, publisher.published)
	}
	assertEventOrder(t, events, []string{"create", "put", "publish"})
	assertUploadedContent(t, uploader, publisher, fileStore)
}

func TestHandler_DedupSkipMinIO(t *testing.T) {
	w, uploader, fileStore, publisher, events := runLifecycleUpload(t, false, nil, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if uploader.statCalls != 1 || uploader.lastStatBucket != "test-bucket" {
		t.Errorf("StatObject calls/bucket = %d/%q, want one stat in test-bucket", uploader.statCalls, uploader.lastStatBucket)
	}
	if uploader.lastStatKey != expectedLifecycleHash() {
		t.Errorf("StatObject key = %q, want sha256 %q", uploader.lastStatKey, expectedLifecycleHash())
	}
	if uploader.putCalls != 0 {
		t.Errorf("PutObject calls = %d, want 0 while the deduplicated object exists", uploader.putCalls)
	}
	if !publisher.published {
		t.Error("publisher was not called for dedup file")
	}
	assertEventOrder(t, events, []string{"create", "stat", "publish"})
	if publisher.lastMsg.FileID != fileStore.fileRec.ID.String() || fileStore.createCalls != 1 {
		t.Errorf("dedup publish used file_id %q after %d record creations; want existing file_id %q and one creation", publisher.lastMsg.FileID, fileStore.createCalls, fileStore.fileRec.ID)
	}
}

func TestHandler_DedupRestoresMissingObjects(t *testing.T) {
	for _, code := range []string{minio.NoSuchKey, "NoSuchObject", "NotFound"} {
		t.Run(code, func(t *testing.T) {
			missingErr := minio.ErrorResponse{Code: code, StatusCode: http.StatusNotFound}
			w, uploader, fileStore, publisher, events := runLifecycleUpload(t, false, fmt.Errorf("stat object: %w", missingErr), nil)
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
			}
			if uploader.statCalls != 1 || uploader.putCalls != 1 || !publisher.published {
				t.Fatalf("stat/put/publish = %d/%d/%t, want 1/1/true", uploader.statCalls, uploader.putCalls, publisher.published)
			}
			assertEventOrder(t, events, []string{"create", "stat", "put", "publish"})
			assertUploadedContent(t, uploader, publisher, fileStore)
		})
	}
}

func TestHandler_DedupStatErrorsDoNotUploadOrPublish(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "network", err: errors.New("connection timeout")},
		{name: "permission", err: minio.ErrorResponse{Code: minio.AccessDenied, StatusCode: http.StatusForbidden}},
		{name: "server", err: minio.ErrorResponse{Code: "ServiceUnavailable", StatusCode: http.StatusServiceUnavailable}},
		{name: "missing bucket", err: minio.ErrorResponse{Code: minio.NoSuchBucket, StatusCode: http.StatusNotFound}},
		{name: "bare typed 404", err: minio.ErrorResponse{StatusCode: http.StatusNotFound}},
		{name: "plain 404 error", err: errors.New("404 Not Found")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, uploader, fileStore, publisher, events := runLifecycleUpload(t, false, tc.err, nil)
			assertStorageErrorResponse(t, w, tc.err)
			if uploader.statCalls != 1 || uploader.putCalls != 0 || publisher.published {
				t.Errorf("stat/put/published = %d/%d/%t, want 1/0/false", uploader.statCalls, uploader.putCalls, publisher.published)
			}
			assertEventOrder(t, events, []string{"create", "stat", "mark_failed"})
			assertJobFailureMarked(t, fileStore, "storage stat failed: "+tc.err.Error())
		})
	}
}

func TestHandler_DedupRepairPutFailureDoesNotPublish(t *testing.T) {
	missingErr := minio.ErrorResponse{Code: minio.NoSuchKey, StatusCode: http.StatusNotFound}
	storageErr := errors.New("put failed")
	w, uploader, fileStore, publisher, events := runLifecycleUpload(t, false, missingErr, storageErr)
	assertStorageErrorResponse(t, w, storageErr)
	if uploader.statCalls != 1 || uploader.putCalls != 1 || publisher.published {
		t.Errorf("stat/put/published = %d/%d/%t, want 1/1/false", uploader.statCalls, uploader.putCalls, publisher.published)
	}
	assertEventOrder(t, events, []string{"create", "stat", "put", "mark_failed"})
	assertJobFailureMarked(t, fileStore, "storage repair put failed: "+storageErr.Error())
}

func TestHandler_StorageFailuresUseDetachedCleanupContext(t *testing.T) {
	missingErr := minio.ErrorResponse{Code: minio.NoSuchKey, StatusCode: http.StatusNotFound}
	cases := []struct {
		name       string
		isNew      bool
		statErr    error
		putErr     error
		failureErr error
		reason     string
		wantEvents []string
		wantStats  int
		wantPuts   int
	}{
		{
			name:       "stat",
			statErr:    errors.New("stat unavailable"),
			failureErr: errors.New("stat unavailable"),
			reason:     "storage stat failed: stat unavailable",
			wantEvents: []string{"create", "stat", "mark_failed"},
			wantStats:  1,
		},
		{
			name:       "new put",
			isNew:      true,
			putErr:     errors.New("upload unavailable"),
			failureErr: errors.New("upload unavailable"),
			reason:     "storage put failed: upload unavailable",
			wantEvents: []string{"create", "put", "mark_failed"},
			wantPuts:   1,
		},
		{
			name:       "repair put",
			statErr:    missingErr,
			putErr:     errors.New("repair unavailable"),
			failureErr: errors.New("repair unavailable"),
			reason:     "storage repair put failed: repair unavailable",
			wantEvents: []string{"create", "stat", "put", "mark_failed"},
			wantStats:  1,
			wantPuts:   1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("TMPDIR", tempDir)

			marker := "trace-" + tc.name
			events := []string{}
			uploader := &mockUploader{statErr: tc.statErr, putErr: tc.putErr, events: &events}
			fileStore := newDefaultMockFileStore()
			fileStore.fileRec.IsNew = tc.isNew
			fileStore.events = &events
			var cleanupCtx context.Context
			fileStore.markFailed = func(ctx context.Context, _ uuid.UUID, _ string) {
				cleanupCtx = ctx
				assertCleanupContextAtCall(t, ctx, marker)
			}
			publisher := &mockJobPublisher{events: &events}
			h := upload.NewHandler(uploader, fileStore, publisher, "test-bucket", 100*1024*1024, slog.Default())

			req := newMultipartRequest(t, "file", "storage-failure.bin", "application/octet-stream", []byte(lifecycleUploadContent))
			requestCtx, cancelRequest := context.WithCancel(context.WithValue(req.Context(), cleanupContextValueKey{}, marker))
			cancelRequest()
			req = req.WithContext(requestCtx)
			if requestCtx.Err() != context.Canceled {
				t.Fatalf("request context err = %v, want canceled before handler", requestCtx.Err())
			}

			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			assertStorageErrorResponse(t, w, tc.failureErr)
			assertJobFailureMarked(t, fileStore, tc.reason)
			assertEventOrder(t, events, tc.wantEvents)
			if uploader.statCalls != tc.wantStats || uploader.putCalls != tc.wantPuts || publisher.published {
				t.Errorf("stat/put/published = %d/%d/%t, want %d/%d/false", uploader.statCalls, uploader.putCalls, publisher.published, tc.wantStats, tc.wantPuts)
			}
			if cleanupCtx == nil {
				t.Fatal("MarkJobFailed did not receive a cleanup context")
			}
			if err := cleanupCtx.Err(); err != context.Canceled {
				t.Errorf("cleanup context err after helper returned = %v, want context.Canceled", err)
			}
		})
	}
}

func TestHandler_NewFilePutFailureMarksJobFailedAndPreservesStorageResponse(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	storageErr := errors.New("object upload failed")
	markErr := errors.New("database unavailable")
	events := []string{}
	uploader := &mockUploader{putErr: storageErr, events: &events}
	fileStore := newDefaultMockFileStore()
	fileStore.markFailedErr = markErr
	fileStore.events = &events
	publisher := &mockJobPublisher{events: &events}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	h := upload.NewHandler(uploader, fileStore, publisher, "test-bucket", 100*1024*1024, logger)

	req := newMultipartRequest(t, "file", "storage-failure.bin", "application/octet-stream", []byte(lifecycleUploadContent))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assertStorageErrorResponse(t, w, storageErr)
	if strings.Contains(w.Body.String(), markErr.Error()) {
		t.Errorf("response contains MarkJobFailed error, want original storage error only: %s", w.Body.String())
	}
	if uploader.statCalls != 0 || uploader.putCalls != 1 || publisher.published {
		t.Errorf("stat/put/published = %d/%d/%t, want 0/1/false", uploader.statCalls, uploader.putCalls, publisher.published)
	}
	assertEventOrder(t, events, []string{"create", "put", "mark_failed"})
	assertJobFailureMarked(t, fileStore, "storage put failed: "+storageErr.Error())
	if !strings.Contains(logOutput.String(), "failed to mark job as failed") ||
		!strings.Contains(logOutput.String(), fileStore.jobRec.ID.String()) ||
		!strings.Contains(logOutput.String(), markErr.Error()) {
		t.Errorf("MarkJobFailed failure log lacks message, job context, or error: %s", logOutput.String())
	}
}

func expectedLifecycleHash() string {
	sum := sha256.Sum256([]byte(lifecycleUploadContent))
	return hex.EncodeToString(sum[:])
}

func assertUploadedContent(t *testing.T, uploader *mockUploader, publisher *mockJobPublisher, fileStore *mockFileStore) {
	t.Helper()
	expectedHash := expectedLifecycleHash()
	if uploader.lastBucket != "test-bucket" || uploader.lastKey != expectedHash {
		t.Errorf("PutObject bucket/key = %q/%q, want test-bucket/%q", uploader.lastBucket, uploader.lastKey, expectedHash)
	}
	if uploader.lastSize != int64(len(lifecycleUploadContent)) {
		t.Errorf("PutObject size = %d, want %d", uploader.lastSize, len(lifecycleUploadContent))
	}
	if uploader.lastCT != "application/x-lifecycle-test" {
		t.Errorf("PutObject content-type = %q, want application/x-lifecycle-test", uploader.lastCT)
	}
	if !bytes.Equal(uploader.lastData, []byte(lifecycleUploadContent)) {
		t.Errorf("PutObject body = %q, want original upload bytes", uploader.lastData)
	}
	if publisher.lastMsg.FileID != fileStore.fileRec.ID.String() || fileStore.createCalls != 1 {
		t.Errorf("publish used file_id %q after %d record creations; want existing file_id %q and one creation", publisher.lastMsg.FileID, fileStore.createCalls, fileStore.fileRec.ID)
	}
	if publisher.lastMsg.SHA256 != expectedHash || publisher.lastMsg.StorageKey != expectedHash {
		t.Errorf("published SHA/storage key = %q/%q, want %q", publisher.lastMsg.SHA256, publisher.lastMsg.StorageKey, expectedHash)
	}
}

func TestHandler_MQPublishFailure(t *testing.T) {
	mock := &mockUploader{}
	publishErr := errors.New("connection lost")
	markErr := errors.New("database unavailable")
	mockStore := newDefaultMockFileStore()
	mockStore.markFailedErr = markErr
	marker := "mq-trace"
	var cleanupCtx context.Context
	mockStore.markFailed = func(ctx context.Context, _ uuid.UUID, _ string) {
		cleanupCtx = ctx
		assertCleanupContextAtCall(t, ctx, marker)
	}
	mockPub := &mockJobPublisher{publishErr: publishErr}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, logger)

	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", []byte("data"))
	requestCtx, cancelRequest := context.WithCancel(context.WithValue(req.Context(), cleanupContextValueKey{}, marker))
	cancelRequest()
	req = req.WithContext(requestCtx)
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
	if errObj["code"] != "QUEUE_PUBLISH_FAILED" || errObj["message"] != "Failed to submit job to processing queue. Please try again." {
		t.Errorf("queue error = %v, want unchanged QUEUE_PUBLISH_FAILED response", errObj)
	}
	if strings.Contains(w.Body.String(), markErr.Error()) {
		t.Errorf("response contains MarkJobFailed error, want original queue error only: %s", w.Body.String())
	}
	if !mockPub.published {
		t.Error("publisher was not called")
	}
	assertJobFailureMarked(t, mockStore, "publish failed: "+publishErr.Error())
	if cleanupCtx == nil {
		t.Fatal("MarkJobFailed did not receive a cleanup context")
	}
	if err := cleanupCtx.Err(); err != context.Canceled {
		t.Errorf("cleanup context err after helper returned = %v, want context.Canceled", err)
	}
	if !strings.Contains(logOutput.String(), "failed to mark job as failed") ||
		!strings.Contains(logOutput.String(), mockStore.jobRec.ID.String()) ||
		!strings.Contains(logOutput.String(), markErr.Error()) {
		t.Errorf("MarkJobFailed failure log lacks message, job context, or error: %s", logOutput.String())
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

func TestHandler_MaxBytesError(t *testing.T) {
	mock := &mockUploader{}
	mockStore := newDefaultMockFileStore()
	mockPub := &mockJobPublisher{}
	h := upload.NewHandler(mock, mockStore, mockPub, "test-bucket", 100*1024*1024, slog.Default())

	// Create a multipart request with a large-ish body
	fileContent := bytes.Repeat([]byte("A"), 100)
	req := newMultipartRequest(t, "file", "test.exe", "application/octet-stream", fileContent)

	// Wrap the request body with http.MaxBytesReader to simulate the server's
	// 150MB limit being exceeded. Use a tiny limit (10 bytes) so the multipart
	// reading triggers MaxBytesError.
	w := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(w, req.Body, 10)

	h.ServeHTTP(w, req)

	// Should return 400 with FILE_TOO_LARGE in JSON envelope
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v; body: %s", err, w.Body.String())
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("response missing 'error' envelope, got: %v", resp)
	}
	if errObj["code"] != "FILE_TOO_LARGE" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "FILE_TOO_LARGE")
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
	if mockStore.markFailedCalls != 0 {
		t.Errorf("MarkJobFailed calls = %d, want 0 when record creation fails", mockStore.markFailedCalls)
	}
	if mock.statCalls != 0 || mock.putCalls != 0 || mockPub.published {
		t.Errorf("storage stat/put/published = %d/%d/%t, want 0/0/false after record creation failure", mock.statCalls, mock.putCalls, mockPub.published)
	}
}
