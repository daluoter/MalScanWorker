package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---------------------------------------------------------------------------
// Mock infrastructure
// ---------------------------------------------------------------------------

// mockRow implements pgx.Row for canned Scan results.
type mockRow struct {
	scanFn func(dest ...any) error
}

func (r *mockRow) Scan(dest ...any) error { return r.scanFn(dest...) }

// sqlCall records a SQL statement and its arguments.
type sqlCall struct {
	SQL  string
	Args []any
}

// mockTx implements pgx.Tx for unit testing.
type mockTx struct {
	pgx.Tx     // embed to satisfy interface; unused methods will panic
	calls      []sqlCall
	queryRowFn func(sql string, args ...any) pgx.Row
	execFn     func(sql string, args ...any) (pgconn.CommandTag, error)
	committed  bool
	rolledBack bool
}

func (tx *mockTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	tx.calls = append(tx.calls, sqlCall{SQL: sql, Args: args})
	if tx.queryRowFn != nil {
		return tx.queryRowFn(sql, args...)
	}
	return &mockRow{scanFn: func(dest ...any) error { return pgx.ErrNoRows }}
}

func (tx *mockTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.calls = append(tx.calls, sqlCall{SQL: sql, Args: args})
	if tx.execFn != nil {
		return tx.execFn(sql, args...)
	}
	return pgconn.NewCommandTag(""), nil
}

func (tx *mockTx) Commit(_ context.Context) error {
	tx.committed = true
	return nil
}

func (tx *mockTx) Rollback(_ context.Context) error {
	tx.rolledBack = true
	return nil
}

// mockDB implements the DB interface for unit testing.
type mockDB struct {
	tx      *mockTx
	beginFn func() (pgx.Tx, error)
	// For non-tx operations (ValidateParentJob, MarkJobFailed)
	queryRowFn func(sql string, args ...any) pgx.Row
	execFn     func(sql string, args ...any) (pgconn.CommandTag, error)
}

func (db *mockDB) Begin(_ context.Context) (pgx.Tx, error) {
	if db.beginFn != nil {
		return db.beginFn()
	}
	return db.tx, nil
}

func (db *mockDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if db.queryRowFn != nil {
		return db.queryRowFn(sql, args...)
	}
	return &mockRow{scanFn: func(dest ...any) error { return pgx.ErrNoRows }}
}

func (db *mockDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if db.execFn != nil {
		return db.execFn(sql, args...)
	}
	return pgconn.NewCommandTag(""), nil
}

func testLogger() *slog.Logger {
	return slog.Default()
}

// ---------------------------------------------------------------------------
// Test 1: CreateFileAndJob — new file
// ---------------------------------------------------------------------------
func TestCreateFileAndJob_NewFile(t *testing.T) {
	fileID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	callNum := 0
	tx := &mockTx{
		queryRowFn: func(sql string, args ...any) pgx.Row {
			callNum++
			switch {
			// First call: INSERT INTO files ... RETURNING id, created_at
			case callNum == 1 && strings.Contains(sql, "INSERT INTO files"):
				return &mockRow{scanFn: func(dest ...any) error {
					// Simulate: INSERT succeeded, row returned
					*dest[0].(*uuid.UUID) = fileID
					*dest[1].(*time.Time) = now
					return nil
				}}
			// Second call: INSERT INTO jobs ... RETURNING id, created_at
			case callNum == 2 && strings.Contains(sql, "INSERT INTO jobs"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = jobID
					*dest[1].(*time.Time) = now
					return nil
				}}
			default:
				return &mockRow{scanFn: func(dest ...any) error {
					return fmt.Errorf("unexpected SQL call #%d: %s", callNum, sql)
				}}
			}
		},
	}

	db := &mockDB{tx: tx}
	s := NewStore(db, 5, 3, testLogger())

	fRec, jRec, err := s.CreateFileAndJob(context.Background(), "abc123", 1024, "test.exe", "application/octet-stream", nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File assertions
	if fRec.ID != fileID {
		t.Errorf("file ID = %v, want %v", fRec.ID, fileID)
	}
	if fRec.SHA256 != "abc123" {
		t.Errorf("file SHA256 = %q, want %q", fRec.SHA256, "abc123")
	}
	if !fRec.IsNew {
		t.Error("expected IsNew=true for new file")
	}
	if !fRec.CreatedAt.Equal(now) {
		t.Errorf("file CreatedAt = %v, want %v", fRec.CreatedAt, now)
	}

	// Job assertions
	if jRec.ID != jobID {
		t.Errorf("job ID = %v, want %v", jRec.ID, jobID)
	}
	if jRec.FileID != fileID {
		t.Errorf("job FileID = %v, want %v", jRec.FileID, fileID)
	}
	if jRec.Status != "queued" {
		t.Errorf("job Status = %q, want %q", jRec.Status, "queued")
	}
	if !jRec.CreatedAt.Equal(now) {
		t.Errorf("job CreatedAt = %v, want %v", jRec.CreatedAt, now)
	}

	// Transaction committed
	if !tx.committed {
		t.Error("expected transaction to be committed")
	}
}

// ---------------------------------------------------------------------------
// Test 2: CreateFileAndJob — duplicate file (dedup hit)
// ---------------------------------------------------------------------------
func TestCreateFileAndJob_DuplicateFile(t *testing.T) {
	existingFileID := uuid.New()
	jobID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	callNum := 0
	tx := &mockTx{
		queryRowFn: func(sql string, args ...any) pgx.Row {
			callNum++
			switch {
			// INSERT INTO files returns no rows (ON CONFLICT DO NOTHING)
			case callNum == 1 && strings.Contains(sql, "INSERT INTO files"):
				return &mockRow{scanFn: func(dest ...any) error {
					return pgx.ErrNoRows
				}}
			// Fallback SELECT to get existing file
			case callNum == 2 && strings.Contains(sql, "SELECT") && strings.Contains(sql, "files"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = existingFileID
					*dest[1].(*time.Time) = now
					return nil
				}}
			// INSERT INTO jobs
			case callNum == 3 && strings.Contains(sql, "INSERT INTO jobs"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = jobID
					*dest[1].(*time.Time) = now
					return nil
				}}
			default:
				return &mockRow{scanFn: func(dest ...any) error {
					return fmt.Errorf("unexpected SQL call #%d: %s", callNum, sql)
				}}
			}
		},
	}

	db := &mockDB{tx: tx}
	s := NewStore(db, 5, 3, testLogger())

	fRec, jRec, err := s.CreateFileAndJob(context.Background(), "abc123", 1024, "test.exe", "application/octet-stream", nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File assertions — reused existing
	if fRec.ID != existingFileID {
		t.Errorf("file ID = %v, want %v", fRec.ID, existingFileID)
	}
	if fRec.IsNew {
		t.Error("expected IsNew=false for duplicate file")
	}

	// Job created
	if jRec.ID != jobID {
		t.Errorf("job ID = %v, want %v", jRec.ID, jobID)
	}
	if jRec.FileID != existingFileID {
		t.Errorf("job FileID = %v, want %v", jRec.FileID, existingFileID)
	}
}

// ---------------------------------------------------------------------------
// Test 3: CreateFileAndJob — atomic rollback on job insert failure
// ---------------------------------------------------------------------------
func TestCreateFileAndJob_AtomicRollback(t *testing.T) {
	fileID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	callNum := 0
	tx := &mockTx{
		queryRowFn: func(sql string, args ...any) pgx.Row {
			callNum++
			switch {
			// File insert succeeds
			case callNum == 1 && strings.Contains(sql, "INSERT INTO files"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = fileID
					*dest[1].(*time.Time) = now
					return nil
				}}
			// Job insert fails
			case callNum == 2 && strings.Contains(sql, "INSERT INTO jobs"):
				return &mockRow{scanFn: func(dest ...any) error {
					return errors.New("unique constraint violation")
				}}
			default:
				return &mockRow{scanFn: func(dest ...any) error {
					return fmt.Errorf("unexpected SQL call #%d: %s", callNum, sql)
				}}
			}
		},
	}

	db := &mockDB{tx: tx}
	s := NewStore(db, 5, 3, testLogger())

	_, _, err := s.CreateFileAndJob(context.Background(), "abc123", 1024, "test.exe", "application/octet-stream", nil, 0)
	if err == nil {
		t.Fatal("expected error from job insert failure")
	}

	// Transaction must NOT have been committed
	if tx.committed {
		t.Error("transaction should not be committed when job insert fails")
	}
}

// ---------------------------------------------------------------------------
// Test 4: CreateFileAndJob — concurrent dedup (two goroutines, same SHA256)
// ---------------------------------------------------------------------------
func TestCreateFileAndJob_ConcurrentDedup(t *testing.T) {
	existingFileID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Both goroutines get ON CONFLICT DO NOTHING (no rows from INSERT),
	// then both fall back to SELECT and get the same existing file.
	makeTx := func(jobID uuid.UUID) *mockTx {
		callNum := 0
		return &mockTx{
			queryRowFn: func(sql string, args ...any) pgx.Row {
				callNum++
				switch {
				case callNum == 1 && strings.Contains(sql, "INSERT INTO files"):
					// ON CONFLICT DO NOTHING — no row returned
					return &mockRow{scanFn: func(dest ...any) error {
						return pgx.ErrNoRows
					}}
				case callNum == 2 && strings.Contains(sql, "SELECT") && strings.Contains(sql, "files"):
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*uuid.UUID) = existingFileID
						*dest[1].(*time.Time) = now
						return nil
					}}
				case callNum == 3 && strings.Contains(sql, "INSERT INTO jobs"):
					return &mockRow{scanFn: func(dest ...any) error {
						*dest[0].(*uuid.UUID) = jobID
						*dest[1].(*time.Time) = now
						return nil
					}}
				default:
					return &mockRow{scanFn: func(dest ...any) error {
						return fmt.Errorf("unexpected SQL call #%d: %s", callNum, sql)
					}}
				}
			},
		}
	}

	jobID1 := uuid.New()
	jobID2 := uuid.New()
	tx1 := makeTx(jobID1)
	tx2 := makeTx(jobID2)

	txIdx := 0
	var mu sync.Mutex
	txes := []*mockTx{tx1, tx2}

	db := &mockDB{
		beginFn: func() (pgx.Tx, error) {
			mu.Lock()
			defer mu.Unlock()
			tx := txes[txIdx]
			txIdx++
			return tx, nil
		},
	}

	s := NewStore(db, 5, 3, testLogger())

	var wg sync.WaitGroup
	errs := make([]error, 2)
	fRecs := make([]FileRecord, 2)
	jRecs := make([]JobRecord, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fRecs[idx], jRecs[idx], errs[idx] = s.CreateFileAndJob(
				context.Background(), "same-sha256", 1024, "test.exe", "application/octet-stream", nil, 0,
			)
		}(i)
	}
	wg.Wait()

	// Both succeed
	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, errs[i])
		}
	}

	// Both reference the same file
	if fRecs[0].ID != existingFileID || fRecs[1].ID != existingFileID {
		t.Errorf("both goroutines should reference same file ID %v, got %v and %v",
			existingFileID, fRecs[0].ID, fRecs[1].ID)
	}

	// Each got its own job
	if jRecs[0].ID == jRecs[1].ID {
		t.Error("each goroutine should have a distinct job ID")
	}
}

// ---------------------------------------------------------------------------
// Test 5: ValidateParentJob — valid parent
// ---------------------------------------------------------------------------
func TestValidateParentJob_ValidParent(t *testing.T) {
	parentID := uuid.New()

	db := &mockDB{
		queryRowFn: func(sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "SELECT") && strings.Contains(sql, "depth") {
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int) = 1 // parent depth = 1
					return nil
				}}
			}
			return &mockRow{scanFn: func(dest ...any) error { return pgx.ErrNoRows }}
		},
	}

	s := NewStore(db, 5, 3, testLogger())

	depth, err := s.ValidateParentJob(context.Background(), parentID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if depth != 1 {
		t.Errorf("depth = %d, want 1 (parent depth returned, caller adds +1)", depth)
	}
}

// ---------------------------------------------------------------------------
// Test 6: ValidateParentJob — parent not found
// ---------------------------------------------------------------------------
func TestValidateParentJob_NotFound(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(sql string, args ...any) pgx.Row {
			return &mockRow{scanFn: func(dest ...any) error {
				return pgx.ErrNoRows
			}}
		},
	}

	s := NewStore(db, 5, 3, testLogger())

	_, err := s.ValidateParentJob(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent parent job")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("error should wrap ErrNotFound, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 7: ValidateParentJob — depth exceeded
// ---------------------------------------------------------------------------
func TestValidateParentJob_DepthExceeded(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(sql string, args ...any) pgx.Row {
			return &mockRow{scanFn: func(dest ...any) error {
				*dest[0].(*int) = 3 // at maxDepth
				return nil
			}}
		},
	}

	s := NewStore(db, 5, 3, testLogger()) // maxDepth=3

	_, err := s.ValidateParentJob(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when parent depth >= maxDepth")
	}
	if !errors.Is(err, ErrDepthExceeded) {
		t.Errorf("error should wrap ErrDepthExceeded, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 8: MarkJobFailed
// ---------------------------------------------------------------------------
func TestMarkJobFailed(t *testing.T) {
	jobID := uuid.New()
	var capturedSQL string
	var capturedArgs []any

	db := &mockDB{
		execFn: func(sql string, args ...any) (pgconn.CommandTag, error) {
			capturedSQL = sql
			capturedArgs = args
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	s := NewStore(db, 5, 3, testLogger())

	err := s.MarkJobFailed(context.Background(), jobID, "something broke")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the SQL is an UPDATE on jobs
	if !strings.Contains(capturedSQL, "UPDATE") || !strings.Contains(capturedSQL, "jobs") {
		t.Errorf("expected UPDATE on jobs table, got SQL: %s", capturedSQL)
	}
	if !strings.Contains(capturedSQL, "failed") && !containsArg(capturedArgs, "failed") {
		t.Error("expected 'failed' in SQL or args")
	}
	if !containsArg(capturedArgs, "something broke") {
		t.Errorf("expected error message in args, got: %v", capturedArgs)
	}
	if !containsArg(capturedArgs, jobID) {
		t.Errorf("expected job ID in args, got: %v", capturedArgs)
	}
}

func containsArg(args []any, target any) bool {
	for _, a := range args {
		if fmt.Sprintf("%v", a) == fmt.Sprintf("%v", target) {
			return true
		}
	}
	return false
}
