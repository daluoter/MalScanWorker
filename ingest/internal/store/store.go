package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel errors for caller inspection.
var (
	ErrNotFound      = errors.New("not found")
	ErrDepthExceeded = errors.New("depth exceeded")
)

// DB is the minimal interface for pgxpool operations (for testability).
// *pgxpool.Pool satisfies this interface natively.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// FileRecord holds the result of a file insert/lookup.
type FileRecord struct {
	ID        uuid.UUID
	SHA256    string
	IsNew     bool // true if newly created, false if dedup hit
	CreatedAt time.Time
}

// JobRecord holds the result of a job insert.
type JobRecord struct {
	ID        uuid.UUID
	FileID    uuid.UUID
	Status    string
	CreatedAt time.Time
}

// Store handles all database operations for the upload pipeline.
type Store struct {
	db          DB
	stagesTotal int
	maxDepth    int
	logger      *slog.Logger
}

// NewStore creates a Store with the given dependencies.
func NewStore(db DB, stagesTotal int, maxDepth int, logger *slog.Logger) *Store {
	return &Store{
		db:          db,
		stagesTotal: stagesTotal,
		maxDepth:    maxDepth,
		logger:      logger,
	}
}

// CreateFileAndJob atomically inserts a file (with SHA256 dedup) and a job
// within a single transaction. If the file's SHA256 already exists, it reuses
// the existing file record (IsNew=false). Returns both records or an error.
func (s *Store) CreateFileAndJob(
	ctx context.Context,
	sha256 string,
	size int64,
	filename, contentType string,
	parentJobID *uuid.UUID,
	depth int,
) (FileRecord, JobRecord, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return FileRecord{}, JobRecord{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is safe

	// --- File upsert with concurrent-safe dedup ---
	now := time.Now().UTC()
	fileID := uuid.New()
	var fRec FileRecord
	fRec.SHA256 = sha256

	err = tx.QueryRow(ctx,
		`INSERT INTO files (id, sha256, size, filename, content_type, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (sha256) DO NOTHING
		 RETURNING id, created_at`,
		fileID, sha256, size, filename, contentType, now,
	).Scan(&fRec.ID, &fRec.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// Dedup hit: row already existed, SELECT it.
		err = tx.QueryRow(ctx,
			`SELECT id, created_at FROM files WHERE sha256 = $1`,
			sha256,
		).Scan(&fRec.ID, &fRec.CreatedAt)
		if err != nil {
			return FileRecord{}, JobRecord{}, fmt.Errorf("select existing file: %w", err)
		}
		fRec.IsNew = false
	} else if err != nil {
		return FileRecord{}, JobRecord{}, fmt.Errorf("insert file: %w", err)
	} else {
		fRec.IsNew = true
	}

	// --- Job insert ---
	jobID := uuid.New()
	var jRec JobRecord

	err = tx.QueryRow(ctx,
		`INSERT INTO jobs (id, file_id, status, stages_total, parent_job_id, depth,
		                    stages_done, total_sub, completed_sub, malicious_sub,
		                    created_at, updated_at)
		 VALUES ($1, $2, 'queued', $3, $4, $5, 0, 0, 0, 0, $6, $7)
		 RETURNING id, created_at`,
		jobID, fRec.ID, s.stagesTotal, parentJobID, depth, now, now,
	).Scan(&jRec.ID, &jRec.CreatedAt)
	if err != nil {
		return FileRecord{}, JobRecord{}, fmt.Errorf("insert job: %w", err)
	}
	jRec.FileID = fRec.ID
	jRec.Status = "queued"

	if err := tx.Commit(ctx); err != nil {
		return FileRecord{}, JobRecord{}, fmt.Errorf("commit tx: %w", err)
	}

	return fRec, jRec, nil
}

// ValidateParentJob checks that a parent job exists and its depth is within
// the configured maximum. Returns the parent's depth (caller adds +1 for the
// child). Returns an error if the parent is not found or depth is exceeded.
func (s *Store) ValidateParentJob(ctx context.Context, parentJobID uuid.UUID) (int, error) {
	var depth int
	err := s.db.QueryRow(ctx,
		`SELECT depth FROM jobs WHERE id = $1`,
		parentJobID,
	).Scan(&depth)

	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("parent job %s: %w", parentJobID, ErrNotFound)
	}
	if err != nil {
		return 0, fmt.Errorf("query parent job: %w", err)
	}

	if depth >= s.maxDepth {
		return 0, fmt.Errorf("maximum recursion depth (%d): %w", s.maxDepth, ErrDepthExceeded)
	}

	return depth, nil
}

// MarkJobFailed sets a job's status to "failed" with the given error message.
func (s *Store) MarkJobFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	ct, err := s.db.Exec(ctx,
		`UPDATE jobs SET status = 'failed', error_message = $1, updated_at = $2 WHERE id = $3`,
		errMsg, time.Now().UTC(), jobID,
	)
	if err != nil {
		return fmt.Errorf("mark job failed: %w", err)
	}
	if ct.RowsAffected() == 0 {
		s.logger.Warn("mark_job_failed_no_rows", "job_id", jobID.String())
	}
	return nil
}
