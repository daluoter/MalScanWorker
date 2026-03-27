# Phase 2: Discussion Log

## Session: File Streaming & Storage

### Gray Areas Identified
1. Package layout — where upload handler code lives
2. Error response format — envelope structure for frontend
3. Chunk size & temp file strategy
4. MinIO upload approach — temp file vs streaming
5. Content-type detection strategy

### Decisions Made

**Package Layout**
- Q: Where should upload handler code live?
- A: `ingest/internal/upload/` — dedicated package with handler.go, sanitize.go, errors.go

**Error Response Format**
- Q: Error envelope structure?
- A: Match Python exactly: `{"error": {"code": "...", "message": "...", "details": {...}}}` — frontend expects this

**Chunk Size**
- Q: Streaming chunk size?
- A: 1MB matching Python's CHUNK_SIZE — proven, consistent behavior

**Temp File Strategy**
- Q: Where to write temp files?
- A: `os.CreateTemp` in system /tmp — matches Python's `tempfile.mkstemp()`

**MinIO Upload**
- Q: PutObject from temp file or streaming PutObject?
- A: PutObject from temp file after hashing — SHA256 known before upload, matches Python flow

**Content-Type**
- Q: How to determine content-type for MinIO metadata?
- A: Use multipart header as-is — matches Python behavior, simple

### Deferred Ideas
- Content-type detection/sniffing (not needed — Python doesn't do it)
- Configurable TEMP_DIR or CHUNK_SIZE env vars (unnecessary complexity for now)
- In-memory buffer with spillover (premature optimization)
