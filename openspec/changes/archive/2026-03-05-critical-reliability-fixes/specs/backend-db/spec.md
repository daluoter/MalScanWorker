## MODIFIED Requirements

### Requirement: Job Status Data
Job status queries MUST reflect the current state from the database. The SSE streaming endpoint MUST use independent database sessions per query iteration rather than reusing a request-scoped session.

#### Scenario: Status Retrieval from DB
- **WHEN** a request is made to `GET /jobs/{job_id}`
- **THEN** the backend queries the `jobs` table
- **AND** returns the current status from the database

#### Scenario: SSE Stream Uses Independent Sessions
- **WHEN** a client connects to `GET /jobs/{job_id}/stream`
- **THEN** each polling iteration inside the async generator SHALL create a new `AsyncSession` via `get_session_factory()`
- **AND** the session SHALL be closed after each iteration
- **AND** the endpoint function signature SHALL NOT use `Depends(get_db)` for the streaming session

#### Scenario: SSE Stream Survives Connection Pool Recycling
- **WHEN** an SSE stream has been open for longer than the DB connection pool recycle time
- **THEN** the stream SHALL continue to function correctly because each iteration obtains a fresh session and connection
