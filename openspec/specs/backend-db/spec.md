# backend-db Specification

## Purpose
TBD - created by archiving change add-database-integration. Update Purpose after archive.
## Requirements
### Requirement: Database Configuration
The application MUST configure and verify the database connection on startup.

#### Scenario: Verify Connection on Startup
- **Given** the backend application starts
- **When** the internal database module initializes
- **Then** it must connect to the PostgreSQL database using `DATABASE_URL` from the environment
- **And** it should verify the connection is active (e.g., ping)

### Requirement: File Upload Persistence
File uploads MUST be recorded in the database and stored in MinIO.

#### Scenario: Persist Upload Record
- **Given** a valid file upload request to `POST /files`
- **When** the file is successfully uploaded to MinIO with SHA256 as storage key
- **Then** a new record must be created in the `files` table (if new SHA256)
- **And** a new record must be created in the `jobs` table with `status='queued'`
- **And** a job message must be published to RabbitMQ `malscan.jobs` queue
- **And** the returned `job_id` matches the database record

#### Scenario: Upload Failure Handling
- **Given** a valid file upload request
- **When** MinIO upload fails due to connection error
- **Then** the endpoint must return HTTP 500 with error details
- **And** no database records are created

### Requirement: Job Status Data
Job status queries MUST reflect the current state from the database.

#### Scenario: Status Retrieval from DB
- **Given** a valid `job_id` exists in the database
- **When** a request is made to `GET /jobs/{job_id}`
- **Then** the backend queries the `jobs` table
- **And** returns the current status (e.g., 'queued') from the database

### Requirement: MinIO File Storage
The backend MUST store uploaded files in MinIO for worker access.

#### Scenario: Store File in MinIO
- **Given** a valid file upload
- **When** the file is processed
- **Then** the file content must be stored in the `uploads` bucket
- **And** the storage key must be the file's SHA256 hash
- **And** the content type must be preserved

### Requirement: RabbitMQ Job Publishing
The backend MUST publish job messages to RabbitMQ for worker consumption.

#### Scenario: Publish Job Message
- **Given** a successful file upload and DB record creation
- **When** the upload processing completes
- **Then** a JSON message must be published to `malscan.jobs` queue
- **And** the message must contain `job_id`, `file_id`, `storage_key`, `sha256`, and `original_filename`
