# Backend Database Integration

## ADDED Requirements

### Requirement: Database Configuration
The application MUST configure and verify the database connection on startup.

#### Scenario: Verify Connection on Startup
- **Given** the backend application starts
- **When** the internal database module initializes
- **Then** it must connect to the PostgreSQL database using `DATABASE_URL` from the environment
- **And** it should verify the connection is active (e.g., ping)

### Requirement: File Upload Persistence
File uploads MUST be recorded in the database immediately upon receipt.

#### Scenario: Persist Upload Record
- **Given** a valid file upload request to `POST /files`
- **When** the file is successfully uploaded to Object Storage
- **Then** a new record must be created in the `files` table (if new SHA256)
- **And** a new record must be created in the `jobs` table with `status='queued'`
- **And** the returned `job_id` matches the database record

### Requirement: Job Status Data
Job status queries MUST reflect the current state from the database.

#### Scenario: Status Retrieval from DB
- **Given** a valid `job_id` exists in the database
- **When** a request is made to `GET /jobs/{job_id}`
- **Then** the backend queries the `jobs` table
- **And** returns the current status (e.g., 'queued') from the database
