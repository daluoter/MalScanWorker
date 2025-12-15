# worker-pipeline Specification

## Purpose
TBD - created by archiving change integrate-minio-rabbitmq. Update Purpose after archive.
## Requirements
### Requirement: MinIO File Download
The worker MUST download files from MinIO for analysis.

#### Scenario: Download File for Analysis
- **Given** a job message is received with `storage_key`
- **When** the worker starts processing the job
- **Then** the worker must download the file from MinIO `uploads` bucket
- **And** store it in a temporary directory `/tmp/{job_id}/`
- **And** the file path must be available to all pipeline stages

#### Scenario: Download Failure Handling
- **Given** a job message with an invalid or missing `storage_key`
- **When** MinIO download fails
- **Then** the job status must be updated to `failed` in the database
- **And** the error message must be recorded
- **And** the RabbitMQ message must be acknowledged (not requeued)

### Requirement: Job Status Updates
The worker MUST update job status in the database during processing.

#### Scenario: Update Status to Processing
- **Given** a job message is received from RabbitMQ
- **When** the worker begins processing
- **Then** the job status must be updated to `processing` in the database

#### Scenario: Update Stage Progress
- **Given** a job is being processed
- **When** each analysis stage completes successfully
- **Then** the `current_stage` must be updated to the stage name
- **And** `stages_done` must be incremented

#### Scenario: Update Status to Completed
- **Given** all analysis stages complete successfully
- **When** the pipeline finishes
- **Then** the job status must be updated to `completed`

#### Scenario: Update Status to Failed
- **Given** any analysis stage fails
- **When** an error occurs during processing
- **Then** the job status must be updated to `failed`
- **And** the `error_message` field must contain the error details

### Requirement: Temporary File Cleanup
The worker MUST clean up temporary files after processing.

#### Scenario: Clean Up After Success
- **Given** a job completes successfully
- **When** the pipeline finishes
- **Then** the temporary directory `/tmp/{job_id}/` must be deleted

#### Scenario: Clean Up After Failure
- **Given** a job fails during processing
- **When** error handling completes
- **Then** the temporary directory `/tmp/{job_id}/` must be deleted

