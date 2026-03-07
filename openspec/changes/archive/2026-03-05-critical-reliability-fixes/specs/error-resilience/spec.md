## ADDED Requirements

### Requirement: Persistent RabbitMQ Connection for Publishing
The backend MUST maintain a persistent RabbitMQ connection singleton for publishing job messages, instead of creating a new connection per publish call.

#### Scenario: Connection initialized at startup
- **WHEN** the FastAPI application starts
- **THEN** the system SHALL call `init_rabbitmq()` to establish a persistent `aio_pika.connect_robust` connection and channel
- **AND** the queue SHALL be declared once during initialization

#### Scenario: Publish reuses existing connection
- **WHEN** `publish_job()` is called
- **THEN** it SHALL use the existing singleton channel to publish the message
- **AND** it SHALL NOT create a new TCP+AMQP connection

#### Scenario: Connection closed at shutdown
- **WHEN** the FastAPI application shuts down
- **THEN** the system SHALL call `close_rabbitmq()` to cleanly close the channel and connection

#### Scenario: Connection not initialized
- **WHEN** `publish_job()` is called before `init_rabbitmq()` completes
- **THEN** the system SHALL raise a `RuntimeError` indicating the connection is not initialized

## MODIFIED Requirements

### Requirement: Exponential Backoff Retry for RabbitMQ Publishing
The backend MUST use exponential backoff when retrying failed RabbitMQ publish operations. The retry decorator SHALL apply to the singleton-based publish function.

#### Scenario: Retry with Exponential Backoff
- **WHEN** the singleton channel publish operation fails due to a transient error
- **THEN** the system MUST retry with exponential backoff delays (1s → 2s → 4s → 8s → 16s)
- **AND** each retry attempt MUST be logged with structured logging
- **AND** after 5 failed attempts, the original exception MUST be raised

#### Scenario: Successful Retry
- **WHEN** the backend is retrying a failed publish operation
- **AND** a subsequent attempt succeeds
- **THEN** the job MUST be published successfully
- **AND** a success log entry MUST be recorded

### Requirement: Configuration Security for Sensitive Fields
The backend and worker MUST NOT define default values for sensitive configuration fields. These fields MUST be provided via environment variables.

#### Scenario: Missing database URL at startup
- **WHEN** the application starts without `DATABASE_URL` environment variable set
- **THEN** the system SHALL fail immediately with a `ValidationError`
- **AND** the error message SHALL indicate which field is missing

#### Scenario: Missing MinIO credentials at startup
- **WHEN** the application starts without `MINIO_ACCESS_KEY` or `MINIO_SECRET_KEY` environment variables
- **THEN** the system SHALL fail immediately with a `ValidationError`

#### Scenario: Missing RabbitMQ URL at startup
- **WHEN** the application starts without `RABBITMQ_URL` environment variable
- **THEN** the system SHALL fail immediately with a `ValidationError`
