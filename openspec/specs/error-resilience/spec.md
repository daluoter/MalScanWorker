# error-resilience Specification

## Purpose
提供錯誤重試與強健性機制，透過 Tenacity 套件實現指數退避重試策略，並使用 Dead Letter Queue (DLQ) 處理持續失敗的訊息。

## Requirements

### Requirement: Exponential Backoff Retry for RabbitMQ Publishing
The backend MUST use exponential backoff when retrying failed RabbitMQ publish operations.

#### Scenario: Retry with Exponential Backoff
- **Given** the backend attempts to publish a job message to RabbitMQ
- **When** the publish operation fails due to connection error
- **Then** the system must retry with exponential backoff delays (1s → 2s → 4s → 8s → 16s)
- **And** each retry attempt must be logged with structured logging
- **And** after 5 failed attempts, the original exception must be raised

#### Scenario: Successful Retry
- **Given** the backend is retrying a failed publish operation
- **When** a subsequent attempt succeeds
- **Then** the job must be published successfully
- **And** a success log entry must be recorded

---

### Requirement: MinIO Download Retry
The worker MUST retry failed MinIO file download operations.

#### Scenario: Download Retry with Backoff
- **Given** the worker attempts to download a file from MinIO
- **When** the download fails due to connection error
- **Then** the system must retry up to 3 times with exponential backoff (1s → 2s → 4s)
- **And** each retry must be logged

#### Scenario: Download Failure After Retries
- **Given** all download retry attempts have failed
- **When** the final attempt fails
- **Then** the job status must be updated to `failed`
- **And** the error must be logged with full context

---

### Requirement: Dead Letter Queue for Failed Messages
The worker MUST route persistently failing messages to a Dead Letter Queue.

#### Scenario: Message Exceeds Retry Limit
- **Given** a job message fails processing 3 times
- **When** the 3rd processing attempt fails
- **Then** the message must be routed to the `malscan-dlq` queue
- **And** the message must not be requeued to the main queue
- **And** a warning log must be recorded with the job_id

#### Scenario: DLQ Queue Declaration
- **Given** the worker starts consuming messages
- **When** the consumer initializes
- **Then** the `malscan-dlq` queue must be declared as durable
- **And** the main queue must be configured with `x-dead-letter-routing-key` pointing to `malscan-dlq`

---

### Requirement: RabbitMQ Connection Retry
The worker MUST retry RabbitMQ connection failures with structured logging.

#### Scenario: Connection Retry with Logging
- **Given** the worker attempts to connect to RabbitMQ
- **When** the connection fails
- **Then** the system must retry up to 90 times with 10-second intervals
- **And** each retry attempt must be logged with attempt number and error details
- **And** after all retries fail, a critical error must be logged

---

### Requirement: Message Processing Error Handling
The worker message processing error handling supports retry counting.

#### Scenario: Track Message Retry Count
- **Given** a message is being processed
- **When** processing fails
- **Then** the system must check the `x-death` header to determine retry count
- **And** if retry count < 3, the message must be rejected with requeue=True
- **And** if retry count >= 3, the message must be rejected with requeue=False
