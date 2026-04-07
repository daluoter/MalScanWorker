export interface UploadResponse {
    job_id: string
    file_id: string
    sha256: string
    status: string
    created_at: string
}

export interface JobProgress {
    current_stage: string
    stages_done: number
    stages_total: number
    percent: number
}

export interface JobStatus {
    job_id: string
    parent_job_id?: string | null
    status: 'queued' | 'scanning' | 'password_required' | 'done' | 'failed'
    progress: JobProgress
    updated_at: string
    error_message: string | null
    password_attempts: number
    password_attempts_remaining: number
}

export interface FileMetadata {
    file_id: string
    sha256: string
    mime: string
    size: number
    original_filename: string
}

export interface AvResult {
    engine: string
    infected: boolean
    threat_name: string | null
}

export interface YaraHit {
    rule: string
    namespace: string
    description: string
    severity: string
    author: string
    tags: string[]
    strings: string[]
}

export interface Iocs {
    urls: string[]
    domains: string[]
    ips: string[]
    hashes: {
        md5: string
        sha1: string
        sha256: string
    }
}

export interface StageTiming {
    name: string
    status: string
    duration_ms: number
}

export interface Report {
    job_id: string
    parent_job_id?: string | null
    file: FileMetadata
    verdict: string
    score: number
    results: {
        av_result: AvResult
        yara_hits: YaraHit[]
        iocs: Iocs
        sandbox: {
            executed: boolean
            behaviors: Array<{ type: string; path?: string; key?: string }>
            network_connections: Array<{ dst_ip: string; dst_port: number; protocol: string }>
            is_mock: boolean
        }
        archive_extract?: {
            archive_type: string | null
            extracted_count: number
            sub_jobs_created: number
            total_extracted_bytes: number
            malicious: boolean
            reason: string | null
            extraction_failed?: boolean
        }
    }
    timings: {
        total_ms: number
        stages: StageTiming[]
    }
    child_jobs: Array<{
        job_id: string
        filename: string
        sha256: string
        status: string
        verdict: string | null
    }>
    created_at: string
}

export interface ApiError {
    error: {
        code: string
        message: string
        details?: Record<string, unknown>
    }
}

export interface HealthResponse {
    status: string
}

export interface PasswordSubmitRequest {
    password: string
}

export interface PasswordSubmitResponse {
    job_id: string
    status: string
    message: string
    attempts_used: number
    attempts_remaining: number
}
