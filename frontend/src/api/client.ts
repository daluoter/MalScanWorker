const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '')

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
    status: 'queued' | 'scanning' | 'done' | 'failed'
    progress: JobProgress
    updated_at: string
    error_message: string | null
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
    }
    timings: {
        total_ms: number
        stages: StageTiming[]
    }
    created_at: string
}

export interface ApiError {
    error: {
        code: string
        message: string
        details?: Record<string, unknown>
    }
}

class ApiClient {
    private baseUrl: string

    constructor(baseUrl: string = API_BASE_URL) {
        this.baseUrl = baseUrl
    }

    async uploadFile(file: File): Promise<UploadResponse> {
        const formData = new FormData()
        formData.append('file', file)

        const response = await fetch(`${this.baseUrl}/api/v1/files`, {
            method: 'POST',
            body: formData,
        })

        if (!response.ok) {
            const errorData = await response.json()
            // FastAPI wraps HTTPException detail in {"detail": ...}
            // Handle both {"detail": {"error": {"message": "..."}}} and {"error": {"message": "..."}}
            const errorMessage =
                errorData?.detail?.error?.message ||
                errorData?.detail?.message ||
                errorData?.error?.message ||
                errorData?.detail ||
                '上傳失敗'
            throw new Error(String(errorMessage))
        }

        return response.json()
    }

    async getJobStatus(jobId: string): Promise<JobStatus> {
        const response = await fetch(`${this.baseUrl}/api/v1/jobs/${jobId}`)

        if (!response.ok) {
            const error: ApiError = await response.json()
            throw new Error(error.error.message)
        }

        return response.json()
    }

    async getReport(jobId: string): Promise<Report> {
        const response = await fetch(`${this.baseUrl}/api/v1/reports/${jobId}`)

        if (!response.ok) {
            const error: ApiError = await response.json()
            throw new Error(error.error.message)
        }

        return response.json()
    }
}

export const apiClient = new ApiClient()
