import type {
    JobStatus,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    Report,
    UploadResponse,
} from './types'

export type {
    ApiError,
    AvResult,
    FileMetadata,
    HealthResponse,
    Iocs,
    JobProgress,
    JobStatus,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    Report,
    StageTiming,
    UploadResponse,
    YaraHit,
} from './types'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '')

class ApiClient {
    public baseUrl: string

    constructor(baseUrl: string = API_BASE_URL) {
        this.baseUrl = baseUrl
    }

    getJobStreamUrl(jobId: string): string {
        return `${this.baseUrl}/api/v1/jobs/${jobId}/stream`
    }

    async checkHealth(): Promise<boolean> {
        try {
            const response = await fetch(`${this.baseUrl}/health`)
            return response.ok
        } catch {
            return false
        }
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
            let errorMessage = '取得工作狀態失敗'
            try {
                const errorData = await response.json()
                errorMessage = errorData?.detail?.error?.message ||
                               errorData?.detail?.message ||
                               errorData?.error?.message ||
                               errorData?.detail ||
                               errorMessage
            } catch {
                errorMessage = response.statusText
            }
            throw new Error(errorMessage)
        }

        return response.json()
    }

    async getReport(jobId: string): Promise<Report> {
        const response = await fetch(`${this.baseUrl}/api/v1/reports/${jobId}`)

        if (!response.ok) {
            let errorMessage = '取得報告失敗'
            try {
                const errorData = await response.json()
                errorMessage = errorData?.detail?.error?.message ||
                               errorData?.error?.message ||
                               errorData?.detail ||
                               errorMessage
            } catch {
                errorMessage = response.statusText
            }
            throw new Error(errorMessage)
        }

        return response.json()
    }

    async submitArchivePassword(jobId: string, payload: PasswordSubmitRequest): Promise<PasswordSubmitResponse> {
        const response = await fetch(`${this.baseUrl}/api/v1/jobs/${jobId}/password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        })

        if (!response.ok) {
            let errorMessage = '提交解壓密碼失敗'
            try {
                const errorData = await response.json()
                errorMessage = errorData?.detail?.error?.message ||
                               errorData?.detail?.message ||
                               errorData?.error?.message ||
                               errorData?.detail ||
                               errorMessage
            } catch {
                errorMessage = response.statusText || errorMessage
            }
            throw new Error(String(errorMessage))
        }

        return response.json()
    }
}

export const apiClient = new ApiClient()
