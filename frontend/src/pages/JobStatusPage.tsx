import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { apiClient, JobStatus } from '../api/client'

export default function JobStatusPage() {
    const { jobId } = useParams<{ jobId: string }>()
    const navigate = useNavigate()
    const [job, setJob] = useState<JobStatus | null>(null)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        if (!jobId) return

        const fetchStatus = async () => {
            try {
                const status = await apiClient.getJobStatus(jobId)
                setJob(status)

                // 如果完成，跳轉到報告頁
                if (status.status === 'done') {
                    navigate(`/reports/${jobId}`)
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : '無法取得狀態')
            }
        }

        // 初次載入
        fetchStatus()

        // 輪詢（每 2 秒）
        const interval = setInterval(fetchStatus, 2000)

        return () => clearInterval(interval)
    }, [jobId, navigate])

    if (error) {
        return (
            <div className="container">
                <h1>❌ 錯誤</h1>
                <div className="error-message">{error}</div>
                <Link to="/" style={{ display: 'inline-block', marginTop: '1rem' }}>
                    ← 返回上傳
                </Link>
            </div>
        )
    }

    if (!job) {
        return (
            <div className="container">
                <h1>⏳ 載入中...</h1>
            </div>
        )
    }

    const statusLabels: Record<string, string> = {
        queued: '排隊中',
        scanning: '分析中',
        done: '完成',
        failed: '失敗',
    }

    const stageLabels: Record<string, string> = {
        'file-type': '檔案類型偵測',
        clamav: 'ClamAV 掃描',
        yara: 'YARA 規則比對',
        'ioc-extract': 'IOC 擷取',
        sandbox: '沙箱分析',
    }

    return (
        <div className="container">
            <h1>🔄 分析進度</h1>

            <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <span>Job ID</span>
                    <code style={{ fontSize: '0.875rem' }}>{job.job_id}</code>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <span>狀態</span>
                    <span className={`status-badge status-${job.status}`}>
                        {statusLabels[job.status] || job.status}
                    </span>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                        <span>進度</span>
                        <span>{job.progress.percent}%</span>
                    </div>
                    <div className="progress-bar">
                        <div
                            className="progress-bar-fill"
                            style={{ width: `${job.progress.percent}%` }}
                        />
                    </div>
                </div>

                {job.progress.current_stage && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <span>當前階段</span>
                        <span>{stageLabels[job.progress.current_stage] || job.progress.current_stage}</span>
                    </div>
                )}

                <div style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>
                    完成 {job.progress.stages_done} / {job.progress.stages_total} 階段
                </div>

                {job.status === 'failed' && job.error_message && (
                    <div className="error-message" style={{ marginTop: '1rem' }}>
                        {job.error_message}
                    </div>
                )}
            </div>

            <Link to="/">← 返回上傳</Link>
        </div>
    )
}
