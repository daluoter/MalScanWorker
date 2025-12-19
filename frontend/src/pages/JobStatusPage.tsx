import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link, useLocation } from 'react-router-dom'
import { apiClient, JobStatus } from '../api/client'

interface LocationState {
    fileName?: string
    fileSize?: number
}

export default function JobStatusPage() {
    const { jobId } = useParams<{ jobId: string }>()
    const navigate = useNavigate()
    const location = useLocation()
    const fileInfo = (location.state as LocationState) || {}
    const [job, setJob] = useState<JobStatus | null>(null)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        if (!jobId) return

        const fetchStatus = async () => {
            try {
                const status = await apiClient.getJobStatus(jobId)
                setJob(status)

                if (status.status === 'done') {
                    navigate(`/reports/${jobId}`)
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : '無法取得狀態')
            }
        }

        fetchStatus()
        const interval = setInterval(fetchStatus, 2000)
        return () => clearInterval(interval)
    }, [jobId, navigate])

    const statusLabels: Record<string, string> = {
        queued: '排隊中',
        scanning: '分析中',
        done: '完成',
        failed: '失敗',
    }

    const stageLabels: Record<string, string> = {
        'file-type': 'FILE_TYPE_DETECT',
        clamav: 'CLAMAV_SCAN',
        yara: 'YARA_MATCH',
        'ioc-extract': 'IOC_EXTRACT',
        sandbox: 'SANDBOX_ANALYZE',
    }

    if (error) {
        return (
            <div className="container">
                <h1 className="text-3xl font-bold mb-6 text-alert-red">
                    ❌ 錯誤
                </h1>
                <div className="error-message">
                    <span className="font-mono">{error}</span>
                </div>
                <Link to="/" className="inline-block mt-6 text-neon-cyan hover:text-neon-purple">
                    ← 返回上傳
                </Link>
            </div>
        )
    }

    if (!job) {
        return (
            <div className="container">
                <div className="glass-card p-8 text-center">
                    <div className="text-4xl mb-4 animate-pulse">⏳</div>
                    <p className="text-xl font-mono text-neon-cyan terminal-cursor">
                        LOADING
                    </p>
                </div>
            </div>
        )
    }

    const statusColors: Record<string, string> = {
        queued: 'text-slate-400',
        scanning: 'text-neon-cyan',
        done: 'text-matrix-green',
        failed: 'text-alert-red',
    }

    return (
        <div className="container">
            {/* Header */}
            <h1 className="text-3xl font-bold mb-6 bg-gradient-to-r from-neon-cyan to-neon-purple bg-clip-text text-transparent">
                🔄 分析進度
            </h1>

            <div className="glass-card p-6">
                {/* Terminal Header */}
                <div className="flex items-center gap-2 mb-4 pb-4 border-b border-white/10">
                    <div className="w-3 h-3 rounded-full bg-alert-red" />
                    <div className="w-3 h-3 rounded-full bg-caution-yellow" />
                    <div className="w-3 h-3 rounded-full bg-matrix-green" />
                    <span className="ml-2 text-slate-500 text-sm font-mono">malscan-terminal</span>
                </div>

                {/* Job Info - Terminal Style */}
                <div className="space-y-2 font-mono text-sm">
                    {fileInfo.fileName && (
                        <div className="flex items-start gap-2">
                            <span className="text-neon-purple">$</span>
                            <span className="text-slate-400">FILE:</span>
                            <span className="text-white">{fileInfo.fileName}</span>
                            {fileInfo.fileSize && (
                                <span className="text-slate-500">
                                    ({(fileInfo.fileSize / 1024 / 1024).toFixed(2)} MB)
                                </span>
                            )}
                        </div>
                    )}
                    <div className="flex items-start gap-2">
                        <span className="text-neon-purple">$</span>
                        <span className="text-slate-400">JOB_ID:</span>
                        <span className="text-neon-cyan break-all">{job.job_id}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-neon-purple">$</span>
                        <span className="text-slate-400">STATUS:</span>
                        <span className={`font-bold ${statusColors[job.status]}`}>
                            {statusLabels[job.status] || job.status}
                        </span>
                    </div>
                </div>

                {/* HUD Progress Bar */}
                <div className="mt-6">
                    <div className="flex justify-between items-center mb-2">
                        <span className="text-sm text-slate-400 font-mono">PROGRESS</span>
                        <span className="text-sm font-mono text-neon-cyan">
                            {job.progress.percent}%
                        </span>
                    </div>
                    <div className="hud-progress">
                        <div
                            className="hud-progress-fill"
                            style={{ width: `${job.progress.percent}%` }}
                        />
                        <div className="hud-progress-scan" />
                    </div>
                </div>

                {/* Current Stage */}
                {job.progress.current_stage && (
                    <div className="mt-6 p-4 bg-deep-space rounded-lg border border-neon-cyan/20">
                        <div className="flex items-center gap-2 font-mono text-sm">
                            <span className="text-neon-cyan animate-pulse">▶</span>
                            <span className="text-matrix-green">EXECUTING:</span>
                            <span className="text-white">
                                {stageLabels[job.progress.current_stage] || job.progress.current_stage}
                            </span>
                            <span className="text-slate-500 animate-pulse">...</span>
                        </div>
                    </div>
                )}

                {/* Stage Progress */}
                <div className="mt-4 text-sm text-slate-400 font-mono">
                    <span className="text-neon-purple">[</span>
                    <span className="text-matrix-green">{job.progress.stages_done}</span>
                    <span className="text-slate-500">/</span>
                    <span className="text-white">{job.progress.stages_total}</span>
                    <span className="text-neon-purple">]</span>
                    <span className="ml-2">STAGES COMPLETED</span>
                </div>

                {/* Error Display */}
                {job.status === 'failed' && job.error_message && (
                    <div className="mt-6 p-4 rounded-lg bg-alert-red/10 border border-alert-red">
                        <div className="font-mono text-sm">
                            <span className="text-alert-red">ERROR:</span>
                            <span className="text-white ml-2">{job.error_message}</span>
                        </div>
                    </div>
                )}
            </div>

            {/* Back Link */}
            <Link
                to="/"
                className="inline-flex items-center gap-2 mt-6 text-sm font-mono text-slate-400 hover:text-neon-cyan transition-colors"
            >
                <span>←</span>
                <span>返回上傳</span>
            </Link>
        </div>
    )
}
