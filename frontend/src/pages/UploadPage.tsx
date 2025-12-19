import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiClient } from '../api/client'

const MAX_SIZE = 20 * 1024 * 1024 // 20MB

export default function UploadPage() {
    const navigate = useNavigate()
    const [file, setFile] = useState<File | null>(null)
    const [isDragging, setIsDragging] = useState(false)
    const [isUploading, setIsUploading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [isBackendOnline, setIsBackendOnline] = useState<boolean | null>(null)

    // Health check polling
    useEffect(() => {
        const checkBackend = async () => {
            const online = await apiClient.checkHealth()
            setIsBackendOnline(online)
        }
        checkBackend()
        const interval = setInterval(checkBackend, 10000)
        return () => clearInterval(interval)
    }, [])

    const handleFile = useCallback((selectedFile: File) => {
        if (selectedFile.size > MAX_SIZE) {
            setError(`檔案大小超過 20MB 限制（實際：${(selectedFile.size / 1024 / 1024).toFixed(2)}MB）`)
            return
        }
        setError(null)
        setFile(selectedFile)
    }, [])

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        setIsDragging(false)
        const droppedFile = e.dataTransfer.files[0]
        if (droppedFile) {
            handleFile(droppedFile)
        }
    }, [handleFile])

    const handleDragOver = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        setIsDragging(true)
    }, [])

    const handleDragLeave = useCallback(() => {
        setIsDragging(false)
    }, [])

    const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0]
        if (selectedFile) {
            handleFile(selectedFile)
        }
    }, [handleFile])

    const handleUpload = async () => {
        if (!file) return

        setIsUploading(true)
        setError(null)

        try {
            const result = await apiClient.uploadFile(file)
            navigate(`/jobs/${result.job_id}`, {
                state: {
                    fileName: file.name,
                    fileSize: file.size
                }
            })
        } catch (err) {
            setError(err instanceof Error ? err.message : '上傳失敗')
        } finally {
            setIsUploading(false)
        }
    }

    return (
        <div className="container">
            {/* Header */}
            <div className="mb-8">
                <h1 className="text-4xl font-bold mb-2 bg-gradient-to-r from-neon-cyan to-neon-purple bg-clip-text text-transparent">
                    🔍 MalScan
                </h1>
                <p className="text-slate-400">
                    上傳檔案進行惡意軟體分析
                </p>
            </div>

            {/* Main Card */}
            <div className="glass-card p-6">
                {/* Backend Status Indicator */}
                <div className="flex items-center justify-center gap-3 mb-6 p-3 rounded-lg bg-void/50">
                    <div className={`status-dot ${isBackendOnline === null
                        ? 'status-dot-checking animate-pulse'
                        : isBackendOnline
                            ? 'status-dot-online'
                            : 'status-dot-offline'
                        }`} />
                    <span className={`text-sm font-medium ${isBackendOnline === null
                        ? 'text-slate-400'
                        : isBackendOnline
                            ? 'text-matrix-green'
                            : 'text-alert-red'
                        }`}>
                        {isBackendOnline === null
                            ? '檢查連線中...'
                            : isBackendOnline
                                ? '後端已連線'
                                : '後端離線 - 無法上傳'}
                    </span>
                </div>

                {/* Holographic Drop Zone */}
                <div
                    className={`drop-zone holographic ${isDragging ? 'dragging' : ''}`}
                    onDrop={handleDrop}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onClick={() => document.getElementById('file-input')?.click()}
                >
                    <input
                        id="file-input"
                        type="file"
                        onChange={handleFileSelect}
                        className="hidden"
                    />

                    {file ? (
                        <div className="text-center">
                            <div className="text-5xl mb-4">📄</div>
                            <p className="text-xl font-semibold text-neon-cyan mb-2">
                                {file.name}
                            </p>
                            <p className="text-slate-400 font-mono text-sm">
                                {(file.size / 1024 / 1024).toFixed(2)} MB
                            </p>
                        </div>
                    ) : (
                        <div className="text-center">
                            <div className="text-5xl mb-4 opacity-50">
                                ⬆️
                            </div>
                            <p className="text-xl font-medium mb-2">
                                拖放檔案到此處
                            </p>
                            <p className="text-slate-400 text-sm">
                                或點擊選擇檔案 • 最大 20MB
                            </p>
                        </div>
                    )}
                </div>

                {/* Error Message */}
                {error && (
                    <div className="error-message mt-4">
                        <span className="font-mono text-sm">⚠ {error}</span>
                    </div>
                )}

                {/* Upload Button */}
                <button
                    className={`btn-neon w-full mt-6 glitch-hover ${isUploading ? 'animate-pulse' : ''}`}
                    onClick={handleUpload}
                    disabled={!file || isUploading || isBackendOnline === false}
                >
                    {isUploading ? (
                        <span className="flex items-center justify-center gap-2">
                            <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            分析中...
                        </span>
                    ) : (
                        '🚀 開始分析'
                    )}
                </button>
            </div>

            {/* Footer */}
            <div className="mt-8 text-center">
                <p className="text-slate-500 text-xs font-mono">
                    MALSCAN v0.1.0 • CYBERSEC ANALYSIS PLATFORM
                </p>
            </div>
        </div>
    )
}
