import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiClient } from '../api/client'

const MAX_SIZE = 20 * 1024 * 1024 // 20MB

export default function UploadPage() {
    const navigate = useNavigate()
    const [file, setFile] = useState<File | null>(null)
    const [isDragging, setIsDragging] = useState(false)
    const [isUploading, setIsUploading] = useState(false)
    const [error, setError] = useState<string | null>(null)

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
            // 上傳成功，跳轉到狀態頁
            navigate(`/jobs/${result.job_id}`)
        } catch (err) {
            setError(err instanceof Error ? err.message : '上傳失敗')
        } finally {
            setIsUploading(false)
        }
    }

    return (
        <div className="container">
            <h1>🔍 MalScan</h1>
            <p style={{ marginBottom: '2rem', color: 'var(--color-text-secondary)' }}>
                上傳檔案進行惡意軟體分析
            </p>

            <div className="card">
                <div
                    className={`upload-zone ${isDragging ? 'dragging' : ''}`}
                    onDrop={handleDrop}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onClick={() => document.getElementById('file-input')?.click()}
                >
                    <input
                        id="file-input"
                        type="file"
                        onChange={handleFileSelect}
                        style={{ display: 'none' }}
                    />
                    {file ? (
                        <div>
                            <p style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>📄 {file.name}</p>
                            <p style={{ color: 'var(--color-text-secondary)' }}>
                                {(file.size / 1024 / 1024).toFixed(2)} MB
                            </p>
                        </div>
                    ) : (
                        <div>
                            <p style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>
                                拖放檔案到此處，或點擊選擇
                            </p>
                            <p style={{ color: 'var(--color-text-secondary)' }}>
                                支援任何檔案類型，最大 20MB
                            </p>
                        </div>
                    )}
                </div>

                {error && (
                    <div className="error-message" style={{ marginTop: '1rem' }}>
                        {error}
                    </div>
                )}

                <button
                    className="btn btn-primary"
                    onClick={handleUpload}
                    disabled={!file || isUploading}
                    style={{ marginTop: '1rem', width: '100%' }}
                >
                    {isUploading ? '上傳中...' : '開始分析'}
                </button>
            </div>
        </div>
    )
}
