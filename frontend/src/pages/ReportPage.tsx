import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { apiClient, Report } from '../api/client'

export default function ReportPage() {
    const { jobId } = useParams<{ jobId: string }>()
    const [report, setReport] = useState<Report | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [copiedHash, setCopiedHash] = useState(false)

    useEffect(() => {
        if (!jobId) return

        const fetchReport = async () => {
            try {
                const data = await apiClient.getReport(jobId)
                setReport(data)
            } catch (err) {
                setError(err instanceof Error ? err.message : '無法取得報告')
            }
        }

        fetchReport()
    }, [jobId])

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text)
            setCopiedHash(true)
            setTimeout(() => setCopiedHash(false), 2000)
        } catch {
            // Fallback for older browsers
            console.error('Failed to copy')
        }
    }

    if (error) {
        return (
            <div className="container">
                <h1 className="text-3xl font-bold mb-6 text-alert-red">❌ 錯誤</h1>
                <div className="error-message">
                    <span className="font-mono">{error}</span>
                </div>
                <Link to="/" className="inline-block mt-6 text-neon-cyan hover:text-neon-purple">
                    ← 返回上傳
                </Link>
            </div>
        )
    }

    if (!report) {
        return (
            <div className="container">
                <div className="glass-card p-8 text-center">
                    <div className="text-4xl mb-4 animate-pulse">📋</div>
                    <p className="text-xl font-mono text-neon-cyan terminal-cursor">
                        LOADING REPORT
                    </p>
                </div>
            </div>
        )
    }

    const verdictLabels: Record<string, string> = {
        clean: '安全',
        suspicious: '可疑',
        malicious: '惡意',
        unknown: '未知',
    }

    const verdictIcons: Record<string, string> = {
        clean: '✅',
        suspicious: '⚠️',
        malicious: '☠️',
        unknown: '❓',
    }

    const verdictClasses: Record<string, string> = {
        clean: 'verdict-clean',
        suspicious: 'verdict-suspicious',
        malicious: 'verdict-malicious',
        unknown: 'glass-card',
    }

    const stageLabels: Record<string, string> = {
        'file-type': 'FILE_TYPE_DETECT',
        clamav: 'CLAMAV_SCAN',
        yara: 'YARA_MATCH',
        'ioc-extract': 'IOC_EXTRACT',
        sandbox: 'SANDBOX_ANALYZE',
    }

    return (
        <div className="container">
            {/* Header */}
            <h1 className="text-3xl font-bold mb-6 bg-gradient-to-r from-neon-cyan to-neon-purple bg-clip-text text-transparent">
                📋 分析報告
            </h1>

            {/* Verdict Card - Prominent Neon Border */}
            <div className={`verdict-card ${verdictClasses[report.verdict]} mb-6 animate-glow-pulse`}>
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-sm font-mono text-slate-400 mb-1">VERDICT</p>
                        <p className="text-3xl font-bold">
                            {verdictIcons[report.verdict]} {verdictLabels[report.verdict] || report.verdict}
                        </p>
                    </div>
                    <div className="text-right">
                        <p className="text-sm font-mono text-slate-400 mb-1">THREAT SCORE</p>
                        <p className="text-4xl font-bold font-mono">
                            {report.score}<span className="text-lg text-slate-400">/100</span>
                        </p>
                    </div>
                </div>
            </div>

            {/* File Info */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">📄 檔案資訊</h2>
                <div className="space-y-3 font-mono text-sm">
                    <div className="flex justify-between">
                        <span className="text-slate-400">FILENAME</span>
                        <span className="text-white">{report.file.original_filename}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">MIME</span>
                        <span className="text-neon-purple">{report.file.mime}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">SIZE</span>
                        <span className="text-white">{(report.file.size / 1024).toFixed(2)} KB</span>
                    </div>
                    <div className="pt-3 border-t border-white/10">
                        <div className="flex justify-between items-start mb-2">
                            <span className="text-slate-400">SHA256</span>
                            <button
                                onClick={() => copyToClipboard(report.file.sha256)}
                                className="text-xs text-neon-cyan hover:text-neon-purple transition-colors"
                            >
                                {copiedHash ? '✓ 已複製' : '📋 複製'}
                            </button>
                        </div>
                        <div className="code-block text-xs break-all text-matrix-green">
                            {report.file.sha256}
                        </div>
                    </div>
                </div>
            </div>

            {/* AV Results */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">🛡️ 防毒掃描</h2>
                <div className="flex justify-between items-center font-mono text-sm">
                    <span className="text-slate-400">{report.results.av_result.engine}</span>
                    <span className={report.results.av_result.infected ? 'text-alert-red' : 'text-matrix-green'}>
                        {report.results.av_result.infected
                            ? `☠️ ${report.results.av_result.threat_name}`
                            : '✓ CLEAN'}
                    </span>
                </div>
            </div>

            {/* YARA Hits */}
            {report.results.yara_hits.length > 0 && (
                <div className="glass-card p-6 mb-4">
                    <h2 className="text-lg font-bold mb-4 text-neon-cyan">🎯 YARA 規則匹配</h2>
                    <div className="space-y-3">
                        {report.results.yara_hits.map((hit, index) => (
                            <div key={index} className="stage-item">
                                <div>
                                    <span className="font-mono text-alert-red">{hit.rule}</span>
                                    {hit.tags.length > 0 && (
                                        <div className="flex gap-2 mt-1">
                                            {hit.tags.map((tag, i) => (
                                                <span key={i} className="text-xs px-2 py-0.5 rounded bg-neon-purple/20 text-neon-purple">
                                                    {tag}
                                                </span>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* IOC - Code Snippet Style */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">🔗 IOC 指標</h2>

                {report.results.iocs.urls.length > 0 && (
                    <div className="mb-4">
                        <p className="text-sm text-slate-400 mb-2 font-mono">
                            URLs <span className="text-neon-cyan">({report.results.iocs.urls.length})</span>
                        </p>
                        <div className="code-block">
                            {report.results.iocs.urls.map((url, i) => (
                                <div key={i} className="flex">
                                    <span className="text-slate-500 select-none mr-4">{String(i + 1).padStart(2, '0')}</span>
                                    <span className="text-caution-yellow break-all">{url}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.domains.length > 0 && (
                    <div className="mb-4">
                        <p className="text-sm text-slate-400 mb-2 font-mono">
                            Domains <span className="text-neon-cyan">({report.results.iocs.domains.length})</span>
                        </p>
                        <div className="code-block">
                            {report.results.iocs.domains.map((domain, i) => (
                                <div key={i} className="flex">
                                    <span className="text-slate-500 select-none mr-4">{String(i + 1).padStart(2, '0')}</span>
                                    <span className="text-neon-purple break-all">{domain}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.ips.length > 0 && (
                    <div>
                        <p className="text-sm text-slate-400 mb-2 font-mono">
                            IPs <span className="text-neon-cyan">({report.results.iocs.ips.length})</span>
                        </p>
                        <div className="code-block">
                            {report.results.iocs.ips.map((ip, i) => (
                                <div key={i} className="flex">
                                    <span className="text-slate-500 select-none mr-4">{String(i + 1).padStart(2, '0')}</span>
                                    <span className="text-alert-red">{ip}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.urls.length === 0 &&
                    report.results.iocs.domains.length === 0 &&
                    report.results.iocs.ips.length === 0 && (
                        <p className="text-slate-500 font-mono text-sm">NO IOC DETECTED</p>
                    )}
            </div>

            {/* Timing */}
            <div className="glass-card p-6 mb-4">
                <h2 className="text-lg font-bold mb-4 text-neon-cyan">⏱️ 分析耗時</h2>
                <div className="space-y-1">
                    {report.timings.stages.map((stage, index) => (
                        <div key={index} className="stage-item font-mono text-sm">
                            <span className="text-slate-400">{stageLabels[stage.name] || stage.name}</span>
                            <span className="text-matrix-green">{stage.duration_ms} ms</span>
                        </div>
                    ))}
                    <div className="stage-item font-mono text-sm pt-2 border-t border-white/10">
                        <span className="font-bold text-white">TOTAL</span>
                        <span className="font-bold text-neon-cyan">{report.timings.total_ms} ms</span>
                    </div>
                </div>
            </div>

            {/* Sandbox Mock Notice */}
            {report.results.sandbox.is_mock && (
                <div className="glass-card p-6 mb-4 opacity-60">
                    <h2 className="text-lg font-bold mb-2 text-slate-400">🧪 沙箱分析 (Mock)</h2>
                    <p className="text-sm text-slate-500 font-mono">
                        SANDBOX_MOCK: TRUE • REAL ANALYSIS AVAILABLE IN V2
                    </p>
                </div>
            )}

            {/* Back Link */}
            <Link
                to="/"
                className="inline-flex items-center gap-2 mt-2 text-sm font-mono text-slate-400 hover:text-neon-cyan transition-colors"
            >
                <span>←</span>
                <span>上傳新檔案</span>
            </Link>
        </div>
    )
}
