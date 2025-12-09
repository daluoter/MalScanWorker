import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { apiClient, Report } from '../api/client'

export default function ReportPage() {
    const { jobId } = useParams<{ jobId: string }>()
    const [report, setReport] = useState<Report | null>(null)
    const [error, setError] = useState<string | null>(null)

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

    if (!report) {
        return (
            <div className="container">
                <h1>⏳ 載入報告中...</h1>
            </div>
        )
    }

    const verdictLabels: Record<string, string> = {
        clean: '安全',
        suspicious: '可疑',
        malicious: '惡意',
        unknown: '未知',
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
            <h1>📋 分析報告</h1>

            {/* 總結 */}
            <div className="card">
                <h2>判定結果</h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                    <span
                        className={`verdict-${report.verdict}`}
                        style={{ fontSize: '2rem', fontWeight: 'bold' }}
                    >
                        {verdictLabels[report.verdict] || report.verdict}
                    </span>
                    <span style={{ fontSize: '1.5rem', color: 'var(--color-text-secondary)' }}>
                        風險分數: {report.score}/100
                    </span>
                </div>
            </div>

            {/* 檔案資訊 */}
            <div className="card">
                <h2>📄 檔案資訊</h2>
                <dl style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '0.5rem' }}>
                    <dt>檔名</dt>
                    <dd>{report.file.original_filename}</dd>
                    <dt>類型</dt>
                    <dd>{report.file.mime}</dd>
                    <dt>大小</dt>
                    <dd>{(report.file.size / 1024).toFixed(2)} KB</dd>
                    <dt>SHA256</dt>
                    <dd style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                        {report.file.sha256}
                    </dd>
                </dl>
            </div>

            {/* AV 結果 */}
            <div className="card">
                <h2>🛡️ 防毒掃描</h2>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>{report.results.av_result.engine}</span>
                    <span className={report.results.av_result.infected ? 'verdict-malicious' : 'verdict-clean'}>
                        {report.results.av_result.infected
                            ? `偵測到威脅: ${report.results.av_result.threat_name}`
                            : '未偵測到威脅'}
                    </span>
                </div>
            </div>

            {/* YARA 結果 */}
            {report.results.yara_hits.length > 0 && (
                <div className="card">
                    <h2>🎯 YARA 規則匹配</h2>
                    <ul className="stage-list">
                        {report.results.yara_hits.map((hit, index) => (
                            <li key={index} className="stage-item">
                                <div>
                                    <strong>{hit.rule}</strong>
                                    <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                                        {hit.tags.join(', ')}
                                    </div>
                                </div>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {/* IOC */}
            <div className="card">
                <h2>🔗 IOC 指標</h2>

                {report.results.iocs.urls.length > 0 && (
                    <div style={{ marginBottom: '1rem' }}>
                        <strong>URLs ({report.results.iocs.urls.length})</strong>
                        <div className="ioc-list" style={{ marginTop: '0.5rem' }}>
                            {report.results.iocs.urls.map((url, i) => (
                                <span key={i} className="ioc-tag">{url}</span>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.domains.length > 0 && (
                    <div style={{ marginBottom: '1rem' }}>
                        <strong>Domains ({report.results.iocs.domains.length})</strong>
                        <div className="ioc-list" style={{ marginTop: '0.5rem' }}>
                            {report.results.iocs.domains.map((domain, i) => (
                                <span key={i} className="ioc-tag">{domain}</span>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.ips.length > 0 && (
                    <div>
                        <strong>IPs ({report.results.iocs.ips.length})</strong>
                        <div className="ioc-list" style={{ marginTop: '0.5rem' }}>
                            {report.results.iocs.ips.map((ip, i) => (
                                <span key={i} className="ioc-tag">{ip}</span>
                            ))}
                        </div>
                    </div>
                )}

                {report.results.iocs.urls.length === 0 &&
                    report.results.iocs.domains.length === 0 &&
                    report.results.iocs.ips.length === 0 && (
                        <p style={{ color: 'var(--color-text-secondary)' }}>未發現 IOC</p>
                    )}
            </div>

            {/* 耗時 */}
            <div className="card">
                <h2>⏱️ 分析耗時</h2>
                <ul className="stage-list">
                    {report.timings.stages.map((stage, index) => (
                        <li key={index} className="stage-item">
                            <span>{stageLabels[stage.name] || stage.name}</span>
                            <span>{stage.duration_ms} ms</span>
                        </li>
                    ))}
                    <li className="stage-item" style={{ fontWeight: 'bold' }}>
                        <span>總耗時</span>
                        <span>{report.timings.total_ms} ms</span>
                    </li>
                </ul>
            </div>

            {/* Sandbox (Mock 提示) */}
            {report.results.sandbox.is_mock && (
                <div className="card" style={{ opacity: 0.7 }}>
                    <h2>🧪 沙箱分析 (Mock)</h2>
                    <p style={{ color: 'var(--color-text-secondary)' }}>
                        此為模擬資料，真實沙箱分析將在 v2 版本提供。
                    </p>
                </div>
            )}

            <Link to="/" style={{ display: 'inline-block', marginTop: '1rem' }}>
                ← 上傳新檔案
            </Link>
        </div>
    )
}
