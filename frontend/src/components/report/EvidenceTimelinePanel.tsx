import type { ExplainabilityBlock } from '../../api/types'
import { localizeAnalyzer, localizeReportText, localizeStage, localizeStatus } from './reportText'

interface EvidenceTimelinePanelProps {
    explainability?: ExplainabilityBlock
}

export default function EvidenceTimelinePanel({ explainability }: EvidenceTimelinePanelProps) {
    const timeline = explainability?.timeline ?? []
    const iocLookup = new Map((explainability?.iocs ?? []).map((item) => [item.ioc_id, item.value]))
    const decodedLookup = new Map(
        (explainability?.decoded_strings ?? []).map((item) => [item.decoded_id, item.content_preview])
    )

    if (!explainability) {
        return null
    }

    return (
        <section className="glass-card p-6 mb-4">
            <h2 className="text-lg font-bold text-neon-cyan">🕒 證據時間軸</h2>
            <div className="mt-4 space-y-3">
                {timeline.length > 0 ? (
                    timeline.map((event) => (
                        <article key={event.timeline_event_id} className="rounded-xl border border-white/10 bg-slate-900/50 p-4">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex items-center gap-3">
                                    <span className="rounded-full border border-neon-cyan/20 px-2 py-0.5 font-mono text-xs text-neon-cyan">
                                        #{event.seq}
                                    </span>
                                    <span className="font-semibold text-white">{localizeReportText(event.summary)}</span>
                                </div>
                                <div className="font-mono text-xs text-slate-400">
                                    {localizeStage(event.stage || 'unknown')}
                                </div>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-3 font-mono text-xs text-slate-500">
                                <span>檔案 {event.artifact_id}</span>
                                <span>狀態 {localizeStatus(event.status)}</span>
                                {event.analyzer && <span>分析器 {localizeAnalyzer(event.analyzer)}</span>}
                            </div>
                            {(event.refs.ioc_ids.length > 0 || event.refs.decoded_ids.length > 0) && (
                                <div className="mt-3 grid gap-2 md:grid-cols-2">
                                    {event.refs.ioc_ids.length > 0 && (
                                        <div className="rounded-lg border border-white/10 bg-black/20 p-3">
                                            <div className="mb-1 font-mono text-[11px] tracking-wide text-caution-yellow">
                                                IOC 關聯
                                            </div>
                                            {event.refs.ioc_ids.map((iocId) => (
                                                <div key={iocId} className="text-sm text-slate-300">
                                                    {iocLookup.get(iocId) || iocId}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    {event.refs.decoded_ids.length > 0 && (
                                        <div className="rounded-lg border border-white/10 bg-black/20 p-3">
                                            <div className="mb-1 font-mono text-[11px] tracking-wide text-neon-purple">
                                                解碼內容
                                            </div>
                                            {event.refs.decoded_ids.map((decodedId) => (
                                                <div key={decodedId} className="text-sm text-slate-300 line-clamp-3 break-all">
                                                    {decodedLookup.get(decodedId) || decodedId}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}
                        </article>
                    ))
                ) : (
                    <div className="rounded-xl border border-white/10 bg-slate-900/40 p-4 text-sm text-slate-400">
                        這份報告目前沒有可顯示的時間軸事件。
                    </div>
                )}
            </div>
        </section>
    )
}
