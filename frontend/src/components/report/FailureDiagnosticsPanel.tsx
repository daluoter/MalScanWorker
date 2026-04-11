import type { ExplainabilityBlock } from '../../api/types'
import {
    localizeConfidence,
    localizeDiagnosticCategory,
    localizeDiagnosticCode,
    localizeDirection,
    localizeEffect,
    localizeReportText,
    localizeSeverity,
    localizeStage,
    localizeStatus,
    localizeUncertaintyKind,
} from './reportText'

interface FailureDiagnosticsPanelProps {
    explainability?: ExplainabilityBlock
}

function statusClass(status: string): string {
    if (status === 'blocked') return 'border-alert-red/30 text-alert-red bg-alert-red/10'
    if (status === 'degraded') return 'border-caution-yellow/30 text-caution-yellow bg-caution-yellow/10'
    return 'border-matrix-green/30 text-matrix-green bg-matrix-green/10'
}

export default function FailureDiagnosticsPanel({ explainability }: FailureDiagnosticsPanelProps) {
    const diagnostics = explainability?.failure_diagnostics
    const uncertainties = explainability?.uncertainties ?? []

    if (!diagnostics) {
        return null
    }

    return (
        <section className="glass-card p-6 mb-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <h2 className="text-lg font-bold text-neon-cyan">🧭 診斷與不確定性</h2>
                <span className={`rounded-full border px-3 py-1 font-mono text-xs ${statusClass(diagnostics.status)}`}>
                    {localizeStatus(diagnostics.status)}
                </span>
            </div>

            {diagnostics.headline && <p className="mt-3 text-sm text-slate-300">{localizeReportText(diagnostics.headline)}</p>}

            <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="space-y-3">
                    <h3 className="font-mono text-xs tracking-[0.3em] text-slate-400">診斷項目</h3>
                    {diagnostics.diagnostics.length > 0 ? (
                        diagnostics.diagnostics.map((diagnostic, index) => (
                            <article key={`${diagnostic.code}-${index}`} className="rounded-xl border border-white/10 bg-slate-900/50 p-4">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                    <span className="font-semibold text-white">{localizeDiagnosticCode(diagnostic.code)}</span>
                                    <span className="font-mono text-xs text-slate-400">
                                        {localizeStage(diagnostic.stage || 'unknown')}
                                    </span>
                                </div>
                                <p className="mt-2 text-sm text-slate-300">{localizeReportText(diagnostic.message)}</p>
                                <div className="mt-2 flex flex-wrap gap-3 font-mono text-xs text-slate-500">
                                    <span>{localizeDiagnosticCategory(diagnostic.category)}</span>
                                    <span>{localizeSeverity(diagnostic.severity)}</span>
                                    <span>{localizeEffect(diagnostic.likely_effect)}</span>
                                    <span>信心 {localizeConfidence(diagnostic.confidence)}</span>
                                </div>
                                {diagnostic.recommended_action && (
                                    <p className="mt-2 text-xs text-neon-cyan">{localizeReportText(diagnostic.recommended_action)}</p>
                                )}
                            </article>
                        ))
                    ) : (
                        <div className="rounded-xl border border-white/10 bg-slate-900/40 p-4 text-sm text-slate-400">
                            目前沒有阻斷或降級類型的診斷項目。
                        </div>
                    )}
                </div>

                <div className="space-y-3">
                    <h3 className="font-mono text-xs tracking-[0.3em] text-slate-400">不確定性</h3>
                    {uncertainties.length > 0 ? (
                        uncertainties.map((uncertainty) => (
                            <article key={uncertainty.uncertainty_id} className="rounded-xl border border-white/10 bg-slate-900/50 p-4">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                    <span className="font-semibold text-white">{localizeUncertaintyKind(uncertainty.kind)}</span>
                                    <span className="font-mono text-xs text-slate-400">{localizeDirection(uncertainty.direction)}</span>
                                </div>
                                <p className="mt-2 text-sm text-slate-300">{localizeReportText(uncertainty.message)}</p>
                            </article>
                        ))
                    ) : diagnostics.suspected_miss_stages.length > 0 ? (
                        diagnostics.suspected_miss_stages.map((stage, index) => (
                            <article key={`${stage.stage}-${index}`} className="rounded-xl border border-white/10 bg-slate-900/50 p-4">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                    <span className="font-semibold text-white">{localizeStage(stage.stage)}</span>
                                    <span className="font-mono text-xs text-slate-400">信心 {localizeConfidence(stage.confidence)}</span>
                                </div>
                                <p className="mt-2 text-sm text-slate-300">{localizeReportText(stage.reason)}</p>
                            </article>
                        ))
                    ) : (
                        <div className="rounded-xl border border-white/10 bg-slate-900/40 p-4 text-sm text-slate-400">
                            目前沒有額外的不確定性說明。
                        </div>
                    )}
                </div>
            </div>
        </section>
    )
}
