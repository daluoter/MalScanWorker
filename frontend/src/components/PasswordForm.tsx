import { FormEvent, useState } from 'react'

interface PasswordFormProps {
    attemptsUsed: number
    attemptsRemaining: number
    onSubmit: (password: string) => Promise<void>
    error?: string | null
}

export default function PasswordForm({
    attemptsUsed,
    attemptsRemaining,
    onSubmit,
    error,
}: PasswordFormProps) {
    const [password, setPassword] = useState('')
    const [isSubmitting, setIsSubmitting] = useState(false)

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault()
        if (!password.trim() || isSubmitting) return

        setIsSubmitting(true)
        try {
            await onSubmit(password)
            setPassword('')
        } finally {
            setIsSubmitting(false)
        }
    }

    return (
        <div className="p-4 rounded-lg bg-caution-yellow/10 border border-caution-yellow/40">
            <h2 className="text-lg font-semibold text-caution-yellow">需要解壓密碼</h2>
            <p className="mt-2 text-sm text-slate-300">
                這個壓縮檔需要密碼才能繼續分析，請輸入密碼後提交。
            </p>

            <div className="mt-3 font-mono text-sm text-slate-300">
                <span>已嘗試: {attemptsUsed}</span>
                <span className="mx-2 text-slate-500">|</span>
                <span>剩餘次數: {attemptsRemaining}</span>
            </div>

            <form className="mt-4 flex flex-col gap-3" onSubmit={handleSubmit}>
                <input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="輸入壓縮檔密碼"
                    className="w-full rounded-lg border border-slate-700 bg-deep-space px-3 py-2 text-white placeholder:text-slate-500 focus:border-caution-yellow focus:outline-none"
                    autoComplete="current-password"
                    disabled={isSubmitting}
                />

                <button
                    type="submit"
                    className="self-start rounded-lg bg-caution-yellow px-4 py-2 font-semibold text-black transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={isSubmitting || !password.trim()}
                >
                    {isSubmitting ? '提交中...' : '提交密碼'}
                </button>
            </form>

            {error && (
                <div className="mt-3 rounded-md border border-alert-red bg-alert-red/10 px-3 py-2 text-sm text-alert-red">
                    {error}
                </div>
            )}
        </div>
    )
}
