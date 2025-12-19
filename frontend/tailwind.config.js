/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                // Background colors
                'deep-space': '#030712',
                'void': '#0B1120',
                // Neon accent colors
                'neon-cyan': '#06b6d4',
                'neon-purple': '#8b5cf6',
                'matrix-green': '#22c55e',
                'alert-red': '#ef4444',
                'caution-yellow': '#eab308',
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'Consolas', 'monospace'],
            },
            animation: {
                'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
                'scan': 'scan 2s linear infinite',
                'glitch': 'glitch 0.3s ease-in-out',
                'terminal-blink': 'terminal-blink 1s step-end infinite',
            },
            keyframes: {
                'glow-pulse': {
                    '0%, 100%': { opacity: '1' },
                    '50%': { opacity: '0.6' },
                },
                'scan': {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100%)' },
                },
                'glitch': {
                    '0%': { transform: 'translate(0)' },
                    '20%': { transform: 'translate(-2px, 2px)' },
                    '40%': { transform: 'translate(-2px, -2px)' },
                    '60%': { transform: 'translate(2px, 2px)' },
                    '80%': { transform: 'translate(2px, -2px)' },
                    '100%': { transform: 'translate(0)' },
                },
                'terminal-blink': {
                    '0%, 100%': { opacity: '1' },
                    '50%': { opacity: '0' },
                },
            },
            dropShadow: {
                'neon-cyan': [
                    '0 0 8px rgba(6, 182, 212, 0.5)',
                    '0 0 20px rgba(6, 182, 212, 0.3)',
                ],
                'neon-purple': [
                    '0 0 8px rgba(139, 92, 246, 0.5)',
                    '0 0 20px rgba(139, 92, 246, 0.3)',
                ],
                'neon-green': [
                    '0 0 8px rgba(34, 197, 94, 0.5)',
                    '0 0 20px rgba(34, 197, 94, 0.3)',
                ],
                'neon-red': [
                    '0 0 8px rgba(239, 68, 68, 0.5)',
                    '0 0 20px rgba(239, 68, 68, 0.3)',
                ],
            },
            boxShadow: {
                'neon-cyan': '0 0 10px rgba(6, 182, 212, 0.5), 0 0 20px rgba(6, 182, 212, 0.3)',
                'neon-purple': '0 0 10px rgba(139, 92, 246, 0.5), 0 0 20px rgba(139, 92, 246, 0.3)',
                'neon-green': '0 0 10px rgba(34, 197, 94, 0.5), 0 0 20px rgba(34, 197, 94, 0.3)',
                'neon-red': '0 0 10px rgba(239, 68, 68, 0.5), 0 0 20px rgba(239, 68, 68, 0.3)',
                'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
            },
            backdropBlur: {
                'glass': '12px',
            },
        },
    },
    plugins: [],
}
