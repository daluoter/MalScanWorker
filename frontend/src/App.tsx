import { BrowserRouter, Routes, Route } from 'react-router-dom'
import UploadPage from './pages/UploadPage'
import JobStatusPage from './pages/JobStatusPage'
import ReportPage from './pages/ReportPage'

function App() {
    // GitHub Pages project pages base path
    const basename = import.meta.env.BASE_URL

    return (
        <div className="min-h-screen bg-deep-space cyber-grid relative">
            {/* Ambient Glow Effects */}
            <div className="fixed inset-0 pointer-events-none overflow-hidden">
                {/* Top-left cyan glow */}
                <div className="absolute -top-40 -left-40 w-80 h-80 bg-neon-cyan/20 rounded-full blur-[100px]" />
                {/* Bottom-right purple glow */}
                <div className="absolute -bottom-40 -right-40 w-80 h-80 bg-neon-purple/20 rounded-full blur-[100px]" />
            </div>

            {/* Main Content */}
            <div className="relative z-10">
                <BrowserRouter basename={basename}>
                    <Routes>
                        <Route path="/" element={<UploadPage />} />
                        <Route path="/jobs/:jobId" element={<JobStatusPage />} />
                        <Route path="/reports/:jobId" element={<ReportPage />} />
                    </Routes>
                </BrowserRouter>
            </div>
        </div>
    )
}

export default App
