import { BrowserRouter, Routes, Route } from 'react-router-dom'
import UploadPage from './pages/UploadPage'
import JobStatusPage from './pages/JobStatusPage'
import ReportPage from './pages/ReportPage'

function App() {
    // GitHub Pages project pages base path
    const basename = import.meta.env.BASE_URL

    return (
        <BrowserRouter basename={basename}>
            <Routes>
                <Route path="/" element={<UploadPage />} />
                <Route path="/jobs/:jobId" element={<JobStatusPage />} />
                <Route path="/reports/:jobId" element={<ReportPage />} />
            </Routes>
        </BrowserRouter>
    )
}

export default App
