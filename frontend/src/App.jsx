import { useState, useEffect } from 'react'
import { Shield } from 'lucide-react'
import ScanForm from './components/ScanForm'
import Statistics from './components/Statistics'
import RecentScans from './components/RecentScans'
import ScanResults from './components/ScanResults'
import { getStats, getScans } from './services/api'

function App() {
  const [stats, setStats] = useState(null)
  const [scans, setScans] = useState([])
  const [currentScan, setCurrentScan] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [refreshKey])

  const loadData = async () => {
    try {
      const [statsData, scansData] = await Promise.all([
        getStats(),
        getScans()
      ])
      setStats(statsData)
      setScans(scansData.scans || [])
    } catch (error) {
      console.error('Error loading data:', error)
    }
  }

  const handleScanComplete = (scanData) => {
    setCurrentScan(scanData)
    setRefreshKey(prev => prev + 1)
  }

  const handleViewScan = (scanData) => {
    setCurrentScan(scanData)
  }

  return (
    <div className="min-h-screen p-5">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="card mb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary-600" />
            <div>
              <h1 className="text-3xl font-bold text-gray-800">CyberSec AI Assistant</h1>
              <p className="text-gray-600">Vulnerability Scanning Platform - Nikto & OWASP ZAP Integration</p>
            </div>
          </div>
        </div>

        {/* Scan Form */}
        <ScanForm onScanComplete={handleScanComplete} />

        {/* Statistics */}
        {stats && <Statistics stats={stats} />}

        {/* Recent Scans */}
        <RecentScans scans={scans} onViewScan={handleViewScan} />

        {/* Scan Results */}
        {currentScan && (
          <ScanResults 
            scan={currentScan} 
            onClose={() => setCurrentScan(null)}
            onRefresh={loadData}
          />
        )}
      </div>
    </div>
  )
}

export default App

