import { useState } from 'react'
import { Play } from 'lucide-react'
import { initiateScan, getScanStatus } from '../services/api'

function ScanForm({ onScanComplete }) {
  const [formData, setFormData] = useState({
    scanner: 'nikto', // 'nikto' or 'zap'
    target: '',
    port: 80,
    ssl: false,
    scanMode: 'all', // 'all' or 'selective'
    selectedScans: [], // Array of selected scan types
  })
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Nikto tuning options
  const scanTypes = [
    { id: '0', name: 'File Upload', description: 'Test for file upload vulnerabilities' },
    { id: '1', name: 'Interesting Files', description: 'Check for interesting files seen in logs' },
    { id: '2', name: 'Misconfiguration', description: 'Default files and misconfigurations' },
    { id: '3', name: 'Information Disclosure', description: 'Sensitive information exposure' },
    { id: '4', name: 'Injection (XSS/Script)', description: 'Cross-site scripting and script injection' },
    { id: '5', name: 'Remote File Retrieval (Web Root)', description: 'Files accessible within web root' },
    { id: '6', name: 'Denial of Service', description: 'DoS vulnerability checks' },
    { id: '7', name: 'Remote File Retrieval (Server Wide)', description: 'Files accessible server-wide' },
    { id: '8', name: 'Code Execution', description: 'Remote code execution vulnerabilities' },
    { id: '9', name: 'SQL Injection', description: 'SQL injection vulnerabilities' },
    { id: 'a', name: 'Authentication Bypass', description: 'Authentication bypass attempts' },
    { id: 'b', name: 'Software Identification', description: 'Identify server software versions' },
    { id: 'c', name: 'Remote Source Inclusion', description: 'Remote file inclusion vulnerabilities' },
  ]

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    // Prevent duplicate submissions
    if (isSubmitting || loading) {
      return
    }
    
    setIsSubmitting(true)
    setLoading(true)
    setStatus({ type: 'pending', message: 'Initiating scan...' })

    try {
      // Build options based on scan mode (only for Nikto)
      const options = []
      if (formData.scanner === 'nikto') {
        if (formData.scanMode === 'selective' && formData.selectedScans.length > 0) {
          // Use selected scan types
          const tuningOptions = formData.selectedScans.join('')
          options.push('-Tuning', tuningOptions)
        } else {
          // Default: all tests
          options.push('-Tuning', 'x')
        }
      }
      // ZAP doesn't need tuning options, it uses scan type (baseline/quick/full)

      const response = await initiateScan({
        target: formData.target,
        port: formData.port,
        ssl: formData.ssl,
        scan_type: formData.scanner,
        options: options,
        scan_mode: formData.scanMode,
        selected_scans: formData.scanMode === 'selective' ? formData.selectedScans : null,
      })

      setStatus({ type: 'pending', message: 'Scan queued. Waiting for results...' })
      pollScanStatus(response.scan_id)
    } catch (error) {
      setStatus({
        type: 'failed',
        message: error.response?.data?.detail || 'Failed to initiate scan',
      })
      setLoading(false)
      setIsSubmitting(false)
    }
  }

  const pollScanStatus = async (scanId) => {
    const pollInterval = setInterval(async () => {
      try {
        const data = await getScanStatus(scanId)
        
        if (data.status === 'running') {
          setStatus({ type: 'running', message: 'Scan in progress...' })
        } else if (data.status === 'completed') {
          clearInterval(pollInterval)
          setStatus({
            type: 'completed',
            message: `Scan completed! Found ${data.findings_count || 0} vulnerabilities.`,
          })
          setLoading(false)
          setIsSubmitting(false)
          onScanComplete(data)
        } else if (data.status === 'failed') {
          clearInterval(pollInterval)
          setStatus({
            type: 'failed',
            message: `Scan failed: ${data.error || 'Unknown error'}`,
          })
          setLoading(false)
          setIsSubmitting(false)
        }
      } catch (error) {
        clearInterval(pollInterval)
        setStatus({
          type: 'failed',
          message: 'Error checking scan status',
        })
        setLoading(false)
        setIsSubmitting(false)
      }
    }, 5000)
  }

  return (
    <div className="card">
      <h2 className="text-2xl font-bold text-gray-800 mb-4">New Scan</h2>
      {loading && (
        <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center gap-2 text-blue-800">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-800"></div>
            <span className="font-semibold">{status.message || 'Scan in progress... Please wait.'}</span>
          </div>
        </div>
      )}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-semibold text-gray-700 mb-2">
            Scanner
          </label>
          <select
            className="input"
            value={formData.scanner}
            onChange={(e) => setFormData({ ...formData, scanner: e.target.value, scanMode: 'all', selectedScans: [] })}
            disabled={loading}
            required
          >
            <option value="nikto">Nikto</option>
            <option value="zap">OWASP ZAP</option>
          </select>
          <p className="text-xs text-gray-500 mt-1">
            {formData.scanner === 'nikto' 
              ? 'Nikto - Fast web server scanner focused on known vulnerabilities'
              : 'OWASP ZAP - Comprehensive web application security scanner with active and passive scanning'}
          </p>
        </div>

        <div>
          <label className="block text-sm font-semibold text-gray-700 mb-2">
            Target (Hostname or IP)
          </label>
          <input
            type="text"
            className="input"
            placeholder="example.com"
            value={formData.target}
            onChange={(e) => setFormData({ ...formData, target: e.target.value })}
            disabled={loading}
            required
          />
        </div>

        <div>
          <label className="block text-sm font-semibold text-gray-700 mb-2">Port</label>
          <input
            type="number"
            className="input"
            min="1"
            max="65535"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) })}
            disabled={loading}
            required
          />
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="ssl"
            className="w-5 h-5"
            checked={formData.ssl}
            onChange={(e) => setFormData({ ...formData, ssl: e.target.checked })}
            disabled={loading}
          />
          <label htmlFor="ssl" className="text-sm font-semibold text-gray-700">
            Use SSL/TLS
          </label>
        </div>

        {/* Scan Mode Selection - Only show for Nikto */}
        {formData.scanner === 'nikto' && (
          <div className="border-t pt-4 mt-4">
            <label className="text-sm font-semibold text-gray-700 mb-3 block">Scan Mode</label>

            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  id="scan-all"
                  name="scanMode"
                  value="all"
                  checked={formData.scanMode === 'all'}
                  onChange={(e) => setFormData({ ...formData, scanMode: 'all', selectedScans: [] })}
                  disabled={loading}
                  className="w-4 h-4"
                />
                <label htmlFor="scan-all" className="text-sm text-gray-700">
                  <strong>Comprehensive Scan</strong> - All vulnerability tests (slower, thorough)
                </label>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  id="scan-selective"
                  name="scanMode"
                  value="selective"
                  checked={formData.scanMode === 'selective'}
                  onChange={(e) => setFormData({ ...formData, scanMode: 'selective' })}
                  disabled={loading}
                  className="w-4 h-4"
                />
                <label htmlFor="scan-selective" className="text-sm text-gray-700">
                  <strong>Selective Scan</strong> - Choose specific vulnerability types (faster, targeted)
                </label>
              </div>
            </div>

            {/* Selective Scan Options */}
            {formData.scanMode === 'selective' && (
            <div className="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200 max-h-64 overflow-y-auto">
              <p className="text-xs text-gray-600 mb-3">
                Select one or more vulnerability types to scan for:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {scanTypes.map((scanType) => (
                  <div key={scanType.id} className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      id={`scan-${scanType.id}`}
                      checked={formData.selectedScans.includes(scanType.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setFormData({
                            ...formData,
                            selectedScans: [...formData.selectedScans, scanType.id],
                          })
                        } else {
                          setFormData({
                            ...formData,
                            selectedScans: formData.selectedScans.filter((id) => id !== scanType.id),
                          })
                        }
                      }}
                      disabled={loading}
                      className="w-4 h-4 mt-1"
                    />
                    <label
                      htmlFor={`scan-${scanType.id}`}
                      className="text-xs text-gray-700 cursor-pointer"
                    >
                      <div className="font-semibold">{scanType.name}</div>
                      <div className="text-gray-500">{scanType.description}</div>
                    </label>
                  </div>
                ))}
              </div>
              {formData.selectedScans.length === 0 && (
                <p className="text-xs text-yellow-600 mt-2">
                  ⚠️ Please select at least one scan type
                </p>
              )}
            </div>
            )}
          </div>
        )}

        <button
          type="submit"
          className="btn btn-primary flex items-center gap-2 w-full"
          disabled={loading || isSubmitting || (formData.scanner === 'nikto' && formData.scanMode === 'selective' && formData.selectedScans.length === 0)}
        >
          <Play className="w-5 h-5" />
          {loading && status?.type === 'pending' ? 'Starting...' : 
           loading && status?.type === 'running' ? 'Scanning...' :
           loading ? 'Processing...' : 'Start Scan'}
        </button>
      </form>

      {status && (
        <div
          className={`mt-4 p-4 rounded-lg ${
            status.type === 'pending'
              ? 'bg-yellow-50 text-yellow-800 border border-yellow-200'
              : status.type === 'running'
              ? 'bg-blue-50 text-blue-800 border border-blue-200'
              : status.type === 'completed'
              ? 'bg-green-50 text-green-800 border border-green-200'
              : 'bg-red-50 text-red-800 border border-red-200'
          }`}
        >
          {status.message}
        </div>
      )}
    </div>
  )
}

export default ScanForm

