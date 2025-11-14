import { useState, useEffect } from 'react'
import { X, Download, Search, Filter, Copy, ChevronDown, ChevronUp } from 'lucide-react'
import { getScanStatus, exportScan } from '../services/api'

function ScanResults({ scan, onClose, onRefresh }) {
  const [findings, setFindings] = useState([])
  const [filteredFindings, setFilteredFindings] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [sortBy, setSortBy] = useState('severity')
  const [expandedFindings, setExpandedFindings] = useState(new Set())

  useEffect(() => {
    loadScanDetails()
  }, [scan])

  useEffect(() => {
    filterAndSortFindings()
  }, [findings, searchTerm, severityFilter, sortBy])

  const loadScanDetails = async () => {
    if (scan.scan_id) {
      try {
        const data = await getScanStatus(scan.scan_id)
        if (data.results && data.results.findings) {
          setFindings(data.results.findings)
        }
      } catch (error) {
        console.error('Error loading scan details:', error)
      }
    } else if (scan.results && scan.results.findings) {
      setFindings(scan.results.findings)
    }
  }

  const filterAndSortFindings = () => {
    let filtered = findings.filter((finding) => {
      const matchesSearch =
        !searchTerm ||
        finding.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.uri?.toLowerCase().includes(searchTerm.toLowerCase())

      const matchesSeverity = !severityFilter || finding.severity === severityFilter

      return matchesSearch && matchesSeverity
    })

    // Sort findings
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
    filtered.sort((a, b) => {
      if (sortBy === 'severity') {
        return (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
      } else if (sortBy === 'title') {
        return (a.title || '').localeCompare(b.title || '')
      } else if (sortBy === 'uri') {
        return (a.uri || '').localeCompare(b.uri || '')
      }
      return 0
    })

    setFilteredFindings(filtered)
  }

  const toggleFinding = (index) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
      alert(`Copied to clipboard: ${text}`)
    } catch (error) {
      console.error('Failed to copy:', error)
    }
  }

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'border-red-500 bg-red-50',
      HIGH: 'border-yellow-500 bg-yellow-50',
      MEDIUM: 'border-blue-500 bg-blue-50',
      LOW: 'border-green-500 bg-green-50',
    }
    return colors[severity] || 'border-gray-300 bg-gray-50'
  }

  const getSeverityBadge = (severity) => {
    const badges = {
      CRITICAL: 'badge-critical',
      HIGH: 'badge-high',
      MEDIUM: 'badge-medium',
      LOW: 'badge-low',
    }
    return badges[severity] || 'badge'
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-gray-800">Scan Results</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={() => exportScan(scan.scan_id || scan.scan_id, 'json')}
            className="btn btn-secondary flex items-center gap-2 text-sm"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
          <button
            onClick={() => exportScan(scan.scan_id || scan.scan_id, 'csv')}
            className="btn btn-secondary flex items-center gap-2 text-sm"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button onClick={onClose} className="btn btn-danger flex items-center gap-2 text-sm">
            <X className="w-4 h-4" />
            Close
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 mb-4">
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              className="input pl-10"
              placeholder="Search findings..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>

        <select
          className="input w-auto min-w-[150px]"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          className="input w-auto min-w-[150px]"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
        >
          <option value="severity">Sort by Severity</option>
          <option value="title">Sort by Title</option>
          <option value="uri">Sort by URI</option>
        </select>
      </div>

      <div className="text-sm text-gray-600 mb-4">
        Showing {filteredFindings.length} of {findings.length} finding(s)
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <p className="text-center text-gray-500 py-8">No findings match your filters.</p>
        ) : (
          filteredFindings.map((finding, index) => {
            const isExpanded = expandedFindings.has(index)
            const severityColor = getSeverityColor(finding.severity)
            const severityBadge = getSeverityBadge(finding.severity)

            return (
              <div
                key={finding.id || index}
                className={`border-l-4 rounded-lg p-4 cursor-pointer transition-all ${severityColor}`}
                onClick={() => toggleFinding(index)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="font-semibold text-gray-800">{finding.title || 'Vulnerability Finding'}</h3>
                      <span className={`badge ${severityBadge}`}>{finding.severity}</span>
                    </div>
                    <p className="text-gray-600 text-sm mb-2">{finding.description || 'No description available'}</p>
                  </div>
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5 text-gray-400 flex-shrink-0 ml-2" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-gray-400 flex-shrink-0 ml-2" />
                  )}
                </div>

                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-gray-200">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      {finding.uri && (
                        <div>
                          <span className="font-semibold text-gray-700">URI:</span>
                          <span className="ml-2 text-gray-600">{finding.uri}</span>
                        </div>
                      )}
                      {finding.method && (
                        <div>
                          <span className="font-semibold text-gray-700">Method:</span>
                          <span className="ml-2 text-gray-600">{finding.method}</span>
                        </div>
                      )}
                      <div>
                        <span className="font-semibold text-gray-700">CVE IDs:</span>
                        <div className="mt-1 flex flex-wrap gap-2">
                          {finding.cve_ids && finding.cve_ids.length > 0 ? (
                            finding.cve_ids.map((cve, idx) => {
                              // Find CVE details if available
                              const cveDetail = finding.cve_details?.find(d => d.id === cve)
                              return (
                              <a
                                key={idx}
                                href={cveDetail?.url || `https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => {
                                  e.stopPropagation()
                                }}
                                className="badge badge-info cursor-pointer hover:bg-blue-200 flex items-center gap-1"
                                title={cveDetail?.description || cve}
                              >
                                {cve}
                                {cveDetail?.cvss_score && (
                                  <span className="text-xs">({cveDetail.cvss_score})</span>
                                )}
                                <Copy className="w-3 h-3" onClick={(e) => {
                                  e.stopPropagation()
                                  e.preventDefault()
                                  copyToClipboard(cve)
                                }} />
                              </a>
                            )
                            })
                          ) : (
                            <span className="text-gray-500">No CVE IDs</span>
                          )}
                        </div>
                      </div>
                      {finding.osvdb_id && (
                        <div>
                          <span className="font-semibold text-gray-700">OSVDB ID:</span>
                          <span className="ml-2 text-gray-600">{finding.osvdb_id}</span>
                        </div>
                      )}
                      {finding.cvss_score && (
                        <div>
                          <span className="font-semibold text-gray-700">CVSS Score:</span>
                          <span className="ml-2 text-gray-600 font-semibold">{finding.cvss_score}</span>
                        </div>
                      )}
                      {finding.remediation && (
                        <div className="mt-2 p-3 bg-blue-50 border border-blue-200 rounded">
                          <div className="font-semibold text-blue-800 mb-1">💡 Remediation:</div>
                          <div className="text-sm text-blue-700">{finding.remediation}</div>
                        </div>
                      )}
                      <div>
                        <span className="font-semibold text-gray-700">Scanner:</span>
                        <span className="ml-2 text-gray-600">{finding.scanner || 'nikto'}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

export default ScanResults

