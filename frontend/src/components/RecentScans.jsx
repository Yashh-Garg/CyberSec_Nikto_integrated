import { Clock, Eye } from 'lucide-react'
import { formatLocalDate } from '../utils/dateFormat'

function RecentScans({ scans, onViewScan }) {
  if (scans.length === 0) {
    return (
      <div className="card">
        <h2 className="text-2xl font-bold text-gray-800 mb-4">Recent Scans</h2>
        <p className="text-gray-500 text-center py-8">No scans yet. Start a new scan above.</p>
      </div>
    )
  }

  return (
    <div className="card">
      <h2 className="text-2xl font-bold text-gray-800 mb-4">Recent Scans</h2>
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {scans.map((scan) => {
          const statusBadgeClass =
            scan.status === 'completed'
              ? 'badge-success'
              : scan.status === 'failed'
              ? 'badge-danger'
              : scan.status === 'running'
              ? 'badge-info'
              : 'badge-warning'

          return (
            <div
              key={scan.scan_id}
              className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer transition-colors"
              onClick={() => onViewScan(scan)}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <strong className="text-gray-800">{scan.target}:{scan.port}</strong>
                    <span className={`badge ${statusBadgeClass}`}>{scan.status}</span>
                  </div>
                    <div className="flex items-center gap-4 text-sm text-gray-600">
                    <div className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      {formatLocalDate(scan.created_at)}
                    </div>
                    {scan.findings_count !== null && (
                      <span>{scan.findings_count} findings</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onViewScan(scan)
                  }}
                  className="btn btn-secondary flex items-center gap-2 text-sm"
                >
                  <Eye className="w-4 h-4" />
                  View
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default RecentScans

