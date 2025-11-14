import { BarChart3, Scan, CheckCircle, AlertTriangle } from 'lucide-react'

function Statistics({ stats }) {
  const severityBreakdown = stats.severity_breakdown || {}
  const maxSeverity = Math.max(
    severityBreakdown.CRITICAL || 0,
    severityBreakdown.HIGH || 0,
    severityBreakdown.MEDIUM || 0,
    severityBreakdown.LOW || 0,
    1
  )

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-gray-800">Statistics</h2>
        <BarChart3 className="w-6 h-6 text-primary-600" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gradient-to-br from-primary-500 to-primary-600 text-white p-5 rounded-lg text-center">
          <Scan className="w-8 h-8 mx-auto mb-2" />
          <div className="text-3xl font-bold">{stats.total_scans || 0}</div>
          <div className="text-sm opacity-90">Total Scans</div>
        </div>

        <div className="bg-gradient-to-br from-green-500 to-green-600 text-white p-5 rounded-lg text-center">
          <CheckCircle className="w-8 h-8 mx-auto mb-2" />
          <div className="text-3xl font-bold">{stats.completed || 0}</div>
          <div className="text-sm opacity-90">Completed</div>
        </div>

        <div className="bg-gradient-to-br from-blue-500 to-blue-600 text-white p-5 rounded-lg text-center">
          <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
          <div className="text-3xl font-bold">{stats.total_findings || 0}</div>
          <div className="text-sm opacity-90">Total Findings</div>
        </div>

        <div className="bg-gradient-to-br from-purple-500 to-purple-600 text-white p-5 rounded-lg text-center">
          <BarChart3 className="w-8 h-8 mx-auto mb-2" />
          <div className="text-3xl font-bold">
            {stats.success_rate ? `${stats.success_rate.toFixed(1)}%` : '0%'}
          </div>
          <div className="text-sm opacity-90">Success Rate</div>
        </div>
      </div>

      {/* Severity Breakdown Chart */}
      <div className="mt-6">
        <h3 className="text-lg font-semibold text-gray-700 mb-4">Severity Breakdown</h3>
        <div className="flex items-end gap-3 h-40">
          <div className="flex-1 flex flex-col items-center">
            <div
              className="w-full bg-gradient-to-t from-red-600 to-red-500 rounded-t-lg flex items-end justify-center text-white font-bold min-h-[40px] transition-all"
              style={{
                height: `${((severityBreakdown.CRITICAL || 0) / maxSeverity) * 100}%`,
              }}
            >
              {severityBreakdown.CRITICAL || 0}
            </div>
            <div className="mt-2 text-xs font-semibold text-gray-600">CRITICAL</div>
          </div>

          <div className="flex-1 flex flex-col items-center">
            <div
              className="w-full bg-gradient-to-t from-yellow-600 to-yellow-500 rounded-t-lg flex items-end justify-center text-white font-bold min-h-[40px] transition-all"
              style={{
                height: `${((severityBreakdown.HIGH || 0) / maxSeverity) * 100}%`,
              }}
            >
              {severityBreakdown.HIGH || 0}
            </div>
            <div className="mt-2 text-xs font-semibold text-gray-600">HIGH</div>
          </div>

          <div className="flex-1 flex flex-col items-center">
            <div
              className="w-full bg-gradient-to-t from-blue-600 to-blue-500 rounded-t-lg flex items-end justify-center text-white font-bold min-h-[40px] transition-all"
              style={{
                height: `${((severityBreakdown.MEDIUM || 0) / maxSeverity) * 100}%`,
              }}
            >
              {severityBreakdown.MEDIUM || 0}
            </div>
            <div className="mt-2 text-xs font-semibold text-gray-600">MEDIUM</div>
          </div>

          <div className="flex-1 flex flex-col items-center">
            <div
              className="w-full bg-gradient-to-t from-green-600 to-green-500 rounded-t-lg flex items-end justify-center text-white font-bold min-h-[40px] transition-all"
              style={{
                height: `${((severityBreakdown.LOW || 0) / maxSeverity) * 100}%`,
              }}
            >
              {severityBreakdown.LOW || 0}
            </div>
            <div className="mt-2 text-xs font-semibold text-gray-600">LOW</div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Statistics

