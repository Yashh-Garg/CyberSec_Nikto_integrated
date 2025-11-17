import { useState } from "react";
import { Play, Info } from "lucide-react";
import { initiateScan, getScanStatus } from "../services/api";

function ScanForm({ onScanComplete }) {
  const [formData, setFormData] = useState({
    scanner: "nikto",
    target: "",
    port: 80,
    ssl: false,
    scanMode: "all",
    selectedScans: [],
    zapScanType: "baseline", // For ZAP: baseline, quick, full
  });
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Nikto tuning options
  const niktoScanTypes = [
    {
      id: "0",
      name: "File Upload",
      description: "Test for file upload vulnerabilities",
    },
    {
      id: "1",
      name: "Interesting Files",
      description: "Check for interesting files seen in logs",
    },
    {
      id: "2",
      name: "Misconfiguration",
      description: "Default files and misconfigurations",
    },
    {
      id: "3",
      name: "Information Disclosure",
      description: "Sensitive information exposure",
    },
    {
      id: "4",
      name: "Injection (XSS/Script)",
      description: "Cross-site scripting and script injection",
    },
    {
      id: "5",
      name: "Remote File Retrieval (Web Root)",
      description: "Files accessible within web root",
    },
    {
      id: "6",
      name: "Denial of Service",
      description: "DoS vulnerability checks",
    },
    {
      id: "7",
      name: "Remote File Retrieval (Server Wide)",
      description: "Files accessible server-wide",
    },
    {
      id: "8",
      name: "Code Execution",
      description: "Remote code execution vulnerabilities",
    },
    {
      id: "9",
      name: "SQL Injection",
      description: "SQL injection vulnerabilities",
    },
    {
      id: "a",
      name: "Authentication Bypass",
      description: "Authentication bypass attempts",
    },
    {
      id: "b",
      name: "Software Identification",
      description: "Identify server software versions",
    },
    {
      id: "c",
      name: "Remote Source Inclusion",
      description: "Remote file inclusion vulnerabilities",
    },
  ];

  // ZAP scan types with estimated times
  const zapScanTypes = [
    {
      id: "baseline",
      name: "Baseline Scan",
      description: "Quick passive scan (10-15 minutes)",
      duration: "~10-15 min",
      icon: "⚡",
    },
    {
      id: "quick",
      name: "Quick Active Scan",
      description: "Limited active scanning (15-20 minutes)",
      duration: "~15-20 min",
      icon: "🔍",
    },
    {
      id: "full",
      name: "Full Scan",
      description: "Comprehensive active scanning (30-60 minutes)",
      duration: "~30-60 min",
      icon: "🔬",
    },
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (isSubmitting || loading) {
      return;
    }

    setIsSubmitting(true);
    setLoading(true);
    setStatus({ type: "pending", message: "Initiating scan..." });

    try {
      // Build options based on scanner and mode
      const options = [];
      if (formData.scanner === "nikto") {
        if (
          formData.scanMode === "selective" &&
          formData.selectedScans.length > 0
        ) {
          const tuningOptions = formData.selectedScans.join("");
          options.push("-Tuning", tuningOptions);
        } else {
          options.push("-Tuning", "x");
        }
      } else if (formData.scanner === "zap") {
        // ZAP scan type is handled separately, not in options
        options.push("--scan-type", formData.zapScanType);
      }

      const response = await initiateScan({
        target: formData.target,
        port: formData.port,
        ssl: formData.ssl,
        scan_type: formData.scanner,
        options: options,
        scan_mode: formData.scanMode,
        selected_scans:
          formData.scanMode === "selective" ? formData.selectedScans : null,
      });

      setStatus({
        type: "pending",
        message: "Scan queued. Waiting for results...",
      });
      pollScanStatus(response.scan_id);
    } catch (error) {
      setStatus({
        type: "failed",
        message: error.response?.data?.detail || "Failed to initiate scan",
      });
      setLoading(false);
      setIsSubmitting(false);
    }
  };

  const pollScanStatus = async (scanId) => {
    const pollInterval = setInterval(async () => {
      try {
        const data = await getScanStatus(scanId);

        if (data.status === "running") {
          setStatus({ type: "running", message: "Scan in progress..." });
        } else if (data.status === "completed") {
          clearInterval(pollInterval);
          setStatus({
            type: "completed",
            message: `Scan completed! Found ${
              data.findings_count || 0
            } vulnerabilities.`,
          });
          setLoading(false);
          setIsSubmitting(false);
          onScanComplete(data);
        } else if (data.status === "failed") {
          clearInterval(pollInterval);
          setStatus({
            type: "failed",
            message: `Scan failed: ${data.error || "Unknown error"}`,
          });
          setLoading(false);
          setIsSubmitting(false);
        }
      } catch (error) {
        clearInterval(pollInterval);
        setStatus({
          type: "failed",
          message: "Error checking scan status",
        });
        setLoading(false);
        setIsSubmitting(false);
      }
    }, 5000);
  };

  return (
    <div className="card">
      <h2 className="text-2xl font-bold text-gray-800 mb-4">New Scan</h2>

      {loading && (
        <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center gap-2 text-blue-800">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-800"></div>
            <span className="font-semibold">
              {status?.message || "Scan in progress... Please wait."}
            </span>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Scanner Selection */}
        <div>
          <label className="block text-sm font-semibold text-gray-700 mb-2">
            Scanner Tool
          </label>
          <select
            className="input"
            value={formData.scanner}
            onChange={(e) =>
              setFormData({
                ...formData,
                scanner: e.target.value,
                scanMode: "all",
                selectedScans: [],
                zapScanType: "baseline",
              })
            }
            disabled={loading}
            required
          >
            <option value="nikto">Nikto - Web Server Scanner</option>
            <option value="zap">
              OWASP ZAP - Application Security Scanner
            </option>
            <option value="nuclei">Nuclei - Template-based CVE Scanner</option>
            <option value="wapiti">Wapiti - Lightweight Web Scanner</option>
          </select>
          <div className="mt-2 p-3 bg-blue-50 border border-blue-200 rounded-lg flex items-start gap-2">
            <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-blue-800">
              {formData.scanner === "nikto"
                ? "Nikto: Fast web server scanner focused on known vulnerabilities, misconfigurations, and security issues. Best for quick server assessments."
                : formData.scanner === "zap"
                ? "OWASP ZAP: Comprehensive web application security scanner with both passive and active testing. Ideal for finding application-level vulnerabilities like XSS, SQLi, and authentication issues."
                : formData.scanner === "nuclei"
                ? "Nuclei: High-speed, template-based scanner focused on CVEs and known vulnerabilities using community-maintained YAML templates."
                : "Wapiti: Lightweight black-box web scanner that injects payloads to find issues like SQL injection, XSS, and file disclosure."}
            </p>
          </div>
        </div>

        {/* Target Input */}
        <div>
          <label className="block text-sm font-semibold text-gray-700 mb-2">
            Target (Hostname or IP)
          </label>
          <input
            type="text"
            className="input"
            placeholder="example.com or 192.168.1.1"
            value={formData.target}
            onChange={(e) =>
              setFormData({ ...formData, target: e.target.value })
            }
            disabled={loading}
            required
          />
        </div>

        {/* Port and SSL */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-2">
              Port
            </label>
            <input
              type="number"
              className="input"
              min="1"
              max="65535"
              value={formData.port}
              onChange={(e) =>
                setFormData({ ...formData, port: parseInt(e.target.value) })
              }
              disabled={loading}
              required
            />
          </div>
          <div className="flex items-end">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-5 h-5"
                checked={formData.ssl}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    ssl: e.target.checked,
                    port: e.target.checked ? 443 : 80,
                  })
                }
                disabled={loading}
              />
              <span className="text-sm font-semibold text-gray-700">
                Use HTTPS/SSL
              </span>
            </label>
          </div>
        </div>

        {/* Nikto-specific options */}
        {formData.scanner === "nikto" && (
          <div className="border-t pt-4 mt-4">
            <label className="text-sm font-semibold text-gray-700 mb-3 block">
              Nikto Scan Configuration
            </label>

            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  id="scan-all"
                  name="scanMode"
                  value="all"
                  checked={formData.scanMode === "all"}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      scanMode: "all",
                      selectedScans: [],
                    })
                  }
                  disabled={loading}
                  className="w-4 h-4"
                />
                <label
                  htmlFor="scan-all"
                  className="text-sm text-gray-700 cursor-pointer"
                >
                  <strong>Comprehensive Scan</strong> - All vulnerability tests
                  (recommended)
                </label>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  id="scan-selective"
                  name="scanMode"
                  value="selective"
                  checked={formData.scanMode === "selective"}
                  onChange={(e) =>
                    setFormData({ ...formData, scanMode: "selective" })
                  }
                  disabled={loading}
                  className="w-4 h-4"
                />
                <label
                  htmlFor="scan-selective"
                  className="text-sm text-gray-700 cursor-pointer"
                >
                  <strong>Selective Scan</strong> - Choose specific
                  vulnerability types
                </label>
              </div>
            </div>

            {formData.scanMode === "selective" && (
              <div className="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200 max-h-64 overflow-y-auto">
                <p className="text-xs text-gray-600 mb-3 font-semibold">
                  Select vulnerability types to test:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {niktoScanTypes.map((scanType) => (
                    <div
                      key={scanType.id}
                      className="flex items-start gap-2 p-2 hover:bg-white rounded border border-transparent hover:border-gray-200 transition-all"
                    >
                      <input
                        type="checkbox"
                        id={`scan-${scanType.id}`}
                        checked={formData.selectedScans.includes(scanType.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setFormData({
                              ...formData,
                              selectedScans: [
                                ...formData.selectedScans,
                                scanType.id,
                              ],
                            });
                          } else {
                            setFormData({
                              ...formData,
                              selectedScans: formData.selectedScans.filter(
                                (id) => id !== scanType.id
                              ),
                            });
                          }
                        }}
                        disabled={loading}
                        className="w-4 h-4 mt-1 flex-shrink-0"
                      />
                      <label
                        htmlFor={`scan-${scanType.id}`}
                        className="text-xs text-gray-700 cursor-pointer"
                      >
                        <div className="font-semibold">{scanType.name}</div>
                        <div className="text-gray-500">
                          {scanType.description}
                        </div>
                      </label>
                    </div>
                  ))}
                </div>
                {formData.selectedScans.length === 0 && (
                  <p className="text-xs text-yellow-600 mt-3 flex items-center gap-1">
                    <span>⚠️</span>
                    <span>Please select at least one scan type</span>
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* ZAP-specific options */}
        {formData.scanner === "zap" && (
          <div className="border-t pt-4 mt-4">
            <label className="text-sm font-semibold text-gray-700 mb-3 block">
              OWASP ZAP Scan Type
            </label>

            <div className="space-y-3">
              {zapScanTypes.map((scanType) => (
                <div
                  key={scanType.id}
                  className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                    formData.zapScanType === scanType.id
                      ? "border-primary-500 bg-primary-50"
                      : "border-gray-200 hover:border-gray-300"
                  }`}
                  onClick={() =>
                    !loading &&
                    setFormData({ ...formData, zapScanType: scanType.id })
                  }
                >
                  <div className="flex items-start gap-3">
                    <input
                      type="radio"
                      id={`zap-${scanType.id}`}
                      name="zapScanType"
                      value={scanType.id}
                      checked={formData.zapScanType === scanType.id}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          zapScanType: e.target.value,
                        })
                      }
                      disabled={loading}
                      className="w-5 h-5 mt-0.5 flex-shrink-0"
                    />
                    <div className="flex-1">
                      <label
                        htmlFor={`zap-${scanType.id}`}
                        className="text-sm font-semibold text-gray-800 cursor-pointer flex items-center gap-2"
                      >
                        <span className="text-lg">{scanType.icon}</span>
                        <span>{scanType.name}</span>
                        <span className="text-xs font-normal text-gray-500 ml-auto">
                          {scanType.duration}
                        </span>
                      </label>
                      <p className="text-xs text-gray-600 mt-1">
                        {scanType.description}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <p className="text-xs text-yellow-800">
                <strong>Note:</strong> ZAP scans may take longer than Nikto. The
                full scan is most thorough but requires significant time. For
                quick assessments, use the baseline scan.
              </p>
            </div>
          </div>
        )}

        {/* Submit Button */}
        <button
          type="submit"
          className="btn btn-primary flex items-center gap-2 w-full justify-center"
          disabled={
            loading ||
            isSubmitting ||
            (formData.scanner === "nikto" &&
              formData.scanMode === "selective" &&
              formData.selectedScans.length === 0)
          }
        >
          <Play className="w-5 h-5" />
          {loading && status?.type === "pending"
            ? "Starting Scan..."
            : loading && status?.type === "running"
            ? "Scanning in Progress..."
            : loading
            ? "Processing..."
            : "Start Security Scan"}
        </button>
      </form>

      {/* Status Messages */}
      {status && (
        <div
          className={`mt-4 p-4 rounded-lg border ${
            status.type === "pending"
              ? "bg-yellow-50 text-yellow-800 border-yellow-200"
              : status.type === "running"
              ? "bg-blue-50 text-blue-800 border-blue-200"
              : status.type === "completed"
              ? "bg-green-50 text-green-800 border-green-200"
              : "bg-red-50 text-red-800 border-red-200"
          }`}
        >
          <div className="flex items-center gap-2">
            {status.type === "running" && (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
            )}
            <span>{status.message}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanForm;
