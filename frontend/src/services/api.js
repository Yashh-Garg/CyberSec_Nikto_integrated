import axios from 'axios'

// In development, use relative URLs to leverage Vite proxy
// In production, use the full API URL
const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? '' : 'http://localhost:8000')

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const initiateScan = async (scanData) => {
  const response = await api.post('/api/v1/scan', scanData)
  return response.data
}

export const getScanStatus = async (scanId) => {
  const response = await api.get(`/api/v1/scan/${scanId}`)
  return response.data
}

export const getScans = async () => {
  const response = await api.get('/api/v1/scans')
  return response.data
}

export const deleteScan = async (scanId) => {
  const response = await api.delete(`/api/v1/scan/${scanId}`)
  return response.data
}

export const getStats = async () => {
  const response = await api.get('/api/v1/stats')
  return response.data
}

export const exportScan = (scanId, format) => {
  const baseUrl = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000' : '')
  window.location.href = `${baseUrl}/api/v1/scan/${scanId}/export?format=${format}`
}

export default api

