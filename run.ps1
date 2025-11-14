# CyberSec AI Assistant - Run Script (PowerShell)
# This script starts the application using Docker Compose

Write-Host "🛡️  CyberSec AI Assistant - Starting" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    docker info | Out-Null
} catch {
    Write-Host "❌ Docker is not running. Please start Docker first." -ForegroundColor Red
    exit 1
}

# Check if .env exists
if (-not (Test-Path .env)) {
    Write-Host "⚠️  .env file not found. Creating default .env..." -ForegroundColor Yellow
    @"
# Docker Configuration
DOCKER_HOST=unix:///var/run/docker.sock

# Logging
LOG_LEVEL=info

# Scan Configuration
SCAN_TIMEOUT=3600
MAX_CONCURRENT_SCANS=5
"@ | Out-File -FilePath .env -Encoding utf8
}

# Build and start containers
Write-Host "🐳 Building and starting containers..." -ForegroundColor Cyan
docker-compose up -d --build

Write-Host ""
Write-Host "✅ Application started!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Services:" -ForegroundColor Cyan
Write-Host "  - Backend API: http://localhost:8000"
Write-Host "  - API Docs: http://localhost:8000/docs"
Write-Host "  - Web UI: http://localhost:8000"
Write-Host ""
Write-Host "📝 Useful commands:" -ForegroundColor Cyan
Write-Host "  - View logs: docker-compose logs -f"
Write-Host "  - Stop services: docker-compose down"
Write-Host "  - Restart: docker-compose restart"
Write-Host ""

