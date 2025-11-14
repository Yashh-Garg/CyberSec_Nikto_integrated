# CyberSec AI Assistant - Stop Script (PowerShell)
# This script stops the application

Write-Host "🛡️  CyberSec AI Assistant - Stopping" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# Stop containers
Write-Host "🛑 Stopping containers..." -ForegroundColor Yellow
docker-compose down

Write-Host ""
Write-Host "✅ Application stopped!" -ForegroundColor Green
Write-Host ""

