#!/bin/bash

# CyberSec AI Assistant - Run Script
# This script starts the application using Docker Compose

set -e

echo "🛡️  CyberSec AI Assistant - Starting"
echo "====================================="
echo ""

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating default .env..."
    cat > .env << EOF
# Docker Configuration
DOCKER_HOST=unix:///var/run/docker.sock

# Logging
LOG_LEVEL=info

# Scan Configuration
SCAN_TIMEOUT=3600
MAX_CONCURRENT_SCANS=5
EOF
fi

# Build and start containers
echo "🐳 Building and starting containers..."
docker-compose up -d --build

echo ""
echo "✅ Application started!"
echo ""
echo "📊 Services:"
echo "  - Backend API: http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - Web UI (React): http://localhost:8000"
echo ""
echo "💡 Development Mode:"
echo "  - Frontend Dev Server: cd frontend && npm run dev"
echo "  - Backend API: http://localhost:8000"
echo ""
echo "📝 Useful commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop services: ./stop.sh"
echo "  - Restart: docker-compose restart"
echo ""

