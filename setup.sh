#!/bin/bash

# CyberSec AI Assistant - Setup Script
# This script sets up the development environment

set -e

echo "🛡️  CyberSec AI Assistant - Setup"
echo "=================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

echo "✅ Docker found: $(docker --version)"

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker Compose found: $(docker-compose --version)"
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p scan_results logs config tests backend utils frontend
echo "✅ Directories created"
echo ""

# Check if Node.js is installed (for React)
if ! command -v node &> /dev/null; then
    echo "⚠️  Node.js is not installed. React frontend development requires Node.js."
    echo "   Install Node.js from https://nodejs.org/"
    echo "   For production, Docker will handle the build."
else
    echo "✅ Node.js found: $(node --version)"
    echo "✅ npm found: $(npm --version)"
fi
echo ""

# Install frontend dependencies if node_modules doesn't exist
if [ -d "frontend" ] && [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend
    npm install
    cd ..
    echo "✅ Frontend dependencies installed"
    echo ""
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
# Docker Configuration
DOCKER_HOST=unix:///var/run/docker.sock

# Logging
LOG_LEVEL=info

# Scan Configuration
SCAN_TIMEOUT=3600
MAX_CONCURRENT_SCANS=5
EOF
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists"
fi
echo ""

# Pull required Docker images
echo "🐳 Pulling Docker images..."
docker pull frapsoft/nikto:latest || echo "⚠️  Failed to pull nikto image, will pull during first scan"
echo "✅ Docker setup complete"
echo ""

# Set permissions for scripts
echo "🔐 Setting script permissions..."
chmod +x run.sh stop.sh setup.sh 2>/dev/null || true
echo "✅ Permissions set"
echo ""

echo "✨ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Review .env file and adjust settings if needed"
echo "  2. Run './run.sh' to start the application"
echo "  3. Open http://localhost:8000 in your browser"
echo ""

