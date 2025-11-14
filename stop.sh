#!/bin/bash

# CyberSec AI Assistant - Stop Script
# This script stops the application

set -e

echo "🛡️  CyberSec AI Assistant - Stopping"
echo "===================================="
echo ""

# Stop containers
echo "🛑 Stopping containers..."
docker-compose down

echo ""
echo "✅ Application stopped!"
echo ""

