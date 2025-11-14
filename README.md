# 🛡️ CyberSec AI Assistant

A comprehensive Docker-based vulnerability scanning platform with Python backend, designed to integrate multiple security scanners and prepare for AI-powered vulnerability analysis.

## 🎯 Project Overview

CyberSec AI Assistant is a modern vulnerability scanning platform that:
- Integrates multiple security scanners (currently Nikto, with more coming)
- Provides a RESTful API for scan management
- Offers a web-based UI for easy interaction
- Normalizes results from different scanners into a unified format
- Prepares for AI-powered vulnerability analysis (Phase 3)

### Current Status: Phase 1 - Nikto Integration ✅

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 1.29+
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd cybersec-ai-assistant
   ```

2. **Run setup script**
   ```bash
   ./setup.sh
   ```

3. **Start the application**
   ```bash
   ./run.sh
   ```

4. **Access the application**
   - Web UI: http://localhost:8000
   - API Docs: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

## 💻 Development Setup (Run Backend and Frontend Separately)

For development, you can run the backend and frontend separately without Docker.

### Prerequisites for Development

- **Backend**: Python 3.8+ and pip
- **Frontend**: Node.js 16+ and npm

### Running the Backend

1. **Navigate to the backend directory**
   ```bash
   cd backend
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the FastAPI server**
   ```bash
   # From the backend directory
   python main.py
   
   # Or using uvicorn directly
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

5. **Verify the backend is running**
   - API Docs: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

### Running the Frontend

1. **Navigate to the frontend directory**
   ```bash
   cd frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm run dev
   ```

4. **Access the frontend**
   - Web UI: http://localhost:5173
   - The frontend will automatically proxy API requests to `http://localhost:8000`

### Development Workflow

1. **Start the backend first** (in one terminal)
   ```bash
   cd backend
   python main.py
   ```

2. **Start the frontend** (in another terminal)
   ```bash
   cd frontend
   npm run dev
   ```

3. **Access the application**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

### Notes

- The frontend is configured to proxy API requests to `http://localhost:8000` (see `frontend/vite.config.js`)
- Hot reload is enabled for both backend (with `--reload` flag) and frontend (Vite default)
- Make sure Docker is running if you're using the Nikto scanner (it requires Docker to run scans)

## 📁 Project Structure

```
cybersec-ai-assistant/
├── frontend/              # React.js frontend with Tailwind CSS
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── services/      # API service layer
│   │   ├── App.jsx        # Main app component
│   │   └── main.jsx       # Entry point
│   ├── package.json
│   └── vite.config.js
├── backend/               # FastAPI backend
│   ├── main.py            # FastAPI application
│   ├── nikto_scanner.py   # Nikto Docker integration
│   ├── utils/             # Utility modules
│   ├── config/            # Configuration files
│   └── requirements.txt   # Python dependencies
├── scan_results/         # Scanner outputs
├── logs/                  # Application logs
├── Dockerfile             # Multi-stage build (React + Python)
├── docker-compose.yml     # Docker Compose configuration
├── setup.sh               # Setup script
├── run.sh                 # Run script
├── stop.sh                # Stop script
├── README.md              # Main documentation
```

## 🔧 API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web UI |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |
| POST | `/api/v1/scan` | Initiate scan |
| GET | `/api/v1/scan/{id}` | Get scan status |
| GET | `/api/v1/scans` | List all scans |
| DELETE | `/api/v1/scan/{id}` | Delete scan |
| GET | `/api/v1/stats` | Get statistics |
| GET | `/api/v1/scan/{id}/export` | Export scan results (JSON/CSV) |

### Example: Initiate Scan

```bash
curl -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "testphp.vulnweb.com",
    "port": 80,
    "ssl": false,
    "scan_type": "nikto"
  }'
```

### Example: Get Scan Status

```bash
curl "http://localhost:8000/api/v1/scan/{scan_id}"
```

### Example: Export Scan Results

```bash
# Export as JSON
curl "http://localhost:8000/api/v1/scan/{scan_id}/export?format=json" -o results.json

# Export as CSV
curl "http://localhost:8000/api/v1/scan/{scan_id}/export?format=csv" -o results.csv
```

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/ -v
```

## 📊 Features

### Phase 1 (Current) ✅
- ✅ **React.js Frontend** with Tailwind CSS
- ✅ **FastAPI REST API** with CORS support
- ✅ Nikto integration via Docker
- ✅ Advanced result parsing and normalization
- ✅ **Export functionality** (JSON, CSV)
- ✅ Real-time scan status updates
- ✅ **Interactive findings display** with expandable cards
- ✅ **Search and filter** capabilities
- ✅ **Severity-based sorting** and filtering
- ✅ **Visual severity charts** and statistics
- ✅ **CVE copy-to-clipboard** functionality
- ✅ **Detailed finding views** with metadata
- ✅ **Responsive design** for mobile devices
- ✅ **Modern UI/UX** with Tailwind CSS

### Phase 2 (Planned)
- [ ] Nmap integration
- [ ] Nuclei template-based scanning
- [ ] CVE correlation (NVD API)
- [ ] CVSS score calculation
- [ ] PostgreSQL persistence
- [ ] Report generation (PDF/HTML)

### Phase 3 (Future)
- [ ] AI-powered vulnerability analysis
- [ ] RAG-based chatbot integration
- [ ] Natural language queries
- [ ] Automated remediation suggestions

## 🔐 Security Considerations

⚠️ **Important**: This is a development tool. For production use:

- Implement API key authentication
- Add rate limiting
- Validate and sanitize all inputs
- Use HTTPS/TLS encryption
- Implement RBAC (Role-Based Access Control)
- Add audit logging
- Restrict Docker socket access

### Ethical Scanning

- Only scan targets you own or have explicit permission
- Configure firewall rules to prevent abuse
- Implement scan approval workflow
- Log all scan activities
- Comply with local regulations

## 🐛 Troubleshooting

### Docker Issues

If you encounter Docker permission errors:

```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

### Port Already in Use

If port 8000 is already in use, modify `docker-compose.yml`:

```yaml
ports:
  - "8001:8000"  # Change 8001 to your preferred port
```

### View Logs

```bash
# View all logs
docker-compose logs -f

# View backend logs only
docker-compose logs -f backend
```

## 📚 Documentation

All documentation is included in this README. For API details, see the API Endpoints section above.

## 🎨 UI Features After Findings

Once scan results are displayed, you can:

- **🔍 Search & Filter**: Search findings by title/description/URI, filter by severity
- **📊 Sort**: Sort by severity, title, or URI
- **💾 Export**: Download results as JSON or CSV
- **🔎 Expand Details**: Click any finding to see full details (URI, CVE IDs, CVSS scores, etc.)
- **📋 Copy CVEs**: Click CVE badges to copy to clipboard
- **📈 View Statistics**: See severity breakdown charts and overall statistics
- **📜 Browse History**: Click previous scans to view their results

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 for Python
- Use type hints
- Add docstrings
- Write tests for new features


## 👥 Support

For issues, questions, or contributions:
- Open an issue on GitHub


---

**Version**: 1.0.0 (Phase 1)  
**Last Updated**: November 14, 2025  
**Status**: Active Development

