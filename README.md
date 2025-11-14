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

## 🏗️ Architecture

### System Architecture Overview

The CyberSec AI Assistant follows a modern microservices-inspired architecture with a clear separation between frontend, backend, and scanner components.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                             │
│  ┌──────────────────┐         ┌──────────────────┐             │
│  │   React Frontend │         │   REST API       │             │
│  │   (Vite + React) │◄───────►│   Clients        │             │
│  │   Port: 5173     │         │   (curl, etc.)   │             │
│  └──────────────────┘         └──────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              FastAPI Backend (Python)                     │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │   API Routes │  │  Background  │  │   File       │  │  │
│  │  │   & Endpoints│  │   Tasks      │  │   Manager    │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │   Parser     │  │  Analytics   │  │   CVE        │  │  │
│  │  │   Utils      │  │   Utils      │  │   Lookup     │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                        Port: 8000                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Scanner Layer                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Scanner Integration                          │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │   Nikto      │  │   Nmap        │  │   Nuclei      │  │  │
│  │  │   Scanner    │  │   (Planned)   │  │   (Planned)   │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Layer                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         Docker Containers (Scanner Execution)            │  │
│  │  ┌──────────────┐                                        │  │
│  │  │   Nikto      │  (frapsoft/nikto:latest)              │  │
│  │  │   Container  │                                        │  │
│  │  └──────────────┘                                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Storage Layer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Scan       │  │   Logs       │  │   Config      │         │
│  │   Results    │  │   Directory  │  │   Files      │         │
│  │   (JSON)     │  │   (app.log)  │  │   (YAML)     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

### Component Details

#### 1. **Frontend Layer** (React + Vite)
- **Technology**: React 18, Vite, Tailwind CSS
- **Purpose**: User interface for scan management and results visualization
- **Features**: Real-time updates, search/filter, export functionality
- **Port**: 5173 (development) or served from backend (production)

#### 2. **Backend Layer** (FastAPI)
- **Technology**: Python 3.11, FastAPI, Uvicorn
- **Purpose**: RESTful API for scan management and result processing
- **Key Components**:
  - **API Routes**: REST endpoints for scan operations
  - **Background Tasks**: Async scan execution
  - **Parser Utils**: Normalize scanner outputs to unified format
  - **Analytics Utils**: Calculate risk scores and statistics
  - **File Manager**: Persist scan results to disk
- **Port**: 8000

#### 3. **Scanner Layer**
- **Current**: Nikto scanner integration
- **Architecture**: Scanner abstraction layer for multiple scanner support
- **Execution**: Runs scanners in Docker containers for isolation
- **Future**: Nmap, Nuclei integration planned

#### 4. **Docker Layer**
- **Purpose**: Isolated execution environment for security scanners
- **Current Scanner**: `frapsoft/nikto:latest`
- **Benefits**: Consistent execution, no local installation required

#### 5. **Storage Layer**
- **Scan Results**: JSON files in `scan_results/` directory
- **Logs**: Application logs in `logs/app.log`
- **Config**: YAML configuration files in `backend/config/`

### Data Flow

1. **Scan Initiation**:
   ```
   User → Frontend → API POST /api/v1/scan → Background Task Queue
   ```

2. **Scan Execution**:
   ```
   Background Task → Scanner Integration → Docker Container → Target
   ```

3. **Result Processing**:
   ```
   Raw Output → Parser → Normalized Results → Analytics → File Storage
   ```

4. **Result Retrieval**:
   ```
   User → Frontend → API GET /api/v1/scan/{id} → File Manager → Results
   ```

### Deployment Architecture

#### Docker Compose Setup
- **Single Container**: Multi-stage build combining frontend and backend
- **Volume Mounts**: 
  - `scan_results/` for persistent scan data
  - `logs/` for application logs
  - Docker socket for scanner execution
- **Network**: Bridge network for container communication

#### Development Setup
- **Separate Processes**: Frontend (Vite dev server) and Backend (Uvicorn) run independently
- **Hot Reload**: Both services support live reloading during development
- **Proxy**: Frontend proxies API requests to backend

## 🚀 Quick Start

### Prerequisites

- **Docker** 20.10+ and **Docker Compose** 1.29+
- **Git** for cloning the repository
- **Docker Desktop** (recommended for Windows/Mac) or Docker Engine (Linux)

### Installation

#### Step 1: Clone the Repository

**Linux/Mac:**
```bash
git clone <your-repo-url>
cd cybersec-ai-assistant
```

**Windows (PowerShell):**
```powershell
git clone <your-repo-url>
cd cybersec-ai-assistant
```

#### Step 2: Run Setup Script

**Linux/Mac:**
```bash
chmod +x setup.sh run.sh stop.sh
./setup.sh
```

**Windows:**
```powershell
# Option 1: Use Git Bash or WSL
bash setup.sh

# Option 2: Use PowerShell (if setup.ps1 exists)
.\setup.ps1

# Option 3: Manual setup (if scripts don't work)
# Create directories
mkdir scan_results, logs, config, tests -Force
# Install frontend dependencies
cd frontend
npm install
cd ..
```

#### Step 3: Start the Application

**Linux/Mac:**
```bash
./run.sh
```

**Windows (PowerShell):**
```powershell
.\run.ps1
```

**Or manually with Docker Compose:**
```bash
docker-compose up -d --build
```

#### Step 4: Access the Application

Once started, access the application at:
- **Web UI**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Alternative API Docs**: http://localhost:8000/redoc

#### Step 5: Stop the Application

**Linux/Mac:**
```bash
./stop.sh
```

**Windows (PowerShell):**
```powershell
.\stop.ps1
```

**Or manually:**
```bash
docker-compose down
```

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

## 📋 Commands Reference

### Docker Commands (Production/Containerized)

#### Linux/Mac

| Command | Description |
|---------|-------------|
| `./setup.sh` | Initial setup: check dependencies, create directories, install frontend deps |
| `./run.sh` | Build and start the application with Docker Compose |
| `./stop.sh` | Stop all Docker containers |
| `docker-compose up -d --build` | Build and start containers in detached mode |
| `docker-compose down` | Stop and remove containers |
| `docker-compose restart` | Restart containers |
| `docker-compose logs -f` | View all container logs (follow mode) |
| `docker-compose logs -f backend` | View backend logs only |
| `docker-compose ps` | List running containers |
| `docker-compose exec backend bash` | Access backend container shell |

#### Windows (PowerShell)

| Command | Description |
|---------|-------------|
| `.\setup.sh` or `bash setup.sh` | Initial setup (requires Git Bash or WSL) |
| `.\run.ps1` | Build and start the application with Docker Compose |
| `.\stop.ps1` | Stop all Docker containers |
| `docker-compose up -d --build` | Build and start containers in detached mode |
| `docker-compose down` | Stop and remove containers |
| `docker-compose restart` | Restart containers |
| `docker-compose logs -f` | View all container logs (follow mode) |
| `docker-compose logs -f backend` | View backend logs only |
| `docker-compose ps` | List running containers |

**Note**: On Windows, if you don't have WSL2, you may need to use `docker-compose -f docker-compose.windows.yml` for Docker socket configuration.

### Development Commands

#### Backend Setup and Run

**Linux/Mac:**
```bash
# Navigate to backend
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python main.py
# OR
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Windows:**
```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run server
python main.py
# OR
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup and Run

**Linux/Mac/Windows:**
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Testing Commands

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_scanner.py -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html
```

### Docker Management Commands

```bash
# Check Docker status
docker info

# List running containers
docker ps

# List all containers (including stopped)
docker ps -a

# View container logs
docker logs <container_name>
docker logs -f <container_name>  # Follow logs

# Execute command in container
docker exec -it <container_name> bash

# Remove stopped containers
docker container prune

# Remove unused images
docker image prune

# Clean up everything (careful!)
docker system prune -a
```

### API Testing Commands (curl)

```bash
# Health check
curl http://localhost:8000/health

# Initiate a scan
curl -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "testphp.vulnweb.com",
    "port": 80,
    "ssl": false,
    "scan_type": "nikto"
  }'

# Get scan status (replace {scan_id} with actual ID)
curl "http://localhost:8000/api/v1/scan/{scan_id}"

# List all scans
curl "http://localhost:8000/api/v1/scans"

# Get statistics
curl "http://localhost:8000/api/v1/stats"

# Export scan results as JSON
curl "http://localhost:8000/api/v1/scan/{scan_id}/export?format=json" -o results.json

# Export scan results as CSV
curl "http://localhost:8000/api/v1/scan/{scan_id}/export?format=csv" -o results.csv

# Delete a scan
curl -X DELETE "http://localhost:8000/api/v1/scan/{scan_id}"
```

### Git Commands

```bash
# Clone repository
git clone <your-repo-url>
cd cybersec-ai-assistant

# Create feature branch
git checkout -b feature/amazing-feature

# Commit changes
git add .
git commit -m "Add amazing feature"

# Push to remote
git push origin feature/amazing-feature
```

### Utility Commands

```bash
# View application logs
tail -f logs/app.log

# Search in logs
grep "ERROR" logs/app.log

# Check Python version
python --version  # or python3 --version

# Check Node.js version
node --version
npm --version

# Check Docker version
docker --version
docker-compose --version

# List installed Python packages
pip list

# List installed npm packages
npm list --depth=0
```

### Troubleshooting Commands

```bash
# Check if port is in use
# Linux/Mac
lsof -i :8000
netstat -an | grep 8000

# Windows
netstat -ano | findstr :8000

# Check Docker daemon status
docker info

# Restart Docker service (Linux)
sudo systemctl restart docker

# View Docker Compose configuration
docker-compose config

# Force rebuild without cache
docker-compose build --no-cache

# Remove volumes (careful - deletes data!)
docker-compose down -v
```

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
- Can connect on LinkedIn


---

**Version**: 1.0.0 (Phase 1)  
**Last Updated**: November 14, 2025  
**Status**: Active Development

