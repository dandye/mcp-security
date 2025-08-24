# Detailed Local Setup Guide

For development purposes, you can run the agent entirely on your local machine.

### Prerequisites
- `python` v3.11+
- `pip`
- `gcloud` CLI

### Setup and Run

```bash
# Clone the repo
git clone https://github.com/google/mcp-security.git

# Navigate to the agent directory
cd mcp-security/run-with-google-adk

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create your .env file from the template
cp agents/google_mcp_security_agent/.env.template agents/google_mcp_security_agent/.env

# Edit agents/google_mcp_security_agent/.env with your credentials and settings
# (e.g., GOOGLE_API_KEY, CHRONICLE_PROJECT_ID, etc.)

# Authenticate for Google Cloud APIs
gcloud auth application-default login

# Option 1: Run with the new development server (recommended for development)
make local-dev-run
# This will:
# - Check your virtual environment
# - Install development dependencies
# - Run uvicorn with auto-reload at http://localhost:8080

# Option 2: Run the agent with the ADK Web UI (legacy approach)
./scripts/run-adk-agent.sh adk_web
```

## Development Options

### Option 1: Modern Development Server (Recommended)
The new development workflow uses FastAPI/Uvicorn with auto-reload for better development experience:

```bash
# Set up development environment (one-time setup)
make local-dev-setup

# Run the development server with auto-reload
make local-dev-run
```

- **URL**: `http://localhost:8080`
- **Features**: Auto-reload on file changes, better error handling
- **Best for**: Active development and debugging

### Option 2: Legacy ADK Web UI
The original approach using ADK's built-in web server:

```bash
./scripts/run-adk-agent.sh adk_web
```

- **URL**: `http://localhost:8000`  
- **Features**: Standard ADK web interface
- **Best for**: Quick testing without modifications
