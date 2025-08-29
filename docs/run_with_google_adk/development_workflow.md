# Development Workflow Guide

This guide covers the complete development cycle for the Google ADK Security Agent, from initial setup through deployment to production. It's designed for developers who want to iterate quickly and test thoroughly before deploying.

## Overview

The development workflow follows this 6-stage cycle designed to catch bugs early:
1. **Initial Setup** - Environment, dependencies, and configuration
2. **Local Development** - Code with auto-reload and rapid testing
3. **Local Testing** - Validate functionality in development environment
4. **Container Testing** - Test in containerized environment (Podman)
5. **Cloud Run Testing** - Integration testing in cloud environment
6. **Production Deployment** - Deploy to AgentSpace for full integration

## 1. Initial Setup

### Prerequisites
- Python 3.11+
- Google Cloud CLI (`gcloud`)
- Git
- A Google Cloud Project with billing enabled

### Environment Setup

```bash
# Clone the repository
git clone https://github.com/google/mcp-security.git
cd mcp-security/run-with-google-adk

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Set up development environment (installs dependencies, checks venv)
make local-dev-setup

# Create environment configuration
make env-setup
```

### Configure Your Environment

Edit `agents/google_mcp_security_agent/.env` with your project settings:

```bash
# Required for all deployments
GOOGLE_CLOUD_PROJECT=<your-project-id>
GOOGLE_CLOUD_LOCATION=us-central1

# Required for Chronicle/SecOps integration
CHRONICLE_PROJECT_ID=<your-chronicle-project>
CHRONICLE_CUSTOMER_ID=<your-customer-id>
CHRONICLE_REGION=us

# Required for SOAR integration
SOAR_URL=<your-soar-instance-url>
SOAR_APP_KEY=<your-soar-app-key>

# Required for Virus Total integration
VT_APIKEY=<your-virustotal-api-key>
```

#### Check your configuration

```
make env-check
```

### Set Project Environment Variables

Set these environment variables for use in commands throughout this guide:

```bash
# Load project variables from your .env file
export PROJECT_ID=$(grep GOOGLE_CLOUD_PROJECT agents/google_mcp_security_agent/.env | cut -d'=' -f2)
export CHRONICLE_PROJECT_ID=$(grep CHRONICLE_PROJECT_ID agents/google_mcp_security_agent/.env | cut -d'=' -f2)
export CHRONICLE_CUSTOMER_ID=$(grep CHRONICLE_CUSTOMER_ID agents/google_mcp_security_agent/.env | cut -d'=' -f2)

# Verify they're set correctly
echo "PROJECT_ID: $PROJECT_ID"
echo "CHRONICLE_PROJECT_ID: $CHRONICLE_PROJECT_ID"
echo "CHRONICLE_CUSTOMER_ID: $CHRONICLE_CUSTOMER_ID"
```

### Authenticate with Google Cloud

```bash
gcloud auth application-default login
gcloud config set project $PROJECT_ID
```

## 2. Local Development

Local MCP agent with web interface.

### Start Development Server

```bash
make local-dev-run
```

This command:
- Validates your virtual environment
- Installs development dependencies (FastAPI, uvicorn, etc.)
- Checks environment configuration
- Starts uvicorn with auto-reload at `http://localhost:8080`

### Development Features

- **Auto-reload**: Changes to Python files automatically restart the server
- **Environment validation**: Ensures all required variables are set
- **Development dependencies**: Includes debugging and development tools
- **FastAPI interface**: Modern web framework with automatic API documentation

### Making Changes

1. **Edit agent code**: Modify files in `agents/google_mcp_security_agent/`
2. **Edit UI components**: Modify files in `ui/static/`
3. **Add MCP servers**: Add servers to the `server/` directory
4. **Update dependencies**: Edit `requirements.txt` or `requirements-dev.txt`

The development server will automatically restart when you save changes.

## 3. Local Testing

### Test Agent Functionality

Open your browser to `http://localhost:8080` and test:

1. **Agent Authentication**: Verify Google Cloud authentication works
2. **MCP Tool Access**: Test individual MCP tools (GTI, SCC, SecOps, SOAR)
3. **Agent Responses**: Send test queries and verify responses
4. **Error Handling**: Test with invalid inputs or missing credentials

### Environment Validation

```bash
# Check environment configuration
make env-check

# View current configuration (masks sensitive values)
make config-show
```

### Debug Mode

Set environment variables for enhanced debugging:

```bash
# In your .env file
DEBUG=true
LOG_LEVEL=DEBUG
```

### Authentication Testing

The `test_chronicle_auth.py` script validates both authentication and Chronicle configuration. It now supports explicit authentication modes and automatically loads configuration from your `.env` file.

#### Authentication Modes

```bash
# Test with Application Default Credentials (default)
# Automatically loads Chronicle configuration from .env file
python test_chronicle_auth.py --auth-mode=adc --verbose

# Test with service account impersonation (recommended for production)
# Step 1: Configure ADC to use impersonation (this modifies ~/.config/gcloud/application_default_credentials.json)
gcloud auth application-default login \
    --impersonate-service-account=chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com

# Step 2: Test that impersonation is working correctly
python test_chronicle_auth.py --auth-mode=impersonation \
    --service-account=chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com

# Test with service account key file
python test_chronicle_auth.py --auth-mode=service-account \
    --key-file=/path/to/service-account-key.json

# Test with manually set environment variables (no .env file)
export CHRONICLE_PROJECT_ID=$CHRONICLE_PROJECT_ID
export CHRONICLE_CUSTOMER_ID=$CHRONICLE_CUSTOMER_ID
python test_chronicle_auth.py --auth-mode=adc --no-env-file
```

#### Key Features

- **Automatic .env Loading**: By default, loads Chronicle configuration from `.env` file
- **Explicit Auth Modes**: Clear specification of authentication method being tested
- **Early Issue Detection**: Tests with the same configuration values that will be deployed
- **Flexible Override**: Use `--no-env-file` to test with manual environment variables

#### Understanding Impersonation Testing

When using `--auth-mode=impersonation`:
- The test **validates** that impersonation is already configured via `gcloud auth application-default login`
- The test does **not** perform the impersonation itself
- The `--service-account` parameter documents which service account should be configured
- Impersonated credentials handle token refresh automatically (different from regular credentials)

The workflow is:
1. Create service account and grant permissions (see below)
2. Configure ADC for impersonation using `gcloud auth application-default login --impersonate-service-account=...`
3. Run the test to validate impersonation is working

#### Service Account Setup (If Using Impersonation)

If you plan to use service account impersonation, you need to create the service account first:

```bash
# Check if the service account already exists
gcloud iam service-accounts list --project=$PROJECT_ID | grep chronicle-mcp-sa

# If it doesn't exist, create it
gcloud iam service-accounts create chronicle-mcp-sa \
    --display-name="Chronicle MCP Service Account" \
    --project=$PROJECT_ID

# Grant yourself permission to impersonate the service account
gcloud iam service-accounts add-iam-policy-binding \
    chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com \
    --member="user:$(gcloud auth list --filter=status:ACTIVE --format='value(account)')" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --project=$PROJECT_ID

# Grant the service account necessary Chronicle permissions
# (Adjust roles as needed for your use case)
gcloud projects add-iam-policy-binding $CHRONICLE_PROJECT_ID \
    --member="serviceAccount:chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/chronicle.viewer"
```

## 4. Container Testing (Podman)

Container testing provides an essential validation layer between local development and cloud deployment. This stage catches container-specific issues and validates authentication in a containerized environment.

### Why Container Testing?

- **Environment Isolation**: Tests application in isolated container environment
- **Authentication Validation**: Ensures Google Cloud auth works in containers
- **Dependency Verification**: Validates all dependencies are properly containerized
- **Performance Testing**: Tests container startup time and resource usage
- **Early Bug Detection**: Catches issues before expensive cloud deployments

### Container Testing Steps

#### Prerequisites

Install Podman if not already available:

```bash
# macOS
brew install podman
podman machine start

# Linux (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install podman

# Verify installation
podman --version
```

#### Build Container Image

```bash
# Build the local Podman image
make local-podman-build
```

This uses `Dockerfile.local` to create a containerized version of your application.

#### Run Container

```bash
# Run the Podman container
make local-podman-run
```

This command:
- Mounts your Google Cloud credentials into the container
- Maps port 8080 for web access
- Sets appropriate environment variables
- Starts the FastAPI application in container

#### Test Container Deployment

```bash
# Open containerized app in browser
open http://localhost:8080

# Test health endpoint
curl -f http://localhost:8080/health || echo "Health check failed"

# Test authentication inside container
podman exec -it $(podman ps -q) python test_chronicle_auth.py --auth-mode=container --verbose
```

#### Container Authentication Testing

The container uses mounted credentials from your local machine:

```bash
# Test with ADC credentials
gcloud auth application-default login
make local-podman-run

# Test with service account impersonation (recommended)
gcloud auth application-default login \
    --impersonate-service-account=chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com
make local-podman-build
make local-podman-run

# Validate authentication inside running container
# Container mode expects pre-configured environment from container runtime
podman exec -it $(podman ps -q) python test_chronicle_auth.py --auth-mode=container

# You can also test specific auth modes inside the container
podman exec -it $(podman ps -q) python test_chronicle_auth.py --auth-mode=adc
```

### Container Testing Checklist

- [ ] Container builds successfully
- [ ] Container starts without errors
- [ ] Application accessible on http://localhost:8080
- [ ] Health endpoint returns success
- [ ] Authentication test passes inside container
- [ ] All MCP tools are accessible
- [ ] Error handling works correctly
- [ ] Performance is acceptable

### Troubleshooting Container Issues

**Common Issues:**

1. **"Application Default Credentials not found"**
   - Verify: `ls -la ~/.config/gcloud/application_default_credentials.json`
   - Fix: `gcloud auth application-default login`

2. **"Permission denied accessing credentials"**
   - Fix: `chmod 600 ~/.config/gcloud/application_default_credentials.json`

3. **"Port 8080 already in use"**
   - Find process: `lsof -i :8080`
   - Stop local dev server if running

For more detailed container troubleshooting, see [Podman Workflow Guide](podman_workflow.md).

## 5. Cloud Run Testing

Once local development is complete, test in a cloud environment:

### Deploy to Cloud Run

```bash
make cloudrun-deploy
```

This creates a Cloud Run service with your current code.

### Test Deployed Service

```bash
# Test the deployment
make cloudrun-test

# Get the service URL
make cloudrun-url

# View logs
make cloudrun-logs
```

### Cloud Run Testing Checklist

- [ ] Service starts successfully
- [ ] Authentication works with cloud credentials
- [ ] All MCP tools are accessible
- [ ] Performance is acceptable
- [ ] Error handling works correctly

### Clean Up Cloud Run (Optional)

```bash
make cloudrun-delete
```

## 6. Production Deployment

After successful Cloud Run testing, deploy to production:

### Deploy to Agent Engine

```bash
make adk-deploy
```

Note the `AGENT_ENGINE_RESOURCE_NAME` from the output.

### Update Environment

```bash
make env-update KEY=AGENT_ENGINE_RESOURCE_NAME VALUE=<resource-name-from-deployment>
```

### Configure OAuth for AgentSpace

```bash
make oauth-setup
```

Follow the interactive prompts to set up OAuth authentication.

### Register with AgentSpace

```bash
make agentspace-register
```

### Verify and Test Production

```bash
# Verify the integration
make agentspace-verify

# Test the deployed agent
make test-agent MSG="List available security tools"

# Get AgentSpace URL
make agentspace-url
```

## Development Best Practices

### Code Quality

1. **Follow Python standards**: Use type hints, proper docstrings
2. **Test thoroughly locally**: Validate all functionality before deploying
3. **Use environment variables**: Never hardcode credentials or config
4. **Handle errors gracefully**: Provide meaningful error messages

### Environment Management

1. **Use virtual environments**: Always activate your venv before development
2. **Separate dev dependencies**: Keep development tools separate from production
3. **Validate configuration**: Use `make env-check` frequently
4. **Document changes**: Update environment templates when adding new variables

### Iterative Development

1. **Start small**: Make incremental changes
2. **Test frequently**: Use `make local-dev-run` for rapid iteration
3. **Validate containers**: Use `make local-podman-run` for container testing
4. **Test in cloud**: Use `make cloudrun-deploy` before production
5. **Monitor deployment**: Check logs and metrics after deployment

## Deployment Comparison

| Stage | Method | Use Case | URL | Authentication | Best For |
|-------|--------|----------|-----|----------------|----------|
| 1 | `make local-dev-run` | Active development | `localhost:8080` | ADC (user) | Rapid coding iteration |
| 2 | `make local-podman-run` | Container testing | `localhost:8080` | ADC or Service Account | Pre-deployment validation |
| 3 | `make cloudrun-deploy` | Cloud integration | Cloud Run URL | Service Account | Cloud environment testing |
| 4 | AgentSpace deployment | Production | AgentSpace URL | OAuth + Service Account | Full platform testing |

### Deployment Strategy

**For Active Development:**
- Use `make local-dev-run` with auto-reload
- Test authentication with `python test_chronicle_auth.py --auth-mode=adc`
- Configuration automatically loaded from `.env` file

**Before Cloud Deployment:**
- Build and test container with `make local-podman-build` and `make local-podman-run`
- Validate containerized authentication with service account impersonation
- Run container auth tests: `podman exec -it $(podman ps -q) python test_chronicle_auth.py --auth-mode=container`
- Test specific auth modes: `podman exec -it $(podman ps -q) python test_chronicle_auth.py --auth-mode=impersonation --service-account=...`

**For Cloud Deployment:**
- Deploy to Cloud Run first for cloud-specific testing
- Validate service account authentication in cloud environment
- Only deploy to AgentSpace after successful Cloud Run testing

## Troubleshooting

### Common Issues

**Virtual Environment Issues**
```bash
# Deactivate and recreate venv
deactivate
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
make local-dev-setup
```

**Environment Configuration Issues**
```bash
# Validate and show current config
make env-check
make config-show

# Update specific variables
make env-update KEY=VARIABLE_NAME VALUE=new_value
```

**Authentication Issues**
```bash
# Re-authenticate with Google Cloud
gcloud auth application-default login
gcloud auth list

# Test authentication with automatic .env loading
python test_chronicle_auth.py --auth-mode=adc --verbose

# Test with service account impersonation
gcloud auth application-default login \
    --impersonate-service-account=chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com
python test_chronicle_auth.py --auth-mode=impersonation \
    --service-account=chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com

# Debug with manual environment variables
export CHRONICLE_PROJECT_ID=$CHRONICLE_PROJECT_ID
export CHRONICLE_CUSTOMER_ID=$CHRONICLE_CUSTOMER_ID
python test_chronicle_auth.py --auth-mode=adc --no-env-file --verbose
```

**Service Account Impersonation Issues**
```bash
# Verify impersonation is configured
cat ~/.config/gcloud/application_default_credentials.json | grep service_account_impersonation_url

# Check if service account exists
gcloud iam service-accounts list --project=$PROJECT_ID | grep chronicle-mcp-sa

# Verify you have impersonation permission
gcloud iam service-accounts get-iam-policy \
    chronicle-mcp-sa@$PROJECT_ID.iam.gserviceaccount.com \
    --project=$PROJECT_ID

# Common issues and solutions:
# 1. "Unable to acquire impersonated credentials" - Run gcloud auth application-default login --impersonate-service-account first
# 2. "Not found; Gaia id not found" - Service account doesn't exist or wrong project ID
# 3. "Permission denied" - Missing roles/iam.serviceAccountTokenCreator permission
# 4. Test passes but credentials don't work - Ensure service account has the required Chronicle API permissions
```

**Port Conflicts**
- Local dev server runs on port 8080
- Legacy ADK web UI runs on port 8000
- Change ports in uvicorn command if needed

### Getting Help

1. **Check logs**: Use `make cloudrun-logs` for deployed services
2. **Validate environment**: Use `make env-check` for configuration issues
3. **Check documentation**: Review server-specific docs in `docs/servers/`
4. **Review examples**: Check the agent implementation for working patterns

## Next Steps

- Explore [Advanced Topics](advanced_topics.md) for performance optimization
- Review [Server Documentation](../servers/) for MCP tool details
- See [AgentSpace App Setup](agentspace_app_setup.md) for platform integration