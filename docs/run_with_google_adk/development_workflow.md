# Development Workflow Guide

This guide covers the complete development cycle for the Google ADK Security Agent, from initial setup through deployment to production. It's designed for developers who want to iterate quickly and test thoroughly before deploying.

## Overview

The development workflow follows this cycle:
1. **Initial Setup** - Environment, dependencies, and configuration
2. **Local Development** - Code with auto-reload and rapid testing
3. **Local Testing** - Validate functionality in development environment
4. **Cloud Run Testing** - Integration testing in cloud environment
5. **Production Deployment** - Deploy to AgentSpace for full integration

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
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_LOCATION=us-central1

# Required for Chronicle/SecOps integration
CHRONICLE_PROJECT_ID=your-chronicle-project
CHRONICLE_CUSTOMER_ID=your-customer-id
CHRONICLE_REGION=us

# Required for SOAR integration
SOAR_URL=your-soar-instance-url
SOAR_APP_KEY=your-soar-app-key

# Required for Virus Total integration
VT_APIKEY=your-virustotal-api-key
```

### Authenticate with Google Cloud

```bash
gcloud auth application-default login
gcloud config set project your-project-id
```

## 2. Local Development

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

## 4. Cloud Run Testing

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

## 5. Production Deployment

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
3. **Validate in cloud**: Test with `make cloudrun-deploy` before production
4. **Monitor deployment**: Check logs and metrics after deployment

## Deployment Comparison

| Method | Use Case | URL | Features | Best For |
|--------|----------|-----|----------|----------|
| `make local-dev-run` | Development | `localhost:8080` | Auto-reload, debugging | Active development |
| `make cloudrun-deploy` | Testing | Cloud Run URL | Cloud integration | Integration testing |
| `make adk-deploy` + AgentSpace | Production | AgentSpace URL | Full platform | Production use |

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