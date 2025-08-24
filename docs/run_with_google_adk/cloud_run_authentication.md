# Cloud Run Authentication Guide for MCP Servers

This guide explains how to properly handle authentication when deploying MCP servers (SecOps, GTI, SCC, SOAR) to Google Cloud Run. It addresses the common issue where Application Default Credentials (ADC) expire in production environments.

## The Problem: ADC Expiration in Cloud Run

When developing locally, you authenticate using:
```bash
gcloud auth application-default login
```

This creates **user credentials** that work perfectly for local development but have significant limitations in Cloud Run:

1. **Credentials expire** - User tokens have limited lifetimes and will cause service failures
2. **Security risk** - User credentials shouldn't be used in production services
3. **No automatic renewal** - Unlike service accounts, user credentials require manual refresh
4. **Audit trail issues** - Actions appear to be performed by individual users rather than the service

## Authentication Methods Overview

| Method | Local Dev | Cloud Run | Security | Maintenance | Recommended |
|--------|-----------|-----------|----------|-------------|-------------|
| **ADC (User Credentials)** | Excellent | Expires | Medium | Manual | Local only |
| **Service Account (IAM)** | Good | Excellent | High | Automatic | **Production** |
| **Service Account Key File** | Works | Works | Risk | Manual | Not recommended |

## Recommended Approach: Service Account with IAM

### Why Service Accounts?

- **Automatic credential management** - Google manages token refresh
- **Precise permissions** - Grant only the minimum required access
- **Audit trail** - Clear attribution of service actions  
- **No expiration issues** - Tokens are automatically renewed
- **Production ready** - Designed for service-to-service authentication

### How It Works

1. **Create a service account** with specific roles for Chronicle/Security services
2. **Assign the service account** to your Cloud Run service
3. **Existing code continues to work** - The `google-auth` library automatically detects and uses service account credentials
4. **Google handles the rest** - Token refresh, rotation, and delivery

## Step-by-Step Implementation

### 0. Get Your Google Cloud Project ID

First, ensure you know your Google Cloud Project ID:

```bash
# Get your current project ID
export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project)
echo "Current project: $GOOGLE_CLOUD_PROJECT"

# Or set it explicitly if needed
gcloud config set project YOUR_PROJECT_ID
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID

# Verify the project is set correctly
gcloud config list project
```

### 1. Create Service Accounts

Create service accounts for each MCP server with minimal required permissions:

#### For SecOps (Chronicle) Server
```bash
# Create service account
gcloud iam service-accounts create chronicle-mcp-sa \
    --description="Service account for Chronicle MCP server" \
    --display-name="Chronicle MCP Service Account"

# Grant Chronicle permissions
gcloud projects add-iam-policy-binding $GOOGLE_CLOUD_PROJECT \
    --member="serviceAccount:chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com" \
    --role="roles/chronicle.viewer"

# If you need admin operations, use this instead:
# --role="roles/chronicle.admin"
```

#### For GTI (Threat Intelligence) Server
```bash
gcloud iam service-accounts create gti-mcp-sa \
    --description="Service account for GTI MCP server" \
    --display-name="GTI MCP Service Account"

# GTI requires specific API access - adjust based on your GTI permissions
gcloud projects add-iam-policy-binding $GOOGLE_CLOUD_PROJECT \
    --member="serviceAccount:gti-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com" \
    --role="roles/threatintelligence.viewer"
```

#### For SCC (Security Command Center) Server  
```bash
gcloud iam service-accounts create scc-mcp-sa \
    --description="Service account for SCC MCP server" \
    --display-name="SCC MCP Service Account"

gcloud projects add-iam-policy-binding $GOOGLE_CLOUD_PROJECT \
    --member="serviceAccount:scc-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com" \
    --role="roles/securitycenter.admin"
```

#### For SOAR Server
```bash
gcloud iam service-accounts create soar-mcp-sa \
    --description="Service account for SOAR MCP server" \
    --display-name="SOAR MCP Service Account"

# SOAR permissions depend on your specific SOAR platform integrations
# Add roles based on the Google Cloud services your SOAR workflows access
```

### 2. Deploy Cloud Run Services with Service Accounts

Update your Cloud Run deployment commands to use service accounts:

#### SecOps Server Deployment
```bash
gcloud run deploy secops-mcp-server \
    --source=server/secops \
    --service-account=chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --set-env-vars="CHRONICLE_PROJECT_ID=$GOOGLE_CLOUD_PROJECT,CHRONICLE_CUSTOMER_ID=$CHRONICLE_CUSTOMER_ID,CHRONICLE_REGION=us" \
    --region=$GOOGLE_CLOUD_REGION \
    --allow-unauthenticated
```

#### GTI Server Deployment
```bash
gcloud run deploy gti-mcp-server \
    --source=server/gti \
    --service-account=gti-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --set-env-vars="VT_APIKEY=$VT_APIKEY" \
    --region=$GOOGLE_CLOUD_REGION \
    --allow-unauthenticated
```

#### SCC Server Deployment
```bash
gcloud run deploy scc-mcp-server \
    --source=server/scc \
    --service-account=scc-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --region=$GOOGLE_CLOUD_REGION \
    --allow-unauthenticated
```

### 3. Verify Authentication

Check that your service can authenticate properly:

#### Test Service Account Assignment
```bash
# Get the service account for your Cloud Run service
gcloud run services describe secops-mcp-server \
    --region=$GOOGLE_CLOUD_REGION \
    --format="value(spec.template.spec.serviceAccountName)"
```

#### Check Service Logs
```bash
# View logs for authentication issues
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=secops-mcp-server" \
    --limit=50 \
    --format="table(timestamp,severity,textPayload)"
```

#### Test API Access
Create a simple test script to verify the service can access Chronicle:

```python
# test_auth.py
from secops import SecOpsClient
import os

def test_chronicle_auth():
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=os.environ['CHRONICLE_CUSTOMER_ID'],
            project_id=os.environ['CHRONICLE_PROJECT_ID'],
            region=os.environ.get('CHRONICLE_REGION', 'us')
        )
        print("Authentication successful")
        return True
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False

if __name__ == "__main__":
    test_chronicle_auth()
```

## Security Best Practices

### 1. Principle of Least Privilege
Grant only the minimum permissions required:

```bash
# Good: Specific, minimal permissions
--role="roles/chronicle.viewer"

# Bad: Overly broad permissions  
--role="roles/editor"
```

### 2. Separate Service Accounts
Use different service accounts for different MCP servers:
- Easier to audit and track access
- Limits blast radius if one account is compromised
- Allows fine-grained permission management

### 3. Regular Permission Audits
```bash
# List service accounts and their roles
gcloud projects get-iam-policy $GOOGLE_CLOUD_PROJECT \
    --format="table(bindings.members,bindings.role)" \
    --filter="bindings.members:serviceAccount"
```

### 4. Monitor Service Account Usage
```bash
# Enable audit logging for service account usage
gcloud logging read 'protoPayload.serviceName="iam.googleapis.com" AND protoPayload.authenticationInfo.principalEmail:*-mcp-sa@*' \
    --limit=10
```

## Troubleshooting Common Issues

### Issue: "Default credentials not found"
**Cause:** Service account not assigned to Cloud Run service  
**Solution:** Redeploy with `--service-account` parameter

### Issue: "Permission denied" errors
**Cause:** Service account lacks required permissions  
**Solution:** Add necessary IAM roles:
```bash
gcloud projects add-iam-policy-binding $PROJECT \
    --member="serviceAccount:SERVICE_ACCOUNT_EMAIL" \
    --role="REQUIRED_ROLE"
```

### Issue: "Customer ID not found" or Chronicle errors
**Cause:** Environment variables not set correctly  
**Solution:** Verify environment variables in Cloud Run:
```bash
gcloud run services describe YOUR_SERVICE \
    --format="export" | grep -A 10 "env:"
```

### Issue: Service works locally but fails in Cloud Run
**Cause:** Different credential sources between local and cloud  
**Solution:** 
1. Ensure service account has same permissions as your user account
2. Test service account locally using impersonation (see "Local Testing" section below)

## Local Testing with Service Account Impersonation

Before deploying to Cloud Run, you should test your service account permissions locally using impersonation. This simulates exactly how authentication will work in production.

### Why Use Impersonation?

**Service account impersonation** allows your personal Google account to temporarily use the service account's permissions without downloading key files.

**Benefits:**
- **Secure** - No key files to lose or steal
- **Automatic expiration** - Tokens expire and refresh automatically  
- **Full audit trail** - Google knows you impersonated the service account
- **Same permissions as production** - Tests exactly what will work in Cloud Run

### Setup Impersonation Permission (One-time)

Grant yourself permission to impersonate each service account:

```bash
# For Chronicle service account
gcloud iam service-accounts add-iam-policy-binding \
    chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --member="user:your-email@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# For GTI service account  
gcloud iam service-accounts add-iam-policy-binding \
    gti-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --member="user:your-email@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# For SCC service account
gcloud iam service-accounts add-iam-policy-binding \
    scc-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --member="user:your-email@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# Or use your current gcloud account automatically
gcloud iam service-accounts add-iam-policy-binding \
    chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \
    --member="user:$(gcloud config get-value account)" \
    --role="roles/iam.serviceAccountTokenCreator"
```

### Test Service Account Locally

#### Step 1: Start Impersonation
```bash
# Impersonate the Chronicle service account
gcloud auth application-default login \
    --impersonate-service-account=chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com

# Verify impersonation is active
gcloud auth list
# Should show: ACTIVE  ACCOUNT with service account email
```

#### Step 2: Set Environment Variables
```bash
export CHRONICLE_PROJECT_ID=$GOOGLE_CLOUD_PROJECT
export CHRONICLE_CUSTOMER_ID=your-chronicle-customer-id
export CHRONICLE_REGION=us
```

#### Step 3: Test the MCP Server
```bash
# Test with uvicorn local development server
cd run-with-google-adk
make local-dev-run

# Or test the SecOps server directly
cd server/secops
uv run secops_mcp.server:main
```

#### Step 4: Test API Access
Create a quick test script:

```python
# test_service_account.py
from secops import SecOpsClient
import os
from google.auth import default

def test_auth():
    # Check current credentials
    credentials, project = default()
    print(f"Project: {project}")
    print(f"Service Account: {getattr(credentials, 'service_account_email', 'N/A')}")
    
    # Test Chronicle access
    client = SecOpsClient()
    chronicle = client.chronicle(
        customer_id=os.environ['CHRONICLE_CUSTOMER_ID'],
        project_id=os.environ['CHRONICLE_PROJECT_ID'],
        region=os.environ.get('CHRONICLE_REGION', 'us')
    )
    print("Chronicle authentication successful")

if __name__ == "__main__":
    test_auth()
```

```bash
python test_service_account.py
```

#### Step 5: Return to Personal Credentials
```bash
# Stop impersonating, return to your personal account
gcloud auth application-default login
```

### Common Impersonation Commands

```bash
# Check who you're currently authenticated as
gcloud auth list

# Get current access token (useful for debugging)
gcloud auth application-default print-access-token

# Impersonate for just one command (doesn't change default)
gcloud --impersonate-service-account=SA_EMAIL compute instances list

# Check if impersonation is working
gcloud auth application-default login --impersonate-service-account=SA_EMAIL
gcloud auth list  # Should show the service account as ACTIVE
```

### Troubleshooting Impersonation

#### Issue: "Permission denied to impersonate"
**Cause:** You don't have `serviceAccountTokenCreator` role  
**Solution:** Run the impersonation permission setup commands above

#### Issue: "Service account not found"
**Cause:** Wrong service account email or project  
**Solution:** Verify service account exists:
```bash
gcloud iam service-accounts list
```

#### Issue: "API access denied" during testing
**Cause:** Service account lacks required API permissions  
**Solution:** Add the necessary roles to the service account:
```bash
gcloud projects add-iam-policy-binding $GOOGLE_CLOUD_PROJECT \
    --member="serviceAccount:chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com" \
    --role="roles/chronicle.viewer"
```

## Multi-Server Deployment Considerations

### Shared vs Individual Service Accounts

**Option 1: Individual Service Accounts (Recommended)**
- Better security isolation
- Easier permission management
- Clear audit trails

**Option 2: Shared Service Account**
- Simpler to manage
- Broader permissions required
- Less secure

### Environment Variable Management

Use consistent environment variable names across servers:

```bash
# Common pattern for all MCP servers
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_REGION=us-central1

# Server-specific variables
CHRONICLE_PROJECT_ID=your-chronicle-project
CHRONICLE_CUSTOMER_ID=your-customer-id
CHRONICLE_REGION=us
VT_APIKEY=your-virustotal-key
SOAR_URL=your-soar-instance
```

### Networking Considerations

If your MCP servers need to communicate with each other:

```bash
# Allow Cloud Run services to communicate
gcloud run services add-iam-policy-binding SERVICE_NAME \
    --member="serviceAccount:OTHER_SERVICE_SA@PROJECT.iam.gserviceaccount.com" \
    --role="roles/run.invoker"
```

## Code Changes (Usually None Required)

The good news is that **no code changes** are typically required! The existing MCP servers already use the `google-auth` library, which automatically detects credentials in this order:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable (key file)
2. `gcloud auth application-default login` credentials (local development)
3. **Service account attached to the compute resource** (Cloud Run)
4. Google Cloud metadata service (GCE, Cloud Run)

This means your existing code like this:
```python
from secops import SecOpsClient

client = SecOpsClient()  # Automatically uses available credentials
chronicle = client.chronicle(customer_id=customer_id, project_id=project_id)
```

Will automatically work with service accounts in Cloud Run.

## Alternative: Service Account Key Files (Not Recommended)

If you must use key files (not recommended for production):

### Generate Key File
```bash
gcloud iam service-accounts keys create chronicle-key.json \
    --iam-account=chronicle-mcp-sa@$PROJECT.iam.gserviceaccount.com
```

### Use with Cloud Run
```bash
# Option 1: Build key into container (SECURITY RISK)
COPY chronicle-key.json /app/
ENV GOOGLE_APPLICATION_CREDENTIALS=/app/chronicle-key.json

# Option 2: Use Secret Manager (Better but complex)
gcloud secrets create chronicle-key --data-file=chronicle-key.json
```

### Why Key Files Are Problematic
- **Security risk**: Keys can be extracted from containers or logs
- **No automatic rotation**: Manual key management required  
- **Audit complexity**: Harder to track key usage
- **Operational overhead**: Key rotation, storage, and distribution

## References and Additional Resources

- [Google Cloud Authentication Overview](https://cloud.google.com/docs/authentication)
- [Cloud Run Service Accounts](https://cloud.google.com/run/docs/configuring/service-accounts)
- [Chronicle IAM Roles](https://cloud.google.com/chronicle/docs/access-control)
- [Security Command Center IAM](https://cloud.google.com/security-command-center/docs/access-control)
- [Google Auth Library Documentation](https://google-auth.readthedocs.io/)

## Summary

**Recommended:**
- **Use service accounts with IAM roles** for Cloud Run deployments  
- **Keep ADC for local development** - it's perfect for that use case  
- **No code changes required** - existing MCP servers will work automatically  
- **Follow principle of least privilege** - grant minimal required permissions  
- **Monitor and audit** service account usage regularly  

**Avoid:**
- **Don't use key files in production** - security and operational risks  
- **Don't use overly broad permissions** - increases security risk  
- **Don't forget environment variables** - services need Chronicle config  

This approach provides secure, maintainable, and production-ready authentication for all MCP servers deployed to Cloud Run.