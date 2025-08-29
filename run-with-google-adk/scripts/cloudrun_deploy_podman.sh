#!/bin/bash

# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Cloud Run deployment script using Podman-built images and Secret Manager
# This script reads from .env file, creates secrets, and deploys to Cloud Run

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENV_FILE="agents/google_mcp_security_agent/.env"
SERVICE_NAME="mcp-security-agent-service"
REGION="us-central1"

# Arrays to hold different types of variables
declare -A ALL_VARS
declare -a SECRET_KEYS
declare -a ENV_KEYS

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Load environment variables from .env file
load_env_file() {
    log_info "Loading environment variables from $ENV_FILE..."
    
    if [ ! -f "$ENV_FILE" ]; then
        log_error "Environment file not found: $ENV_FILE"
        exit 1
    fi
    
    # Read .env file and populate ALL_VARS associative array
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines and comments
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ ! "$line" =~ = ]] && continue
        
        # Skip DEFAULT_PROMPT (handled separately due to multiline)
        [[ "$line" =~ ^DEFAULT_PROMPT ]] && continue
        
        # Extract key and value
        key=$(echo "$line" | cut -d'=' -f1 | xargs)
        value=$(echo "$line" | cut -d'=' -f2- | xargs)
        
        # Remove quotes if present
        value=$(echo "$value" | sed -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')
        
        # Store in array
        ALL_VARS["$key"]="$value"
        
        # Categorize as secret or regular env var
        if [[ "$key" == *"APIKEY"* ]] || [[ "$key" == *"API_KEY"* ]] || \
           [[ "$key" == *"APP_KEY"* ]] || [[ "$key" == *"SECRET"* ]] || \
           [[ "$key" == *"PASSWORD"* ]] || [[ "$key" == *"TOKEN"* ]]; then
            SECRET_KEYS+=("$key")
            log_info "  Found secret: $key"
        else
            ENV_KEYS+=("$key")
            if [[ "$key" == "GOOGLE_CLOUD_PROJECT" ]]; then
                PROJECT_ID="${value}"
            fi
        fi
    done < "$ENV_FILE"
    
    log_success "Loaded ${#ALL_VARS[@]} variables (${#SECRET_KEYS[@]} secrets, ${#ENV_KEYS[@]} env vars)"
    
    # Set derived values
    if [ -z "$PROJECT_ID" ]; then
        log_error "GOOGLE_CLOUD_PROJECT not found in .env file"
        exit 1
    fi
    
    SERVICE_ACCOUNT="chronicle-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com"
    IMAGE_NAME="gcr.io/${PROJECT_ID}/mcp-security-agent:latest"
    
    log_info "Project ID: $PROJECT_ID"
    log_info "Service Account: $SERVICE_ACCOUNT"
    log_info "Image: $IMAGE_NAME"
}

# Create or update secrets in Secret Manager
create_secrets() {
    log_info "Creating/updating secrets in Secret Manager..."
    
    for key in "${SECRET_KEYS[@]}"; do
        value="${ALL_VARS[$key]}"
        secret_name=$(echo "$key" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
        
        # Check if secret exists
        if gcloud secrets describe "$secret_name" --project="$PROJECT_ID" &>/dev/null; then
            log_info "  Updating secret: $secret_name"
            echo -n "$value" | gcloud secrets versions add "$secret_name" \
                --project="$PROJECT_ID" \
                --data-file=- &>/dev/null
        else
            log_info "  Creating secret: $secret_name"
            echo -n "$value" | gcloud secrets create "$secret_name" \
                --project="$PROJECT_ID" \
                --replication-policy="automatic" \
                --data-file=- &>/dev/null
        fi
    done
    
    log_success "Secrets created/updated in Secret Manager"
    
    # Grant service account access to secrets
    log_info "Granting service account access to secrets..."
    for key in "${SECRET_KEYS[@]}"; do
        secret_name=$(echo "$key" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
        gcloud secrets add-iam-policy-binding "$secret_name" \
            --project="$PROJECT_ID" \
            --member="serviceAccount:$SERVICE_ACCOUNT" \
            --role="roles/secretmanager.secretAccessor" &>/dev/null || true
    done
    log_success "Service account granted access to secrets"
}

# Build environment variables string for Cloud Run
build_env_vars() {
    local env_vars=""
    
    for key in "${ENV_KEYS[@]}"; do
        value="${ALL_VARS[$key]}"
        if [ -n "$env_vars" ]; then
            env_vars="${env_vars},"
        fi
        env_vars="${env_vars}${key}=${value}"
    done
    
    echo "$env_vars"
}

# Build secrets string for Cloud Run
build_secrets() {
    local secrets=""
    
    for key in "${SECRET_KEYS[@]}"; do
        secret_name=$(echo "$key" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
        if [ -n "$secrets" ]; then
            secrets="${secrets},"
        fi
        secrets="${secrets}${key}=${secret_name}:latest"
    done
    
    echo "$secrets"
}

# Check if image exists in registry
check_image() {
    log_info "Checking if image exists in registry..."
    
    if gcloud container images describe "$IMAGE_NAME" --project="$PROJECT_ID" &>/dev/null; then
        log_success "Image found: $IMAGE_NAME"
        return 0
    else
        log_warning "Image not found in registry: $IMAGE_NAME"
        log_warning "You need to build and push the image first:"
        echo ""
        echo "  cd .."
        echo "  podman build -t $IMAGE_NAME -f run-with-google-adk/Dockerfile.local ."
        echo "  podman push $IMAGE_NAME"
        echo ""
        read -p "Do you want to continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Deploy to Cloud Run
deploy_to_cloudrun() {
    log_info "Deploying to Cloud Run..."
    
    # Build the environment variables and secrets strings
    ENV_VARS_STRING=$(build_env_vars)
    SECRETS_STRING=$(build_secrets)
    
    log_info "Service: $SERVICE_NAME"
    log_info "Region: $REGION"
    log_info "Image: $IMAGE_NAME"
    log_info "Service Account: $SERVICE_ACCOUNT"
    
    # Deploy with both secrets and env vars
    if [ -n "$SECRETS_STRING" ]; then
        gcloud run deploy "$SERVICE_NAME" \
            --image "$IMAGE_NAME" \
            --service-account="$SERVICE_ACCOUNT" \
            --set-secrets="$SECRETS_STRING" \
            --set-env-vars="$ENV_VARS_STRING" \
            --region "$REGION" \
            --project "$PROJECT_ID" \
            --memory 2Gi \
            --timeout 600 \
            --allow-unauthenticated \
            --quiet
    else
        gcloud run deploy "$SERVICE_NAME" \
            --image "$IMAGE_NAME" \
            --service-account="$SERVICE_ACCOUNT" \
            --set-env-vars="$ENV_VARS_STRING" \
            --region "$REGION" \
            --project "$PROJECT_ID" \
            --memory 2Gi \
            --timeout 600 \
            --allow-unauthenticated \
            --quiet
    fi
    
    if [ $? -eq 0 ]; then
        log_success "Deployment successful!"
        
        # Get the service URL
        SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
            --region "$REGION" \
            --project "$PROJECT_ID" \
            --format 'value(status.url)')
        
        log_success "Service URL: $SERVICE_URL"
    else
        log_error "Deployment failed"
        exit 1
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo "Cloud Run Deployment Script (Podman)"
    echo "=========================================="
    echo ""
    
    # Check prerequisites
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI not found. Please install it first."
        exit 1
    fi
    
    # Load environment variables
    load_env_file
    
    # Check if image exists
    check_image
    
    # Create/update secrets
    create_secrets
    
    # Deploy to Cloud Run
    deploy_to_cloudrun
    
    echo ""
    echo "=========================================="
    echo "Deployment Complete"
    echo "=========================================="
    log_info "Next steps:"
    log_info "1. Test the service: curl $SERVICE_URL"
    log_info "2. Check logs: gcloud run logs read --service=$SERVICE_NAME --region=$REGION"
    log_info "3. Monitor: gcloud run services describe $SERVICE_NAME --region=$REGION"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Deploy MCP Security Agent to Cloud Run using Podman-built image"
            echo ""
            echo "OPTIONS:"
            echo "  -h, --help     Show this help message"
            echo "  --skip-secrets Skip creating/updating secrets"
            echo ""
            echo "PREREQUISITES:"
            echo "  1. Build image: podman build -t gcr.io/PROJECT/mcp-security-agent ."
            echo "  2. Push image: podman push gcr.io/PROJECT/mcp-security-agent"
            echo "  3. Have .env file at: agents/google_mcp_security_agent/.env"
            echo ""
            exit 0
            ;;
        --skip-secrets)
            SKIP_SECRETS=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            log_error "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main function
main