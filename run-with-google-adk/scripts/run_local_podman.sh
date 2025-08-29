#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Running local Podman container for google-adk-app-local..."

# Define variables for easier modification
IMAGE_NAME="localhost/google-adk-app-local:latest"
HOST_PORT="8080"
CONTAINER_PORT="8080"
ADC_PATH="$HOME/.config/gcloud/application_default_credentials.json"
CONTAINER_ADC_PATH="/app/application_default_credentials.json"
ENV_FILE="run-with-google-adk/agents/google_mcp_security_agent/.env"

# Check if the ADC file exists
if [ ! -f "$ADC_PATH" ]; then
  echo "Error: Application Default Credentials file not found at $ADC_PATH"
  echo "Please ensure you have authenticated with 'gcloud auth application-default login' or provided a service account key."
  exit 1
fi

# Check if .env file exists
if [ ! -f "$ENV_FILE" ]; then
  echo "Error: .env file not found at $ENV_FILE"
  echo "Please create it with your environment variables."
  echo "Expected location: run-with-google-adk/agents/google_mcp_security_agent/.env"
  exit 1
fi

echo "Reading environment variables from $ENV_FILE..."

# Build environment variable flags from .env file
env_flags=""
while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed_line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Skip empty lines and comments
    [[ -z "$trimmed_line" ]] && continue
    [[ "$trimmed_line" =~ ^# ]] && continue
    [[ ! "$trimmed_line" =~ = ]] && continue
    
    # Extract key and value
    key=$(echo "$trimmed_line" | cut -d "=" -f1)
    value=$(echo "$trimmed_line" | cut -d "=" -f2-)
    
    # Remove quotes if present
    value=$(echo "$value" | sed -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')
    
    # Add to environment flags
    env_flags="$env_flags -e $key=\"$value\""
    
    # Log important variables (without sensitive values)
    if [[ "$key" == "LOAD_"* ]] || [[ "$key" == "CHRONICLE_"* ]] || [[ "$key" == "GOOGLE_CLOUD_"* ]]; then
        if [[ "$key" == *"KEY"* ]] || [[ "$key" == *"SECRET"* ]]; then
            echo "  - $key=***"
        else
            echo "  - $key=$value"
        fi
    fi
done < "$ENV_FILE"

echo "Starting container with environment variables..."

# Run container with all environment variables
eval podman run --rm -it -p "${HOST_PORT}:${CONTAINER_PORT}" \
  -v "${ADC_PATH}:${CONTAINER_ADC_PATH}" \
  -e GOOGLE_APPLICATION_CREDENTIALS="${CONTAINER_ADC_PATH}" \
  -e LOCAL_RUN=true \
  $env_flags \
  "${IMAGE_NAME}"
