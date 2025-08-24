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
GCS_BUCKET="local-dev-bucket"

# Check if the ADC file exists
if [ ! -f "$ADC_PATH" ]; then
  echo "Error: Application Default Credentials file not found at $ADC_PATH"
  echo "Please ensure you have authenticated with 'gcloud auth application-default login' or provided a service account key."
  exit 1
fi

podman run --rm -it -p "${HOST_PORT}:${CONTAINER_PORT}" \
  -v "${ADC_PATH}:${CONTAINER_ADC_PATH}" \
  -e GOOGLE_APPLICATION_CREDENTIALS="${CONTAINER_ADC_PATH}" \
  -e GCS_ARTIFACT_SERVICE_BUCKET="${GCS_BUCKET}" \
  "${IMAGE_NAME}"
