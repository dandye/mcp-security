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

# Startup script for local Podman container
# Mimics Cloud Run's behavior of creating .env file from environment variables

echo "Local container startup..."

# Create /tmp/.env file from environment variables (like Cloud Run does)
echo "Creating /tmp/.env from environment variables..."
env > /tmp/.env

# Also create the .env file in the expected location for the agent
# The agent looks for it in multiple places including /app/agents/google_mcp_security_agent/.env
if [ ! -d "/app/agents/google_mcp_security_agent" ]; then
    mkdir -p /app/agents/google_mcp_security_agent
fi
cp /tmp/.env /app/agents/google_mcp_security_agent/.env

echo "Environment file created. Starting application..."

# Log MCP server configuration
echo "MCP Server Configuration:"
for var in LOAD_SCC_MCP LOAD_SECOPS_MCP LOAD_GTI_MCP LOAD_SECOPS_SOAR_MCP; do
    value=$(eval "echo \$$var")
    if [ "$value" = "true" ]; then
        echo "  - $var: ENABLED"
    else
        echo "  - $var: DISABLED"
    fi
done

# Log Chronicle configuration (without sensitive values)
if [ -n "$CHRONICLE_PROJECT_ID" ]; then
    echo "Chronicle Configuration:"
    echo "  - CHRONICLE_PROJECT_ID: $CHRONICLE_PROJECT_ID"
    echo "  - CHRONICLE_CUSTOMER_ID: $CHRONICLE_CUSTOMER_ID"
    echo "  - CHRONICLE_REGION: $CHRONICLE_REGION"
fi

# Start the application
echo "Starting uvicorn server..."
exec uvicorn ui.main:app --host 0.0.0.0 --port 8080