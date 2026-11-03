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
#
# Build from the repository root:
#   SERVER_TARGET="secops"
#   docker build -f deployments/ax-mcp-gateway/Dockerfile \
#     --build-arg SERVER_TARGET="$SERVER_TARGET" \
#     -t "us-docker.pkg.dev/$PROJECT_ID/secops-mcp/${SERVER_TARGET}-mcp-gateway:latest" .
FROM python:3.11-slim

ARG SERVER_TARGET=secops

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATEWAY_SERVER=${SERVER_TARGET} \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8080

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.6.10 /uv /usr/local/bin/uv

COPY server/${SERVER_TARGET} /app/server/${SERVER_TARGET}
COPY deployments/ax-mcp-gateway /app/deployments/ax-mcp-gateway

RUN groupadd --gid 65532 nonroot && \
    useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin nonroot && \
    uv pip install --system \
      "/app/server/${SERVER_TARGET}" \
      "/app/deployments/ax-mcp-gateway" && \
    chown -R 65532:65532 /app

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["mcp-security-gateway"]
