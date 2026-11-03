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
#   PROJECT_ID="my-secops-project"
#   SERVER_TARGET="secops"  # secops | gti | secops-soar | scc | vertex-llm
#   docker build -f deployments/ax-mcp-gateway/Dockerfile \
#     --build-arg SERVER_TARGET="$SERVER_TARGET" \
#     -t "us-docker.pkg.dev/$PROJECT_ID/secops-mcp/${SERVER_TARGET}-mcp-gateway:v0.1.0" .
ARG SERVER_TARGET=secops

FROM python:3.11-slim AS gateway-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8080

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.6.10 /uv /usr/local/bin/uv

RUN groupadd --gid 65532 nonroot && \
    useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin nonroot

# Only the installable package sources are copied; tests, manifests, and
# scripts stay out of the image.
COPY deployments/ax-mcp-gateway/pyproject.toml deployments/ax-mcp-gateway/README.md /app/deployments/ax-mcp-gateway/
COPY deployments/ax-mcp-gateway/src /app/deployments/ax-mcp-gateway/src
RUN uv pip install --system "/app/deployments/ax-mcp-gateway"

FROM gateway-base AS target-secops
ENV GATEWAY_SERVER=secops
COPY server/secops /app/server/secops
RUN uv pip install --system "/app/server/secops"

FROM gateway-base AS target-gti
ENV GATEWAY_SERVER=gti
COPY server/gti /app/server/gti
RUN uv pip install --system "/app/server/gti"

FROM gateway-base AS target-secops-soar
ENV GATEWAY_SERVER=secops-soar
COPY server/secops-soar /app/server/secops-soar
RUN uv pip install --system "/app/server/secops-soar"

FROM gateway-base AS target-scc
ENV GATEWAY_SERVER=scc
COPY server/scc /app/server/scc
RUN uv pip install --system "/app/server/scc"

FROM gateway-base AS target-vertex-llm
ENV GATEWAY_SERVER=vertex-llm

FROM target-${SERVER_TARGET} AS runtime

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["mcp-security-gateway"]
