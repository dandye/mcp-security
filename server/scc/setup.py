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
import setuptools

setup = setuptools.setup

setup(
    name="scc-mcp",
    version="0.3.0",
    py_modules=["scc_mcp"],
    install_requires=[
        "aiohttp>=3.9.0",
        "cryptography>=42.0.0",
        "google-api-core>=2.19.0",
        "google-auth>=2.48.0",
        "google-cloud-asset>=3.15.0",
        "google-cloud-securitycenter>=1.38.0",
        "httpx>=0.28.1",
        "httpx2>=2.10.0",
        "mcp[cli]>=2.3.0,<3.0.0",
        "protobuf>=4.25.0",
        "pydantic>=2.11.2",
        "python-dotenv>=1.0.0",
        "requests>=2.32.0",
        "starlette>=0.40.0",
        "typing-extensions>=4.8.0",
        "uvicorn[standard]>=0.30.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "scc_mcp=scc_mcp:main",
        ],
        "mcp": [
            "scc-mcp=scc_mcp:main",
        ],
    },
)
