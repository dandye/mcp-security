# Copyright 2026 Google LLC
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
"""Runnable examples for Google Threat Intelligence (GTI) DSPy RLM MCP tools.

Usage (from the repository or worktree root with direnv configured):
  direnv exec . python3 server/gti/examples/rlm_file_triage_demo.py --tool report
  direnv exec . python3 server/gti/examples/rlm_file_triage_demo.py --tool behavior
  direnv exec . python3 server/gti/examples/rlm_file_triage_demo.py --tool entities
  direnv exec . python3 server/gti/examples/rlm_file_triage_demo.py --tool investigate
  direnv exec . python3 server/gti/examples/rlm_file_triage_demo.py --tool all
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import time
from typing import Any
from unittest.mock import MagicMock

from dotenv import load_dotenv

from gti_mcp.tools.rlm_files import (
    rlm_get_entities_related_to_a_file,
    rlm_get_file_behavior_summary,
    rlm_get_file_report,
    rlm_investigate_file,
)

# Public WannaCry ransomware SHA-256 sample on VirusTotal / GTI
DEFAULT_WANNACRY_SHA256 = (
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
)


def _load_env_if_needed() -> None:
  """Loads .env from repo root if VT_APIKEY is not already exported by direnv."""
  if os.environ.get("VT_APIKEY"):
    return
  repo_root = Path(__file__).resolve().parents[3]
  env_file = repo_root / ".env"
  if env_file.exists():
    load_dotenv(env_file)


def _print_summary(title: str, result: dict[str, Any], elapsed_s: float) -> None:
  """Prints a concise human-readable summary of a distilled RLM tool response."""
  metrics = result.get("compression_metrics", {})
  raw_b = metrics.get("raw_bytes", 0)
  out_b = metrics.get("output_bytes", 0)
  pct = metrics.get("reduction_pct", 0.0)
  mode = metrics.get("rlm_mode", "unknown")
  iters = metrics.get("rlm_iters", 0)
  api_calls = metrics.get("api_calls_made", 0)
  endpoints = metrics.get("endpoints_called", [])

  print("=" * 80)
  print(f"Tool: {title} ({result.get('tool')})")
  print(
      f"Compression: {raw_b:,} B -> {out_b:,} B ({pct:.2f}% reduction) | "
      f"mode={mode} | iters={iters} | api_calls={api_calls} | elapsed={elapsed_s:.2f}s"
  )
  print(f"Endpoints: {endpoints}")
  print("-" * 80)
  print(f"Verdict: {result.get('verdict_and_summary')}")
  print(f"Answer : {result.get('answer')}")
  print("\nKey Findings:")
  for finding in result.get("key_findings", [])[:6]:
    print(f"  - {finding}")
  iocs = result.get("high_signal_iocs", {})
  print("\nHigh-Signal IOC Counts:")
  for cat, items in iocs.items():
    sample_preview = ", ".join(str(x) for x in items[:3])
    suffix = f" (e.g. {sample_preview})" if sample_preview else ""
    print(f"  - {cat}: {len(items)}{suffix}")
  print(f"\nFiltered Noise: {result.get('filtered_noise_summary')}")
  print("=" * 80 + "\n")


async def run_examples(
    sample_hash: str,
    selected_tool: str,
    output_json: str | None = None,
) -> dict[str, Any]:
  """Executes the selected RLM tool(s) and returns the structured outputs."""
  _load_env_if_needed()
  ctx = MagicMock()
  collected: dict[str, Any] = {}

  if selected_tool in ("report", "all"):
    t0 = time.monotonic()
    res = await rlm_get_file_report(
        hash=sample_hash,
        ctx=ctx,
        query="What malware family is this, what is the vendor consensus, and what domains or IPs does it contact?",
    )
    elapsed = time.monotonic() - t0
    _print_summary("rlm_get_file_report", res, elapsed)
    collected["rlm_get_file_report"] = res

  if selected_tool in ("behavior", "all"):
    t0 = time.monotonic()
    res = await rlm_get_file_behavior_summary(
        hash=sample_hash,
        ctx=ctx,
        query="What processes, command lines, mutexes, and persistence mechanisms are created, and what network traffic occurs?",
    )
    elapsed = time.monotonic() - t0
    _print_summary("rlm_get_file_behavior_summary", res, elapsed)
    collected["rlm_get_file_behavior_summary"] = res

  if selected_tool in ("entities", "all"):
    t0 = time.monotonic()
    res = await rlm_get_entities_related_to_a_file(
        hash=sample_hash,
        relationship_name="contacted_domains",
        ctx=ctx,
        query="Which contacted domains are associated with the WannaCry kill-switch or C2?",
        limit=10,
    )
    elapsed = time.monotonic() - t0
    _print_summary("rlm_get_entities_related_to_a_file", res, elapsed)
    collected["rlm_get_entities_related_to_a_file"] = res

  if selected_tool in ("investigate", "all"):
    t0 = time.monotonic()
    res = await rlm_investigate_file(
        hash=sample_hash,
        ctx=ctx,
        investigation_goal=(
            "Correlate static PE/YARA indicators with dynamic sandbox execution "
            "behavior and threat actor/malware family attributions."
        ),
        max_api_calls=3,
    )
    elapsed = time.monotonic() - t0
    _print_summary("rlm_investigate_file", res, elapsed)
    collected["rlm_investigate_file"] = res

  if output_json:
    out_path = Path(output_json)
    out_path.write_text(json.dumps(collected, indent=2, default=str), encoding="utf-8")
    print(f"Saved full JSON outputs to {out_path}")

  return collected


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Run live GTI DSPy RLM MCP tool examples."
  )
  parser.add_argument(
      "--hash",
      default=DEFAULT_WANNACRY_SHA256,
      help="Target file hash (MD5, SHA-1, or SHA-256). Defaults to WannaCry.",
  )
  parser.add_argument(
      "--tool",
      choices=("report", "behavior", "entities", "investigate", "all"),
      default="report",
      help="Which RLM tool example to run.",
  )
  parser.add_argument(
      "--output-json",
      default=None,
      help="Optional path to write the full JSON response(s).",
  )
  args = parser.parse_args()
  asyncio.run(run_examples(args.hash, args.tool, args.output_json))


if __name__ == "__main__":
  main()
