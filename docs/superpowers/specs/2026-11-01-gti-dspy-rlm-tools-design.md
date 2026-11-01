# GTI MCP DSPy RLM Tools Design Specification

**Date:** 2026-11-01
**Repository:** `dandye/mcp-security` (worktree `gti__dspy-rlm-tools`)
**Target Package:** `server/gti` (`gti-mcp`)

---

## 1. Problem Statement & Motivation

Google Threat Intelligence (GTI) / VirusTotal v3 API endpoints for files and sandbox behaviors return deeply nested JSON payloads that frequently exceed 50 KB to 500 KB per request:

- `GET /files/{hash}` includes 70+ vendor results (`last_analysis_results`), PE/ELF/Mach-O headers and full import tables (`pe_info.import_list`), crowdsourced YARA/Sigma/IDS rules, submission filenames, and relationship descriptors.
- `GET /files/{hash}/behaviour_summary` and `GET /file_behaviours/{id}` include 26+ behavioral arrays (`processes_tree`, `command_executions`, `registry_keys_opened`, `registry_keys_set`, `mutexes_created`, `files_opened`, `files_written`, `files_dropped`, `ip_traffic`, `http_conversations`, `memory_pattern_urls`, `signature_matches`), where hundreds of benign OS/sandbox operations (`SyncRootManager`, `MSIExecute`, font/locale registry reads) drown out high-signal malware actions.

Prior mitigation attempts had structural flaws:
1. **TOON (Token-Oriented Object Notation):** Flattened nested dictionaries into tab-separated tables and truncated values at 100 characters, losing structural hierarchy and still emitting every noisy row regardless of the analyst's question.
2. **Static Exclusion Lists (PR #275 / Issue #327):** Blindly stripped 26 behavioral keys (`processes_tree`, `command_executions`, `ip_traffic`, `attack_techniques`), discarding critical threat signal alongside noise.

By embedding **DSPy 3.4+ Recursive Language Models (`dspy.RLM`)** inside additive MCP tools, the full un-truncated VT response is loaded into a sandboxed Python REPL where an RLM (paired with a fast `sub_lm` for `llm_query` / `llm_query_batched`) programmatically slices, counts, filters benign noise, and synthesizes a high-signal structured intelligence payload.

---

## 2. Architecture & Tool Surface

We adopt a **Two-Tier Additive Architecture** in `server/gti/gti_mcp/`:
- Existing raw tools in `server/gti/gti_mcp/tools/files.py` remain untouched.
- Five new `@server.tool()` functions are registered in `server/gti/gti_mcp/tools/rlm_files.py`, backed by `server/gti/gti_mcp/rlm_engine.py`.

### Tier 1: Strict 1-API-Call Distillers (`rlm_get_*`)

Each `rlm_get_*` tool preserves 1:1 API call parity with its raw `get_*` counterpart (exactly 1 VT API request per tool invocation) and runs `dspy.RLM` in-memory over that response:

1. `rlm_get_file_report(hash: str, ctx: Context, query: Optional[str] = None) -> dict[str, Any]`
   - Calls `GET /files/{hash}` with `relationships=FILE_KEY_RELATIONSHIPS`.
   - Retains `last_analysis_results` inside the REPL so the RLM can compute vendor consensus and extract unique family labels in Python without dumping 75 vendor entries over MCP.
2. `rlm_get_file_behavior_summary(hash: str, ctx: Context, query: Optional[str] = None) -> dict[str, Any]`
   - Calls `GET /files/{hash}/behaviour_summary`.
   - Inspects all behavioral arrays in Python, filters known benign OS/sandbox artifacts (`SyncRootManager`, `MSIExecute`, standard font/locale registry keys), and extracts malicious execution trees, persistence, C2 traffic, and MITRE ATT&CK techniques.
3. `rlm_get_file_behavior_report(file_behaviour_id: str, ctx: Context, query: Optional[str] = None) -> dict[str, Any]`
   - Calls `GET /file_behaviours/{file_behaviour_id}` with key relationships (`contacted_domains`, `contacted_ips`, `contacted_urls`, `dropped_files`, `embedded_domains`, `embedded_ips`, `embedded_urls`, `associations`).
   - Distills a specific sandbox execution report in Python.
4. `rlm_get_entities_related_to_a_file(hash: str, relationship_name: str, ctx: Context, descriptors_only: bool = False, limit: int = 10, query: Optional[str] = None) -> dict[str, Any]`
   - Validates `relationship_name` against `FILE_RELATIONSHIPS`.
   - Calls `GET /files/{hash}/{relationship_name}` (automatically forcing `descriptors_only=True` only for relationship types where VT v3 mandates descriptor-only queries, or using the caller's setting) and distills the related objects in Python.

### Tier 2: Multi-Call Autonomous Investigator (`rlm_investigate_file`)

5. `rlm_investigate_file(hash: str, ctx: Context, investigation_goal: Optional[str] = None, max_api_calls: int = 4) -> dict[str, Any]`
   - Explicitly named for multi-endpoint autonomous investigation.
   - Seeds the REPL with `GET /files/{hash}` (API call 1) and binds four budget-tracked Python tools inside the `dspy.RLM` sandbox:
     - `fetch_behavior_summary() -> dict[str, Any]` (`GET /files/{hash}/behaviour_summary`)
     - `fetch_sandbox_report(file_behaviour_id: str) -> dict[str, Any]` (`GET /file_behaviours/{file_behaviour_id}`)
     - `fetch_related_entities(relationship_name: str, descriptors_only: bool = False, limit: int = 10) -> list[dict[str, Any]]` (`GET /files/{hash}/{relationship_name}`)
     - `fetch_collection_summary(collection_id: str) -> dict[str, Any]` (`GET /collections/{collection_id}`)
   - Enforces `max_api_calls` (clamped between `1` and `10`, default `4`) via `APICallTracker`, caching duplicate calls within the same run.

---

## 3. Unified Output Schema

Every `rlm_*` tool returns a dictionary with deterministic verbatim anchors, RLM-distilled intelligence, and compression telemetry:

```python
{
    "id": str,                          # File hash or file_behaviour_id
    "tool": str,                        # Tool name invoked
    "query": str,                       # Caller query or default triage objective
    "verbatim_anchors": {               # Extracted deterministically in Python (never LLM-generated)
        "sha256": Optional[str],
        "sha1": Optional[str],
        "md5": Optional[str],
        "imphash": Optional[str],
        "ssdeep": Optional[str],
        "tlsh": Optional[str],
        "meaningful_name": Optional[str],
        "type_description": Optional[str],
        "size": Optional[int],
        "last_analysis_stats": dict[str, int],
        "popular_threat_classification": dict[str, Any],
        "gti_assessment": dict[str, Any],
        "code_insights": Optional[str],
    },
    "verdict_and_summary": str,         # Concise executive assessment
    "answer": str,                      # Direct answer to query / investigation_goal
    "key_findings": list[str],          # Grounded technical findings
    "high_signal_iocs": {
        "network": list[str],
        "files_dropped_or_modified": list[str],
        "process_and_command_lines": list[str],
        "persistence_and_mutexes": list[str],
        "yara_and_sigma_matches": list[str],
    },
    "attributions": list[dict[str, str]],      # [{"id": ..., "name": ..., "collection_type": ...}]
    "mitre_techniques": list[dict[str, str]],  # [{"id": ..., "name": ..., "evidence": ...}]
    "filtered_noise_summary": str,             # Count/summary of benign noise omitted
    "compression_metrics": {
        "raw_bytes": int,
        "output_bytes": int,
        "reduction_pct": float,
        "api_calls_made": int,
        "endpoints_called": list[str],
        "rlm_iters": int,
        "rlm_mode": str,                # "dspy_rlm" or "deterministic_fallback"
    },
}
```

If the initial VT API call returns an `"error"` dictionary (e.g., `NotFoundError` / 404), the tool short-circuits and returns the error dictionary immediately without invoking `dspy.RLM`.

---

## 4. `dspy.RLM` Engine & `GTISandboxedInterpreter` Design

### 4.1 LM Configuration (`configure_gti_rlm_lms`)
- Root LM default: `os.getenv("GTI_RLM_MODEL", "vertex_ai/gemini-2.5-flash")` (or `gemini/gemini-2.5-flash` if `GEMINI_API_KEY` / `GOOGLE_API_KEY` is set and `GOOGLE_CLOUD_PROJECT` is unset).
- Sub-LM default: `os.getenv("GTI_RLM_SUB_MODEL", "vertex_ai/gemini-2.5-flash-lite")` (or `gemini/gemini-2.5-flash-lite`).
- Iteration & call caps: `GTI_RLM_MAX_ITERS` (default `5`), `GTI_RLM_MAX_LLM_CALLS` (default `10`), `GTI_RLM_MAX_OUTPUT_CHARS` (default `12000`).

### 4.2 REPL Variables & Structural Pre-Indexing
To minimize wasted discovery turns inside the REPL:
- `raw_data`: Plain JSON-compatible dict/list containing the full VT payload.
- `payload_index`: Deterministic summary dict computed in Python listing:
  - Top-level keys and `attributes` keys with value types and collection lengths.
  - Pre-filtered noise counts (how many benign mutexes/registry keys match `COMMON_BENIGN_NOISE_PATTERNS`).
  - `verbatim_anchors` extracted directly from `raw_data`.
- `query`: The target question or triage objective.

### 4.3 `GTISandboxedInterpreter(LocalInterpreter)` Safeguards
1. **Facade Setup Bypass:** Allows `FacadeInvocation.install`'s internal `SHIM_SETUP` call (`variables and "__dspy_host_token" in variables`) to pass directly to `super().execute(code, variables)` without incrementing `self.user_turns`.
2. **Positional Tool-Argument Binding:** Overrides `invoke_tool(self, name, args, kwargs)` to bind positional `args` via `inspect.signature(fn).bind(*args, **kwargs)` whenever `args and hasattr(fn, "__wrapped__")`, preventing `TypeError: takes 0 positional arguments` when REPL Python calls a bound `dspy.Tool` positionally.
3. **Grounded `sub_lm` Prompts:** Validates `llm_query` and `llm_query_batched` calls in `invoke_tool` so prompts passed to the stateless worker LM must exceed a minimum payload context threshold (`>= 40` characters), preventing ungrounded speculation.
4. **Post-RLM Normalization & `self.extract` Guard:** Because `dspy.RLM` falls back to `self.extract(...)` outside `CodeInterpreter.execute` if `max_iters` is exhausted before `SUBMIT()`, `normalize_rlm_prediction()` validates and coerces all output fields (`key_findings`, `high_signal_iocs`, `attributions`, `mitre_techniques`) after `rlm(...)` returns, and merges the deterministic `verbatim_anchors` so cryptographic digests can never be hallucinated or corrupted.

### 4.4 Deterministic Fallback (`deterministic_distill_payload`)
When LM credentials are unavailable or an unexpected LM runtime exception occurs, `deterministic_distill_payload()` distills `raw_data` in pure Python (extracting `verbatim_anchors`, top vendor family names, crowdsourced YARA/Sigma/IDS hits, non-noisy process/command/network/file indicators, MITRE techniques, and relationship summaries) and sets `compression_metrics["rlm_mode"] = "deterministic_fallback"`.

---

## 5. Testing Strategy (`server/gti/tests/test_rlm_files.py`)

1. **Hermetic Scripted `dspy.LM` Engine:** Implements `complete(self, request: dspy.lm15.Request) -> dspy.lm15.Response` on `dspy.LM("test/scripted", engine=..., cache=False)` to test the real `GTISandboxedInterpreter` subprocess worker, REPL Python slicing, `SUBMIT()`, and `max_iters` `self.extract` fallback without external network calls.
2. **1-API-Call Parity Tests:** Verifies `rlm_get_file_report`, `rlm_get_file_behavior_summary`, `rlm_get_file_behavior_report`, and `rlm_get_entities_related_to_a_file` each make exactly 1 VT request and achieve `>90%` byte reduction on bloated 150 KB+ fixtures while preserving 100% verbatim SHA-256/SHA-1/MD5/imphash digests.
3. **Multi-Call REPL Pivoting & Budget Tests:** Verifies `rlm_investigate_file` executes bound REPL tools (`fetch_behavior_summary`, `fetch_related_entities`, `fetch_sandbox_report`, `fetch_collection_summary`) positionally and by keyword, deduplicates repeated calls, and enforces `max_api_calls`.
4. **Error & Fallback Tests:** Verifies VT API error short-circuiting, invalid `relationship_name` rejection, and graceful fallback to `deterministic_distill_payload` when the LM raises an exception.
