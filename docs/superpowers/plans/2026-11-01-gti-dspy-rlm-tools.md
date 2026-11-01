# GTI MCP DSPy RLM Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:executing-plans (with final code review subagent) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five DSPy 3.4+ `dspy.RLM`-powered file and behavior analysis tools (`rlm_get_file_report`, `rlm_get_file_behavior_summary`, `rlm_get_file_behavior_report`, `rlm_get_entities_related_to_a_file`, and `rlm_investigate_file`) to `gti-mcp` (`server/gti`) so large VirusTotal/GTI v3 JSON payloads are sliced and distilled inside a sandboxed Python REPL with high signal-to-noise ratio and 100% verbatim hash/indicator fidelity.

**Architecture:** We add `server/gti/gti_mcp/rlm_engine.py` containing deterministic verbatim anchor extraction (`extract_verbatim_anchors`), structural payload indexing (`build_payload_index`), benign sandbox noise filtering (`COMMON_BENIGN_NOISE_PATTERNS`), a hardened `GTISandboxedInterpreter(LocalInterpreter)` subclass, thread-safe `APICallTracker`, `dspy.RLM` distillation (`distill_gti_payload`), and deterministic fallback (`deterministic_distill_payload`). We register the 5 new MCP tools in `server/gti/gti_mcp/tools/rlm_files.py` and re-export them from `server/gti/gti_mcp/tools/__init__.py`.

**Tech Stack:** Python 3.11+, `mcp>=1.23.0,<2.0` (`FastMCP`), `vt-py`, `dspy>=3.4.1` (`dspy.RLM`, `LocalInterpreter`), `pytest`, `pytest-asyncio`.

**Spec:** `docs/superpowers/specs/2026-11-01-gti-dspy-rlm-tools-design.md`

## Global Constraints

- Existing raw tools in `server/gti/gti_mcp/tools/files.py` (`get_file_report`, `get_file_behavior_summary`, `get_file_behavior_report`, `get_entities_related_to_a_file`, `analyse_file`, `search_digital_threat_monitoring`) MUST remain untouched and keep all 58 existing tests passing.
- `mcp>=1.23.0,<2.0` pin in `server/gti/pyproject.toml` and `server/gti/setup.py` MUST be preserved alongside `dspy>=3.4.1`.
- Never use f-strings in `logger.*` calls; always use lazy `%s` formatting per Google Python Style Guide Section 3.10.1.
- Never run `git add .`, `git add -A`, or `git add --all`; stage explicit file paths only.
- Always run pytest from inside `server/gti` with `PYTHONPATH=""` so Google3 directories do not shadow Python stdlib modules.

---

### Task 1: Dependencies, Verbatim Anchors, Structural Indexing, and Deterministic Fallback (`rlm_engine.py` Part 1)

**Files:**
- Modify: `server/gti/pyproject.toml`
- Modify: `server/gti/setup.py`
- Create: `server/gti/gti_mcp/rlm_engine.py`
- Create: `server/gti/tests/test_rlm_files.py`

**Interfaces:**
- Produces:
  - `extract_verbatim_anchors(raw_data: Any) -> dict[str, Any]`
  - `build_payload_index(raw_data: Any) -> dict[str, Any]`
  - `is_benign_sandbox_noise(value: str) -> bool`
  - `deterministic_distill_payload(raw_data: Any, *, entity_id: str, tool_name: str, query: str, api_calls_made: int = 1, endpoints_called: Optional[list[str]] = None) -> dict[str, Any]`

- [ ] **Step 1: Add `dspy>=3.4.1` to `server/gti/pyproject.toml` and `server/gti/setup.py` and write failing unit tests for anchor extraction, noise filtering, payload indexing, and deterministic distillation**
- [ ] **Step 2: Run pytest on `tests/test_rlm_files.py` to verify RED state**
- [ ] **Step 3: Implement `extract_verbatim_anchors`, `build_payload_index`, `is_benign_sandbox_noise`, and `deterministic_distill_payload` in `server/gti/gti_mcp/rlm_engine.py`**
- [ ] **Step 4: Run pytest to verify GREEN state**
- [ ] **Step 5: Commit Task 1**

---

### Task 2: `GTISandboxedInterpreter`, `APICallTracker`, and `dspy.RLM` Execution Pipeline (`rlm_engine.py` Part 2)

**Files:**
- Modify: `server/gti/gti_mcp/rlm_engine.py`
- Modify: `server/gti/tests/test_rlm_files.py`

**Interfaces:**
- Consumes: `extract_verbatim_anchors`, `build_payload_index`, `deterministic_distill_payload` from Task 1
- Produces:
  - `GTISandboxedInterpreter(LocalInterpreter)`
  - `APICallTracker`
  - `distill_gti_payload(raw_data: Any, *, entity_id: str, tool_name: str, query: Optional[str] = None, default_objective: str = ..., extra_tools: Optional[list[Any]] = None, tracker: Optional[APICallTracker] = None, lm: Optional[dspy.LM] = None, sub_lm: Optional[dspy.LM] = None) -> dict[str, Any]`
  - `distill_gti_payload_async(...) -> dict[str, Any]`

- [ ] **Step 1: Write failing unit tests in `server/gti/tests/test_rlm_files.py` using a hermetic scripted `dspy.lm15` engine for `GTISandboxedInterpreter` (`__dspy_host_token` shim bypass, positional tool-arg binding, `llm_query` grounding gate, `SUBMIT()` distillation, `max_iters` `self.extract` normalization, and LM exception fallback)**
- [ ] **Step 2: Run pytest to verify RED state**
- [ ] **Step 3: Implement `GTISandboxedInterpreter`, `APICallTracker`, `GTIPayloadDistillSignature`, `normalize_rlm_prediction`, `distill_gti_payload`, and `distill_gti_payload_async` in `server/gti/gti_mcp/rlm_engine.py`**
- [ ] **Step 4: Run pytest to verify GREEN state**
- [ ] **Step 5: Commit Task 2**

---

### Task 3: The 5 GTI RLM MCP Tools (`rlm_files.py`), Tool Exports, and Documentation

**Files:**
- Create: `server/gti/gti_mcp/tools/rlm_files.py`
- Modify: `server/gti/gti_mcp/tools/__init__.py`
- Modify: `server/gti/README.md`
- Modify: `server/gti/tests/test_rlm_files.py`

**Interfaces:**
- Consumes: `distill_gti_payload_async`, `APICallTracker` from `gti_mcp.rlm_engine`
- Produces:
  - `rlm_get_file_report(hash: str, ctx: Context, query: Optional[str] = None) -> dict[str, Any]`
  - `rlm_get_file_behavior_summary(hash: str, ctx: Context, query: Optional[str] = None) -> dict[str, Any]`
  - `rlm_get_file_behavior_report(file_behaviour_id: str, ctx: Context, query: Optional[str] = None) -> dict[str, Any]`
  - `rlm_get_entities_related_to_a_file(hash: str, relationship_name: str, ctx: Context, descriptors_only: bool = False, limit: int = 10, query: Optional[str] = None) -> dict[str, Any]`
  - `rlm_investigate_file(hash: str, ctx: Context, investigation_goal: Optional[str] = None, max_api_calls: int = 4) -> dict[str, Any]`

- [ ] **Step 1: Write failing MCP integration and unit tests in `server/gti/tests/test_rlm_files.py` for all 5 tools (verifying 1-API-call parity on `rlm_get_*`, `>90%` byte compression on 150KB+ bloated fixtures, multi-call REPL pivoting and `max_api_calls` cap on `rlm_investigate_file`, and error handling)**
- [ ] **Step 2: Run pytest to verify RED state**
- [ ] **Step 3: Implement `server/gti/gti_mcp/tools/rlm_files.py`, export in `server/gti/gti_mcp/tools/__init__.py`, and document the 5 RLM tools and environment variables in `server/gti/README.md`**
- [ ] **Step 4: Run full `pytest` suite across `server/gti` to verify all existing 58 tests + all new RLM tests pass**
- [ ] **Step 5: Commit Task 3**
