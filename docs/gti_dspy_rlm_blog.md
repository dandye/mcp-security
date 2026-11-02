# Distilling 1 MB threat intelligence payloads with DSPy Recursive Language Models

In this post, I explain how I built five new DSPy 3.4+ Recursive Language Model (`dspy.RLM`) tools for the Google Threat Intelligence MCP server (`server/gti`) in my fork of [`google/mcp-security`](https://github.com/google/mcp-security). By keeping raw VirusTotal v3 payloads out of the host model's context window and mounting them inside a sandboxed Python REPL driven by Gemini 3.8 Flash and Gemini 3.5 Flash-Lite on Vertex AI, I reduced live payload sizes by **84.53% to 98.49%** while retaining 100% of high-signal indicators and guaranteeing zero cryptographic hash hallucinations.

Google Threat Intelligence (GTI) and the VirusTotal v3 API return far more JSON than an LLM agent's context window should absorb through the Model Context Protocol (MCP). A single call to `GET /files/{hash}/behaviour_summary` for a sample like WannaCry (`24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`) returns **998,460 bytes** of raw JSON. Even after stripping empty nulls and links with `utils.sanitize_response`, the payload still weighs **867,904 bytes**, or roughly 220,000 tokens. Over 95% of those bytes are benign operating system and sandbox background noise: thousands of Windows Error Reporting (`WER`) temporary file reads, `SyncRootManager` registry lookups, `MSIExecute` mutexes, standard Win32 DLL loads, and `.ttf` font opens.

![Direct context dumping and syntactic compression vs. DSPy 3.4+ out-of-core RLM](img/gti_dspy_rlm/01_context_rot_vs_rlm_architecture.png)

---

## Why security telemetry breaks standard MCP tool calling

Modern frontier models advertise million-token context windows, which makes it tempting to return raw API responses directly from MCP tools. In practice, stuffing hundreds of kilobytes of raw JSON into an agent's conversation history causes three distinct failures during multi-step security investigations.

**Context rot and lost-in-the-middle attention dilution.** Liu et al. demonstrated in *"Lost in the Middle: How Language Models Use Long Contexts"* ([arXiv:2307.03172](https://arxiv.org/abs/2307.03172)) that transformer retrieval accuracy drops sharply when relevant facts are buried inside long inputs. Hong et al. at Chroma Research extended this finding in their 2025 technical report *"Context Rot: How Increasing Input Tokens Impacts LLM Performance"* ([Chroma Context Rot Report](https://research.trychroma.com/context-rot)), showing that distraction tokens actively degrade multi-hop reasoning even when the needle is technically within the context limit. When a single `behaviour_summary` call injects 385 KB of `files_opened` noise and 290 KB of benign `registry_keys_opened` reads between the WannaCry kill-switch DNS lookup (`www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`) and the Windows service creation (`T1543.003`), the host agent loses track of the attack chain.

**Hard field exclusion blinds the analyst.** The existing [`get_file_report`](servers/gti_mcp.md) tool in `google/mcp-security` works around payload size by passing `exclude_attributes="last_analysis_results"` to the VirusTotal v3 API. That cuts the payload down to 50,286 bytes, but it throws away all 76 individual security vendor detection names. If an analyst asks which engines classified the binary as `WannaCry` versus a generic `Trojan` or whether any vendor flagged `CVE-2017-0147` (`EternalBlue`), the data is already gone. Worse, attempts to apply static field exclusion lists to sandbox behavior reports (such as dropping `command_executions` or `processes_tree` to save space, which I tracked in [`google/mcp-security` Issue #327](https://github.com/google/mcp-security/issues/327)) strip out the exact process trees and command lines needed to write a detection rule.

**Syntactic compression hits a semantic ceiling.** Before turning to Recursive Language Models, I experimented with [TOON (Token-Oriented Object Notation)](https://github.com/toon-format/toon) to compress MCP tool responses. TOON is a clever serialization format that factors repeated keys out of homogeneous JSON object arrays into a tabular header, cutting syntactic overhead from braces, quotes, and duplicate field names by 35% to 45%. However, TOON is lossless syntactic repacking. If a VirusTotal sandbox report contains 4,000 benign `C:\ProgramData\Microsoft\Windows\WER\Temp\WER*.tmp` file operations, TOON faithfully encodes all 4,000 rows into a slightly smaller table. What security telemetry needs is semantic distillation in code, not just tighter punctuation.

![Comparing payload reduction approaches for security threat intelligence MCP tools](img/gti_dspy_rlm/05_toon_vs_truncation_vs_rlm_comparison.png)

---

## Theoretical foundation: Recursive Language Models and DSPy 3.4+

To solve this properly, I drew on two foundational bodies of research and applied them to Google's security MCP ecosystem.

### 1. Recursive Language Models (Zhang, Kraska, & Khattab, 2025)

In *"Recursive Language Models"* ([arXiv:2512.24601](https://arxiv.org/abs/2512.24601)), Alex L. Zhang, Tim Kraska, and Omar Khattab (MIT CSAIL) introduce a general inference strategy for unbounded context lengths. Rather than feeding a massive payload $P$ directly into a transformer's context window, an RLM mounts $P$ as an external variable inside an interactive Python Read-Eval-Print Loop (REPL).

The root language model sees only the user's query and a compact metadata description of the environment. Across a bounded number of turns, the root LM writes executable Python code to inspect keys, compute collection lengths, filter arrays with regular expressions or set comprehensions, and optionally invoke a recursive sub-LM (`llm_query` or `llm_query_batched`) on small, isolated text slices. Once the root LM has assembled the exact evidence it needs, it calls `SUBMIT(...)` to terminate the loop and return a structured result.

### 2. Declarative compilation with DSPy (`dspy.RLM`)

In *"DSPy: Compiling Declarative Language Model Calls into Self-Improving Pipelines"* ([arXiv:2310.03714](https://arxiv.org/abs/2310.03714), ICLR 2024), Khattab et al. showed how to replace brittle prompt templates with typed Python signatures (`dspy.Signature`) and composable modules. Starting in DSPy 3.4+, the [`dspy.RLM` module](https://dspy.ai/current/diving-deeper/rlm/) brings Recursive Language Models directly into DSPy's declarative programming model.

In my implementation (`server/gti/gti_mcp/rlm_engine.py`), I defined `GTIPayloadDistillSignature(dspy.Signature)` to specify the exact contract between the raw VirusTotal v3 payload in the REPL and the distilled threat intelligence dictionary returned to the MCP client:

```python
class GTIPayloadDistillSignature(dspy.Signature):
  """Explore a Google Threat Intelligence (VirusTotal v3) payload in Python to extract high-signal threat intelligence."""

  entity_id: str = dspy.InputField(desc="Target file hash or behaviour ID.")
  tool_name: str = dspy.InputField(desc="MCP tool name being executed.")
  query: str = dspy.InputField(
      desc="Specific analyst question or triage objective."
  )
  payload_index: dict[str, Any] = dspy.InputField(
      desc="Compact structural index of top-level keys, collection lengths, and benign noise counts."
  )
  raw_data: Any = dspy.InputField(
      desc="Full un-truncated VirusTotal v3 JSON payload (dict or list) loaded in the Python REPL."
  )

  verdict_and_summary: str = dspy.OutputField(
      desc="Concise executive threat assessment (verdict, malware family, severity, and primary capability)."
  )
  answer: str = dspy.OutputField(
      desc="Direct, evidence-backed answer to `query`."
  )
  key_findings: list[str] = dspy.OutputField(
      desc="Bullet list of grounded technical findings."
  )
  high_signal_iocs: dict[str, list[str]] = dspy.OutputField(
      desc="Dict with keys: network, files_dropped_or_modified, process_and_command_lines, persistence_and_mutexes, yara_and_sigma_matches."
  )
  attributions: list[dict[str, str]] = dspy.OutputField(
      desc="List of associated threat actors, malware families, campaigns, or reports: [{'id': ..., 'name': ..., 'collection_type': ...}]."
  )
  mitre_techniques: list[dict[str, str]] = dspy.OutputField(
      desc="List of MITRE ATT&CK techniques: [{'id': ..., 'name': ..., 'evidence': ...}]."
  )
  filtered_noise_summary: str = dspy.OutputField(
      desc="Summary of noisy/benign fields and entries omitted during distillation."
  )
```

### 3. Pairing Gemini 3.8 Flash and Gemini 3.5 Flash-Lite on Vertex AI

To execute `dspy.RLM` efficiently in production, I paired two models from Google's [Gemini 3 model family on Vertex AI](https://cloud.google.com/vertex-ai/generative-ai/docs/models):

- **Root REPL controller (`vertex_ai/gemini-3.8-flash`):** Handles Python code generation, schema exploration, and cross-indicator correlation across REPL turns on the global Vertex AI endpoint (`vertex_location="global"`).
  - *ProTip on thinking budget and output token limits:* On reasoning models like Gemini 3.8 Flash, `max_tokens` caps the combined total of internal thinking tokens and visible output tokens. When the RLM emits its final `SUBMIT(...)` call containing 34 MITRE ATT&CK techniques and dozens of structured IOCs, default thinking budgets can consume enough of the output allowance to truncate the JSON response mid-stream. Setting `reasoning_effort="low"` keeps per-turn REPL code generation fast and concise, while setting `max_tokens=16384` provides ample headroom so large `SUBMIT(...)` payloads never truncate.
- **Recursive worker (`vertex_ai/gemini-3.5-flash-lite`):** Serves `llm_query` and `llm_query_batched` calls inside the REPL when the root model wants semantic summarization of unstructured report descriptions or GTI Code Insights.

### 4. Guaranteeing zero hash hallucinations with deterministic verbatim anchors

A single transposed character in a 64-character SHA-256 hash or a 72-character TLSH digest breaks downstream SIEM and EDR pivoting. Rather than asking the LLM to copy cryptographic digests into its `SUBMIT(...)` call, `extract_verbatim_anchors(raw_data)` extracts `sha256`, `sha1`, `md5`, `imphash`, `ssdeep`, `tlsh`, `meaningful_name`, `size`, `last_analysis_stats`, `popular_threat_classification`, `gti_assessment`, and `code_insights` deterministically in pure Python and merges them into the final response outside the LLM generation path.

When these GTI RLM MCP tools are consumed by an upstream agent built with the [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/) (such as the autonomous SOC agent in [`run-with-google-adk`](https://github.com/google/mcp-security/blob/main/run-with-google-adk/README.md)), the host ADK agent receives a 3 KB to 15 KB structured summary with guaranteed-exact hashes instead of a 1 MB raw dump.

---

## Anatomy of a 1 MB VirusTotal behavior summary

To see why out-of-core Python filtering works so well on security telemetry, look at where the bytes actually go inside the 998.5 KB VirusTotal v3 `/files/{hash}/behaviour_summary` response for WannaCry (`24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`).

![Anatomy of a 998 KB VirusTotal behaviour summary: noise vs. signal](img/gti_dspy_rlm/03_anatomy_of_1mb_behavior_payload.png)

Over 98% of the raw payload consists of repetitive Windows background activity recorded by multiple sandboxes (CAPE, Zenbox, Tencent HABO, Jujubox):

1. **`files_opened` and `files_written` clutter (~385 KB):** Hundreds of temporary crashpad and Windows Error Reporting files (`C:\ProgramData\Microsoft\Windows\WER\Temp\WER*.tmp.WERInternalMetadata.xml`), `.nls` locale tables, and font caches.
2. **`registry_keys_opened` clutter (~290 KB):** Background queries to `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager` and COM class registrations.
3. **`modules_loaded` and benign Win32 DLLs (~165 KB):** Standard Windows runtime libraries loaded by every Win32 executable.
4. **Duplicate multi-sandbox mutexes (~140.5 KB):** Benign Internet Explorer and Windows zone cache mutexes (`Local\ZonesCacheCounterMutex`, `RasPbFile`, `Local\!IETld!Mutex`).

Inside `server/gti/gti_mcp/rlm_engine.py`, I give the RLM both a pre-computed `payload_index` (which summarizes collection lengths and noise counts before Turn 0) and a helper function `compact_behavior_for_repl()` that strips known benign sandbox patterns (`SyncRootManager`, `MSIExecute`, `WER\Temp\WER`, Fonts/Adobe/NLS reads) whenever the RLM fetches behavioral data. What survives inside the **13,073-byte** RLM output (`98.49%` reduction) is pure signal:

- The exact command-line launch chain (`C:\Windows\system32\cmd.exe /c "START /MIN cmd.exe /c "C:\XXX\lhdfrgui.exe""` and `%WINDIR%\explorer.exe -> %SAMPLEPATH%\lhdfrgui.exe`).
- The WannaCry kill-switch DNS query (`www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`) and external C2 IP connections (`113.19.145.202`, `213.61.66.116`, `104.16.167.228`).
- All 34 MITRE ATT&CK techniques observed across sandboxes, including `T1543.003` (Windows service creation and persistence), `T1486` (ransomware document encryption), `T1070.004` (shadow volume deletion), `T1490` (`bcdedit` boot configuration modification), `T1135` (SMB lateral movement across private subnets), and `T1090.003` (Tor anonymizer installation).
- An explicit `filtered_noise_summary` audit string documenting how many benign command executions, system mutexes, and Microsoft background DNS queries were omitted.

**Future work: Externalizing benign sandbox noise rules from code.** Currently, the benign sandbox filter patterns (`_NOISY_PROCESS_PATTERNS`, `_NOISY_MUTEX_EXACT`, `_NOISY_FILE_SUBSTRINGS`, and `_NOISY_DNS_DOMAINS`) are defined as Python constants inside `rlm_engine.py`. As sandbox vendors update their base OS images or new background noise patterns emerge, we can decouple these filter definitions from code by loading them from a versioned YAML/JSON ruleset or a Google SecOps Reference List at startup, allowing detection engineers to continuously tune benign sandbox baselines without redeploying the MCP server.

---

## Five new GTI RLM MCP tools

I added five tools in `server/gti/gti_mcp/tools/rlm_files.py`, keeping all existing GTI tools untouched so MCP clients can adopt RLM distillation incrementally:

1. **`rlm_get_file_report(hash, ctx, query=None)` (1 VT API call):** Fetches `GET /files/{hash}` *without* excluding `last_analysis_results`. All 76 vendor results stay inside the Python REPL so the RLM can compute vendor consensus and extract CVE/exploit references while omitting `undetected` vendor rows and bulky PE import tables.
2. **`rlm_get_file_behavior_summary(hash, ctx, query=None)` (1 VT API call):** Distills `GET /files/{hash}/behaviour_summary` (`~1 MB` raw) into high-signal process trees, command lines, persistence registry modifications, non-noisy mutexes, dropped files, network C2 traffic, and MITRE ATT&CK techniques.
3. **`rlm_get_file_behavior_report(file_behaviour_id, ctx, query=None)` (1 VT API call):** Distills an individual sandbox execution report (`GET /file_behaviours/{file_hash}_{sandbox_name}`).
4. **`rlm_get_entities_related_to_a_file(hash, relationship_name, ctx, descriptors_only=False, limit=10, query=None)` (1 VT API call):** Fetches full related entity objects (such as `contacted_domains`, `contacted_ips`, `dropped_files`, or `associations`) and compresses them in the REPL.
5. **`rlm_investigate_file(hash, ctx, investigation_goal=None, max_api_calls=4)` (Multi-call autonomous investigator):** Seeds the RLM REPL with `GET /files/{hash}` and binds four VirusTotal pivot functions directly into the Python sandbox:
   - `fetch_behavior_summary()`
   - `fetch_sandbox_report(sandbox_id)`
   - `fetch_related_entities(relationship_name, limit=10)`
   - `fetch_collection_summary(collection_id)`

![Multi-call autonomous investigation trajectory: rlm_investigate_file](img/gti_dspy_rlm/04_autonomous_investigation_trajectory.png)

When I run `rlm_investigate_file` on WannaCry with `max_api_calls=3`, the RLM inspects the static file report on Turn 0, notices the `WannaCry_Ransomware` YARA matches and 68 malicious vendor detections, and autonomously calls `fetch_behavior_summary()` inside the Python REPL. It correlates the static PE masquerading (`lhdfrgui.exe`, `imphash` `9ecee117164e0b870a53dd187cdd7174`) and crowdsourced YARA/IDS rules with the dynamic kill-switch DNS query (`www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`) and service persistence (`T1543.003`, `T1569.002`), compressing **920,367 bytes** across 2 VirusTotal API calls into a single **14,875-byte** investigative report (`98.38%` reduction) in 2 REPL turns.

---

## Live compression benchmarks on VirusTotal v3 and Vertex AI

I benchmarked the tools against live VirusTotal v3 endpoints and Vertex AI (`vertex_ai/gemini-3.8-flash` root model + `vertex_ai/gemini-3.5-flash-lite` sub-model) on WannaCry (`24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`).

![Live VirusTotal v3 payload compression on WannaCry](img/gti_dspy_rlm/02_payload_compression_benchmarks.png)

| Tool | Raw Sanitized VT Payload | RLM Distilled Output | Byte Reduction | VT API Calls | RLM REPL Turns |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `rlm_get_file_report` | `52,463 B` | `8,117 B` | **84.53%** | `1` | `3` |
| `rlm_get_file_behavior_summary` | `867,904 B` (`998,460 B` raw) | `13,073 B` | **98.49%** | `1` | `3` |
| `rlm_get_entities_related_to_a_file` (`contacted_domains`) | `116,330 B` | `2,996 B` | **97.42%** | `1` | `2` |
| `rlm_investigate_file` (`/files/{hash}` + `/behaviour_summary`) | `920,367 B` | `14,875 B` | **98.38%** | `2` | `2` |

---

## Head-to-head SOC investigation: without vs. with the RLM refactor

When an agent conducts a multi-turn investigation, it triages the primary file report (Turn 1), inspects dynamic sandbox behavior (Turn 2), and pivots into network infrastructure and dropped artifacts (Turn 3).

To measure the end-to-end impact on a host SOC agent (`vertex_ai/gemini-3.8-flash`), I wrote [`server/gti/examples/compare_baseline_vs_rlm_investigation.py`](https://github.com/google/mcp-security) and ran the exact same multi-artifact WannaCry investigation (primary dropper `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c` plus dropped shortcut artifact `0a989a89d77d48f9a25ec64cb30043896bc976e85b8940b59dcf2afce2797227`) across three modes:

1. **Mode 1 - Baseline (Without Refactor):** Uses the legacy raw tools (`get_file_report`, `get_file_behavior_summary`, `get_entities_related_to_a_file`) across 3 host turns.
2. **Mode 2 - Refactored Stepwise RLM (`rlm_get_*`):** Uses `rlm_get_file_report`, `rlm_get_file_behavior_summary`, and `rlm_get_entities_related_to_a_file` across the same 3 host turns.
3. **Mode 3 - Refactored Autonomous RLM (`rlm_investigate_file`):** Uses `rlm_investigate_file` to correlate static and dynamic telemetry inside the sandboxed Python REPL and synthesize the investigation in a single host turn.

![End-to-end SOC investigation comparison: baseline raw tools vs. DSPy RLM tools](img/gti_dspy_rlm/07_baseline_vs_rlm_investigation_comparison.png)

| Investigation Metric | 1. Baseline Raw Tools (Without Refactor) | 2. Stepwise RLM (`rlm_get_*`) | 3. Autonomous RLM (`rlm_investigate_file`) |
| :--- | ---: | ---: | ---: |
| **Host Context Tool Bytes Injected** | `1,030,327 B` (`1.03 MB`) | `27,087 B` (**-97.37%**) | `21,083 B` (**-97.95%**) |
| **Turn 1 Host Prompt Tokens** | `18,864` | `4,486` | `9,579` (single turn) |
| **Turn 2 Host Prompt Tokens** | `423,870` | `10,074` | — |
| **Turn 3 Host Prompt Tokens** | `467,732` | `15,426` | — |
| **Cumulative Host Prompt Tokens Billed** | **`910,466`** | **`29,986` (-96.71%)** | **`9,579` (-98.95%)** |
| **Host Agent LLM Synthesis Time** | `109.92 s` | `42.63 s` (`2.6x` faster) | `25.51 s` (`4.3x` faster) |
| **76-Vendor Engine Signatures Visible?** | **No** (stripped by `exclude_attributes`) | **Yes** (analyzed in REPL) | **Yes** (analyzed in REPL) |
| **15-Point Ground-Truth Rubric Recall** | `14 / 15` (`93.3%`) | **`15 / 15` (`100.0%`)** | **`15 / 15` (`100.0%`)** |

Two qualitative differences stand out when comparing the transcripts side by side:

- **Eliminating the `exclude_attributes` blind spot:** In Mode 1 (Baseline), `get_file_report` hardcodes `params={"exclude_attributes": "last_analysis_results"}` to keep the raw JSON under 50 KB. When asked for specific vendor classifications from Kaspersky, Microsoft, and ESET, the baseline host agent had to report that per-vendor engine signatures were missing from the payload (`14/15` rubric score). In Modes 2 and 3, `rlm_get_file_report` and `rlm_investigate_file` load all 76 vendor results into the Python REPL and extract the exact signatures (`Kaspersky: Trojan-Ransom.Win32.Wanna.m`, `Microsoft: Ransom:Win32/WannaCrypt!pz`, `ESET-NOD32: Win32/Exploit.CVE-2017-0147.A trojan`, and on the dropped `.lnk` file `Symantec: Ransom.Wannacry`, `Skyhigh: Ransom-WannaCry!lnk`) while discarding undetected rows (`15/15` rubric score).
- **Cutting host context volume and synthesis latency:** Mode 1 injects `1,030,327 bytes` (`1.03 MB`) of raw JSON into the host agent across the three steps (`109.92s` of host LLM synthesis time). Modes 2 and 3 reduce total injected tool bytes by **97.37%** (`27,087 B`) and **97.95%** (`21,083 B`), cutting host LLM synthesis time to `42.63s` and `25.51s`.

---

## Cross-platform threat hunting in Google SecOps (Chronicle SIEM) and GTI

While a single-sample file investigation demonstrates the problem, the context explosion becomes even more acute during a live cross-platform threat hunt in [Google Security Operations (Chronicle SIEM)](https://cloud.google.com/security/products/security-operations), where a single UDM process timeline often uncovers *multiple* distinct binaries that must be enriched in GTI to separate attacker malware from legitimate operating system Living-off-the-Land Binaries (LOLBins).

To measure this multi-hash amplification effect in a test Google SecOps tenant, I connected both `secops-mcp` (`server/secops`) and `gti-mcp` (`server/gti`) and wrote a reproducible cross-platform threat hunt harness in `server/gti/examples/secops_gti_threat_hunt_comparison.py`.

### The live Active Directory Domain Controller intrusion chain (`activedir.stackedpads.local`)

In Stage 1 of the hunt, `secops-mcp` queries live Chronicle SIEM telemetry (`get_ioc_matches`, `lookup_entity`, `get_security_alerts`, and `chronicle.search_udm` for `WINDOWS_SYSMON` process and file events on `activedir.stackedpads.local`, `10.10.20.60`), returning `29,922 bytes` across 50 UDM events:

1. **Initial access & SIEM IoC correlation:** `lookup_entity("activedir")` surfaces 12 `win_repeatedAuthFailure_thenSuccess_T1110_001` brute-force alerts (`T1110.001`), and `get_ioc_matches` surfaces active `Google Threat Intelligence` MD5 IoC matches (`priority="ACTIVE_BREACH"`, `rawSeverity="HIGH"`) attributed to `MALWARE:MIMIKATZ` and threat actor clusters `UNC3313`, `UNC3591`, `UNC3661`, `UNC2727`, and `UNC5883`.
2. **Stage 1 - LSASS memory credential dumping (`T1003.001`):** Compromised domain account `frank.kolzig` (`fkolzig`) extracts `C:\Users\fkolzig\Downloads\mimikatz_trunk\x64\` (`mimikatz.exe` MD5 `bb8bdb3e8c92e97e2f63626bc3b254c4` and `mimilib.dll` MD5 `ddfad0d55be70acdfea36acf28d418b3`) and executes `mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit`, triggering 19 alerts for `MimiKatz Command Arguments [Mandiant Intel Emerging Threats]`.
3. **Stage 2 - DiskShadow script & `ntds.dit` extraction (`T1003.003`):** `cmd.exe` runs `diskshadow /s c:\temp\orange.txt`, which spawns `"c:\windows\system32\cmd.exe" /c copy x:\windows\ntds\ntds.dit c:\ntds.dit` to exfiltrate the Active Directory database.
4. **Stage 3 - WMI execution & Volume Shadow Copy creation (`T1047` / `T1003.003`):** `WMIC.exe` executes `wmic process call create "cmd /c vssadmin create shadow /for=C:"`, which spawns `C:\Windows\System32\vssadmin.exe` (MD5 `614b5c4238977130aa2270c8ad58ce6c`).

To recommend safe containment actions, the threat hunting agent must enrich all **three** kill-chain file hashes (`bb8bdb3e8c92e97e2f63626bc3b254c4`, `ddfad0d55be70acdfea36acf28d418b3`, and `614b5c4238977130aa2270c8ad58ce6c`) with GTI static reports and dynamic sandbox behavior summaries so it does not accidentally block a core Microsoft Windows system executable (`vssadmin.exe`).

![Cross-platform Google SecOps (Chronicle SIEM) + GTI threat hunt: baseline vs. DSPy RLM](img/gti_dspy_rlm/08_secops_siem_gti_threat_hunt_comparison.png)

| Cross-Platform SIEM + GTI Threat Hunt Metric | 1. Baseline Raw GTI + SecOps MCP | 2. Stepwise RLM (`rlm_get_*`) + SecOps MCP | 3. Autonomous RLM (`rlm_investigate_file`) + SecOps MCP |
| :--- | ---: | ---: | ---: |
| **SIEM Telemetry Payload (`secops-mcp`, 50 UDM Events)** | `29,922 B` | `29,922 B` | `29,922 B` |
| **GTI Enrichment Payload (3 Kill-Chain File Hashes)** | `1,268,723 B` (`1.27 MB`) | `77,937 B` (**-93.86%**) | `61,561 B` (**-95.15%**) |
| **Total Combined SIEM + GTI Bytes Injected** | `1,298,645 B` (`1.30 MB`) | `107,859 B` (**-91.69%**) | `91,483 B` (**-92.96%**) |
| **Turn 1 Host Prompt Tokens (SIEM Discovery)** | `13,301` | `13,301` | `41,027` (single turn) |
| **Turn 2 Host Prompt Tokens (`mimikatz.exe` + `mimilib.dll`)** | `444,506` | `37,709` | — |
| **Turn 3 Host Prompt Tokens (`vssadmin.exe` + Final Synthesis)** | `580,201` | `52,648` | — |
| **Cumulative Host Prompt Tokens Billed** | **`1,038,008` (`1.04M`)** | **`103,658` (-90.01%)** | **`41,027` (-96.05%)** |
| **Host Threat Hunter LLM Synthesis Time** | `153.79 s` | `71.97 s` (`2.1x` faster) | `43.90 s` (`3.5x` faster) |
| **72-Vendor Signatures Visible in REPL?** | **No** (stripped by `exclude_attributes`) | **Yes** (`Microsoft`, `ESET`, `Kaspersky`) | **Yes** (`Microsoft`, `ESET`, `Kaspersky`) |
| **18-Point SIEM + GTI + LOLBin Rubric Recall** | `17 / 18` (`94.4%`) | **`18 / 18` (`100.0%`)** | **`18 / 18` (`100.0%`)** |

Enriching three binaries in a single SIEM investigation demonstrates why raw GTI JSON does not scale in multi-artifact threat hunts:

- **1.27 MB of raw GTI JSON vs. 29.9 KB of SIEM telemetry:** While the entire Chronicle SIEM telemetry bundle (IoC matches, entity lookups, alerts, and 50 `WINDOWS_SYSMON` UDM events) occupies just `29,922 bytes`, enriching `mimikatz.exe` (`433.8 KB`), `mimilib.dll` (`539.9 KB`), and `vssadmin.exe` (`295.0 KB`) with legacy raw GTI tools injects **`1,268,723 bytes` (`1.27 MB`)** into the host Threat Hunter conversation (`1,038,008` cumulative prompt tokens).
- **90.0% to 96.1% host token reduction with 100% rubric recall:** Mode 2 (`rlm_get_*` tools) compresses the 3-hash GTI enrichment payload by **93.86%** (`1,268,723 B` -> `77,937 B`) and cuts cumulative host prompt tokens by **90.01%** (`1,038,008` -> `103,658 tokens`). Mode 3 (`rlm_investigate_file` across all 3 hashes in parallel) compresses GTI enrichment by **95.15%** (`61,561 B`) and cuts cumulative host tokens by **96.05%** (`41,027 tokens`), while recovering the exact per-vendor detection signatures (`Microsoft: HackTool:Win32/Mimikatz!pz`, `ESET-NOD32: Win64/Riskware.Mimikatz.G`, `Kaspersky: HEUR:Trojan.Win32.Generic`) and verifying that `vssadmin.exe` (`614b5c4238977130aa2270c8ad58ce6c`, `0/76` detections, signed by `Microsoft Windows Production PCA 2011`) is a legitimate LOLBin that must not be hash-blocked globally.

---

## Try it yourself

I included runnable CLI scripts in `server/gti/examples/` so you can reproduce every benchmark above against your own VirusTotal API key and Google Cloud project:

```bash
WORKTREE_DIR="/path/to/mcp-security"
SAMPLE_SHA256="24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
cd "$WORKTREE_DIR/server/gti"

# 1. Distill a full 76-vendor file report (52.5 KB -> 8.1 KB)
python3 examples/rlm_file_triage_demo.py \
  --hash "$SAMPLE_SHA256" \
  --tool report

# 2. Distill a ~1 MB multi-sandbox behaviour_summary (867.9 KB -> 13.1 KB)
python3 examples/rlm_file_triage_demo.py \
  --hash "$SAMPLE_SHA256" \
  --tool behavior

# 3. Distill full related entity objects (116.3 KB -> 3.0 KB)
python3 examples/rlm_file_triage_demo.py \
  --hash "$SAMPLE_SHA256" \
  --tool entities

# 4. Run a multi-call autonomous file investigation (920.4 KB -> 14.9 KB)
python3 examples/rlm_file_triage_demo.py \
  --hash "$SAMPLE_SHA256" \
  --tool investigate

# 5. Run the head-to-head SOC investigation comparison (Baseline vs. RLM)
python3 examples/compare_baseline_vs_rlm_investigation.py \
  --output-json /tmp/gti_rlm_comparison.json

# 6. Run the cross-platform Google SecOps (Chronicle SIEM) + GTI threat hunt comparison
python3 examples/secops_gti_threat_hunt_comparison.py \
  --output-json /tmp/secops_gti_hunt_comparison.json
```

---

## Conclusion

While these five new GTI MCP tools work out of the box, I built them as a reference implementation to show how Recursive Language Models (`dspy.RLM`) can be applied to high-volume security telemetry. Any MCP endpoint that returns tens or hundreds of kilobytes of noisy JSON, whether from sandbox behavior reports, SIEM event searches, cloud configuration snapshots, or vulnerability scans, can use this same out-of-core Python REPL pattern to keep the host agent's context window compact, fast, and grounded.

---

## References and further reading

1. **Zhang, A. L., Kraska, T., & Khattab, O. (2025).** *Recursive Language Models.* MIT CSAIL, arXiv preprint [arXiv:2512.24601](https://arxiv.org/abs/2512.24601).
2. **Khattab, O., Singhvi, A., Maheshwari, P., Zhang, Z., Santhanam, K., Vardhamanan, S., Haq, S., Sharma, A., Joshi, T. T., Moazam, H., Miller, H., Zaharia, M., & Potts, C. (2024).** *DSPy: Compiling Declarative Language Model Calls into Self-Improving Pipelines.* International Conference on Learning Representations (ICLR 2024), [arXiv:2310.03714](https://arxiv.org/abs/2310.03714), and [DSPy `dspy.RLM` Documentation](https://dspy.ai/current/diving-deeper/rlm/).
3. **Hong, K., Troynikov, A., & Huber, J. (2025).** *Context Rot: How Increasing Input Tokens Impacts LLM Performance.* Chroma Research Technical Report, [https://research.trychroma.com/context-rot](https://research.trychroma.com/context-rot).
4. **Liu, N. F., Lin, K., Hewitt, J., Paranjape, A., Bevilacqua, M., Petroni, F., & Liang, P. (2024).** *Lost in the Middle: How Language Models Use Long Contexts.* Transactions of the Association for Computational Linguistics (TACL), [arXiv:2307.03172](https://arxiv.org/abs/2307.03172).
5. **TOON Contributors (2025).** *TOON: Token-Oriented Object Notation for LLMs.* [https://github.com/toon-format/toon](https://github.com/toon-format/toon).
6. **Google Cloud Security & Google Threat Intelligence (2025-2026).** [Google Threat Intelligence Overview](https://cloud.google.com/security/products/threat-intelligence), [VirusTotal v3 API Reference](https://docs.virustotal.com/reference/overview), and the open-source [Google `mcp-security` Repository](https://github.com/google/mcp-security).
7. **Google DeepMind & Google Cloud Vertex AI (2025-2026).** [Gemini Models on Vertex AI](https://cloud.google.com/vertex-ai/generative-ai/docs/models) and the [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/).
