# Lateral Movement Detection Hunt (Example: PsExec/WMI)

## Objective

Proactively hunt for signs of lateral movement using common administrative tools like PsExec or WMI abuse, which attackers often leverage.

## Scope

This runbook provides a template for hunting specific lateral movement TTPs, focusing on PsExec and WMI examples using SIEM queries.

## Inputs

*   `${TIME_FRAME_HOURS}`: Lookback period in hours for SIEM searches (default: 72).
*   *(Optional) `${TARGET_SCOPE_QUERY}`: A UDM query fragment to narrow the scope (e.g., `principal.hostname = "server1"` or `target.hostname = "domain_controller"`).*
*   *(Optional) `${HUNT_HYPOTHESIS}`: Brief description of the reason for the hunt (e.g., "Hunting for PsExec usage originating from non-admin workstations").*

## Tools

*   `gti-mcp`: `get_threat_intel` (for technique understanding).
*   `secops-mcp`: `search_security_events` (core hunting tool), `lookup_entity` (for enriching findings).
*   `secops-soar`: `post_case_comment` (for documenting hunt/findings), `list_cases` (optional, check related cases).

## Workflow Steps & Diagram

1.  **Receive Input & Define Scope:** Obtain `${TIME_FRAME_HOURS}`, optionally `${TARGET_SCOPE_QUERY}` and `${HUNT_HYPOTHESIS}`.
2.  **Research Techniques (GTI/External):**
    *   Use `gti-mcp.get_threat_intel` for TTPs like T1570 (Lateral Tool Transfer - PsExec often copied), T1021.002 (Remote Services: SMB/Windows Admin Shares - PsExec uses this), T1047 (Windows Management Instrumentation - WMI abuse).
    *   *(Manual Step: Review MITRE ATT&CK website for detailed procedures and detection guidance for these techniques).*
3.  **Develop SIEM Hunt Queries:**
    *   Based on research, formulate specific `secops-mcp.search_security_events` UDM queries targeting indicators. Examples:
        *   **PsExec Service Installation:** `metadata.product_event_type = "ServiceInstalled" AND target.process.file.full_path CONTAINS "PSEXESVC.exe"` (Requires appropriate Windows Event Log source - System Log Event ID 7045).
        *   **PsExec Execution (Indirect):** Look for `services.exe` spawning unusual processes, especially on remote machines shortly after potential SMB connection. `metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = "C:\Windows\System32\services.exe" AND target.process.file.full_path NOT IN ("standard_service_process1.exe", "standard_service_process2.exe")` (Needs significant tuning based on environment).
        *   **WMI Process Creation:** `metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = "C:\Windows\System32\wbem\WmiPrvSE.exe"` (Look for `WmiPrvSE.exe` spawning suspicious child processes like `cmd.exe`, `powershell.exe`).
        *   **WMI Command-Line Execution:** `metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = "C:\Windows\System32\cmd.exe" AND principal.process.command_line CONTAINS "wmic"` AND `principal.process.command_line CONTAINS "/node:"` AND `principal.process.command_line CONTAINS "process call create"`
        *   **Network Activity:** Correlate process activity with network connections on SMB port 445 (`target.port = 445`) originating from potential source machines to target machines around the time of suspicious process launches.
    *   Combine technique-specific queries with `${TARGET_SCOPE_QUERY}` if provided.
4.  **Execute SIEM Searches:**
    *   Run the developed queries using `secops-mcp.search_security_events` with `hours_back=${TIME_FRAME_HOURS}`.
5.  **Analyze Results:**
    *   Review results for anomalous patterns: PsExec/WMI usage originating from unexpected sources (e.g., user workstations instead of admin servers), execution targeting a large number of hosts, execution of suspicious commands via WMI.
6.  **Enrich Findings:**
    *   If suspicious activity is found, use `secops-mcp.lookup_entity` for involved source/destination hosts, users.
    *   Use `gti-mcp` tools to enrich any associated IPs, domains, or hashes if applicable.
7.  **Document Hunt & Findings:**
    *   Use `secops-soar.post_case_comment` in a dedicated hunting case or relevant existing case.
    *   Document: Hunt Hypothesis/Objective, Techniques Hunted, Scope, Timeframe, Queries Used, Summary of Findings (including negative results), Details of suspicious activity, Enrichment results.
8.  **Escalate or Conclude:**
    *   If confirmed lateral movement or tool abuse is found, escalate by creating a new incident case or linking findings to an existing one.
    *   If no significant findings, conclude the hunt and document it.
9.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar
    participant MITRE as MITRE ATT&CK (External)

    Analyst->>Cline: Start Lateral Movement Hunt (PsExec/WMI)\nInput: TIME_FRAME_HOURS, TARGET_SCOPE_QUERY (opt), HUNT_HYPOTHESIS (opt)

    %% Step 2: Research Techniques
    Cline->>GTI: get_threat_intel(query="MITRE T1021.002")
    GTI-->>Cline: Technique Context
    Cline->>GTI: get_threat_intel(query="MITRE T1047")
    GTI-->>Cline: Technique Context
    Cline->>MITRE: (Manual) Review ATT&CK Website
    MITRE-->>Cline: Detailed Procedures/Detections

    %% Step 3: Develop SIEM Queries
    Note over Cline: Formulate UDM queries for PsExec/WMI indicators

    %% Step 4: Execute SIEM Searches
    loop For each developed Query Qi
        Cline->>SIEM: search_security_events(text=Qi, hours_back=TIME_FRAME_HOURS)
        SIEM-->>Cline: Search Results for Qi
    end

    %% Step 5: Analyze Results
    Note over Cline: Analyze results for anomalous PsExec/WMI usage

    %% Step 6: Enrich Findings
    opt Suspicious Activity Found (Hosts H1, H2..., Users U1...)
        loop For each Suspicious Entity Ei (H1, U1...)
            Cline->>SIEM: lookup_entity(entity_value=Ei)
            SIEM-->>Cline: SIEM Summary for Ei
            %% Potentially enrich related IOCs if found
            %% Cline->>GTI: get_..._report(ioc=...)
            %% GTI-->>Cline: GTI Report
        end
    end

    %% Step 7: Document Hunt
    Note over Cline: Prepare hunt summary comment
    Cline->>SOAR: post_case_comment(case_id=[Hunt Case/Relevant Case], comment="Lateral Movement Hunt (PsExec/WMI) Summary: Scope [...], Queries [...], Findings [...], Enrichment [...]")
    SOAR-->>Cline: Comment Confirmation

    %% Step 8 & 9: Escalate or Conclude
    alt Confirmed Malicious Activity Found
        Note over Cline: Escalate findings (Create new case or link to existing)
        Cline->>Analyst: attempt_completion(result="Lateral Movement Hunt complete. Findings escalated.")
    else No Significant Findings
        Cline->>Analyst: attempt_completion(result="Lateral Movement Hunt complete. No significant findings. Hunt documented.")
    end
