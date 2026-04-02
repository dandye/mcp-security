# Ransomware Response Runbook

## Objective

Respond to a suspected ransomware incident by identifying the ransomware strain, isolating affected systems, searching for initial access vectors and lateral movement, identifying potential recovery options, and documenting the investigation.

## Scope

This runbook covers the initial critical response steps for a ransomware event. It focuses on identification, containment, and initial impact assessment. Full recovery and post-mortem analysis may require additional procedures.

## Inputs

*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   `${INITIAL_INDICATORS}`: Information about the initial detection, which could include:
    *   Alert details (e.g., EDR detection name, SIEM rule).
    *   Affected endpoint(s) (`ENDPOINT_ID`, `ENDPOINT_TYPE`).
    *   Observed file hashes (`FILE_HASH`).
    *   Ransom note details (file names, contact info - **handle with care**).
    *   Observed suspicious network connections (IPs/Domains).

## Tools

*   `gti-mcp`: `get_file_report`, `search_threats` (querying ransomware name/family), `get_collection_report` (for known families/actors).
*   `secops-mcp`: `search_security_events`, `lookup_entity`.
*   `secops-soar`: `post_case_comment`, `get_case_full_details`.
*   **Basic Endpoint Triage & Isolation Runbook:** `.clinerules/run_books/basic_endpoint_triage_isolation.md` (Crucial for containment).
*   **IOC Containment Runbook:** `.clinerules/run_books/ioc_containment.md` (For network IOCs).
*   **Compromised User Account Response Runbook:** `.clinerules/run_books/compromised_user_account_response.md` (If initial access vector involves user).
*   `ask_followup_question` (To confirm actions, especially isolation).
*   *(External Resources: Ransomware identification sites, known decryptor databases - manual step)*.

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain initial indicators, `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`. Get case details via `secops-soar.get_case_full_details`.
2.  **Identify Ransomware Strain:**
    *   If a file hash (`${FILE_HASH}`) is available, use `gti-mcp.get_file_report` to identify the malware family/ransomware name.
    *   If EDR alert name or ransom note details provide a name, use `gti-mcp.search_threats` (e.g., `query="LockBit ransomware" collection_type:"malware-family"`) or `get_collection_report` if a specific GTI ID is known.
    *   *(Manual Step: Use external resources like ID Ransomware if GTI doesn't yield results).*
    *   Document the identified (or suspected) strain.
3.  **Isolate Affected Endpoints:**
    *   For each initially identified affected endpoint (`${ENDPOINT_ID}`):
        *   **Trigger Basic Endpoint Triage & Isolation Runbook:** Initiate `.clinerules/run_books/basic_endpoint_triage_isolation.md` for the endpoint ID. **Prioritize immediate isolation confirmation.**
4.  **Identify & Contain Network IOCs:**
    *   Extract any observed Command & Control (C2) IPs/Domains from alerts, endpoint data (if available via EDR tools), or GTI reports for the identified strain.
    *   For each confirmed malicious network IOC:
        *   **Call IOC Containment Runbook:** Execute `.clinerules/run_books/ioc_containment.md` with the IOC details and current `${CASE_ID}`.
5.  **Investigate Initial Access & Lateral Movement (SIEM):**
    *   Use `secops-mcp.search_security_events` focusing on the time *before* and *during* the initial encryption activity on the affected endpoints:
        *   Search for suspicious logins, RDP activity, or exploit attempts targeting the initially affected endpoints.
        *   Search for execution of suspicious tools (PsExec, Cobalt Strike beacons, etc.).
        *   Search for activity related to the user logged into the endpoint at the time of infection (potentially trigger `compromised_user_account_response.md`).
        *   Trace network connections *from* the affected endpoints to identify potential lateral movement targets.
    *   Identify potential initial access vector (e.g., phishing email leading to download, exploited vulnerability) and other potentially affected systems.
6.  **Isolate Newly Identified Endpoints:**
    *   If Step 5 identifies other endpoints likely involved in lateral movement or also encrypted:
        *   **Trigger Basic Endpoint Triage & Isolation Runbook:** Initiate `.clinerules/run_books/basic_endpoint_triage_isolation.md` for each new endpoint ID.
7.  **Assess Scope & Check Recovery Options:**
    *   Summarize the number of affected endpoints identified and isolated.
    *   Based on the identified ransomware strain (Step 2), check known decryptor availability *(Manual Step: NoMoreRansom.org, vendor sites)*.
    *   Identify available backups for affected systems *(Requires knowledge of backup systems/procedures - likely manual)*.
8.  **Document Findings:** Record all analysis steps, identified strain, IOCs, isolated endpoints, potential initial access/lateral movement findings, recovery options assessment, and triggered runbooks in the SOAR case using `secops-soar.post_case_comment`.
9.  **Handover / Next Steps:** Escalate to full Incident Response team / Management. Recommend next steps (e.g., full forensic analysis, recovery planning, communication plan).
10. **Completion:** Conclude the initial response runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar
    participant Endpoint_Triage as Endpoint Triage Runbook
    participant IOC_Containment as IOC Containment Runbook
    participant User_Comp_Response as User Comp. Response Runbook
    participant External_Resources as External Resources (Manual)

    Analyst/User->>Cline: Start Ransomware Response\nInput: Initial Indicators (Endpoint E1, Hash H1...), CASE_ID, ALERT_GROUP_IDS

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: Identify Strain
    opt Hash H1 available
        Cline->>GTI: get_file_report(hash=H1)
        GTI-->>Cline: File Report (Identify Strain S1)
    end
    opt Strain Name N1 known
        Cline->>GTI: search_threats(query=N1, collection_type="malware-family")
        GTI-->>Cline: GTI Info for Strain N1
    end
    opt Strain Identification Needed
        Cline->>External_Resources: (Manual) Check ID Ransomware, etc.
        External_Resources-->>Cline: Potential Strain S2
    end
    Note over Cline: Document Identified Strain

    %% Step 3: Isolate Initial Endpoints
    loop For each Initial Endpoint Ei (e.g., E1)
        Cline->>Endpoint_Triage: Execute(endpoint_id=Ei, case_id=CASE_ID)
        Endpoint_Triage-->>Cline: Isolation Result for Ei
    end

    %% Step 4: Identify & Contain Network IOCs
    Note over Cline: Extract Network IOCs (IP_C2, DOM_C2...) from data
    loop For each Malicious Network IOC NIi
        Cline->>IOC_Containment: Execute(ioc=NIi, case_id=CASE_ID)
        IOC_Containment-->>Cline: Containment Result for NIi
    end

    %% Step 5: Investigate Initial Access & Lateral Movement
    Cline->>SIEM: search_security_events(text="Activity on E1 before encryption, logins, process exec...")
    SIEM-->>Cline: Related Events (User U_suspicious, Endpoint E2_lateral...)
    opt User U_suspicious identified
        Cline->>User_Comp_Response: Execute(user_id=U_suspicious, case_id=CASE_ID)
        User_Comp_Response-->>Cline: User Triage Result
    end

    %% Step 6: Isolate Newly Identified Endpoints
    loop For each New Endpoint Ej (e.g., E2_lateral)
        Cline->>Endpoint_Triage: Execute(endpoint_id=Ej, case_id=CASE_ID)
        Endpoint_Triage-->>Cline: Isolation Result for Ej
    end

    %% Step 7: Assess Scope & Recovery
    Note over Cline: Summarize affected systems
    Cline->>External_Resources: (Manual) Check NoMoreRansom for Strain S1/S2
    External_Resources-->>Cline: Decryptor Availability Info
    Note over Cline: Check internal backup status (Manual)

    %% Step 8, 9, 10: Document & Handover
    Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Ransomware Response Summary: Strain [Strain]. Endpoints [...] isolated. IOCs [...] contained. Initial Access/Lateral Movement [...]. Recovery Options [...]. Handover to IR Team.")
    SOAR-->>Cline: Comment Confirmation
    Cline->>Analyst/User: attempt_completion(result="Initial Ransomware Response runbook complete for case CASE_ID. Handover recommended.")
