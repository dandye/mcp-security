# Deep Dive IOC Analysis Runbook

## Objective

Perform an exhaustive analysis of a single, potentially critical Indicator of Compromise (IOC) escalated from Tier 1 or identified during an investigation. This goes beyond the basic enrichment done by Tier 1, leveraging advanced tool features and pivoting techniques.

## Scope

This runbook covers in-depth analysis of a single IOC (IP, Domain, Hash, URL) using available GTI and SIEM tools to uncover related infrastructure, activity, and context.

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...", "http://bad.url/path").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash", "URL").
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   *(Optional) `${TIME_FRAME_HOURS}`: Lookback period in hours for SIEM searches (default: 168 = 7 days).*

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`, `get_entities_related_to_an_ip_address`, `get_entities_related_to_a_domain`, `get_entities_related_to_a_file`, `get_entities_related_to_an_url`, `get_file_behavior_summary` (optional for hashes).
*   `secops-mcp`: `lookup_entity`, `search_security_events`, `get_security_alerts`.
*   `secops-soar`: `post_case_comment`, `get_case_full_details`, `list_cases`.

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`, and optionally `${TIME_FRAME_HOURS}`. Get case details via `secops-soar.get_case_full_details`.
2.  **Detailed GTI Report:**
    *   Use the appropriate `gti-mcp.get_..._report` tool based on `${IOC_TYPE}` to retrieve the full GTI analysis report (`${GTI_REPORT_DETAILS}`) for `${IOC_VALUE}`.
    *   Record key details: reputation, classifications, first/last seen dates, associated threats (malware families, actors), key behaviors (if file hash).
3.  **GTI Pivoting:**
    *   Execute `common_steps/pivot_on_ioc_gti.md` with `${IOC_VALUE}`, `${IOC_TYPE}`, and relevant `${RELATIONSHIP_NAMES}` (determined based on IOC type and report details). Obtain `${RELATED_ENTITIES}`.
    *   *(Optional: If IOC is File Hash, use `gti-mcp.get_file_behavior_summary`)*.
4.  **Deep SIEM Search:**
    *   Use `secops-mcp.search_security_events` with detailed UDM queries covering `${TIME_FRAME_HOURS}` (default 168). Search for:
        *   Activity directly involving `${IOC_VALUE}`.
        *   Activity involving significant IOCs from `${RELATED_ENTITIES}`.
    *   Analyze event details (`${SIEM_SEARCH_RESULTS}`).
5.  **SIEM Context & Correlation:**
    *   Initialize `SIEM_ENRICHMENT_RESULTS`. For each key IOC `Ki` (including `${IOC_VALUE}` and significant IOCs from `${RELATED_ENTITIES}`):
        *   Execute `common_steps/enrich_ioc.md` with `IOC_VALUE=Ki` and appropriate `IOC_TYPE`. Store results in `SIEM_ENRICHMENT_RESULTS[Ki]`.
    *   Execute `common_steps/correlate_ioc_with_alerts_cases.md` with `IOC_LIST` containing `${IOC_VALUE}` and significant IOCs from `${RELATED_ENTITIES}`. Obtain `${RELATED_SIEM_ALERTS}` and `${RELATED_SOAR_CASES}`.
6.  **Synthesize & Document:**
    *   Combine all findings: `${GTI_REPORT_DETAILS}`, `${RELATED_ENTITIES}`, `${SIEM_SEARCH_RESULTS}`, `SIEM_ENRICHMENT_RESULTS`, `${RELATED_SIEM_ALERTS}`, `${RELATED_SOAR_CASES}`.
    *   Assess the overall impact and scope. Identify potentially compromised assets or users.
    *   Prepare `COMMENT_TEXT` summarizing the deep dive: "Deep Dive Analysis for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI Details: [...]. GTI Pivots found: [...]. SIEM Search revealed: [...]. SIEM Enrichment: [...]. Related Alerts/Cases: [...]. Assessment: [...]. Recommendation: [Contain/Escalate/Monitor/Close]".
    *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and `${COMMENT_TEXT}`. Obtain `${COMMENT_POST_STATUS}`.
7.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant PivotOnIOC as common_steps/pivot_on_ioc_gti.md
    participant SIEM as secops-mcp
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant CorrelateIOC as common_steps/correlate_ioc_with_alerts_cases.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant SOAR as secops-soar %% Underlying tool for documentation & context

    Analyst->>Cline: Start Deep Dive IOC Analysis\nInput: IOC_VALUE, IOC_TYPE, CASE_ID, ALERT_GROUP_IDS, TIME_FRAME_HOURS

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: Detailed GTI Report
    Cline->>GTI: get_..._report(ioc=IOC_VALUE) %% Based on IOC_TYPE
    GTI-->>Cline: Detailed GTI Report (GTI_REPORT_DETAILS)

    %% Step 3: GTI Pivoting
    Note over Cline: Determine relevant RELATIONSHIP_NAMES
    Cline->>PivotOnIOC: Execute(Input: IOC_VALUE, IOC_TYPE, RELATIONSHIP_NAMES)
    PivotOnIOC-->>Cline: Results: RELATED_ENTITIES
    opt IOC_TYPE is File Hash
        Cline->>GTI: get_file_behavior_summary(hash=IOC_VALUE)
        GTI-->>Cline: File Behavior Summary
    end

    %% Step 4: Deep SIEM Search
    Note over Cline: Construct UDM queries for IOC_VALUE and RELATED_ENTITIES
    Cline->>SIEM: search_security_events(text=Query1, hours_back=TIME_FRAME_HOURS)
    SIEM-->>Cline: SIEM Search Results 1
    Cline->>SIEM: search_security_events(text=Query2, hours_back=TIME_FRAME_HOURS)
    SIEM-->>Cline: SIEM Search Results 2 (SIEM_SEARCH_RESULTS)

    %% Step 5: SIEM Context & Correlation
    Note over Cline: Initialize SIEM_ENRICHMENT_RESULTS
    loop For each key IOC Ki (IOC_VALUE + RELATED_ENTITIES)
        Cline->>EnrichIOC: Execute(Input: IOC_VALUE=Ki, IOC_TYPE=...)
        EnrichIOC-->>Cline: Results: Store in SIEM_ENRICHMENT_RESULTS[Ki]
    end
    Note over Cline: Prepare IOC_LIST for correlation
    Cline->>CorrelateIOC: Execute(Input: IOC_LIST, TIME_FRAME_HOURS)
    CorrelateIOC-->>Cline: Results: RELATED_SIEM_ALERTS, RELATED_SOAR_CASES

    %% Step 6: Synthesize & Document
    Note over Cline: Synthesize all findings, assess impact, prepare COMMENT_TEXT with Recommendation
    Cline->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
    DocumentInSOAR-->>Cline: Results: COMMENT_POST_STATUS

    %% Step 7: Completion
    Cline->>Analyst: attempt_completion(result="Deep Dive IOC Analysis complete for IOC_VALUE. Findings and recommendation documented in case CASE_ID.")
