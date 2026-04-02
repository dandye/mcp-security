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
    *   Use the appropriate `gti-mcp.get_..._report` tool based on `${IOC_TYPE}` to retrieve the full GTI analysis report for `${IOC_VALUE}`.
    *   Record key details: reputation, classifications, first/last seen dates, associated threats (malware families, actors), key behaviors (if file hash).
3.  **GTI Pivoting:**
    *   Based on `${IOC_TYPE}` and the detailed report, use `gti-mcp.get_entities_related_to_a_...` to explore critical relationships. Examples:
        *   **IP Address:** Check `resolutions` (domains hosted), `communicating_files`, `related_threat_actors`.
        *   **Domain:** Check `resolutions` (IPs hosting), `communicating_files`, `downloaded_files`, `subdomains`, `related_threat_actors`.
        *   **File Hash:** Check `contacted_domains`, `contacted_ips`, `dropped_files`, `execution_parents`, `malware_families`, `related_threat_actors`. *(Optional: `get_file_behavior_summary`)*.
        *   **URL:** Check `network_location` (domain/IP), `downloaded_files`, `contacted_domains`, `contacted_ips`, `redirects_to`.
    *   Record significant related entities found during pivoting. Let's call these `${RELATED_IOCs}`.
4.  **Deep SIEM Search:**
    *   Use `secops-mcp.search_security_events` with detailed UDM queries covering `${TIME_FRAME_HOURS}` (default 168). Search for:
        *   Activity directly involving `${IOC_VALUE}` (e.g., network connections to IP, DNS lookups for domain, file executions for hash, URL access).
        *   Activity involving significant `${RELATED_IOCs}` identified in Step 3.
        *   Analyze event details: parent processes, command lines, user context, source/destination assets.
5.  **SIEM Context & Correlation:**
    *   Use `secops-mcp.lookup_entity` for `${IOC_VALUE}` and key `${RELATED_IOCs}` to get SIEM summaries (first/last seen, prevalence).
    *   Use `secops-mcp.get_security_alerts` filtering for `${IOC_VALUE}` or key `${RELATED_IOCs}` within the timeframe.
    *   *(Optional) Use `secops-soar.list_cases` filtering for `${IOC_VALUE}` or key `${RELATED_IOCs}` to find potentially linked SOAR cases.*
6.  **Synthesize & Document:**
    *   Combine all findings: Detailed GTI report, GTI pivot results, deep SIEM search results, SIEM context/alerts/cases.
    *   Assess the overall impact and scope based on the combined data. Identify potentially compromised assets or users.
    *   Use `secops-soar.post_case_comment` for `${CASE_ID}`. Provide a comprehensive summary: "Deep Dive Analysis for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI Details: [...]. GTI Pivots found: [...]. SIEM Search revealed: [...]. Related Alerts/Cases: [...]. Assessment: [...]."
7.  **Recommend Next Steps:**
    *   Based on the synthesis, add recommendations to the comment: "[Containment Actions Needed (Trigger IOC Containment/Endpoint Triage/User Response Runbooks) | Escalate to Tier 3/IR | Monitor | Close as Benign/Informational]".
8.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar

    Analyst->>Cline: Start Deep Dive IOC Analysis\nInput: IOC_VALUE, IOC_TYPE, CASE_ID, ALERT_GROUP_IDS, TIME_FRAME_HOURS

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: Detailed GTI Report
    Cline->>GTI: get_..._report(ioc=IOC_VALUE) %% Based on IOC_TYPE
    GTI-->>Cline: Detailed GTI Report
    Note over Cline: Record key GTI details

    %% Step 3: GTI Pivoting
    Note over Cline: Identify key relationships based on IOC_TYPE
    loop For each key relationship R
        Cline->>GTI: get_entities_related_to_a_...(ioc=IOC_VALUE, relationship_name=R)
        GTI-->>Cline: Related Entities (RELATED_IOCs)
    end
    Note over Cline: Record significant RELATED_IOCs
    opt IOC_TYPE is File Hash
        Cline->>GTI: get_file_behavior_summary(hash=IOC_VALUE)
        GTI-->>Cline: File Behavior Summary
    end

    %% Step 4: Deep SIEM Search
    Cline->>SIEM: search_security_events(text="Events involving IOC_VALUE or RELATED_IOCs", hours_back=TIME_FRAME_HOURS)
    SIEM-->>Cline: Detailed SIEM Events
    Note over Cline: Analyze event details

    %% Step 5: SIEM Context & Correlation
    loop For each key IOC Ki (IOC_VALUE + RELATED_IOCs)
        Cline->>SIEM: lookup_entity(entity_value=Ki)
        SIEM-->>Cline: SIEM Summary for Ki
    end
    Cline->>SIEM: get_security_alerts(query="Contains IOC_VALUE or RELATED_IOCs", hours_back=TIME_FRAME_HOURS)
    SIEM-->>Cline: Related SIEM Alerts
    opt Check SOAR Cases
        Cline->>SOAR: list_cases(filter="Contains IOC_VALUE or RELATED_IOCs") %% Conceptual Filter
        SOAR-->>Cline: Potentially related SOAR Cases
    end

    %% Step 6 & 7: Synthesize, Document & Recommend
    Note over Cline: Synthesize all findings, assess impact
    Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Deep Dive Analysis Summary... Assessment: [...]. Recommendation: [Contain/Escalate/Monitor/Close]")
    SOAR-->>Cline: Comment Confirmation

    %% Step 8: Completion
    Cline->>Analyst: attempt_completion(result="Deep Dive IOC Analysis complete for IOC_VALUE. Findings and recommendation documented in case CASE_ID.")
