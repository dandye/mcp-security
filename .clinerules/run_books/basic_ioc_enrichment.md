# Basic IOC Enrichment Runbook

## Objective

Standardize the initial enrichment process for a single Indicator of Compromise (IOC) identified in an alert or case, suitable for Tier 1 SOC Analysts.

## Scope

This runbook covers the fundamental enrichment steps using readily available GTI and SIEM lookup tools. It aims to provide quick context to aid in the decision to close or escalate.

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...", "http://bad.url/path").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash", "URL").
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`
*   `secops-mcp`: `lookup_entity`, `get_ioc_matches`
*   `secops-soar`: `post_case_comment`

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, `${CASE_ID}`, and `${ALERT_GROUP_IDENTIFIERS}`.
2.  **GTI Enrichment:**
    *   Based on `${IOC_TYPE}`:
        *   If "IP Address", use `gti-mcp.get_ip_address_report` with `ip_address=${IOC_VALUE}`.
        *   If "Domain", use `gti-mcp.get_domain_report` with `domain=${IOC_VALUE}`.
        *   If "File Hash", use `gti-mcp.get_file_report` with `hash=${IOC_VALUE}`.
        *   If "URL", use `gti-mcp.get_url_report` with `url=${IOC_VALUE}`.
    *   Record the key findings (e.g., reputation, detection ratio, key relationships if available in the summary).
3.  **SIEM Context - Entity Lookup:**
    *   Use `secops-mcp.lookup_entity` with `entity_value=${IOC_VALUE}`.
    *   Record the summary provided (e.g., first/last seen, related alerts/entities within the SIEM timeframe).
4.  **SIEM Context - IOC Match Check:**
    *   Use `secops-mcp.get_ioc_matches` (potentially filter by `${IOC_VALUE}` if the tool supports it, otherwise review the general list for the IOC).
    *   Record if the specific `${IOC_VALUE}` was found in recent SIEM IOC matches.
5.  **Document Findings:**
    *   Use `secops-soar.post_case_comment` for `${CASE_ID}`.
    *   The comment should summarize the findings: "Basic IOC Enrichment for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI Reputation: [...]. SIEM Activity: [...]. Recent SIEM IOC Match: [Yes/No]."
6.  **Completion:** Conclude the runbook execution. The Tier 1 analyst uses the documented summary to inform their next steps (close, escalate, further investigation if within scope).

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar

    Analyst->>Cline: Start Basic IOC Enrichment\nInput: IOC_VALUE, IOC_TYPE, CASE_ID, ALERT_GROUP_IDS

    %% Step 2: GTI Enrichment
    alt IOC_TYPE is IP Address
        Cline->>GTI: get_ip_address_report(ip_address=IOC_VALUE)
        GTI-->>Cline: IP Report Summary
    else IOC_TYPE is Domain
        Cline->>GTI: get_domain_report(domain=IOC_VALUE)
        GTI-->>Cline: Domain Report Summary
    else IOC_TYPE is File Hash
        Cline->>GTI: get_file_report(hash=IOC_VALUE)
        GTI-->>Cline: File Report Summary
    else IOC_TYPE is URL
        Cline->>GTI: get_url_report(url=IOC_VALUE)
        GTI-->>Cline: URL Report Summary
    end
    Note over Cline: Record GTI Findings

    %% Step 3: SIEM Entity Lookup
    Cline->>SIEM: lookup_entity(entity_value=IOC_VALUE)
    SIEM-->>Cline: SIEM Entity Summary
    Note over Cline: Record SIEM Lookup Findings

    %% Step 4: SIEM IOC Match Check
    Cline->>SIEM: get_ioc_matches() %% Potentially filter if supported
    SIEM-->>Cline: List of Recent IOC Matches
    Note over Cline: Check if IOC_VALUE is in the list. Record Yes/No.

    %% Step 5: Document Findings
    Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Basic IOC Enrichment Summary...")
    SOAR-->>Cline: Comment Confirmation

    %% Step 6: Completion
    Cline->>Analyst: attempt_completion(result="Basic IOC enrichment complete for IOC_VALUE. Findings documented in case CASE_ID.")
