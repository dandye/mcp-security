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
2.  **Enrich IOC:** Execute `common_steps/enrich_ioc.md` with `${IOC_VALUE}` and `${IOC_TYPE}`. Obtain `${GTI_FINDINGS}`, `${SIEM_ENTITY_SUMMARY}`, `${SIEM_IOC_MATCH_STATUS}`.
3.  **Document Findings:** Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and a comment summarizing the enrichment results (e.g., "Basic IOC Enrichment for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI: `${GTI_FINDINGS}`. SIEM Summary: `${SIEM_ENTITY_SUMMARY}`. SIEM IOC Match: `${SIEM_IOC_MATCH_STATUS}`."). Obtain `${COMMENT_POST_STATUS}`.
4.  **Completion:** Conclude the runbook execution. The Tier 1 analyst uses the documented summary to inform their next steps (close, escalate, further investigation if within scope).

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant SOAR as secops-soar %% Underlying tool for documentation

    Analyst->>Cline: Start Basic IOC Enrichment\nInput: IOC_VALUE, IOC_TYPE, CASE_ID, ALERT_GROUP_IDS

    %% Step 2: Enrich IOC
    Cline->>EnrichIOC: Execute(Input: IOC_VALUE, IOC_TYPE)
    EnrichIOC-->>Cline: Results: GTI_FINDINGS, SIEM_ENTITY_SUMMARY, SIEM_IOC_MATCH_STATUS

    %% Step 3: Document Findings
    Note over Cline: Format comment using enrichment results
    Cline->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
    DocumentInSOAR-->>Cline: Results: COMMENT_POST_STATUS

    %% Step 4: Completion
    Cline->>Analyst: attempt_completion(result="Basic IOC enrichment complete for IOC_VALUE. Findings documented in case CASE_ID.")
