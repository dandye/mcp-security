# Basic IOC Enrichment Runbook

## Objective

Standardize the initial enrichment process for a single Indicator of Compromise (IOC) identified in an alert or case, suitable for Tier 1 SOC Analysts.

## Scope

This runbook covers the fundamental enrichment steps using readily available GTI and SIEM lookup tools. It aims to provide quick context to aid in the decision to close or escalate.

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...", "http://bad.url/path").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash", "URL").
*   *(Optional) `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers if needed for context in SOAR actions.*

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`
*   `secops-mcp`: `lookup_entity`, `get_ioc_matches`
*   `secops-soar`: `list_cases`, `post_case_comment`
*   `ask_followup_question`

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, and optionally `${ALERT_GROUP_IDENTIFIERS}`.
2.  **Enrich IOC:** Execute `common_steps/enrich_ioc.md` with `${IOC_VALUE}` and `${IOC_TYPE}`. Obtain `${GTI_FINDINGS}`, `${SIEM_ENTITY_SUMMARY}`, `${SIEM_IOC_MATCH_STATUS}`.
3.  **Search Relevant SOAR Cases:**
    *   Use `secops-soar.list_cases` with a filter targeting open cases related to `${IOC_VALUE}`. *Note: The exact filter depends on SOAR capabilities (e.g., searching entities, names, tags).*
    *   Store the list of found open case IDs/names in `${FOUND_CASES}`.
4.  **Conditional Documentation:**
    *   **If `${FOUND_CASES}` is not empty:**
        *   Use `ask_followup_question` to present the `${FOUND_CASES}` list to the user and ask: "Found relevant open case(s): [List Cases]. Enter the Case ID to document enrichment findings in, or type 'skip' to not document.". Obtain `${USER_CHOICE}`.
        *   **If `${USER_CHOICE}` is a valid Case ID from the list:**
            *   Set `${TARGET_CASE_ID}` = `${USER_CHOICE}`.
            *   Prepare `COMMENT_TEXT` summarizing enrichment results (e.g., "Basic IOC Enrichment for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI: `${GTI_FINDINGS}`. SIEM Summary: `${SIEM_ENTITY_SUMMARY}`. SIEM IOC Match: `${SIEM_IOC_MATCH_STATUS}`.").
            *   Execute `common_steps/document_in_soar.md` with `CASE_ID=${TARGET_CASE_ID}` and `COMMENT_TEXT`. Obtain `${COMMENT_POST_STATUS}`.
        *   **Else (User typed 'skip' or provided invalid ID):** Skip documentation.
    *   **Else (`${FOUND_CASES}` is empty):** Skip documentation.
5.  **Completion:** Conclude the runbook execution. The analyst uses the enrichment findings (and potential documentation status) to inform their next steps.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant SOAR as secops-soar
    participant User

    Analyst->>Cline: Start Basic IOC Enrichment\nInput: IOC_VALUE, IOC_TYPE, ALERT_GROUP_IDS (opt)

    %% Step 2: Enrich IOC
    Cline->>EnrichIOC: Execute(Input: IOC_VALUE, IOC_TYPE)
    EnrichIOC-->>Cline: Results: GTI_FINDINGS, SIEM_ENTITY_SUMMARY, SIEM_IOC_MATCH_STATUS

    %% Step 3: Search Relevant SOAR Cases
    Note over Cline: Construct filter for list_cases based on IOC_VALUE
    Cline->>SOAR: list_cases(filter=..., status="OPEN")
    SOAR-->>Cline: List of relevant open cases (FOUND_CASES)

    %% Step 4: Conditional Documentation
    alt FOUND_CASES is not empty
        Cline->>User: ask_followup_question(question="Found cases: [FOUND_CASES]. Enter Case ID to document in, or 'skip'.")
        User-->>Cline: User Choice (USER_CHOICE)
        alt USER_CHOICE is a valid Case ID
            Note over Cline: TARGET_CASE_ID = USER_CHOICE
            Note over Cline: Format COMMENT_TEXT with enrichment results
            Cline->>DocumentInSOAR: Execute(Input: CASE_ID=TARGET_CASE_ID, COMMENT_TEXT)
            DocumentInSOAR-->>Cline: Results: COMMENT_POST_STATUS
        else USER_CHOICE is 'skip' or invalid
            Note over Cline: Skip documentation
        end
    else FOUND_CASES is empty
        Note over Cline: Skip documentation
    end

    %% Step 5: Completion
    Cline->>Analyst: attempt_completion(result="Basic IOC enrichment complete for IOC_VALUE. Findings gathered. SOAR documentation status: [Documented in Case X | Skipped].")
