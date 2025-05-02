# Phishing Response Runbook

## Objective

Analyze a reported phishing email, extract and enrich Indicators of Compromise (IOCs), search for related activity (e.g., user clicks, similar emails), contain malicious IOCs, identify potentially compromised users/endpoints, and document the investigation.

## Scope

This runbook covers the response to a single reported phishing email or a set of similar emails. It focuses on analyzing the email, identifying risks, performing initial containment, and identifying potential impact.

## Inputs

*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   `${REPORTED_EMAIL_ARTIFACTS}`: Information about the reported email, which could include:
    *   Email headers (as text or file).
    *   Email body (as text or file).
    *   Attached files (hashes or potentially file content if available safely).
    *   Reported URLs within the email.
    *   Recipient user ID(s).
    *   Sender address/domain.
*   *(Optional) `${EMAIL_GATEWAY_LOG_ID}`: Identifier for the email in the gateway logs.*

## Tools

*   **Email Analysis Tools (Conceptual/External):** Tools to parse headers, extract URLs/attachments, detonate URLs/attachments safely (sandbox). *MCP might not have direct tools for deep EML parsing/detonation.*
*   `gti-mcp`: `get_domain_report`, `get_ip_address_report`, `get_url_report`, `get_file_report`, `search_iocs`.
*   `secops-mcp`: `search_security_events`, `lookup_entity`.
*   `secops-soar`: `post_case_comment`, `get_case_full_details`.
*   **IOC Containment Runbook:** `.clinerules/run_books/ioc_containment.md` (To be called as a sub-procedure).
*   **Compromised User Account Response Runbook:** `.clinerules/run_books/compromised_user_account_response.md` (Potentially triggered).
*   **Basic Endpoint Triage & Isolation Runbook:** `.clinerules/run_books/basic_endpoint_triage_isolation.md` (Potentially triggered).
*   `ask_followup_question` (To confirm actions).

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain email artifacts, `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`. Get case details via `secops-soar.get_case_full_details`.
2.  **Analyze Email Artifacts:**
    *   Parse headers to identify true sender, path, etc.
    *   Extract all URLs, sender domains/IPs, and attachment hashes (`EXTRACTED_IOCs`) from the email body and headers.
    *   *(Conceptual/Manual Step: If attachments are present, submit hashes to GTI/sandbox. If safe detonation is possible, analyze behavior).*
3.  **Enrich Extracted IOCs:**
    *   Initialize `ENRICHMENT_RESULTS`. For each IOC `Ii` in `EXTRACTED_IOCs`:
        *   Execute `common_steps/enrich_ioc.md` with `IOC_VALUE=Ii` and appropriate `IOC_TYPE`.
        *   Store results in `ENRICHMENT_RESULTS[Ii]`.
    *   Identify IOCs confirmed or strongly suspected to be malicious (`MALICIOUS_IOCs`).
4.  **Search for Related Activity (SIEM):**
    *   Use `secops-mcp.search_security_events` to search for:
        *   Other emails with the same subject, sender, or key body phrases.
        *   Network connections or DNS lookups to `MALICIOUS_IOCs` (Domains/IPs).
        *   URL clicks involving `MALICIOUS_IOCs` (URLs).
        *   File execution events involving `MALICIOUS_IOCs` (Hashes).
        *   Logins or other suspicious activity from recipient users around the time the email was received/clicked.
    *   Record findings (`SIEM_FINDINGS`).
5.  **Identify Impact:**
    *   Based on `SIEM_FINDINGS`, identify:
        *   Users who received similar emails (`SIMILAR_EMAIL_RECIPIENTS`).
        *   Users who potentially clicked/opened (`POTENTIAL_COMPROMISED_USERS`).
        *   Endpoints exhibiting suspicious activity (`SUSPICIOUS_ENDPOINTS`).
6.  **Contain Malicious IOCs:**
    *   For each IOC `MIi` in `MALICIOUS_IOCs`:
        *   **Call IOC Containment Runbook:** Execute `.clinerules/run_books/ioc_containment.md` with `IOC_VALUE=MIi`, appropriate `IOC_TYPE`, and `${CASE_ID}`. Record status (`CONTAINMENT_STATUS[MIi]`).
7.  **Triage Potentially Compromised Users/Endpoints:**
    *   For each user `Ui` in `POTENTIAL_COMPROMISED_USERS`:
        *   **Trigger Compromised User Account Response Runbook:** Initiate `.clinerules/run_books/compromised_user_account_response.md` for `USER_ID=Ui`. Record status (`USER_TRIAGE_STATUS[Ui]`).
    *   For each endpoint `Ei` in `SUSPICIOUS_ENDPOINTS`:
        *   **Trigger Basic Endpoint Triage & Isolation Runbook:** Initiate `.clinerules/run_books/basic_endpoint_triage_isolation.md` for `ENDPOINT_ID=Ei`. Record status (`ENDPOINT_TRIAGE_STATUS[Ei]`).
8.  **Document Findings:**
    *   Prepare `COMMENT_TEXT` summarizing: Email analysis, `ENRICHMENT_RESULTS`, `SIEM_FINDINGS`, identified impact (`SIMILAR_EMAIL_RECIPIENTS`, `POTENTIAL_COMPROMISED_USERS`, `SUSPICIOUS_ENDPOINTS`), `CONTAINMENT_STATUS`, `USER_TRIAGE_STATUS`, `ENDPOINT_TRIAGE_STATUS`.
    *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and `${COMMENT_TEXT}`. Obtain `${COMMENT_POST_STATUS}`.
9.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant Cline as Cline (MCP Client)
    participant EmailParser as Email Parser (Conceptual)
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant SIEM as secops-mcp
    participant SOAR as secops-soar
    participant IOC_Containment as IOC Containment Runbook
    participant User_Comp_Response as User Comp. Response Runbook
    participant Endpoint_Triage as Endpoint Triage Runbook
    participant DocumentInSOAR as common_steps/document_in_soar.md

    Analyst/User->>Cline: Start Phishing Response\nInput: Email Artifacts, CASE_ID, ALERT_GROUP_IDS

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: Analyze Email
    Cline->>EmailParser: Parse Headers, Body, Attachments
    EmailParser-->>Cline: Extracted IOCs (EXTRACTED_IOCs)

    %% Step 3: Enrich IOCs
    loop For each IOC Ii in EXTRACTED_IOCs
        Cline->>EnrichIOC: Execute(Input: IOC_VALUE=Ii, IOC_TYPE=...)
        EnrichIOC-->>Cline: Results: Store in ENRICHMENT_RESULTS[Ii]
    end
    Note over Cline: Identify Malicious IOCs (MALICIOUS_IOCs)

    %% Step 4: Search SIEM
    Cline->>SIEM: search_security_events(text="Similar emails, clicks, connections...")
    SIEM-->>Cline: Related Events (SIEM_FINDINGS)

    %% Step 5: Identify Impact
    Note over Cline: Identify Impacted Users/Endpoints from SIEM_FINDINGS

    %% Step 6: Contain IOCs
    loop For each Malicious IOC MIi in MALICIOUS_IOCs
        Cline->>IOC_Containment: Execute(ioc=MIi, case_id=CASE_ID)
        IOC_Containment-->>Cline: Containment Result for MIi (CONTAINMENT_STATUS[MIi])
    end

    %% Step 7: Triage Users/Endpoints
    loop For each Impacted User Ui
        Cline->>User_Comp_Response: Execute(user_id=Ui, case_id=CASE_ID)
        User_Comp_Response-->>Cline: User Triage Result (USER_TRIAGE_STATUS[Ui])
    end
    loop For each Suspicious Endpoint Ei
        Cline->>Endpoint_Triage: Execute(endpoint_id=Ei, case_id=CASE_ID)
        Endpoint_Triage-->>Cline: Endpoint Triage Result (ENDPOINT_TRIAGE_STATUS[Ei])
    end

    %% Step 8: Document
    Note over Cline: Prepare COMMENT_TEXT summarizing all findings and actions
    Cline->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
    DocumentInSOAR-->>Cline: Results: COMMENT_POST_STATUS

    %% Step 9: Completion
    Cline->>Analyst/User: attempt_completion(result="Phishing Response runbook complete for case CASE_ID.")
