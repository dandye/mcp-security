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
    *   Extract all URLs, sender domains/IPs, and attachment hashes from the email body and headers.
    *   *(Conceptual/Manual Step: If attachments are present, submit hashes to GTI/sandbox. If safe detonation is possible, analyze behavior).*
3.  **Enrich Extracted IOCs:**
    *   For each extracted URL, Domain, IP, and Hash:
        *   Use the appropriate `gti-mcp` tool (`get_url_report`, `get_domain_report`, `get_ip_address_report`, `get_file_report`) to check reputation and gather context.
        *   Use `secops-mcp.lookup_entity` to check for prior SIEM activity.
    *   Identify IOCs confirmed or strongly suspected to be malicious.
4.  **Search for Related Activity (SIEM):**
    *   Use `secops-mcp.search_security_events` to search for:
        *   Other emails with the same subject, sender, or key body phrases.
        *   Network connections or DNS lookups to malicious Domains/IPs extracted.
        *   URL clicks (requires proxy/DNS log analysis) involving malicious URLs extracted.
        *   File execution events involving malicious hashes extracted.
        *   Logins or other suspicious activity from recipient users around the time the email was received/clicked.
5.  **Identify Impact:**
    *   Based on SIEM searches, identify:
        *   Users who received similar emails.
        *   Users who potentially clicked malicious links or opened attachments.
        *   Endpoints exhibiting suspicious activity following potential interaction.
6.  **Contain Malicious IOCs:**
    *   For each confirmed malicious IOC (URL, Domain, IP, Hash):
        *   **Call IOC Containment Runbook:** Execute `.clinerules/run_books/ioc_containment.md` with the IOC details and current `${CASE_ID}`.
7.  **Triage Potentially Compromised Users/Endpoints:**
    *   For users identified in Step 5 as potentially clicking/opening:
        *   **Trigger Compromised User Account Response Runbook:** Initiate `.clinerules/run_books/compromised_user_account_response.md` for the user ID.
    *   For endpoints identified in Step 5 with suspicious activity:
        *   **Trigger Basic Endpoint Triage & Isolation Runbook:** Initiate `.clinerules/run_books/basic_endpoint_triage_isolation.md` for the endpoint ID.
8.  **Document Findings:** Record all analysis steps, enrichment results, SIEM findings, identified impact (users/endpoints), containment actions, and triggered runbooks in the SOAR case using `secops-soar.post_case_comment`.
9.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant Cline as Cline (MCP Client)
    participant EmailParser as Email Parser (Conceptual)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar
    participant IOC_Containment as IOC Containment Runbook
    participant User_Comp_Response as User Comp. Response Runbook
    participant Endpoint_Triage as Endpoint Triage Runbook

    Analyst/User->>Cline: Start Phishing Response\nInput: Email Artifacts, CASE_ID, ALERT_GROUP_IDS

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: Analyze Email
    Cline->>EmailParser: Parse Headers, Body, Attachments
    EmailParser-->>Cline: Extracted IOCs (URLs U1, Domains D1, IPs IP1, Hashes H1...)

    %% Step 3: Enrich IOCs
    loop For each IOC Ii (U1, D1, IP1, H1...)
        Cline->>GTI: get_..._report(ioc=Ii)
        GTI-->>Cline: GTI Report for Ii
        Cline->>SIEM: lookup_entity(entity_value=Ii)
        SIEM-->>Cline: SIEM Summary for Ii
    end
    Note over Cline: Identify Malicious IOCs (MI1, MI2...)

    %% Step 4: Search SIEM
    Cline->>SIEM: search_security_events(text="Similar emails, clicks on MI1, connections to MI2...")
    SIEM-->>Cline: Related Events (Users U_clicked, Endpoints E_suspicious...)

    %% Step 5: Identify Impact
    Note over Cline: Identify impacted Users (U_clicked) and Endpoints (E_suspicious)

    %% Step 6: Contain IOCs
    loop For each Malicious IOC MIi
        Cline->>IOC_Containment: Execute(ioc=MIi, case_id=CASE_ID)
        IOC_Containment-->>Cline: Containment Result for MIi
    end

    %% Step 7: Triage Users/Endpoints
    loop For each Impacted User Ui
        Cline->>User_Comp_Response: Execute(user_id=Ui, case_id=CASE_ID)
        User_Comp_Response-->>Cline: User Triage Result for Ui
    end
    loop For each Suspicious Endpoint Ei
        Cline->>Endpoint_Triage: Execute(endpoint_id=Ei, case_id=CASE_ID)
        Endpoint_Triage-->>Cline: Endpoint Triage Result for Ei
    end

    %% Step 8: Document
    Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Phishing Response Summary: Email analyzed. IOCs [...] enriched. Malicious IOCs [...] contained. Related SIEM activity found [...]. Impacted Users [...] / Endpoints [...] triaged.")
    SOAR-->>Cline: Comment Confirmation

    %% Step 9: Completion
    Cline->>Analyst/User: attempt_completion(result="Phishing Response runbook complete for case CASE_ID.")
