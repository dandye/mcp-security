# Phishing Incident Response Plan (IRP) / Runbook

## Objective

Provide a structured workflow for responding to reported phishing emails, coordinating investigation, containment, eradication, and recovery efforts using available tools and procedures. This runbook orchestrates various specialized runbooks.

## Scope

This runbook covers the end-to-end response lifecycle for phishing incidents. It relies on specific sub-runbooks for detailed execution steps.

## Phases (PICERL Model)

1.  **Preparation:** *(Ongoing)* Ensure tools are operational, user reporting mechanisms are clear, communication templates exist, and relevant detections (e.g., for known bad domains/URLs) are active.
2.  **Identification:** Detect/Receive the report, perform initial triage, analyze email artifacts, enrich IOCs, and identify initial impact.
3.  **Containment:** Limit the spread and impact by blocking malicious IOCs and isolating/containing affected users or endpoints.
4.  **Eradication:** Remove malicious artifacts (e.g., delete similar emails, potentially remove malware if dropped).
5.  **Recovery:** Restore affected user accounts or systems to normal operation.
6.  **Lessons Learned (Post-Incident):** Review the incident and response to identify improvements.

## Inputs

*   `${CASE_ID}`: The SOAR case ID created for or associated with the initial report/alert(s).
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
*   **IOC Containment Runbook:** `../ioc_containment.md`
*   **Compromised User Account Response Runbook:** `../compromised_user_account_response.md`
*   **Basic Endpoint Triage & Isolation Runbook:** `../basic_endpoint_triage_isolation.md`
*   `ask_followup_question` (To confirm actions).
*   *(Potentially Email Gateway tools if integrated via MCP for searching/deleting emails)*

## Workflow Steps & Diagram

```{mermaid}
sequenceDiagram
    participant Analyst
    participant IRP as phishing_response.md (This Runbook)
    participant Preparation as Phase 1: Preparation
    participant Identification as Phase 2: Identification
    participant Containment as Phase 3: Containment
    participant Eradication as Phase 4: Eradication
    participant Recovery as Phase 5: Recovery
    participant LessonsLearned as Phase 6: Lessons Learned

    Analyst->>IRP: Start Phishing Response\nInput: CASE_ID, ALERT_GROUP_IDS, REPORTED_EMAIL_ARTIFACTS

    IRP->>Preparation: Verify Prerequisites (Ongoing)
    Preparation-->>IRP: Readiness Confirmed

    IRP->>Identification: Execute Identification Steps
    Identification-->>IRP: Initial Findings, Malicious IOCs, Affected Users/Endpoints

    IRP->>Containment: Execute Containment Steps
    Containment-->>IRP: Containment Status (IOCs, Users, Endpoints)

    IRP->>Eradication: Execute Eradication Steps
    Eradication-->>IRP: Eradication Status (e.g., Emails Deleted)

    IRP->>Recovery: Execute Recovery Steps
    Recovery-->>IRP: Recovery Status (Users/Endpoints)

    IRP->>LessonsLearned: Execute Post-Incident Steps
    LessonsLearned-->>IRP: Review Complete

    IRP-->>Analyst: Incident Response Complete
```

---

### Phase 1: Preparation (Ongoing)

*   **Objective:** Ensure readiness to respond effectively to phishing reports.
*   **Actions:**
    *   Verify tool connectivity.
    *   Ensure user reporting mechanisms (e.g., "Report Phish" button) are functional and users are aware.
    *   Maintain communication templates for user warnings or vendor notifications.
    *   Ensure relevant detections for known phishing indicators (domains, IPs, TTPs) are active in SIEM/Email Gateway.
    *   Familiarity with escalation paths (`.clinerules/escalation_paths.md`).

---

### Phase 2: Identification

*   **Objective:** Analyze the reported email, identify malicious indicators, and determine the initial scope of impact.
*   **Sub-Runbooks/Steps:**
    1.  **Receive Input & Context:** Obtain email artifacts, `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`. Get case details via `secops-soar.get_case_full_details`. Check for duplicates (`../common_steps/check_duplicate_cases.md`).
    2.  **Analyze Email Artifacts:**
        *   *(Conceptual/Manual Step or External Tool)* Parse headers to identify true sender, path, etc.
        *   Extract all URLs, sender domains/IPs, and attachment hashes (`EXTRACTED_IOCs`) from the email body and headers.
        *   *(Conceptual/Manual Step: If attachments are present, submit hashes to GTI/sandbox. If safe detonation is possible, analyze behavior).*
    3.  **Enrich Extracted IOCs:**
        *   Initialize `ENRICHMENT_RESULTS`. For each IOC `Ii` in `EXTRACTED_IOCs`:
            *   Execute `../common_steps/enrich_ioc.md` with `IOC_VALUE=Ii` and appropriate `IOC_TYPE`.
            *   Store results in `ENRICHMENT_RESULTS[Ii]`.
        *   Identify IOCs confirmed or strongly suspected to be malicious (`MALICIOUS_IOCs`).
    4.  **Search for Related Activity (SIEM):**
        *   Use `secops-mcp.search_security_events` to search for:
            *   Other emails with the same subject, sender, or key body phrases (requires email log source).
            *   Network connections or DNS lookups to `MALICIOUS_IOCs` (Domains/IPs).
            *   URL clicks involving `MALICIOUS_IOCs` (URLs) (requires proxy/DNS logs).
            *   File execution events involving `MALICIOUS_IOCs` (Hashes) (requires endpoint logs).
            *   Logins or other suspicious activity from recipient users around the time the email was received/clicked.
        *   Record findings (`SIEM_FINDINGS`).
    5.  **Identify Initial Impact:**
        *   Based on `SIEM_FINDINGS` and recipient lists, identify:
            *   Users who received similar emails (`SIMILAR_EMAIL_RECIPIENTS`).
            *   Users who potentially clicked/opened/interacted (`POTENTIAL_COMPROMISED_USERS`).
            *   Endpoints exhibiting suspicious activity related to the phish (`SUSPICIOUS_ENDPOINTS`).
    6.  **Document Identification Phase:**
        *   Document findings using `../common_steps/document_in_soar.md`.

---

### Phase 3: Containment

*   **Objective:** Prevent further impact from the phishing campaign and contain any resulting compromises.
*   **Sub-Runbooks/Steps:**
    1.  **Network IOC Containment:**
        *   For each IOC `MIi` in `MALICIOUS_IOCs` (IPs, Domains, URLs):
            *   Execute `../ioc_containment.md` with `IOC_VALUE=MIi`, appropriate `IOC_TYPE`, and `${CASE_ID}`. **Confirm action with analyst.** Record status (`CONTAINMENT_STATUS[MIi]`).
    2.  **User Account Containment:**
        *   For each user `Ui` in `POTENTIAL_COMPROMISED_USERS`:
            *   Execute `../compromised_user_account_response.md` for `USER_ID=Ui`. **Confirm actions with analyst.** Record status (`USER_TRIAGE_STATUS[Ui]`).
    3.  **Endpoint Isolation:**
        *   For each endpoint `Ei` in `SUSPICIOUS_ENDPOINTS`:
            *   Execute `../basic_endpoint_triage_isolation.md` for `ENDPOINT_ID=Ei`. **Confirm action with analyst.** Record status (`ENDPOINT_TRIAGE_STATUS[Ei]`).
    4.  **Verify Containment:**
        *   Monitor SIEM (`secops-mcp.search_security_events`) for continued activity related to `MALICIOUS_IOCs` or contained users/endpoints.
        *   Document containment status using `../common_steps/document_in_soar.md`.

---

### Phase 4: Eradication

*   **Objective:** Remove malicious artifacts related to the phishing campaign.
*   **Sub-Runbooks/Steps:**
    1.  **Delete Malicious Emails:**
        *   *(Requires Email Gateway/Platform integration or manual action)*
        *   Search for and delete similar malicious emails from user inboxes across the organization based on sender, subject, IOCs.
    2.  **Address Malware (If Applicable):**
        *   If the phishing email led to malware execution (identified in Phase 2/3), follow the Eradication steps outlined in the `malware_incident_response.md` runbook for the affected endpoints.
    3.  **Document Eradication:**
        *   Document actions taken (e.g., email deletion counts) using `../common_steps/document_in_soar.md`.

---

### Phase 5: Recovery

*   **Objective:** Restore affected user accounts or systems to normal operation safely.
*   **Sub-Runbooks/Steps:**
    1.  **User Account Recovery:**
        *   If user accounts were disabled/passwords reset during Containment, follow procedures to safely re-enable them after confirming the threat is removed (potentially involves re-imaging user endpoint).
    2.  **Endpoint Recovery:**
        *   If endpoints were isolated and potentially infected with malware, follow the Recovery steps outlined in the `malware_incident_response.md` runbook or a dedicated system recovery runbook.
    3.  **Lift Containment:**
        *   Gradually remove IOC blocks or endpoint/user containment measures once confidence in recovery is high. Monitor closely.
    4.  **Document Recovery:**
        *   Document steps taken using `../common_steps/document_in_soar.md`.

---

### Phase 6: Lessons Learned (Post-Incident)

*   **Objective:** Review the incident and response to identify areas for improvement.
*   **Sub-Runbooks/Steps:** *(Placeholder - Requires dedicated Post-Incident Runbook)*
    1.  **Incident Review Meeting:** Discuss the phishing campaign, response effectiveness, and root cause.
    2.  **Analyze Response:** Review timeline, tool usage, communication effectiveness.
    3.  **Identify Gaps:** Were detections missed? Was user reporting effective? Were containment actions swift enough?
    4.  **Develop Recommendations:** Suggest improvements (e.g., new email filtering rules, enhanced detection logic for specific IOC types, targeted user awareness training, runbook updates).
    5.  **Update Documentation:** Update runbooks, policies, etc.
    6.  **Track Recommendations:** Assign and track implementation.
    7.  **Final Report:** Generate using guidelines from `.clinerules/reporting_templates.md` and `../report_writing.md`.
    8.  **Document Review:** Document outcomes using `../common_steps/document_in_soar.md`.
