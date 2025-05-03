# Compromised User Account Incident Response Plan (IRP) / Runbook

## Objective

Provide a structured workflow for responding to incidents involving a potentially compromised user account (e.g., identified via impossible travel alerts, credential stuffing, successful phishing, etc.), coordinating investigation, containment, eradication, and recovery efforts.

## Scope

This runbook covers the end-to-end response lifecycle for compromised user account incidents. It relies on specific sub-runbooks or steps for detailed execution.

## Phases (PICERL Model)

1.  **Preparation:** *(Ongoing)* Ensure tools are operational, relevant detections are active, identity provider access is available, and communication/escalation plans are clear.
2.  **Identification:** Detect the potential compromise, perform initial triage, analyze user activity, and assess likelihood.
3.  **Containment:** Limit the impact by disabling the account, resetting passwords, or terminating sessions.
4.  **Eradication:** Remove any attacker persistence related to the compromised account (e.g., malicious OAuth apps, forwarding rules). Investigate actions taken by the compromised account.
5.  **Recovery:** Restore the user account to normal operation safely.
6.  **Lessons Learned (Post-Incident):** Review the incident and response to identify improvements.

## Inputs

*   `${USER_ID}`: The identifier of the potentially compromised user (e.g., username, email address).
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   *(Optional) `${INITIAL_ALERT_DETAILS}`: Summary of the alert that triggered this runbook.*

## Tools

*   `secops-mcp`: `search_security_events`, `lookup_entity`
*   `secops-soar`: `post_case_comment`, `get_case_full_details`
*   *(Potentially Identity Provider tools like `okta-mcp` if available: `lookup_okta_user`, `disable_okta_user`, `reset_okta_user_password`, `terminate_sessions`, etc.)*
*   `ask_followup_question` (To confirm actions)
*   *(Potentially Email platform tools for checking rules/delegation)*
*   *(Potentially Endpoint tools if investigating actions taken on hosts)*

## Workflow Steps & Diagram

```{mermaid}
sequenceDiagram
    participant Analyst
    participant IRP as compromised_user_account_response.md (This Runbook)
    participant Preparation as Phase 1: Preparation
    participant Identification as Phase 2: Identification
    participant Containment as Phase 3: Containment
    participant Eradication as Phase 4: Eradication
    participant Recovery as Phase 5: Recovery
    participant LessonsLearned as Phase 6: Lessons Learned

    Analyst->>IRP: Start Compromised User Account Response\nInput: USER_ID, CASE_ID, ALERT_GROUP_IDS, INITIAL_ALERT_DETAILS (opt)

    IRP->>Preparation: Verify Prerequisites (Ongoing)
    Preparation-->>IRP: Readiness Confirmed (Tools, Detections, Plans)

    IRP->>Identification: Execute Identification Steps
    Identification-->>IRP: Findings (Suspicious Activity, Likelihood Assessment)

    IRP->>Containment: Execute Containment Steps
    Containment-->>IRP: Containment Status (Account Disabled/Reset/Sessions Terminated)

    IRP->>Eradication: Execute Eradication Steps
    Eradication-->>IRP: Eradication Status (Persistence Removed, Actions Investigated)

    IRP->>Recovery: Execute Recovery Steps
    Recovery-->>IRP: Recovery Status (Account Restored)

    IRP->>LessonsLearned: Execute Post-Incident Steps
    LessonsLearned-->>IRP: Review Complete

    IRP-->>Analyst: Incident Response Complete
```

---

### Phase 1: Preparation (Ongoing)

*   **Objective:** Ensure readiness to respond to compromised account incidents.
*   **Actions:**
    *   Verify tool connectivity (SIEM, SOAR, IDP).
    *   Ensure relevant detections for suspicious logins, impossible travel, credential stuffing, etc., are active.
    *   Maintain access credentials and procedures for Identity Provider actions (disable, reset, session termination).
    *   Review and understand communication and escalation plans (`.clinerules/escalation_paths.md`).

---

### Phase 2: Identification

*   **Objective:** Detect the potential compromise, perform initial triage, analyze user activity, and assess likelihood.
*   **Sub-Runbooks/Steps:**
    1.  **Receive Input & Context:** Obtain `${USER_ID}`, `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`, and optionally `${INITIAL_ALERT_DETAILS}`. Get case details via `secops-soar.get_case_full_details`. Check for duplicates (`../common_steps/check_duplicate_cases.md`).
    2.  **Gather Initial Context:**
        *   Use `secops-mcp.lookup_entity` for `${USER_ID}` to get a quick summary of recent activity in SIEM.
        *   *(Optional: Use `okta-mcp.lookup_okta_user` or similar identity tool for `${USER_ID}` to get account status, recent logins, MFA details etc.)*
    3.  **Analyze User Activity:**
        *   Perform detailed searches in SIEM using `secops-mcp.search_security_events` for `${USER_ID}` covering the relevant timeframe (e.g., last 24-72 hours). Look for:
            *   Anomalous login locations/times/IPs/User Agents.
            *   Suspicious command-line activity on associated endpoints.
            *   Access to sensitive resources (files, applications, databases).
            *   Evidence of lateral movement (e.g., logins to other systems using this account).
            *   Large data transfers or exfiltration patterns.
            *   Failed login attempts followed by success.
            *   Changes to account settings (MFA, recovery email/phone, forwarding rules).
            *   Creation/modification of OAuth application grants.
    4.  **Assess Compromise Likelihood:** Based on the initial alert, context, and activity analysis, determine the likelihood of compromise (Low, Medium, High, Confirmed).
    5.  **Document Identification Phase:** Document findings using `../common_steps/document_in_soar.md`.

---

### Phase 3: Containment

*   **Objective:** Limit the impact of the compromise by restricting the attacker's access.
*   **Sub-Runbooks/Steps:**
    1.  **Confirm Containment Actions:** Use `../common_steps/confirm_action.md` to confirm with the analyst which containment actions (e.g., disable account, reset password, terminate sessions) should be taken based on the likelihood assessment. **Prioritize based on risk.**
    2.  **Execute Containment:**
        *   *(Requires specific Identity Provider integration tools)*
        *   If confirmed, execute actions like:
            *   Disable user account (e.g., `okta-mcp.disable_okta_user`).
            *   Reset user password (force change on next login) (e.g., `okta-mcp.reset_okta_user_password`).
            *   Terminate active sessions (e.g., `okta-mcp.terminate_sessions`).
    3.  **Verify Containment:** Monitor SIEM/IDP logs for further activity from the account or associated sessions.
    4.  **Document Containment:** Document actions taken and verification status using `../common_steps/document_in_soar.md`.

---

### Phase 4: Eradication

*   **Objective:** Remove any attacker persistence mechanisms tied to the account and investigate actions taken while compromised.
*   **Sub-Runbooks/Steps:**
    1.  **Investigate Attacker Actions:**
        *   Thoroughly review SIEM logs (`secops-mcp.search_security_events`) for all actions performed by the `${USER_ID}` during the suspected compromise window (identified in Phase 2). Focus on access to sensitive data, lateral movement attempts, configuration changes, emails sent/received.
        *   *(Requires Email Platform tools)* Check for malicious email forwarding rules, delegate access changes, or malicious emails sent from the account.
        *   *(Requires Cloud Platform tools)* Check for creation of malicious OAuth applications or other persistence in connected cloud services.
        *   *(Requires Endpoint tools)* If the account was used to access specific endpoints, trigger endpoint investigation (e.g., `../basic_endpoint_triage_isolation.md` or deeper forensics) to look for malware or persistence.
    2.  **Remove Persistence:**
        *   Remove any identified persistence mechanisms (e.g., delete forwarding rules, revoke malicious OAuth apps).
    3.  **Document Eradication:** Document investigation findings and eradication steps using `../common_steps/document_in_soar.md`.

---

### Phase 5: Recovery

*   **Objective:** Restore the user account to normal operation safely.
*   **Sub-Runbooks/Steps:**
    1.  **Ensure Threat Removed:** Confirm eradication steps are complete and associated endpoint threats (if any) are handled.
    2.  **Secure Account:** Ensure password has been reset and MFA is appropriately configured. Review account recovery options.
    3.  **Re-enable Account (If Disabled):** *(Requires IDP tools)* Re-enable the account if it was disabled during containment.
    4.  **Communicate with User:** Inform the user about the incident (as appropriate), the actions taken, and any necessary steps they need to take.
    5.  **Monitor Account:** Closely monitor the account's activity for a period post-recovery using SIEM/IDP logs.
    6.  **Document Recovery:** Document steps taken using `../common_steps/document_in_soar.md`.

---

### Phase 6: Lessons Learned (Post-Incident)

*   **Objective:** Review the incident and response to identify areas for improvement.
*   **Sub-Runbooks/Steps:** *(Placeholder - Requires dedicated Post-Incident Runbook)*
    1.  **Incident Review Meeting:** Discuss the initial access vector (if known), detection method, response effectiveness, and recovery process.
    2.  **Analyze Response:** Review timeline, tool effectiveness, runbook adherence.
    3.  **Identify Gaps:** Focus on prevention (e.g., MFA effectiveness, phishing awareness), detection (e.g., login anomaly tuning), and response gaps.
    4.  **Develop Recommendations:** Suggest improvements (e.g., security control changes, new detections, user training).
    5.  **Update Documentation:** Update runbooks, policies, etc.
    6.  **Track Recommendations:** Assign and track implementation.
    7.  **Final Report:** Generate using guidelines from `.clinerules/reporting_templates.md` and `../report_writing.md`.
    8.  **Document Review:** Document outcomes using `../common_steps/document_in_soar.md`.
