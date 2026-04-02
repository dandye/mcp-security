# Suspicious Login Alert Triage Runbook

## Objective

Guide the initial triage of common suspicious login alerts (e.g., Impossible Travel, Login from Untrusted Location, Multiple Failed Logins) for Tier 1 SOC Analysts.

## Scope

This runbook covers the initial investigation steps to gather context about a suspicious login event, focusing on user history and source IP reputation, to help determine if escalation is needed.

## Inputs

*   `${CASE_ID}`: The relevant SOAR case ID containing the alert(s).
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   `${USER_ID}`: The user ID associated with the suspicious login.
*   `${SOURCE_IP}`: The source IP address from which the suspicious login originated.
*   *(Optional) `${ALERT_DETAILS}`: Specific details from the alert (e.g., alert name, timestamp).*

## Tools

*   `secops-soar`: `get_case_full_details`, `post_case_comment`
*   `secops-mcp`: `lookup_entity`, `search_security_events`
*   `gti-mcp`: `get_ip_address_report`
*   *(Optional: Identity Provider tools like `okta-mcp.lookup_okta_user`)*

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`, `${USER_ID}`, `${SOURCE_IP}`, and optionally `${ALERT_DETAILS}`. Get full case details using `secops-soar.get_case_full_details`.
2.  **User Context (SIEM):**
    *   Use `secops-mcp.lookup_entity` with `entity_value=${USER_ID}`.
    *   Record summary of user's recent activity, first/last seen, related alerts.
3.  **Source IP Context (SIEM):**
    *   Use `secops-mcp.lookup_entity` with `entity_value=${SOURCE_IP}`.
    *   Record summary of IP's recent activity, first/last seen, related alerts.
4.  **Source IP Reputation (GTI):**
    *   Use `gti-mcp.get_ip_address_report` with `ip_address=${SOURCE_IP}`.
    *   Record key findings (e.g., reputation score, known associations, geolocation).
5.  **Recent Login Activity (SIEM):**
    *   Use `secops-mcp.search_security_events` with a query like `text="User login events for ${USER_ID}"` focusing on the last 24-72 hours.
    *   Look for patterns: logins from other unusual IPs, successful logins after failures, frequency of logins from `${SOURCE_IP}` vs. others.
6.  **(Optional) Identity Provider Check:**
    *   *(If available, use `okta-mcp.lookup_okta_user` or similar with `${USER_ID}` to check account status, recent legitimate logins, MFA methods, etc.)*
7.  **Synthesize & Document:**
    *   Combine findings: Is the user known to travel or use VPNs? Is the source IP known malicious or associated with legitimate services (e.g., known VPN provider)? Does the recent login pattern look anomalous compared to history?
    *   Use `secops-soar.post_case_comment` for `${CASE_ID}`. Summarize findings: "Suspicious Login Triage for `${USER_ID}` from `${SOURCE_IP}`: User History: [...]. Source IP Reputation (GTI): [...]. Recent Login Pattern: [...]. Optional IDP Check: [...]."
8.  **Recommend Next Step:**
    *   Based on the synthesis, add a recommendation to the comment: "Recommendation: [Close as FP/Known Activity | Escalate to Tier 2 for further investigation]".
9.  **Completion:** Conclude the runbook execution. Tier 1 analyst acts on the recommendation.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant IDP as Identity Provider (Optional)

    Analyst->>Cline: Start Suspicious Login Triage\nInput: CASE_ID, ALERT_GROUP_IDS, USER_ID, SOURCE_IP

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: User Context
    Cline->>SIEM: lookup_entity(entity_value=USER_ID)
    SIEM-->>Cline: User SIEM Summary
    Note over Cline: Record User Context

    %% Step 3: Source IP Context
    Cline->>SIEM: lookup_entity(entity_value=SOURCE_IP)
    SIEM-->>Cline: Source IP SIEM Summary
    Note over Cline: Record IP SIEM Context

    %% Step 4: Source IP Reputation
    Cline->>GTI: get_ip_address_report(ip_address=SOURCE_IP)
    GTI-->>Cline: IP Reputation Report
    Note over Cline: Record IP GTI Reputation

    %% Step 5: Recent Login Activity
    Cline->>SIEM: search_security_events(text="Logins for USER_ID", hours_back=72)
    SIEM-->>Cline: Recent Login Events
    Note over Cline: Analyze Login Patterns

    %% Step 6: Optional IDP Check
    opt IDP Tool Available
        Cline->>IDP: lookup_user(user=USER_ID)
        IDP-->>Cline: User Account Details from IDP
        Note over Cline: Record IDP Context
    end

    %% Step 7 & 8: Synthesize & Document
    Note over Cline: Synthesize all findings
    Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Suspicious Login Triage Summary... Recommendation: [Close/Escalate]")
    SOAR-->>Cline: Comment Confirmation

    %% Step 9: Completion
    Cline->>Analyst: attempt_completion(result="Suspicious Login Triage complete for USER_ID from SOURCE_IP. Findings and recommendation documented in case CASE_ID.")
