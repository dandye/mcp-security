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
    *   Record summary of user's recent activity, first/last seen, related alerts (`USER_SIEM_SUMMARY`).
3.  **Source IP Enrichment:**
    *   Execute `common_steps/enrich_ioc.md` with `IOC_VALUE=${SOURCE_IP}` and `IOC_TYPE="IP Address"`.
    *   Obtain `${GTI_FINDINGS}`, `${SIEM_ENTITY_SUMMARY}` (for IP), `${SIEM_IOC_MATCH_STATUS}`. Let's call these `IP_GTI_FINDINGS`, `IP_SIEM_SUMMARY`, `IP_SIEM_MATCH`.
4.  **Recent Login Activity (SIEM):**
    *   Use `secops-mcp.search_security_events` with a query like `text="User login events for ${USER_ID}"` focusing on the last 24-72 hours.
    *   Look for patterns: logins from other unusual IPs, successful logins after failures, frequency of logins from `${SOURCE_IP}` vs. others (`LOGIN_ACTIVITY_SUMMARY`).
5.  **(Optional) Identity Provider Check:**
    *   *(If available, use `okta-mcp.lookup_okta_user` or similar with `${USER_ID}` to check account status, recent legitimate logins, MFA methods, etc. (`IDP_SUMMARY`))*
6.  **Synthesize & Document:**
    *   Combine findings: Is the user known to travel or use VPNs (`USER_SIEM_SUMMARY`)? Is the source IP known malicious (`IP_GTI_FINDINGS`, `IP_SIEM_MATCH`) or associated with legitimate services? Does the recent login pattern look anomalous (`LOGIN_ACTIVITY_SUMMARY`)?
    *   Prepare comment text: `COMMENT_TEXT = "Suspicious Login Triage for ${USER_ID} from ${SOURCE_IP}: User SIEM Summary: ${USER_SIEM_SUMMARY}. Source IP GTI: ${IP_GTI_FINDINGS}. Source IP SIEM: ${IP_SIEM_SUMMARY}. Source IP IOC Match: ${IP_SIEM_MATCH}. Recent Login Pattern: ${LOGIN_ACTIVITY_SUMMARY}. Optional IDP Check: ${IDP_SUMMARY}. Recommendation: [Close as FP/Known Activity | Escalate to Tier 2 for further investigation]"`
    *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and `${COMMENT_TEXT}`. Obtain `${COMMENT_POST_STATUS}`.
7.  **Completion:** Conclude the runbook execution. Tier 1 analyst acts on the recommendation in the comment.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant IDP as Identity Provider (Optional)

    Analyst->>Cline: Start Suspicious Login Triage\nInput: CASE_ID, ALERT_GROUP_IDS, USER_ID, SOURCE_IP

    %% Step 1: Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details

    %% Step 2: User Context
    Cline->>SIEM: lookup_entity(entity_value=USER_ID)
    SIEM-->>Cline: User SIEM Summary (USER_SIEM_SUMMARY)

    %% Step 3: Source IP Enrichment
    Cline->>EnrichIOC: Execute(Input: IOC_VALUE=SOURCE_IP, IOC_TYPE="IP Address")
    EnrichIOC-->>Cline: Results: IP_GTI_FINDINGS, IP_SIEM_SUMMARY, IP_SIEM_MATCH

    %% Step 4: Recent Login Activity
    Cline->>SIEM: search_security_events(text="Logins for USER_ID", hours_back=72)
    SIEM-->>Cline: Recent Login Events (LOGIN_ACTIVITY_SUMMARY)

    %% Step 5: Optional IDP Check
    opt IDP Tool Available
        Cline->>IDP: lookup_user(user=USER_ID)
        IDP-->>Cline: User Account Details from IDP (IDP_SUMMARY)
    end

    %% Step 6: Synthesize & Document
    Note over Cline: Synthesize findings and prepare COMMENT_TEXT with Recommendation
    Cline->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
    DocumentInSOAR-->>Cline: Results: COMMENT_POST_STATUS

    %% Step 7: Completion
    Cline->>Analyst: attempt_completion(result="Suspicious Login Triage complete for USER_ID from SOURCE_IP. Findings and recommendation documented in case CASE_ID.")
