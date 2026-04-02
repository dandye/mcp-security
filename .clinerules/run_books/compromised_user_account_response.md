# Compromised User Account Response Runbook

## Objective

Respond to incidents involving a potentially compromised user account (e.g., identified via impossible travel alerts, credential stuffing, successful phishing, etc.) by gathering context, assessing activity, taking containment actions, and documenting findings.

## Scope

This runbook covers the initial response phase for a suspected compromised user account. It focuses on confirming the compromise, containing the account, and gathering initial information for further investigation or handover.

## Inputs

*   `${USER_ID}`: The identifier of the potentially compromised user (e.g., username, email address).
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   *(Optional) `${INITIAL_ALERT_DETAILS}`: Summary of the alert that triggered this runbook.*

## Tools

*   `secops-mcp`: `search_security_events`, `lookup_entity`
*   `secops-soar`: `post_case_comment`, `get_case_full_details`
*   *(Potentially Identity Provider tools like `okta-mcp` if available: `lookup_okta_user`, `disable_okta_user`, `reset_okta_user_password`, etc.)*
*   `ask_followup_question` (To confirm actions)

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${USER_ID}`, `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`, and optionally `${INITIAL_ALERT_DETAILS}`.
2.  **Gather Initial Context:**
    *   Retrieve full case details using `secops-soar.get_case_full_details` for `${CASE_ID}` to understand existing information.
    *   Use `secops-mcp.lookup_entity` for `${USER_ID}` to get a quick summary of recent activity in SIEM.
    *   *(Optional: Use `okta-mcp.lookup_okta_user` or similar identity tool for `${USER_ID}` to get account status, recent logins, MFA details etc.)*
3.  **Analyze User Activity:**
    *   Perform detailed searches in SIEM using `secops-mcp.search_security_events` for `${USER_ID}` covering the relevant timeframe (e.g., last 24-72 hours). Look for:
        *   Anomalous login locations/times.
        *   Suspicious command-line activity.
        *   Access to sensitive resources.
        *   Evidence of lateral movement (e.g., logins to other systems).
        *   Large data transfers or exfiltration patterns.
        *   Failed login attempts followed by success.
4.  **Assess Compromise Likelihood:** Based on the initial alert, context, and activity analysis, determine the likelihood of compromise.
5.  **Confirm Containment Actions:** Use `ask_followup_question` to confirm with the analyst which containment actions (e.g., disable account, reset password, terminate sessions) should be taken based on the assessment.
6.  **Execute Containment:**
    *   *(Requires specific Identity Provider integration tools)*
    *   If confirmed, execute actions like:
        *   Disable user account (e.g., `okta-mcp.disable_okta_user`).
        *   Reset user password (e.g., `okta-mcp.reset_okta_user_password`).
        *   Terminate active sessions.
7.  **Document Findings & Actions:** Record the analysis findings, assessment, and containment actions taken for `${USER_ID}` in the SOAR case using `secops-soar.post_case_comment`.
8.  **Next Steps / Handover:**
    *   If compromise is confirmed and contained, determine next steps: deeper investigation into attacker actions, endpoint analysis for related malware, handover to Tier 3/IR team.
    *   Document recommended next steps in the case comment.
9.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant IdentityProvider as IDP (e.g., Okta)

    Analyst->>Cline: Start Compromised User Account Response\nInput: USER_ID, CASE_ID, ALERT_GROUP_IDS

    %% Step 2: Gather Initial Context
    Cline->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>Cline: Case Details
    Cline->>SIEM: lookup_entity(entity_value=USER_ID)
    SIEM-->>Cline: SIEM User Summary
    opt IDP Tool Available
        Cline->>IdentityProvider: lookup_user(user=USER_ID)
        IdentityProvider-->>Cline: User Account Details (Status, Logins)
    end

    %% Step 3: Analyze User Activity
    Cline->>SIEM: search_security_events(text="Activity for user USER_ID", hours_back=72)
    SIEM-->>Cline: Detailed User Events (Logins, Commands, Access...)

    %% Step 4: Assess Likelihood
    Note over Cline: Analyze events, assess compromise likelihood

    %% Step 5: Confirm Containment
    Cline->>Analyst: ask_followup_question(question="Compromise likely for USER_ID. Containment actions?", options=["Disable Account", "Reset Password", "Terminate Sessions", "Monitor Only", "No Action"])
    Analyst->>Cline: Confirmation (e.g., "Disable Account")

    %% Step 6: Execute Containment
    alt Containment Action Confirmed != "No Action" / "Monitor Only"
        opt IDP Tool Available
            alt Action is "Disable Account"
                Cline->>IdentityProvider: disable_user(user=USER_ID)
                IdentityProvider-->>Cline: Disable Confirmation
            else Action is "Reset Password"
                Cline->>IdentityProvider: reset_password(user=USER_ID)
                IdentityProvider-->>Cline: Reset Confirmation
            else Action is "Terminate Sessions"
                Cline->>IdentityProvider: terminate_sessions(user=USER_ID)
                IdentityProvider-->>Cline: Termination Confirmation
            end
        else IDP Tool Not Available
            Note over Cline: Manual action required via IDP console
        end
    end

    %% Step 7 & 8: Document & Next Steps
    Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="User USER_ID investigation: Findings [...]. Assessment: [Likely/Unlikely Compromise]. Action Taken: [Action]. Next Steps: [Investigate further/Monitor/Handover]")
    SOAR-->>Cline: Comment Confirmation

    %% Step 9: Completion
    Cline->>Analyst: attempt_completion(result="Compromised User Account Response runbook complete for USER_ID.")
