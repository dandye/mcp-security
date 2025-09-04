# Runbook: Alert Triage (Placeholder)

## Objective

*(Define the goal, e.g., To provide a standardized process for the initial assessment and triage of incoming security alerts, determining if they represent a potential threat requiring further investigation or if they can be closed as false positives/duplicates.)*

## Scope

*(Define what is included/excluded, e.g., Covers initial alert review, basic entity enrichment, and decision-making based on predefined criteria. Excludes deep investigation or containment actions.)*

## Inputs

*   `${ALERT_ID}` or `${CASE_ID}`: The identifier for the alert or case to be triaged.
*   *(Optional) `${ALERT_DETAILS}`: Initial details provided by the alerting system.*

## Tools

*   `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment`, `change_case_priority`, `siemplify_get_similar_cases`, `siemplify_close_case`, `siemplify_close_alert`
*   `secops-mcp`: `lookup_entity`, `get_ioc_matches`
*   `gti-mcp`: `get_file_report`, `get_domain_report`, `get_ip_address_report`, `get_url_report`

## Workflow Steps & Diagram

1.  **Receive Alert/Case:** Obtain the `${ALERT_ID}` or `${CASE_ID}`.
2.  **Gather Initial Context:** Use `get_case_full_details` or `list_alerts_by_case` / `list_events_by_alert` to understand the alert type, severity, involved entities, and triggering events.
3.  **Check for Duplicates:** Use `siemplify_get_similar_cases` to identify potential duplicate cases. If a duplicate is confirmed, close the current case/alert following procedure (e.g., using `siemplify_close_case` with appropriate reason).
4.  **Basic Enrichment:** Use `lookup_entity` (SIEM) and relevant `get_*_report` (GTI) tools for key involved entities (IPs, domains, hashes, users). Check `get_ioc_matches` for known bad indicators.
5.  **Initial Assessment:** Based on alert type, entity reputation, SIEM context, and potential known benign patterns (referencing `.clinerules/common_benign_alerts.md` if available), make an initial assessment:
    *   False Positive (FP)
    *   Benign True Positive (BTP - expected/authorized activity)
    *   Requires Further Investigation (True Positive - TP or Suspicious)
6.  **Action Based on Assessment:**
    *   **If FP/BTP:** Document the reason clearly using `post_case_comment` and close the alert/case using `siemplify_close_alert` or `siemplify_close_case`.
    *   **If TP/Suspicious:** Ensure appropriate priority is set (`change_case_priority`), document initial findings (`post_case_comment`), and escalate/assign to the appropriate next tier or trigger a relevant investigation runbook (e.g., `basic_ioc_enrichment.md`, `suspicious_login_triage.md`).

```{mermaid}
sequenceDiagram
    participant Analyst
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp

    Analyst->>SOAR: Receive Alert/Case (ID)
    SOAR-->>Analyst: Alert/Case Details
    Analyst->>SOAR: get_case_full_details / list_alerts_by_case / list_events_by_alert
    SOAR-->>Analyst: Context (Entities E1, E2...)
    Analyst->>SOAR: siemplify_get_similar_cases
    SOAR-->>Analyst: Potential Duplicates
    alt Duplicate Found & Confirmed
        Analyst->>SOAR: post_case_comment (Reason: Duplicate)
        Analyst->>SOAR: siemplify_close_case / siemplify_close_alert
        Analyst->>Analyst: End Triage
    end
    loop For each Key Entity Ei
        Analyst->>SIEM: lookup_entity(entity_value=Ei)
        SIEM-->>Analyst: SIEM Context
        Analyst->>GTI: get...report(ioc=Ei)
        GTI-->>Analyst: GTI Context
    end
    Analyst->>SIEM: get_ioc_matches
    SIEM-->>Analyst: IOC Match Results
    Note over Analyst: Assess: FP / BTP / TP / Suspicious
    alt FP / BTP
        Analyst->>SOAR: post_case_comment (Reason: FP/BTP Explanation)
        Analyst->>SOAR: siemplify_close_case / siemplify_close_alert
        Analyst->>Analyst: End Triage
    else TP / Suspicious
        Analyst->>SOAR: change_case_priority (If needed)
        Analyst->>SOAR: post_case_comment (Initial Findings)
        Note over Analyst: Escalate / Assign / Trigger Next Runbook
        Analyst->>Analyst: End Triage
    end

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Alert assessed, documented, and either closed or escalated appropriately.)*
