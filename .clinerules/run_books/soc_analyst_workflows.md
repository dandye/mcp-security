# Runbook: SOC Analyst Workflows (Overview/Placeholder)

## Objective

*(Define the goal, e.g., To provide an overview or entry point for common SOC analyst workflows, potentially linking to more specific runbooks like alert triage, basic enrichment, or escalation procedures.)*

## Scope

*(Define what is included/excluded, e.g., High-level description of typical Tier 1/2 analyst tasks and pointers to detailed runbooks. Excludes deep technical steps.)*

## Inputs

*(Likely none directly, or perhaps a general task description)*

## Tools

*(List common tools used across various workflows, e.g., `secops-soar`, `secops-mcp`, `gti-mcp`)*

## Workflow Steps & Diagram

*(This section would likely describe the general flow, e.g., Monitor Queue -> Triage Alert -> Basic Enrichment -> Escalate/Close, and reference specific runbooks for each stage.)*

1.  **Monitor Alert Queue:** Regularly check the SOAR platform for new or assigned cases/alerts.
2.  **Initial Triage:** Assess alert severity and type. Refer to `.clinerules/run_books/triage_alerts.md`.
3.  **Basic Enrichment:** Gather initial context on IOCs. Refer to `.clinerules/run_books/basic_ioc_enrichment.md`.
4.  **Specific Alert Type Handling:** Follow dedicated runbooks for common types (e.g., `.clinerules/run_books/suspicious_login_triage.md`, `.clinerules/run_books/phishing_response.md`).
5.  **Documentation:** Document findings in the SOAR case. Refer to `.clinerules/run_books/report_writing.md` guidelines.
6.  **Escalation/Closure:** Escalate to Tier 2/3 or close as appropriate. Refer to `.clinerules/run_books/close_duplicate_or_similar_cases.md`.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant Runbooks as .clinerules/run_books/

    Analyst->>SOAR: Monitor Alert Queue (list_cases)
    SOAR-->>Analyst: New/Assigned Alerts/Cases
    Analyst->>Runbooks: Consult triage_alerts.md
    Analyst->>SOAR: Get Case/Alert Details (get_case_full_details, list_alerts_by_case)
    SOAR-->>Analyst: Details (IOCs: I1, I2...)
    Analyst->>Runbooks: Consult basic_ioc_enrichment.md
    loop For each IOC Ii
        Analyst->>SIEM: lookup_entity(entity_value=Ii)
        SIEM-->>Analyst: SIEM Context
        Analyst->>GTI: get...report(ioc=Ii)
        GTI-->>Analyst: GTI Context
    end
    Analyst->>Runbooks: Consult specific runbook (e.g., suspicious_login_triage.md)
    Note over Analyst: Follow specific runbook steps...
    Analyst->>SOAR: Document Findings (post_case_comment)
    alt Escalate
        Analyst->>SOAR: Assign Case to Tier 2/3
    else Close
        Analyst->>Runbooks: Consult close_duplicate_or_similar_cases.md
        Analyst->>SOAR: Close Case/Alert (siemplify_close_case)
    end

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Alert/case processed according to defined procedures, documented, and either closed or escalated.)*
