### Investigate a Case + external tools

Using SecOps, GTI, and Okta. Start with a Case (anomalous login Alerts). Find the entities involved and look up any related indicators. Find any users involved and look up Okta information to determine any suspicious characteristics. If confident in disposition, disable that User. Finally, provide a report about any identified activity for security analyst consumption.

Uses tools:

 * List Cases
 * Get Alerts in a Case
 * Entity Lookup
 * GTI Lookup
 * Event Search
 * OKTA user information
 * OKTA action"


```{mermaid}
sequenceDiagram
    participant User
    participant Cline as Cline (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant Okta as okta-mcp

    User->>Cline: Investigate Case Y (Anomalous Login)
    Cline->>SOAR: list_alerts_by_case(case_id=Y)
    SOAR-->>Cline: Alerts for Case Y (Entities: User U, IP I, Host H...)
    loop For each relevant Entity Ei (U, I, H...)
        Cline->>SIEM: lookup_entity(entity_value=Ei)
        SIEM-->>Cline: SIEM context for Ei
        Cline->>GTI: get_file_report/get_domain_report/get_ip_address_report(entity=Ei)
        GTI-->>Cline: GTI context for Ei
        Cline->>SIEM: search_security_events(text="Events involving entity Ei", hours_back=...)
        SIEM-->>Cline: Related UDM events for Ei
    end
    Note over Cline: Identify primary user entity (User U)
    Cline->>Okta: lookup_okta_user(user=U)
    Okta-->>Cline: Okta user details for User U
    Note over Cline: Analyze Okta details for suspicious activity/characteristics
    Cline->>User: ask_followup_question(question="Okta user U shows suspicious activity. Disable user?", options=["Yes", "No"])
    User->>Cline: Response (e.g., "Yes")
    alt Disable User Confirmed
        Cline->>Okta: disable_okta_user(user=U)
        Okta-->>Cline: Disable confirmation
    end
    Note over Cline: Synthesize all findings into a report summary
    Cline->>SOAR: post_case_comment(case_id=Y, comment="Investigation Summary: Anomalous login for User U from IP I. GTI/SIEM checks performed. Okta details reviewed. User disabled due to suspicious activity. Findings: [...]")
    SOAR-->>Cline: Comment confirmation
    Cline->>Cline: attempt_completion(result="Completed investigation for Case Y. User U potentially disabled. Summary posted as comment.")

```