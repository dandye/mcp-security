### Compare GTI Collection to IoCs, Events in SecOps

From a GTI Collection (could be a Private Collection as well), search the past 3 days for any UDM events containing:
 1) Indicators of Compromise
 2) IOC++ (Modeled behvaioral data) (Would need to interpret relevant UDM fields)
 3) Get Chronicle SIEM IoC Matches (`get_ioc_matches`)
 4) Produce report on findings
 5) Add report to SOAR Case

Analyze results and compare against GTI Collection context (report or campaign). (Optional) Notable indicators are added to SQLite Table. Provide analyst report with prescribed follow on response actions.

Uses tools:

 * `gti-mcp.get_collection_report`
 * `secops-mcp.get_ioc_matches`
 * `secops-mcp.search_security_events`
 * `secops-mcp.get_security_alerts`
 * `gti-mcp.*` (various lookups like `get_file_report`, etc.)
 * (Optional) Add to SQLite Table
 * `secops-soar.post_case_comment`

```{mermaid}
sequenceDiagram
    participant User
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar

    User->>Cline: Sweep environment based on GTI Collection ID 'GTI-XYZ'
    Cline->>GTI: get_collection_report(id='GTI-XYZ')
    GTI-->>Cline: Collection details (Report/Campaign context, IOCs I1, I2...)
    Note over Cline: Extract IOCs (I1, I2...) and behavioral patterns (TTPs)
    Cline->>SIEM: get_ioc_matches(hours_back=...)
    SIEM-->>Cline: List of recent IOC matches in environment
    loop For each IOC Ii from Collection
        Cline->>SIEM: search_security_events(text="Events containing IOC Ii", hours_back=...)
        SIEM-->>Cline: UDM events related to IOC Ii
        Cline->>SIEM: get_security_alerts(query="alert contains Ii", hours_back=...)
        SIEM-->>Cline: Alerts related to IOC Ii
    end
    Note over Cline: Interpret behavioral patterns (TTPs) into UDM search queries
    loop For each Behavioral Pattern Bp
        Cline->>SIEM: search_security_events(text="Events matching pattern Bp", hours_back=...)
        SIEM-->>Cline: UDM events potentially matching pattern Bp
    end
    Note over Cline: Analyze results (IOC matches, events, alerts) against GTI context
    Note over Cline: Identify notable indicators (N1, N2...) found in environment
    loop For each Notable Indicator Ni
        Note over Cline: Add Ni to Chronicle Data Table (Conceptual Step - No direct tool)
        Cline->>SIEM: (Conceptual) Add Ni to Data Table 'Notable_Indicators'
    end
    Note over Cline: Synthesize report: Findings, GTI context correlation, Recommended Actions
    Cline->>SOAR: post_case_comment(case_id=[Relevant Case or New Case], comment="Sweep Report for GTI-XYZ: Found indicators [N1, N2...]. Events [...] observed. Recommended actions: [...]")
    SOAR-->>Cline: Comment confirmation
    Cline->>Cline: attempt_completion(result="Environment sweep based on GTI Collection 'GTI-XYZ' complete. Report posted.")

```