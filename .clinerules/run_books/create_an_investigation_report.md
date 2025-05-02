### Create an Investigation Report

Create an Investigation Report of your investigation actions through multiple products	Perform an investigation (can be any set of actions) across SecOps, GTI, SCC, Okta, and Crowdstrike. Then, summarize all the actions, put it into a document, and add it as an attachment to the Case in SecOps. Redact/defang sensitive data from the document and (optionally and with confirmation) upload it to Google Drive or GCS Bucket.

Uses the MCP Tools:

 * List Cases
 * Get Alerts in a Case
 * Entity Lookup
 * GTI Lookup
 * OKTA User Lookup
 * SCC Findings Search
 * Attach Document to Case
 * Upload file to Google Drive"

```{mermaid}
sequenceDiagram
    participant User
    participant Cline as Cline (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant SCC as scc-mcp
    participant Okta as okta-mcp
    participant CS as crowdstrike-mcp
    participant Drive as google-drive-mcp
    participant GCS as gcs-mcp

    User->>Cline: Request Investigation Report for Case X
    Cline->>SOAR: list_alerts_by_case(case_id=X)
    SOAR-->>Cline: Alerts for Case X (containing entities E1, E2...)
    loop For each relevant Entity Ei
        Cline->>SIEM: lookup_entity(entity_value=Ei)
        SIEM-->>Cline: SIEM context for Ei
        Cline->>GTI: get_file_report/get_domain_report(entity=Ei)
        GTI-->>Cline: GTI context for Ei
        Cline->>SCC: search_scc_findings(query=Ei)
        SCC-->>Cline: SCC findings for Ei
        Cline->>Okta: lookup_okta_user(user=Ei)
        Okta-->>Cline: Okta user details for Ei
        Cline->>CS: get_host_details(host=Ei)
        CS-->>Cline: CrowdStrike host details for Ei
    end
    Note over Cline: Synthesize findings, redact/defang sensitive data
    Cline->>Cline: Create report content (e.g., report_content)
    Cline->>Cline: write_to_file(path="investigation_report_case_X.md", content=report_content)
    Note over Cline: Report created locally
    Cline->>SOAR: siemplify_add_attachment_to_case(case_id=X, file_path="investigation_report_case_X.md")
    SOAR-->>Cline: Attachment confirmation
    Cline->>User: ask_followup_question(question="Upload redacted report to Drive/GCS?", options=["Yes, Drive", "Yes, GCS", "No"])
    User->>Cline: Response (e.g., "Yes, Drive")
    alt Upload Confirmed
        alt Upload to Drive
            Cline->>Drive: upload_to_drive(file_path="investigation_report_case_X.md", destination="Reports Folder")
            Drive-->>Cline: Drive upload confirmation
        else Upload to GCS
            Cline->>GCS: upload_to_gcs(file_path="investigation_report_case_X.md", bucket="security-reports", object_name="case_X_report.md")
            GCS-->>Cline: GCS upload confirmation
        end
    end
    Cline->>Cline: attempt_completion(result="Investigation report created, attached to Case X, and optionally uploaded.")

```