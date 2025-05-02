# IOC Containment Runbook

## Objective

Quickly execute containment actions for identified malicious Indicators of Compromise (IOCs) such as IP addresses, domains, or file hashes, leveraging available SIEM, SOAR, GTI, and potentially EDR/Firewall tools.

## Scope

This runbook focuses on the immediate containment actions based on confirmed malicious IOCs. It assumes the IOCs have been identified through prior investigation (e.g., alert triage, threat hunting, GTI research).

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash").
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report` (Optional: for final reputation check)
*   `secops-soar`: `google_chronicle_add_values_to_reference_list` (Example: for adding to SIEM blocklist)
*   `secops-soar`: `post_case_comment` (For documentation)
*   *(Potentially other SOAR actions for specific integrations like Firewalls, Proxies, EDR)*
*   `secops-mcp`: `search_security_events` (To find related activity/endpoints for file hashes)
*   `ask_followup_question` (To confirm actions)

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, `${CASE_ID}`, and `${ALERT_GROUP_IDENTIFIERS}`.
2.  **(Optional) Final Reputation Check:** Use the appropriate `gti-mcp` tool (`get_ip_address_report`, `get_domain_report`, `get_file_report`) for `${IOC_VALUE}` to confirm malicious reputation before blocking.
3.  **Confirm Containment Action:** Use `ask_followup_question` to confirm with the analyst that containment actions should proceed for `${IOC_VALUE}`.
4.  **Execute Containment:**
    *   **If `${IOC_TYPE}` is IP Address or Domain:**
        *   Add `${IOC_VALUE}` to the appropriate blocklist reference list in Chronicle SIEM using `secops-soar.google_chronicle_add_values_to_reference_list`. (Requires knowing the correct `reference_list_name`, e.g., "IP_Blocklist", "Domain_Blocklist").
        *   *(Optional: Execute actions via specific Firewall/Proxy SOAR integrations if available)*.
    *   **If `${IOC_TYPE}` is File Hash:**
        *   Search SIEM (`secops-mcp.search_security_events`) for events involving the file hash (`target.file.md5 = "${IOC_VALUE}"` or similar) to identify affected endpoints.
        *   *(Optional: Execute EDR actions like file quarantine/deletion on identified endpoints via specific EDR SOAR integrations if available)*.
5.  **Document Actions:** Record the containment actions taken for `${IOC_VALUE}` in the SOAR case using `secops-soar.post_case_comment`. Include the IOC, type, action taken (e.g., added to blocklist, EDR action attempted), and timestamp.
6.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant Cline as Cline (MCP Client)
    participant GTI as gti-mcp
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    %% EDR/Firewall conceptual participants
    participant EDR as EDR (Conceptual)
    participant Firewall as Firewall (Conceptual)

    Analyst->>Cline: Start IOC Containment Runbook\nInput: IOC_VALUE, IOC_TYPE, CASE_ID, ALERT_GROUP_IDS

    %% Step 2: Optional Reputation Check
    opt Reputation Check
        alt IOC_TYPE is IP Address
            Cline->>GTI: get_ip_address_report(ip_address=IOC_VALUE)
            GTI-->>Cline: IP Report (Confirm Malicious)
        else IOC_TYPE is Domain
            Cline->>GTI: get_domain_report(domain=IOC_VALUE)
            GTI-->>Cline: Domain Report (Confirm Malicious)
        else IOC_TYPE is File Hash
            Cline->>GTI: get_file_report(hash=IOC_VALUE)
            GTI-->>Cline: File Report (Confirm Malicious)
        end
    end

    %% Step 3: Confirm Action
    Cline->>Analyst: ask_followup_question(question="Proceed with containment for IOC_VALUE?", options=["Yes", "No"])
    Analyst->>Cline: Confirmation ("Yes")

    %% Step 4: Execute Containment
    alt Confirmation is "Yes"
        alt IOC_TYPE is IP Address or Domain
            Note over Cline: Determine Reference List Name (e.g., "IP_Blocklist")
            Cline->>SOAR: google_chronicle_add_values_to_reference_list(case_id=CASE_ID, alert_group_identifiers=ALERT_GROUP_IDS, reference_list_name="...", values=IOC_VALUE)
            SOAR-->>Cline: Blocklist Add Confirmation
            opt Firewall/Proxy Integration Available
                 Cline->>Firewall: (Conceptual) Block IOC_VALUE
                 Firewall-->>Cline: Block Confirmation
            end
        else IOC_TYPE is File Hash
            Cline->>SIEM: search_security_events(text="Events with hash IOC_VALUE")
            SIEM-->>Cline: Events (Identify Endpoints E1, E2...)
            opt EDR Integration Available
                loop For each Endpoint Ei
                    Cline->>EDR: (Conceptual) Quarantine/Delete Hash IOC_VALUE on Ei
                    EDR-->>Cline: EDR Action Confirmation for Ei
                end
            end
        end

        %% Step 5: Document Actions
        Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Containment action taken for IOC: IOC_VALUE (Type: IOC_TYPE). Action: [Blocked/EDR Action Attempted]")
        SOAR-->>Cline: Comment Confirmation

        %% Step 6: Completion
        Cline->>Analyst: attempt_completion(result="IOC Containment runbook complete for IOC_VALUE.")

    else Confirmation is "No"
         Cline->>SOAR: post_case_comment(case_id=CASE_ID, comment="Containment action aborted for IOC: IOC_VALUE (Type: IOC_TYPE).")
         SOAR-->>Cline: Comment Confirmation
         Cline->>Analyst: attempt_completion(result="IOC Containment runbook aborted for IOC_VALUE.")
    end
