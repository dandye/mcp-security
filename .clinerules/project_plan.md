# Project Plan: Enhance LLM Agent Context

**Project Goal:** To create a comprehensive set of context files within the `.clinerules` directory, improving the LLM Agent's understanding of the environment, tools, policies, and relevant threats.

**Project Phases & Tasks:**

**Phase 1: Environment & Infrastructure Context**
*   **Objective:** Document the technical environment to provide operational context.
*   **Tasks:**
    1.  **Create `network_map.md`**:
        *   Gather information on key network segments (DMZ, Prod, User nets).
        *   Document IP ranges and primary functions for each segment.
        *   *Potential Action:* Ask user/Network Team for this information or relevant documentation.
    2.  **Create `asset_inventory_guidelines.md`**:
        *   Document host/server naming conventions.
        *   List common OS types deployed.
        *   Identify and map critical assets to roles/owners (if possible).
        *   *Potential Action:* Ask user/IT Asset Management for guidelines or inventory access.
    3.  **Create `critical_applications.md`**:
        *   List key business applications.
        *   Map applications to supporting servers/IPs.
        *   Describe expected communication patterns.
        *   *Potential Action:* Ask user/Application Owners for this information.
    4.  **Create `cloud_architecture.md`**:
        *   Outline GCP project structure.
        *   List key cloud services in use (GKE, Cloud SQL, etc.).
        *   Describe basic cloud network topology (VPCs, subnets).
        *   *Potential Action:* Ask user/Cloud Team for architecture diagrams or descriptions.

**Phase 2: Tool Configuration & Usage**
*   **Objective:** Document specific tool configurations and best practices.
*   **Tasks:**
    1.  **Create `tool_configurations.md`**:
        *   Identify and list important Chronicle Reference List names (Blocklists, Allowlists).
        *   Document key SOAR playbook names/IDs and their triggers.
        *   Define preferred default timeframes/limits for searches.
        *   *Potential Action:* Ask user/Security Engineering about these configurations.
    2.  **Create `mcp_tool_best_practices.md`**:
        *   Compile tips for optimizing `search_security_events`.
        *   Note important fields or interpretation guidance for GTI tools.
        *   Add any other tool-specific usage advice.
        *   *Potential Action:* Gather this information iteratively based on experience or ask user/senior analysts.
    3.  **Create `tool_rate_limits.md`**:
        *   Document known rate limits (e.g., Chronicle UDM query limits per hour).
        *   *Potential Action:* Check tool documentation or ask user/tool administrators.

**Phase 3: Organizational Policies & Procedures**
*   **Objective:** Codify key organizational processes relevant to security operations.
*   **Tasks:**
    1.  **Create `incident_severity_matrix.md`**:
        *   Define criteria for Low, Medium, High, Critical incidents.
        *   *Potential Action:* Ask user/SOC Manager for the existing matrix or definitions.
    2.  **Create `escalation_paths.md`**:
        *   Document who to notify for specific incident types (Ransomware, PII exposure, etc.).
        *   *Potential Action:* Ask user/IR Lead/SOC Manager for escalation procedures.
    3.  **Create `reporting_templates.md`**:
        *   Provide standard formats/sections for common reports (Daily Summary, Post-Incident).
        *   *Potential Action:* Ask user/SOC Manager for existing templates.
    4.  **Create `approved_remediations.md`**:
        *   List pre-approved actions for common low-severity findings.
        *   *Potential Action:* Ask user/Security Engineering/SOC Manager for this list.
    5.  **Create `key_contacts.md`**:
        *   List relevant teams/individuals (Network Ops, Identity, Legal).
        *   *Potential Action:* Ask user/SOC Manager for contact points.

**Phase 4: Threat Intelligence & Context**
*   **Objective:** Document organization-specific threat context and known benign activity.
*   **Tasks:**
    1.  **Create `internal_threat_profile.md`**:
        *   List high-concern threat actors, campaigns, or TTPs specific to the organization.
        *   *Potential Action:* Ask user/CTI Team for this profile.
    2.  **Create `whitelists.md`**:
        *   List known-good IPs, domains, hashes, process names specific to the environment.
        *   *Potential Action:* Gather this from user/Security Engineering/existing documentation.
    3.  **Create `common_benign_alerts.md`**:
        *   Describe alerts often triggered by benign activity (scans, admin scripts).
        *   Outline typical handling procedures for these.
        *   *Potential Action:* Gather this from user/SOC team experience.

**Next Steps:**

This plan outlines the creation of the suggested files. We can tackle these phases and tasks sequentially or prioritize based on which information would provide the most immediate value.

Would you like to start working on creating one of these files, perhaps beginning with Phase 1? Or would you like to adjust this plan? Please let me know how you'd like to proceed and toggle to ACT MODE when you're ready for me to start creating the files.
