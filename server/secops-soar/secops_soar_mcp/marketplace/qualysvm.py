# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from secops_soar_mcp import bindings
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from secops_soar_mcp.utils.consts import Endpoints
from secops_soar_mcp.utils.utils import marketplace_error_result, normalize_marketplace_response
from secops_soar_mcp.utils.models import ApiManualActionDataModel, EmailContent, TargetEntity
import json
from typing import Any, Optional, List, Dict, Union, Annotated
from pydantic import Field
from secops_soar_mcp.utils.pydantic_list_field import PydanticListField
from logger_utils import get_logger

logger = get_logger(__name__)


def register_tools(mcp: MCPServer):
    # This function registers all tools (actions) for the QualysVM integration.

    @mcp.tool(
        title='Qualys VM: List Scans',
        annotations=ToolAnnotations(
            title='Qualys VM: List Scans',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_list_scans(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """List of scans launched within the past 30 days.

        Returns:
            dict: A dictionary containing the result of the action execution.
        """
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_List Scans",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_List Scans",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_List Scans")
            except Exception as e:
                logger.error("Error executing action QualysVM_List Scans for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Launch Patch Report',
        annotations=ToolAnnotations(
            title='Qualys VM: Launch Patch Report',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_launch_patch_report(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], report_title: Annotated[str, Field(..., description="A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed.")], report_type: Annotated[str, Field(..., description="Template name. For example: Qualys Patch Report.")], output_format: Annotated[str, Field(..., description="One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. e.g: pdf, online, xml or csv.")], i_ps_ranges: Annotated[Optional[str], Field(default=None, description="Specify IPs/ranges to change (override) the report target, as defined in the patch report template. Multiple IPs/ranges are comma separated.")], asset_groups: Annotated[Optional[str], Field(default=None, description="Asset groups.if more than one has to be comma separated.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Launch a patch report

Action Parameters: Report Title: A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed., Report Type: Template name., Output Format: One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Example: pdf, mht and html, IPs/Ranges: Specify IPs or ranges to change (override) the report target, as defined in the patch report template. Multiple IPs or ranges are comma-separated., Asset Groups: Asset groups. If more than one has to be comma-separated.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Report Title"] = report_title
            script_params["Report Type"] = report_type
            script_params["Output Format"] = output_format
            if i_ps_ranges is not None:
                script_params["IPs/Ranges"] = i_ps_ranges
            if asset_groups is not None:
                script_params["Asset Groups"] = asset_groups
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Launch Patch Report",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Launch Patch Report",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Launch Patch Report")
            except Exception as e:
                logger.error("Error executing action QualysVM_Launch Patch Report for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Download VM Scan Results',
        annotations=ToolAnnotations(
            title='Qualys VM: Download VM Scan Results',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_download_vm_scan_results(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], scan_id: Annotated[str, Field(..., description="Scan ID value. Scan ID format: scan/{integer}.{integer}")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Fetch vulnerability scan results by scan id.

Action Parameters: Scan ID: Scan ID value.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Scan ID"] = scan_id
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Download Vm Scan Results",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Download Vm Scan Results",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Download Vm Scan Results")
            except Exception as e:
                logger.error("Error executing action QualysVM_Download Vm Scan Results for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Launch VM Scan and Fetch Results',
        annotations=ToolAnnotations(
            title='Qualys VM: Launch VM Scan and Fetch Results',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_launch_vm_scan_and_fetch_results(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], processing_priority: Annotated[str, Field(..., description="Specify a value of 0 - 9 to set a processing priority level for the scan. When not specified, a value of 0 (no priority) is used. Valid values are: 0 for No Priority (the default), 1 for Emergency, 2 for Ultimate,3 for Critical, 4 for Major, 5 for High, 6 for Standard 7 for Medium, 8 for Minor and 9 for Low")], scan_profile: Annotated[str, Field(..., description="The title of the compliance option profile to be used. One of these parameters must be specified in a request: option_title or option_id. For example: Qualys Top 20 Options.")], title: Annotated[Optional[str], Field(default=None, description="The scan title. This can be a maximum of 2000 characters (ascii)")], scanner_appliance: Annotated[Optional[str], Field(default=None, description="The friendly names of the scanner appliances to be used or \"External\" for external scanners. Multiple entries are comma separated.")], network: Annotated[Optional[str], Field(default=None, description="The ID of a network used to filter the IPs/ranges specified in the \"ip\" parameter. Set to a custom network ID (note this does not filter IPs/ranges specified in \"asset_groups\" or \"asset_group_ids\"). Or set to \"0\" (the default) for the Global Default Network - this is used to scan hosts outside of your custom networks.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Launch vulnerability scan on a host in your network and fetch results. NOTICE! This action will automatically new hosts to Qualys as assets. Please note that your license limit number of hosts depends on your subscription. Supported entities: IP Address.

Action Parameters: Title: The scan title. It can be up to 2000 characters (ASCII) long., Processing Priority: Specify a value between 0 and 9 to set a processing priority level for the scan. When not specified, a value of 0 (no priority) is used. Valid values are: 0 for No Priority (the default) 1 for Emergency 2 for Ultimate 3 for Critical 4 for Major 5 for High 6 for Standard 7 for Medium 8 for Minor 9 for Low, Scan Profile: The title of the compliance option profile to be used. One of these parameters must be specified in a request: option_title option_id, Scanner Appliance: The friendly names of the scanner appliances to be used or "External" for external scanners. Multiple entries are comma-separated., Network: The ID of a network used to filter the IPs or ranges specified in the "ip" parameter. Set to a custom network ID. Note: This does not filter IPs or ranges specified in "asset_groups" or "asset_group_ids". Or set to "0" (the default) for the Global Default Network. This is used to scan hosts outside of your custom networks.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if title is not None:
                script_params["Title"] = title
            script_params["Processing Priority"] = processing_priority
            script_params["Scan Profile"] = scan_profile
            if scanner_appliance is not None:
                script_params["Scanner Appliance"] = scanner_appliance
            if network is not None:
                script_params["Network"] = network
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Launch VM Scan And Fetch Results",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Launch VM Scan And Fetch Results",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Launch VM Scan And Fetch Results")
            except Exception as e:
                logger.error("Error executing action QualysVM_Launch VM Scan And Fetch Results for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Download Report',
        annotations=ToolAnnotations(
            title='Qualys VM: Download Report',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_download_report(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], report_id: Annotated[str, Field(..., description="Report ID value.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Fetch report by ID

Action Parameters: Report ID: Report ID value.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Report ID"] = report_id
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Download Report",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Download Report",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Download Report")
            except Exception as e:
                logger.error("Error executing action QualysVM_Download Report for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: List IPs',
        annotations=ToolAnnotations(
            title='Qualys VM: List IPs',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_list_ips(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """List IP addresses in the user's account. By default, all hosts in the user's account are included.

        Returns:
            dict: A dictionary containing the result of the action execution.
        """
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_List Ips",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_List Ips",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_List Ips")
            except Exception as e:
                logger.error("Error executing action QualysVM_List Ips for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Launch Scan Report',
        annotations=ToolAnnotations(
            title='Qualys VM: Launch Scan Report',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_launch_scan_report(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], report_title: Annotated[str, Field(..., description="A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed.")], report_type: Annotated[str, Field(..., description="Template name. For example: Technical Report.")], output_format: Annotated[str, Field(..., description="One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. e.g: pdf, mht and html.")], i_ps_ranges: Annotated[Optional[str], Field(default=None, description="Specify IPs/ranges to change (override) the report target, as defined in the patch report template. Multiple IPs/ranges are comma separated.")], asset_groups: Annotated[Optional[str], Field(default=None, description="Asset groups.if more than one has to be comma separated.")], scan_reference: Annotated[Optional[str], Field(default=None, description="For a PCI compliance report, either the technical or executive report, this parameter specifies the scan reference to include. A scan reference starts with the string \"scan/\" followed by a reference ID number. The scan reference must be for a scan that was run using the PCI Options profile. Only one scan reference may be specified.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Launch a scan report

Action Parameters: Report Title: A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed., Report Type: Template name., Output Format: One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Example: pdf, mht and html., IPs/Ranges: Specify IPs or ranges to change (override) the report target, as defined in the patch report template. Multiple IPs or ranges are comma-separated., Asset Groups: Asset groups. If more than one has to be comma-separated., Scan Reference: Show only a scan with a certain scan reference code.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Report Title"] = report_title
            script_params["Report Type"] = report_type
            script_params["Output Format"] = output_format
            if i_ps_ranges is not None:
                script_params["IPs/Ranges"] = i_ps_ranges
            if asset_groups is not None:
                script_params["Asset Groups"] = asset_groups
            if scan_reference is not None:
                script_params["Scan Reference"] = scan_reference
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Launch Scan Report",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Launch Scan Report",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Launch Scan Report")
            except Exception as e:
                logger.error("Error executing action QualysVM_Launch Scan Report for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Ping',
        annotations=ToolAnnotations(
            title='Qualys VM: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Test Connectivity

        Returns:
            dict: A dictionary containing the result of the action execution.
        """
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Ping")
            except Exception as e:
                logger.error("Error executing action QualysVM_Ping for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: List Groups',
        annotations=ToolAnnotations(
            title='Qualys VM: List Groups',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_list_groups(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """List asset groups in the user's account.

        Returns:
            dict: A dictionary containing the result of the action execution.
        """
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_List Groups",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_List Groups",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_List Groups")
            except Exception as e:
                logger.error("Error executing action QualysVM_List Groups for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: List Endpoint Detections',
        annotations=ToolAnnotations(
            title='Qualys VM: List Endpoint Detections',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_list_endpoint_detections(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], status_filter: Annotated[Optional[str], Field(default=None, description="Specify a comma-separated list of statuses that should be used during ingestion. If nothing is provided, the action will ingest detections with New, Active, Re-Opened statuses. Possible values: New, Active, Re-Opened, Fixed")], lowest_severity_to_fetch: Annotated[Optional[List[str]], Field(default=None, description="Specify the lowest severity that will be used to fetch detections.")], max_detections_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many detections to return per entity. Default: 50. Maximum: 200.")], ingest_ignored_detections: Annotated[Optional[bool], Field(default=None, description="If enabled, action will also return ignored detections.")], ingest_disabled_detections: Annotated[Optional[bool], Field(default=None, description="If enabled, action will also return disabled detections.")], create_insight: Annotated[Optional[bool], Field(default=None, description="If enabled, action will create an insight containing information about vulnerabilities found on the entity.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
List endpoint detections in Qualys VM. Supported entities: IP Address, Hostname.

Action Parameters: Status Filter: Specify a comma-separated list of statuses that should be used during ingestion. If nothing is provided, the action ingests detections with "New, Active, Re-Opened" statuses. Possible values: New, Active, Fixed, Re-Opened., Ingest Ignored Detections: If enabled, the action also returns ignored detections., Ingest Disabled Detections: If enabled, the action also returns disabled detections., Lowest Severity To Fetch: Specify the lowest severity that is used to fetch detections., Create Insight: If enabled, the action creates an insight containing information about vulnerabilities found on the entity., Max Detections To Return: Specify the number of detections to return per entity. Maximum: 200

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if status_filter is not None:
                script_params["Status Filter"] = status_filter
            if lowest_severity_to_fetch is not None:
                script_params["Lowest Severity To Fetch"] = lowest_severity_to_fetch
            if max_detections_to_return is not None:
                script_params["Max Detections To Return"] = max_detections_to_return
            if ingest_ignored_detections is not None:
                script_params["Ingest Ignored Detections"] = ingest_ignored_detections
            if ingest_disabled_detections is not None:
                script_params["Ingest Disabled Detections"] = ingest_disabled_detections
            if create_insight is not None:
                script_params["Create Insight"] = create_insight
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_List Endpoint Detections",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_List Endpoint Detections",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_List Endpoint Detections")
            except Exception as e:
                logger.error("Error executing action QualysVM_List Endpoint Detections for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: List Reports',
        annotations=ToolAnnotations(
            title='Qualys VM: List Reports',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_list_reports(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """List of reports in the user's account when Report Share feature is enabled. The report list output includes all report types, including scorecard reports. 

        Returns:
            dict: A dictionary containing the result of the action execution.
        """
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_List Reports",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_List Reports",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_List Reports")
            except Exception as e:
                logger.error("Error executing action QualysVM_List Reports for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Launch Remediation Report',
        annotations=ToolAnnotations(
            title='Qualys VM: Launch Remediation Report',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_launch_remediation_report(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], report_title: Annotated[str, Field(..., description="A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed.")], report_type: Annotated[str, Field(..., description="Template name. For example: Tickets per Asset Group, Tickets per Vulnerability.")], output_format: Annotated[str, Field(..., description="One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. e.g: pdf, mht and html.")], i_ps_ranges: Annotated[Optional[str], Field(default=None, description="Specify IPs/ranges to change (override) the report target, as defined in the patch report template. Multiple IPs/ranges are comma separated.")], asset_groups: Annotated[Optional[str], Field(default=None, description="Asset groups.if more than one has to be comma separated.")], display_results_for_all_tickets: Annotated[Optional[bool], Field(default=None, description="Specifies whether the report will include tickets assigned to the current user (User is set by default), or all tickets in the user account. By default tickets assigned to the current user are included.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Launch a remediation report

Action Parameters: Report Title: A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed., Report Type: Template name., Output Format: One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Example: pdf, mht and html, IPs/Ranges: Specify IPs or ranges to change (override) the report target, as defined in the patch report template. Multiple IPs or ranges are comma separated., Asset Groups: Asset groups. If more than one has to be comma-separated., Display Results For All tickets: Specifies whether the report includes tickets assigned to the current user (User is set by default), or all tickets in the user account. By default tickets assigned to the current user are included.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Report Title"] = report_title
            script_params["Report Type"] = report_type
            script_params["Output Format"] = output_format
            if i_ps_ranges is not None:
                script_params["IPs/Ranges"] = i_ps_ranges
            if asset_groups is not None:
                script_params["Asset Groups"] = asset_groups
            if display_results_for_all_tickets is not None:
                script_params["Display Results For All tickets"] = display_results_for_all_tickets
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Launch Remediation Report",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Launch Remediation Report",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Launch Remediation Report")
            except Exception as e:
                logger.error("Error executing action QualysVM_Launch Remediation Report for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Launch Compliance Report',
        annotations=ToolAnnotations(
            title='Qualys VM: Launch Compliance Report',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_launch_compliance_report(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], report_title: Annotated[str, Field(..., description="A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed.")], report_type: Annotated[str, Field(..., description="Template name. For example: Qualys Top 20 Report, Payment Card Industry (PCI).")], output_format: Annotated[str, Field(..., description="One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. e.g: pdf, mht and html.")], i_ps_ranges: Annotated[Optional[str], Field(default=None, description="Specify IPs/ranges to change (override) the report target, as defined in the patch report template. Multiple IPs/ranges are comma separated.")], asset_groups: Annotated[Optional[str], Field(default=None, description="Asset groups.if more than one has to be comma separated.")], scan_reference: Annotated[Optional[str], Field(default=None, description="Show only a scan with a certain scan reference code.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Launch a compliance report

Action Parameters: Report Title: A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed., Report Type: Template name., Output Format: One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Example: pdf, mht, and html, IPs/Ranges: Specify IPs or ranges to change (override) the report target, as defined in the patch report template. Multiple IPs or ranges are comma-separated., Asset Groups: A comma-separated list of asset groups., Scan Reference: Show only a scan with a certain scan reference code.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Report Title"] = report_title
            script_params["Report Type"] = report_type
            script_params["Output Format"] = output_format
            if i_ps_ranges is not None:
                script_params["IPs/Ranges"] = i_ps_ranges
            if asset_groups is not None:
                script_params["Asset Groups"] = asset_groups
            if scan_reference is not None:
                script_params["Scan Reference"] = scan_reference
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Launch Compliance Report",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Launch Compliance Report",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Launch Compliance Report")
            except Exception as e:
                logger.error("Error executing action QualysVM_Launch Compliance Report for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Qualys VM: Enrich Host',
        annotations=ToolAnnotations(
            title='Qualys VM: Enrich Host',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def qualys_vm_enrich_host(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], create_insight: Annotated[Optional[bool], Field(default=None, description="If enabled, action will create an insight containing all of the retrieved information about the entity.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Enrich host with information from Qualys VM. Note: AssetView module is required. Supported entities: IP Address, Hostname.

Action Parameters: Create Insight: If enabled, the action creates an insight containing all of the retrieved information about the entity.

Returns:
dict: A dictionary containing the result of the action execution.
"""
        if bindings.http_client is None:
            return marketplace_error_result(
                "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
            )

        final_target_entities: Optional[List[TargetEntity]] = None
        final_scope: Optional[str] = None
        is_predefined_scope: Optional[bool] = None
    
        if target_entities:
            # Specific target entities provided, ignore scope parameter
            final_target_entities = target_entities
            final_scope = None
            is_predefined_scope = False
        else:
            # Check if the provided scope is valid
            if scope not in bindings.valid_scopes:
                allowed_values_str = ", ".join(sorted(list(bindings.valid_scopes)))
                return marketplace_error_result(f"Invalid scope '{scope}'. Allowed values are: {allowed_values_str}")
            final_target_entities = [] # Pass empty list for entities when using scope
            final_scope = scope
            is_predefined_scope = True
    
        # Fetch integration instance identifier
        try:
            instance_response = await bindings.http_client.get(
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="QualysVM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for QualysVM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if create_insight is not None:
                script_params["Create Insight"] = create_insight
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="QualysVM_Enrich Host",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "QualysVM_Enrich Host",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "QualysVM_Enrich Host")
            except Exception as e:
                logger.error("Error executing action QualysVM_Enrich Host for QualysVM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for QualysVM")
            return marketplace_error_result("No active instance found.")
