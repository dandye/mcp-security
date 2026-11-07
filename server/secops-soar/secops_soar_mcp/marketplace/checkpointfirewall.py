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
    # This function registers all tools (actions) for the CheckPointFirewall integration.

    @mcp.tool(
        title='Check Point Firewall: Run Script',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Run Script',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_run_script(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], script_text: Annotated[str, Field(..., description="Script to execute. For example, fw sam command: fw sam -t 600 -I src 8.9.10.12")], target: Annotated[str, Field(..., description="Specify CheckPoint device to execute script on, for example: gaia80.10. Parameter accepts multiple values as a comma separated list.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Run arbitrary script with CheckPoint run-script API call. Note: action is not using Siemplify entities to operate.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Script text"] = script_text
            script_params["Target"] = target
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Run Script",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Run Script",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Run Script")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Run Script for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Add URL to Group',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Add URL to Group',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_add_url_to_group(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ur_ls_group_name: Annotated[str, Field(..., description="Specify the name of the group to which you want to add URL.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Add Url to the Checkpoint FireWall Group

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["URLs Group Name"] = ur_ls_group_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Add Url To Group",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Add Url To Group",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Add Url To Group")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Add Url To Group for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Download Log Attachment',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Download Log Attachment',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_download_log_attachment(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], log_i_ds: Annotated[str, Field(..., description="Specify the comma-separated list of log IDs from which you want to download attachments.")], download_folder_path: Annotated[str, Field(..., description="Specify the absolute path for the folder where the action should store the attachments.")], create_case_wall_attachment: Annotated[Optional[bool], Field(default=None, description="If enabled, action will create a case wall attachment for each successfully downloaded file. Note: that attachment will only be created if it\u2019s size is less than 3 MB.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Download log attachments from CheckPoint FireWall.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Log IDs"] = log_i_ds
            script_params["Download Folder Path"] = download_folder_path
            if create_case_wall_attachment is not None:
                script_params["Create Case Wall Attachment"] = create_case_wall_attachment
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Download Log Attachment",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Download Log Attachment",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Download Log Attachment")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Download Log Attachment for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Add a SAM Rule',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Add a SAM Rule',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_add_a_sam_rule(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], security_gateway_to_create_sam_rule_on: Annotated[str, Field(..., description="Specify the name of Security Gateway to create a rule for.")], action_for_the_matching_connections: Annotated[List[str], Field(..., description="Specify the action that should be executed for the matching connections.")], how_to_track_matching_connections: Annotated[List[str], Field(..., description="Specify how to track matching connections.")], source_ip: Annotated[Optional[str], Field(default=None, description="Specify the source IP to be added to the rule.")], source_netmask: Annotated[Optional[str], Field(default=None, description="Specify the source netmask to be added to the rule.")], destination_ip: Annotated[Optional[str], Field(default=None, description="Specify the destination IP to be added to the rule.")], destination_netmask: Annotated[Optional[str], Field(default=None, description="Specify the destination netmask to be added to the rule.")], port: Annotated[Optional[str], Field(default=None, description="Specify the port number to be added to the rule for example, 5005")], protocol: Annotated[Optional[str], Field(default=None, description="Specify the protocol name to be added to the rule for example, TCP")], expiration: Annotated[Optional[str], Field(default=None, description="Specify how long in seconds the newly added SAM rule should be active for example, 4. If nothing is specified - then the rule never expires.")], close_connections: Annotated[Optional[bool], Field(default=None, description="Specify if the existing matching connections should be closed.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Add a SAM (suspicious activity monitoring) rule for Checkpoint Firewall. Please refer to the Checkpoint fw_sam command criteria section documentation for available ip, netmask, port and protocol combinations - https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_CLI_ReferenceGuide/Content/Topics-CLIG/MDSG/fw-sam.htm

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Security Gateway to Create SAM Rule on"] = security_gateway_to_create_sam_rule_on
            if source_ip is not None:
                script_params["Source IP"] = source_ip
            if source_netmask is not None:
                script_params["Source Netmask"] = source_netmask
            if destination_ip is not None:
                script_params["Destination IP"] = destination_ip
            if destination_netmask is not None:
                script_params["Destination Netmask"] = destination_netmask
            if port is not None:
                script_params["Port"] = port
            if protocol is not None:
                script_params["Protocol"] = protocol
            if expiration is not None:
                script_params["Expiration"] = expiration
            script_params["Action for the Matching Connections"] = action_for_the_matching_connections
            script_params["How to Track Matching Connections"] = how_to_track_matching_connections
            if close_connections is not None:
                script_params["Close Connections"] = close_connections
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Add a SAM Rule",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Add a SAM Rule",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Add a SAM Rule")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Add a SAM Rule for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Add IP to Group',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Add IP to Group',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_add_ip_to_group(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], blacklist_group_name: Annotated[str, Field(..., description="Specify the name of the group to which you want to add IP address.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Add IP to the Checkpoint FireWall Group

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Blacklist Group Name"] = blacklist_group_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Add Ip To Group",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Add Ip To Group",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Add Ip To Group")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Add Ip To Group for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Ping',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
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
                actionName="CheckPointFirewall_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Ping")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Ping for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: List Policies on Site',
        annotations=ToolAnnotations(
            title='Check Point Firewall: List Policies on Site',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_list_policies_on_site(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], max_policies_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many policies to return in the response. Default: 50.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Retrieve all existing policies

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if max_policies_to_return is not None:
                script_params["Max Policies To Return"] = max_policies_to_return
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_List Policies On Site",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_List Policies On Site",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_List Policies On Site")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_List Policies On Site for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Remove SAM Rule',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Remove SAM Rule',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_remove_sam_rule(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], security_gateway: Annotated[str, Field(..., description="Specify the name of Security Gateway from where to remove SAM Rule")], action_for_the_matching_connections: Annotated[List[str], Field(..., description="Specify the action that should be executed for the matching connections.")], how_to_track_matching_connections: Annotated[List[str], Field(..., description="Specify how to track matching connections.")], source_ip: Annotated[Optional[str], Field(default=None, description="Specify the source IP to be added to the rule.")], source_netmask: Annotated[Optional[str], Field(default=None, description="Specify the source netmask to be added to the rule.")], destination_ip: Annotated[Optional[str], Field(default=None, description="Specify the destination IP to be added to the rule.")], destination_netmask: Annotated[Optional[str], Field(default=None, description="Specify the destination netmask to be added to the rule.")], port: Annotated[Optional[str], Field(default=None, description="Specify the port number to be added to the rule for example, 5005")], protocol: Annotated[Optional[str], Field(default=None, description="Specify the protocol name to be added to the rule for example, TCP")], close_connections: Annotated[Optional[bool], Field(default=None, description="Specify if the existing matching connections should be closed.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Remove a SAM (suspicious activity monitoring) rule from Checkpoint Firewall. Note: you need to match the current rule in order to remove it. Please refer to the Checkpoint fw_sam command criteria section documentation for available ip, netmask, port and protocol combinations - https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_CLI_ReferenceGuide/Topics-CLIG/MDSG/fw-sam.htm

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Security Gateway"] = security_gateway
            if source_ip is not None:
                script_params["Source IP"] = source_ip
            if source_netmask is not None:
                script_params["Source Netmask"] = source_netmask
            if destination_ip is not None:
                script_params["Destination IP"] = destination_ip
            if destination_netmask is not None:
                script_params["Destination Netmask"] = destination_netmask
            if port is not None:
                script_params["Port"] = port
            if protocol is not None:
                script_params["Protocol"] = protocol
            script_params["Action for the Matching Connections"] = action_for_the_matching_connections
            script_params["How to Track Matching Connections"] = how_to_track_matching_connections
            if close_connections is not None:
                script_params["Close Connections"] = close_connections
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Remove SAM Rule",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Remove SAM Rule",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Remove SAM Rule")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Remove SAM Rule for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Show Logs',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Show Logs',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_show_logs(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], time_frame: Annotated[List[str], Field(..., description="Specify what time frame should be used for log retrieval.")], log_type: Annotated[List[str], Field(..., description="Specify what type of logs should be returned.")], query_filter: Annotated[Optional[str], Field(default=None, description="Specify the query filter that will be used to return logs.")], max_logs_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many logs to return. Maximum is 100. This is Checkpoint FireWall limitation.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Retrieve logs from CheckPoint FireWall based on the filter.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if query_filter is not None:
                script_params["Query Filter"] = query_filter
            script_params["Time Frame"] = time_frame
            script_params["Log Type"] = log_type
            if max_logs_to_return is not None:
                script_params["Max Logs To Return"] = max_logs_to_return
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Show Logs",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Show Logs",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Show Logs")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Show Logs for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Remove URL from Group',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Remove URL from Group',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_remove_url_from_group(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ur_ls_group_name: Annotated[str, Field(..., description="Specify the name of the group from which you want to remove URL.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Remove URL from the Checkpoint FireWall Group

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["URLs Group Name"] = ur_ls_group_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Remove Url From Group",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Remove Url From Group",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Remove Url From Group")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Remove Url From Group for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: Remove IP from Group',
        annotations=ToolAnnotations(
            title='Check Point Firewall: Remove IP from Group',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_remove_ip_from_group(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], blacklist_group_name: Annotated[str, Field(..., description="Specify the name of the group from which you want to remove IP address.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Remove IP from the Checkpoint FireWall Group

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Blacklist Group Name"] = blacklist_group_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_Remove IP From Group",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_Remove IP From Group",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_Remove IP From Group")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_Remove IP From Group for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Check Point Firewall: List Layers on Site',
        annotations=ToolAnnotations(
            title='Check Point Firewall: List Layers on Site',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def check_point_firewall_list_layers_on_site(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], max_layers_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many layers to return in the response. Default: 50.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Retrieve all of the available Access Control and Threat Prevention layers

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="CheckPointFirewall")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for CheckPointFirewall: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if max_layers_to_return is not None:
                script_params["Max Layers To Return"] = max_layers_to_return
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="CheckPointFirewall_List Layers On Site",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "CheckPointFirewall_List Layers On Site",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "CheckPointFirewall_List Layers On Site")
            except Exception as e:
                logger.error("Error executing action CheckPointFirewall_List Layers On Site for CheckPointFirewall: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for CheckPointFirewall")
            return marketplace_error_result("No active instance found.")
