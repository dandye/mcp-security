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
    # This function registers all tools (actions) for the PaloAltoNGFW integration.

    @mcp.tool(
        title='Palo Alto NGFW: Edit Blocked Applications',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Edit Blocked Applications',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_edit_blocked_applications(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], device_name: Annotated[str, Field(..., description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[str, Field(..., description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], policy_name: Annotated[str, Field(..., description="Policy name value.")], applications_to_block: Annotated[Optional[str], Field(default=None, description="List of applications to block, comma separated, e.g: apple-siri,app2.")], applications_to_un_block: Annotated[Optional[str], Field(default=None, description="List of applications to unblock, comma separated, e.g: apple-siri,app2.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Block and unblock applications. Each application is added to or removed from a given policy.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if applications_to_block is not None:
                script_params["Applications To Block"] = applications_to_block
            if applications_to_un_block is not None:
                script_params["Applications To UnBlock"] = applications_to_un_block
            script_params["Device Name"] = device_name
            script_params["Vsys Name"] = vsys_name
            script_params["Policy Name"] = policy_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Edit Blocked Applications",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Edit Blocked Applications",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Edit Blocked Applications")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Edit Blocked Applications for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Block IPS in Policy',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Block IPS in Policy',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_block_ips_in_policy(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], device_name: Annotated[str, Field(..., description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[str, Field(..., description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], policy_name: Annotated[str, Field(..., description="Policy name value.")], target: Annotated[str, Field(..., description="Has to be source or destination.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Block IP addresses in a policy (each IP is added individually to the policy)

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Device Name"] = device_name
            script_params["Vsys Name"] = vsys_name
            script_params["Policy Name"] = policy_name
            script_params["Target"] = target
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Block ips in policy",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Block ips in policy",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Block ips in policy")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Block ips in policy for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Add IPS to Group',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Add IPS to Group',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_add_ips_to_group(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], address_group_name: Annotated[str, Field(..., description="Group name value.")], device_name: Annotated[Optional[str], Field(default=None, description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[Optional[str], Field(default=None, description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], use_shared_objects: Annotated[Optional[bool], Field(default=None, description="If enabled, action will use shared objects instead of vsys. Note: action will not create a shared address group, if it doesn't exist.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Add IP addresses to an address group

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if device_name is not None:
                script_params["Device Name"] = device_name
            if vsys_name is not None:
                script_params["Vsys Name"] = vsys_name
            script_params["Address Group Name"] = address_group_name
            if use_shared_objects is not None:
                script_params["Use Shared Objects"] = use_shared_objects
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Add Ips to group",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Add Ips to group",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Add Ips to group")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Add Ips to group for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Commit Changes',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Commit Changes',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_commit_changes(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], only_my_changes: Annotated[bool, Field(..., description="Commit only the configured use changes.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Commit changes in Palo Alto NGFW. NOTICE! For using Only My Changes option, the user must be an admin.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Only My Changes"] = only_my_changes
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Commit Changes",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Commit Changes",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Commit Changes")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Commit Changes for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Ping',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Test connectivity to Panorama

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
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
                actionName="PaloAltoNGFW_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Ping")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Ping for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Unblock URLs',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Unblock URLs',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_unblock_urls(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], url_category_name: Annotated[str, Field(..., description="")], device_name: Annotated[Optional[str], Field(default=None, description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[Optional[str], Field(default=None, description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], use_shared_objects: Annotated[Optional[bool], Field(default=None, description="If enabled, action will use shared objects instead of vsys.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Remove URLs from a given URL category

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if device_name is not None:
                script_params["Device Name"] = device_name
            if vsys_name is not None:
                script_params["Vsys Name"] = vsys_name
            script_params["URL Category Name"] = url_category_name
            if use_shared_objects is not None:
                script_params["Use Shared Objects"] = use_shared_objects
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Unblock Urls",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Unblock Urls",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Unblock Urls")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Unblock Urls for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Block URLs',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Block URLs',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_block_urls(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], url_category_name: Annotated[str, Field(..., description="Policy name value.")], device_name: Annotated[Optional[str], Field(default=None, description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[Optional[str], Field(default=None, description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], use_shared_objects: Annotated[Optional[bool], Field(default=None, description="If enabled, action will use shared objects instead of vsys.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Add URLs to a given URL category (NOTE- To actually block the URL, create a policy and add the desired URL category to it.). Note: the length of URL can't exceed 255 characters.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if device_name is not None:
                script_params["Device Name"] = device_name
            if vsys_name is not None:
                script_params["Vsys Name"] = vsys_name
            script_params["URL Category Name"] = url_category_name
            if use_shared_objects is not None:
                script_params["Use Shared Objects"] = use_shared_objects
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Block Urls",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Block Urls",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Block Urls")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Block Urls for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Remove IPS from Group',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Remove IPS from Group',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_remove_ips_from_group(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], address_group_name: Annotated[str, Field(..., description="The name of the required address group.")], device_name: Annotated[Optional[str], Field(default=None, description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[Optional[str], Field(default=None, description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], use_shared_objects: Annotated[Optional[bool], Field(default=None, description="If enabled, action will use shared objects instead of vsys. Note: action will not create a shared address group, if it doesn't exist.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Remove IP addresses from an address group

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if device_name is not None:
                script_params["Device Name"] = device_name
            if vsys_name is not None:
                script_params["Vsys Name"] = vsys_name
            script_params["Address Group Name"] = address_group_name
            if use_shared_objects is not None:
                script_params["Use Shared Objects"] = use_shared_objects
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Remove Ips from group",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Remove Ips from group",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Remove Ips from group")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Remove Ips from group for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Unblock IPS in Policy',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Unblock IPS in Policy',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_unblock_ips_in_policy(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], device_name: Annotated[str, Field(..., description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[str, Field(..., description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], policy_name: Annotated[str, Field(..., description="Policy name value.")], target: Annotated[str, Field(..., description="Has to be source or destination.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Unblock IP addresses in a policy (each IP address is removed individually from the policy).

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Device Name"] = device_name
            script_params["Vsys Name"] = vsys_name
            script_params["Policy Name"] = policy_name
            script_params["Target"] = target
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Unblock ips in policy",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Unblock ips in policy",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Unblock ips in policy")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Unblock ips in policy for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Palo Alto NGFW: Get Blocked Applications',
        annotations=ToolAnnotations(
            title='Palo Alto NGFW: Get Blocked Applications',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def palo_alto_ngfw_get_blocked_applications(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], device_name: Annotated[str, Field(..., description="The device name in which the group is located. The default device name of NGFW is localhost.localdomain. In case configured differently, please refer to https://<NGFWIP>/php/rest/browse.php/config::devices for the list of all the device names and select the relevant device.")], vsys_name: Annotated[str, Field(..., description="The vsys in which the group is located. The default vsys name of NGFW is vsys1. In case configured differently, please refer to https://<NGFW IP>/php/rest/browse.php/config::devices::entry[@name='<DEVICE NAME>']::vsys for the list of all the vsys names of the device and select the relevant vsys.")], policy_name: Annotated[str, Field(..., description="Policy name value.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """List all blocked applications in a given policy

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="PaloAltoNGFW")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for PaloAltoNGFW: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Device Name"] = device_name
            script_params["Vsys Name"] = vsys_name
            script_params["Policy Name"] = policy_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="PaloAltoNGFW_Get Blocked Applications",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "PaloAltoNGFW_Get Blocked Applications",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "PaloAltoNGFW_Get Blocked Applications")
            except Exception as e:
                logger.error("Error executing action PaloAltoNGFW_Get Blocked Applications for PaloAltoNGFW: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for PaloAltoNGFW")
            return marketplace_error_result("No active instance found.")
