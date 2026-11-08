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
    # This function registers all tools (actions) for the TrendMicroDeepSecurity integration.

    @mcp.tool(
        title='Trend Micro Deep Security: Get Security Profiles',
        annotations=ToolAnnotations(
            title='Trend Micro Deep Security: Get Security Profiles',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def trend_micro_deep_security_get_security_profiles(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Get all of the policies from Deep Security

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="TrendMicroDeepSecurity")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for TrendMicroDeepSecurity: %s", e)
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
                actionName="TrendMicroDeepSecurity_Get Security Profiles",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "TrendMicroDeepSecurity_Get Security Profiles",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "TrendMicroDeepSecurity_Get Security Profiles")
            except Exception as e:
                logger.error("Error executing action TrendMicroDeepSecurity_Get Security Profiles for TrendMicroDeepSecurity: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for TrendMicroDeepSecurity")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Trend Micro Deep Security: Get Host Info',
        annotations=ToolAnnotations(
            title='Trend Micro Deep Security: Get Host Info',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def trend_micro_deep_security_get_host_info(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Describe a computer

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="TrendMicroDeepSecurity")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for TrendMicroDeepSecurity: %s", e)
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
                actionName="TrendMicroDeepSecurity_Get Host Info",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "TrendMicroDeepSecurity_Get Host Info",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "TrendMicroDeepSecurity_Get Host Info")
            except Exception as e:
                logger.error("Error executing action TrendMicroDeepSecurity_Get Host Info for TrendMicroDeepSecurity: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for TrendMicroDeepSecurity")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Trend Micro Deep Security: Ping',
        annotations=ToolAnnotations(
            title='Trend Micro Deep Security: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def trend_micro_deep_security_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="TrendMicroDeepSecurity")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for TrendMicroDeepSecurity: %s", e)
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
                actionName="TrendMicroDeepSecurity_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "TrendMicroDeepSecurity_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "TrendMicroDeepSecurity_Ping")
            except Exception as e:
                logger.error("Error executing action TrendMicroDeepSecurity_Ping for TrendMicroDeepSecurity: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for TrendMicroDeepSecurity")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Trend Micro Deep Security: Scan Host',
        annotations=ToolAnnotations(
            title='Trend Micro Deep Security: Scan Host',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def trend_micro_deep_security_scan_host(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Request a malware scan

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="TrendMicroDeepSecurity")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for TrendMicroDeepSecurity: %s", e)
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
                actionName="TrendMicroDeepSecurity_Scan Host",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "TrendMicroDeepSecurity_Scan Host",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "TrendMicroDeepSecurity_Scan Host")
            except Exception as e:
                logger.error("Error executing action TrendMicroDeepSecurity_Scan Host for TrendMicroDeepSecurity: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for TrendMicroDeepSecurity")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Trend Micro Deep Security: Assign Security Profile to Host',
        annotations=ToolAnnotations(
            title='Trend Micro Deep Security: Assign Security Profile to Host',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def trend_micro_deep_security_assign_security_profile_to_host(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], security_profile_name: Annotated[str, Field(..., description="Policy name.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Assign the specified policy to computers

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="TrendMicroDeepSecurity")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for TrendMicroDeepSecurity: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Security Profile Name"] = security_profile_name
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="TrendMicroDeepSecurity_Assign Security Profile To Host",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "TrendMicroDeepSecurity_Assign Security Profile To Host",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "TrendMicroDeepSecurity_Assign Security Profile To Host")
            except Exception as e:
                logger.error("Error executing action TrendMicroDeepSecurity_Assign Security Profile To Host for TrendMicroDeepSecurity: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for TrendMicroDeepSecurity")
            return marketplace_error_result("No active instance found.")
