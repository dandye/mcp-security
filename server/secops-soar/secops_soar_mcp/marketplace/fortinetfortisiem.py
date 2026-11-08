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
    # This function registers all tools (actions) for the FortinetFortiSIEM integration.

    @mcp.tool(
        title='Fortinet Forti SIEM: Ping',
        annotations=ToolAnnotations(
            title='Fortinet Forti SIEM: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def fortinet_forti_siem_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Test connectivity to the FortiSIEM installation with parameters provided at the integration configuration page on the Marketplace tab.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="FortinetFortiSIEM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for FortinetFortiSIEM: %s", e)
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
                actionName="FortinetFortiSIEM_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "FortinetFortiSIEM_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "FortinetFortiSIEM_Ping")
            except Exception as e:
                logger.error("Error executing action FortinetFortiSIEM_Ping for FortinetFortiSIEM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for FortinetFortiSIEM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Fortinet Forti SIEM: Execute Simple Query',
        annotations=ToolAnnotations(
            title='Fortinet Forti SIEM: Execute Simple Query',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def fortinet_forti_siem_execute_simple_query(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], fields_to_return: Annotated[Optional[str], Field(default=None, description="Specify what fields to return. If nothing is provided, action will return all fields.")], sort_field: Annotated[Optional[str], Field(default=None, description="Specify what parameter should be used for sorting.")], sort_order: Annotated[Optional[List[str]], Field(default=None, description="Specify the order of sorting.")], minimum_severity_to_fetch: Annotated[Optional[str], Field(default=None, description="Specify minimum event severity to fetch to Siemplify in numbers, for example 5 or 7.")], event_types: Annotated[Optional[str], Field(default=None, description="Specify event types query should fetch. Parameter accepts multiple values as a comma separated string.")], event_category: Annotated[Optional[str], Field(default=None, description="Specify event category query should fetch. Parameter accepts multiple values as a comma separated string.")], event_i_ds: Annotated[Optional[str], Field(default=None, description="Specify optionally exact event ids query should fetch. Parameter accepts multiple values as a comma separated string.")], start_time: Annotated[Optional[str], Field(default=None, description="Specify the start time for the results. This parameter is mandatory, if \"Custom\" is selected for the \"Time Frame\" parameter. Format: ISO 8601. Example: 2021-04-23T12:38Z")], end_time: Annotated[Optional[str], Field(default=None, description="Specify the end time for the results. Format: ISO 8601. If nothing is provided and \"Custom\" is selected for the \"Time Frame\" parameter then this parameter will use current time.")], max_results_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many results to return. Default: 50.")], time_frame: Annotated[Optional[List[str]], Field(default=None, description="Specify a time frame for the results. If \"Custom\" is selected, you also need to provide \"Start Time\".")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Execute FortiSIEM events query based on the provided parameters.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="FortinetFortiSIEM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for FortinetFortiSIEM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if fields_to_return is not None:
                script_params["Fields To Return"] = fields_to_return
            if sort_field is not None:
                script_params["Sort Field"] = sort_field
            if sort_order is not None:
                script_params["Sort Order"] = sort_order
            if minimum_severity_to_fetch is not None:
                script_params["Minimum Severity to Fetch"] = minimum_severity_to_fetch
            if event_types is not None:
                script_params["Event Types"] = event_types
            if event_category is not None:
                script_params["Event Category"] = event_category
            if event_i_ds is not None:
                script_params["Event IDs"] = event_i_ds
            if start_time is not None:
                script_params["Start Time"] = start_time
            if end_time is not None:
                script_params["End Time"] = end_time
            if max_results_to_return is not None:
                script_params["Max Results To Return"] = max_results_to_return
            if time_frame is not None:
                script_params["Time Frame"] = time_frame
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="FortinetFortiSIEM_Execute Simple Query",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "FortinetFortiSIEM_Execute Simple Query",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "FortinetFortiSIEM_Execute Simple Query")
            except Exception as e:
                logger.error("Error executing action FortinetFortiSIEM_Execute Simple Query for FortinetFortiSIEM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for FortinetFortiSIEM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Fortinet Forti SIEM: Enrich Entities',
        annotations=ToolAnnotations(
            title='Fortinet Forti SIEM: Enrich Entities',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def fortinet_forti_siem_enrich_entities(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_organization: Annotated[Optional[str], Field(default=None, description="Specify optional target organization name to look for enrichment information in this organization only.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Enrich entities using information from Fortinet FortiSIEM CMDB. Supported entities: Hostname, IP. Note: Hostname entity should contain the "name" of the device.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="FortinetFortiSIEM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for FortinetFortiSIEM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if target_organization is not None:
                script_params["Target Organization"] = target_organization
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="FortinetFortiSIEM_Enrich Entities",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "FortinetFortiSIEM_Enrich Entities",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "FortinetFortiSIEM_Enrich Entities")
            except Exception as e:
                logger.error("Error executing action FortinetFortiSIEM_Enrich Entities for FortinetFortiSIEM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for FortinetFortiSIEM")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Fortinet Forti SIEM: Execute Custom Query',
        annotations=ToolAnnotations(
            title='Fortinet Forti SIEM: Execute Custom Query',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def fortinet_forti_siem_execute_custom_query(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], query: Annotated[str, Field(..., description="Specify a query that will be used to retrieve information about the events. Example: (relayDevIpAddr = 172.30.202.1 OR 172.30.202.2) AND (reptDevName = HOST1)")], fields_to_return: Annotated[Optional[str], Field(default=None, description="Specify what fields to return. If nothing is provided, action will return all fields.")], sort_field: Annotated[Optional[str], Field(default=None, description="Specify what parameter should be used for sorting.")], sort_order: Annotated[Optional[List[str]], Field(default=None, description="Specify the order of sorting.")], max_results_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many results to return. Default: 50.")], start_time: Annotated[Optional[str], Field(default=None, description="Specify the start time for the results. This parameter is mandatory, if \"Custom\" is selected for the \"Time Frame\" parameter. Format: ISO 8601. Example: 2021-04-23T12:38Z")], end_time: Annotated[Optional[str], Field(default=None, description="Specify the end time for the results. Format: ISO 8601. If nothing is provided and \"Custom\" is selected for the \"Time Frame\" parameter then this parameter will use current time.")], time_frame: Annotated[Optional[List[str]], Field(default=None, description="Specify a time frame for the results. If \"Custom\" is selected, you also need to provide \"Start Time\".")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Execute a custom query in FortiSIEM.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="FortinetFortiSIEM")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for FortinetFortiSIEM: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if fields_to_return is not None:
                script_params["Fields To Return"] = fields_to_return
            if sort_field is not None:
                script_params["Sort Field"] = sort_field
            if sort_order is not None:
                script_params["Sort Order"] = sort_order
            script_params["Query"] = query
            if max_results_to_return is not None:
                script_params["Max Results To Return"] = max_results_to_return
            if start_time is not None:
                script_params["Start Time"] = start_time
            if end_time is not None:
                script_params["End Time"] = end_time
            if time_frame is not None:
                script_params["Time Frame"] = time_frame
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="FortinetFortiSIEM_Execute Custom Query",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "FortinetFortiSIEM_Execute Custom Query",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "FortinetFortiSIEM_Execute Custom Query")
            except Exception as e:
                logger.error("Error executing action FortinetFortiSIEM_Execute Custom Query for FortinetFortiSIEM: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for FortinetFortiSIEM")
            return marketplace_error_result("No active instance found.")
