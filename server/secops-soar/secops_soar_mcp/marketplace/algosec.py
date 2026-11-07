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
    # This function registers all tools (actions) for the AlgoSec integration.

    @mcp.tool(
        title='Algo Sec: List Templates',
        annotations=ToolAnnotations(
            title='Algo Sec: List Templates',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def algo_sec_list_templates(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], filter_logic: Annotated[Optional[List[str]], Field(default=None, description="Specify what filter logic should be applied.")], filter_value: Annotated[Optional[str], Field(default=None, description="Specify what value should be used in the filter. If \"Equal\" is selected, action will try to find the exact match among record types and if \"Contains\" is selected, action will try to find items that contain that substring. If nothing is provided in this parameter, the filter will not be applied.")], max_templates_to_return: Annotated[Optional[str], Field(default=None, description="Specify how many templates to return. Default: 50.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """List available templates in AlgoSec.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="AlgoSec")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for AlgoSec: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if filter_logic is not None:
                script_params["Filter Logic"] = filter_logic
            if filter_value is not None:
                script_params["Filter Value"] = filter_value
            if max_templates_to_return is not None:
                script_params["Max Templates To Return"] = max_templates_to_return
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="AlgoSec_List Templates",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "AlgoSec_List Templates",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "AlgoSec_List Templates")
            except Exception as e:
                logger.error("Error executing action AlgoSec_List Templates for AlgoSec: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for AlgoSec")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Algo Sec: Wait for Change Request Status Update',
        annotations=ToolAnnotations(
            title='Algo Sec: Wait for Change Request Status Update',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def algo_sec_wait_for_change_request_status_update(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], request_id: Annotated[str, Field(..., description="Specify the id of the request for which action needs to check the status.")], status: Annotated[str, Field(..., description="Specify a comma-separated list of change request statuses for which action should wait. Possible values: resolved, reconcile, open, check, implementation plan, implement, validate.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Wait for change request status update in AlgoSec. Note: Action is running as async, please adjust script timeout value in Siemplify IDE for action as needed. Only traffic change requests are supported.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="AlgoSec")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for AlgoSec: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Request ID"] = request_id
            script_params["Status"] = status
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="AlgoSec_Wait for Change Request Status Update",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "AlgoSec_Wait for Change Request Status Update",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "AlgoSec_Wait for Change Request Status Update")
            except Exception as e:
                logger.error("Error executing action AlgoSec_Wait for Change Request Status Update for AlgoSec: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for AlgoSec")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Algo Sec: Ping',
        annotations=ToolAnnotations(
            title='Algo Sec: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def algo_sec_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Test connectivity to the AlgoSec with parameters provided at the integration configuration page on the Marketplace tab.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="AlgoSec")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for AlgoSec: %s", e)
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
                actionName="AlgoSec_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "AlgoSec_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "AlgoSec_Ping")
            except Exception as e:
                logger.error("Error executing action AlgoSec_Ping for AlgoSec: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for AlgoSec")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Algo Sec: Allow IP',
        annotations=ToolAnnotations(
            title='Algo Sec: Allow IP',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def algo_sec_allow_ip(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], template: Annotated[str, Field(..., description="Specify the template for the change request.")], source: Annotated[str, Field(..., description="Specify a comma-separated list of sources for the allow rule. It can be an IP address, IP Set or special keyword like (all).")], service: Annotated[str, Field(..., description="Specify a comma-separated list of services that needs to be allowed. Values can have a look of {TCP/UDP}/{port} (tcp/80) or special reserved keyword (all).")], subject: Annotated[Optional[str], Field(default=None, description="Specify the subject for the change request. If nothing is provided action will put \"Siemplify Allow IP request\" in the subject.")], owner: Annotated[Optional[str], Field(default=None, description="Specify who should be the owner of the change request. If nothing is provided, the user that created the ticket will be the owner.")], due_date: Annotated[Optional[str], Field(default=None, description="Specify the due date for the change request. Format: ISO 8601. Example: 2021-08-13T08:16:10Z.")], expiration_date: Annotated[Optional[str], Field(default=None, description="Specify the expiration date for the change request. Format: ISO 8601. Example: 2021-08-13T08:16:10Z.")], custom_fields: Annotated[Optional[str], Field(default=None, description="Specify a JSON object containing information about all of the fields that need to be added to the change request. Note: this parameter has a priority over other fields")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Allow IPs in AlgoSec. Supported entities: IP address. Note: IP address entities are treated as destinations in the change request. This action creates a traffic change request to allow traffic to IP entities.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="AlgoSec")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for AlgoSec: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Template"] = template
            script_params["Source"] = source
            script_params["Service"] = service
            if subject is not None:
                script_params["Subject"] = subject
            if owner is not None:
                script_params["Owner"] = owner
            if due_date is not None:
                script_params["Due Date"] = due_date
            if expiration_date is not None:
                script_params["Expiration Date"] = expiration_date
            if custom_fields is not None:
                script_params["Custom Fields"] = custom_fields
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="AlgoSec_Allow IP",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "AlgoSec_Allow IP",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "AlgoSec_Allow IP")
            except Exception as e:
                logger.error("Error executing action AlgoSec_Allow IP for AlgoSec: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for AlgoSec")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Algo Sec: Block IP',
        annotations=ToolAnnotations(
            title='Algo Sec: Block IP',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def algo_sec_block_ip(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], template: Annotated[str, Field(..., description="Specify the template for the change request.")], source: Annotated[str, Field(..., description="Specify a comma-separated list of sources for the block rule. It can be an IP address, IP Set or special keyword like (all).")], service: Annotated[str, Field(..., description="Specify a comma-separated list of services that needs to be blocked. Values can have a look of {TCP/UDP}/{port} (tcp/80) or special reserved keyword (all).")], subject: Annotated[Optional[str], Field(default=None, description="Specify the subject for the change request. If nothing is provided action will put \u201cSiemplify Block IP request\u201d in the subject.")], owner: Annotated[Optional[str], Field(default=None, description="Specify who should be the owner of the change request. If nothing is provided, the user that created the ticket will be the owner.")], due_date: Annotated[Optional[str], Field(default=None, description="Specify the due date for the change request. Format: ISO 8601. Example: 2021-08-13T08:16:10Z.")], expiration_date: Annotated[Optional[str], Field(default=None, description="Specify the expiration date for the change request. Format: ISO 8601. Example: 2021-08-13T08:16:10Z.")], custom_fields: Annotated[Optional[str], Field(default=None, description="Specify a JSON object containing information about all of the fields that need to be added to the change request. Note: this parameter has a priority over other fields")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Block IPs in AlgoSec. Supported entities: IP address. Note: IP address entities are treated as destinations in the change request. This action creates a traffic change request to block traffic to IP entities.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="AlgoSec")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for AlgoSec: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Template"] = template
            script_params["Source"] = source
            script_params["Service"] = service
            if subject is not None:
                script_params["Subject"] = subject
            if owner is not None:
                script_params["Owner"] = owner
            if due_date is not None:
                script_params["Due Date"] = due_date
            if expiration_date is not None:
                script_params["Expiration Date"] = expiration_date
            if custom_fields is not None:
                script_params["Custom Fields"] = custom_fields
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="AlgoSec_Block IP",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "AlgoSec_Block IP",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "AlgoSec_Block IP")
            except Exception as e:
                logger.error("Error executing action AlgoSec_Block IP for AlgoSec: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for AlgoSec")
            return marketplace_error_result("No active instance found.")
