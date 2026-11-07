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
    # This function registers all tools (actions) for the ConnectWise integration.

    @mcp.tool(
        title='Connect Wise: Create Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Create Ticket',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def connect_wise_create_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], company: Annotated[str, Field(..., description="Company identifier")], board: Annotated[str, Field(..., description="Board name")], summary: Annotated[str, Field(..., description="Specify the summary for the new ticket. Note: if the summary is more than 100 characters, it will be truncated.")], status: Annotated[str, Field(..., description="e.g. Unassigned")], priority: Annotated[str, Field(..., description="e.g. Priority 3 - Normal Response")], owner_name: Annotated[Optional[str], Field(default=None, description="ConnectWise member name to assign this ticket to, e.g. connectwise_user_1.")], email_note_cc: Annotated[Optional[str], Field(default=None, description="Specify a comma-separated list of email addresses that should receive all of the notes via email.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Create a ConnectWise ticket

Action Parameters: Company: Company name., Board: Board name, Summary: , Status: e.g. Unassigned., Priority: Example: Priority 3 - Normal Response, Owner Name: ConnectWise member name to assign this ticket to. Example: connectwise_user_1

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Company"] = company
            if owner_name is not None:
                script_params["Owner Name"] = owner_name
            script_params["Board"] = board
            script_params["Summary"] = summary
            script_params["Status"] = status
            script_params["Priority"] = priority
            if email_note_cc is not None:
                script_params["Email Note CC"] = email_note_cc
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Create Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Create Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Create Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Create Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Add Comment to Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Add Comment to Ticket',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def connect_wise_add_comment_to_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ticket_id: Annotated[str, Field(..., description="ConnectWise ticket id. e.g. 608718")], comment: Annotated[str, Field(..., description="Comment content to attach to a ticket")], internal: Annotated[Optional[bool], Field(default=None, description="If checked, put comment in internal section")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Add new comment to a ticket in ConnectWise

Action Parameters: Ticket ID: ConnectWise ticket ID.Example: 608718, Comment: Comment content to attach to a ticket., Internal: If checked, puts comment in the internal section.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Ticket Id"] = ticket_id
            script_params["Comment"] = comment
            if internal is not None:
                script_params["Internal"] = internal
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Add Comment To Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Add Comment To Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Add Comment To Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Add Comment To Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Get Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Get Ticket',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def connect_wise_get_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ticket_id: Annotated[str, Field(..., description="Fetch ticket by ID")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Get ConnectWise ticket by ID and attach ticket JSON as a file

Action Parameters: Ticket ID: Fetch a ticket by ID.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Ticket Id"] = ticket_id
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Get Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Get Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Get Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Get Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Create Alerts Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Create Alerts Ticket',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def connect_wise_create_alerts_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], company: Annotated[str, Field(..., description="Company identifier")], board: Annotated[str, Field(..., description="Board name")], status: Annotated[str, Field(..., description="e.g. Unassigned")], priority: Annotated[str, Field(..., description="e.g. Priority 3 - Normal Response")], initial_description: Annotated[str, Field(..., description="")], owner_name: Annotated[Optional[str], Field(default=None, description="ConnectWise member name to assign this ticket to, e.g. connectwise_user_1.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Create a ConnectWise ticket for each new Siemplify alert

Action Parameters: Company: Company name., Board: Board name., Status: Example: Unassigned, Priority: Example: Priority 3 - Normal Response, Initial Description: , Owner Name: ConnectWise member name to assign this ticket to.Example: connectwise_user_1.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Company"] = company
            if owner_name is not None:
                script_params["Owner Name"] = owner_name
            script_params["Board"] = board
            script_params["Status"] = status
            script_params["Priority"] = priority
            script_params["Initial Description"] = initial_description
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Create Alerts Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Create Alerts Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Create Alerts Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Create Alerts Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Ping',
        annotations=ToolAnnotations(
            title='Connect Wise: Ping',
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def connect_wise_ping(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
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
                actionName="ConnectWise_Ping",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Ping",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Ping")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Ping for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Close Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Close Ticket',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def connect_wise_close_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ticket_id: Annotated[str, Field(..., description="ConnectWise ticket id. e.g. 608718")], custom_close_status: Annotated[Optional[str], Field(default=None, description="If the specific system use a custom closed status (e.g. Completed)")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Close ConnectWise ticket

Action Parameters: Ticket ID: ConnectWise ticket ID. Example: 608718., Custom Close Status: If the specific system uses a custom closed status, for example Completed.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Ticket Id"] = ticket_id
            if custom_close_status is not None:
                script_params["Custom Close Status"] = custom_close_status
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Close Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Close Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Close Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Close Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Add Attachment to Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Add Attachment to Ticket',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def connect_wise_add_attachment_to_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], filename: Annotated[str, Field(..., description="Specify the filename behind the attachment. This value will be also used as a title. Note: action needs to provide the correct extension for the file.")], base64_encoded_file: Annotated[str, Field(..., description="Specify the base64 encoded file that needs to be added as an attachment.")], ticket_id: Annotated[str, Field(..., description="Specify the ID of the ticket to which the document would need to be added.")], allow_only_owner_update: Annotated[Optional[bool], Field(default=None, description="If enabled, action will only allow the owner to update the attachment.")], display_in_customer_portal: Annotated[Optional[bool], Field(default=None, description="If enabled, attachment will be shown in the customer portal.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """Add an attachment to the ticket in ConnectWise.

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            if allow_only_owner_update is not None:
                script_params["Allow Only Owner Update"] = allow_only_owner_update
            if display_in_customer_portal is not None:
                script_params["Display In Customer Portal"] = display_in_customer_portal
            script_params["Filename"] = filename
            script_params["Base64 Encoded File"] = base64_encoded_file
            script_params["Ticket ID"] = ticket_id
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Add Attachment To Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Add Attachment To Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Add Attachment To Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Add Attachment To Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Update Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Update Ticket',
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def connect_wise_update_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ticket_id: Annotated[str, Field(..., description="Ticket ID to be updated. e.g. 609620")], summary: Annotated[Optional[str], Field(default=None, description="Specify the summary for the updated ticket. Note: if the summary is more than 100 characters, it will be truncated.")], type_name: Annotated[Optional[str], Field(default=None, description="e.g. Application")], sub_type_name: Annotated[Optional[str], Field(default=None, description="e.g. Adobe")], item_name: Annotated[Optional[str], Field(default=None, description="e.g. Development")], owner_name: Annotated[Optional[str], Field(default=None, description="ConnectWise member name to assign this ticket to, e.g. connectwise_user_1.")], board: Annotated[Optional[str], Field(default=None, description="Board name.")], priority: Annotated[Optional[str], Field(default=None, description="e.g. Priority 3 - Normal Response.")], status: Annotated[Optional[str], Field(default=None, description="New ticket status, e.g. In Progress (plan of action)")], email_note_cc: Annotated[Optional[str], Field(default=None, description="Specify a comma-separated list of email addresses that should receive all of the notes via email.")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Update ticket details in ConnectWIse

Action Parameters: Parameter: Description, Ticket ID: The ID of the ticket to be updated. Example: 609620, Summary: Updated summary., Type Name: Example: Application, SubType Name: Example: Adobe, Item Name: Example: Development, Status: New ticket status. Example: In Progress (plan of action)

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Ticket Id"] = ticket_id
            if summary is not None:
                script_params["Summary"] = summary
            if type_name is not None:
                script_params["Type Name"] = type_name
            if sub_type_name is not None:
                script_params["SubType Name"] = sub_type_name
            if item_name is not None:
                script_params["Item Name"] = item_name
            if owner_name is not None:
                script_params["Owner Name"] = owner_name
            if board is not None:
                script_params["Board"] = board
            if priority is not None:
                script_params["Priority"] = priority
            if status is not None:
                script_params["Status"] = status
            if email_note_cc is not None:
                script_params["Email Note CC"] = email_note_cc
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Update Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Update Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Update Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Update Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")

    @mcp.tool(
        title='Connect Wise: Delete Ticket',
        annotations=ToolAnnotations(
            title='Connect Wise: Delete Ticket',
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    async def connect_wise_delete_ticket(case_id: Annotated[str, Field(..., description="The ID of the case.")], alert_group_identifiers: Annotated[List[str], Field(..., description="Identifiers for the alert groups.")], ticket_id: Annotated[str, Field(..., description="Ticket ID to be deleted. e.g. 607167")], target_entities: Annotated[List[TargetEntity], PydanticListField(TargetEntity, description="Optional list of specific target entities (Identifier, EntityType) to run the action on.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope for the action.")]) -> dict[str, Any]:
        """
Delete ConnectWise ticket by ID

Action Parameters: Ticket ID: The ID of the ticket to be deleted. Example: 607167

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
                Endpoints.LIST_INTEGRATION_INSTANCES.format(INTEGRATION_NAME="ConnectWise")
            )
            if not isinstance(instance_response, dict):
                return marketplace_error_result(
                    "Failed to fetch integration instances from SOAR API."
                )
            instances = instance_response.get("integration_instances", [])
        except Exception as e:
            logger.error("Error fetching instance for ConnectWise: %s", e)
            return marketplace_error_result(f"Error fetching instance: {e}")
    
        if instances:
            instance_identifier = instances[0].get("identifier")
            if not instance_identifier:
                return marketplace_error_result("Instance found but identifier is missing.")
    
            script_params = {}
            script_params["Ticket Id"] = ticket_id
    
            # Prepare data model for the API request
            action_data = ApiManualActionDataModel(
                alertGroupIdentifiers=alert_group_identifiers,
                caseId=case_id,
                targetEntities=final_target_entities,
                scope=final_scope,
                isPredefinedScope=is_predefined_scope,
                actionProvider="Scripts",
                actionName="ConnectWise_Delete Ticket",
                properties={
                    "IntegrationInstance": instance_identifier,
                    "ScriptName": "ConnectWise_Delete Ticket",
                    "ScriptParametersEntityFields": json.dumps(script_params)
                }
            )
    
            try:
                execution_response = await bindings.http_client.post(
                    Endpoints.EXECUTE_MANUAL_ACTION,
                    req=action_data.model_dump()
                )
                return normalize_marketplace_response(execution_response, "ConnectWise_Delete Ticket")
            except Exception as e:
                logger.error("Error executing action ConnectWise_Delete Ticket for ConnectWise: %s", e)
                return marketplace_error_result(f"Error executing action: {e}")
        else:
            logger.warning("Warning: No active integration instance found for ConnectWise")
            return marketplace_error_result("No active instance found.")
