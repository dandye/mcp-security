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
import logging
import typing

from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations as _ToolAnnotations

from .. import utils
from ..server import server, vt_client


HUNTING_RULESET_RELATIONSHIPS = [
    "hunting_notification_files",
]


@server.tool(
    title="Search Indicators of Compromise",
    annotations=_ToolAnnotations(
        title="Search Indicators of Compromise",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
async def search_iocs(query: str, ctx: Context, limit: int = 10, order_by: str = "last_submission_date-") -> list[dict[str, typing.Any]]:
  """Search Indicators of Compromise (IOC) in the Google Threat Intelligence platform.

  You can search by for different IOC types using the `entity` modifier. Below, the different IOC types and the supported orders:

    | Entity type   | Supported orders | Default order |
    | ------------- | ---------------- | ------------- |
    | file          | first_submission_date, last_submission_date, positives, times_submitted, size	    | last_submission_date- |
    | url           | first_submission_date, last_submission_date, positives, times_submitted, status   | last_submission_date- |
    | domain        | creation_date, last_modification_date, last_update_date, positives                | last_modification_date- |
    | ip            | ip, last_modification_date, positives                                             | last_modification_date- |

  Note: The `entity` modifier can only be used ONCE per query.

  You can find all available modifers at:
    - Files: https://gtidocs.virustotal.com/docs/file-search-modifiers
    - URLs: https://gtidocs.virustotal.com/docs/url-search-modifiers
    - Domains: https://gtidocs.virustotal.com/docs/domain-search-modifiers
    - IP Addresses: https://gtidocs.virustotal.com/docs/ip-address-search-modifiers

  With integer modifers, use the `-` and `+` characters to indicate:
    - Greater than: `p:60+`
    - Less than: `p:60-`
    - Equal to: `p:60`

  Args
    query (required): Search query to find IOCs.
    limit: Limit the number of IoCs to retrieve. 10 by default.
    order_by: Order the results. "last_submission_date-" by default.

  Returns:
    List of Indicators of Compromise (IoCs).
  """
  try:
    async with vt_client(ctx) as client:
      res = await utils.consume_vt_iterator(
          client,
          "/intelligence/search",
          params={
              "query": query,
              "order": order_by},
          limit=limit)
  except Exception as e:
    logging.exception("Error searching IOCs: %s", e)
    return utils.tool_error_result(f"Failed to search IOCs: {e}")  # type: ignore[return-value]
  return utils.sanitize_response([o.to_dict() for o in res])


@server.tool(
    title="Get Threat Hunting Ruleset",
    annotations=_ToolAnnotations(
        title="Get Threat Hunting Ruleset",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
async def get_hunting_ruleset(ruleset_id: str, ctx: Context) -> dict[str, typing.Any]:
  """Get a Hunting Ruleset object from Google Threat Intelligence.

  A Hunting Ruleset object describes a user's hunting ruleset. It may contain multiple
  Yara rules. 

  The content of the Yara rules is in the `rules` attribute.

  Some important object attributes:
    - creation_date: creation date as UTC timestamp.
    - modification_date (int): last modification date as UTC timestamp.
    - name (str): ruleset name.
    - rule_names (list[str]): contains the names of all rules in the ruleset.
    - number_of_rules (int): number of rules in the ruleset.
    - rules (str): rule file contents.
    - tags (list[str]): ruleset's custom tags.
    
  Args:
    ruleset_id (required): Hunting ruleset identifier.

  Returns:
    Hunting Ruleset object.
  """
  async with vt_client(ctx) as client:
    res = await utils.fetch_object(
        client,
        "intelligence/hunting_rulesets",
        "hunting_ruleset",
        ruleset_id,
    )
  if utils.is_error_dict(res):
    return utils.tool_error_result_from_dict(res)  # type: ignore[return-value]
  return utils.sanitize_response(res)


@server.tool(
    title="Get Entities Related to Hunting Ruleset",
    annotations=_ToolAnnotations(
        title="Get Entities Related to Hunting Ruleset",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
async def get_entities_related_to_a_hunting_ruleset(
    ruleset_id: str, relationship_name: str, ctx: Context, limit: int = 10
) -> list[dict[str, typing.Any]]:
  """Retrieve entities related to the the given Hunting Ruleset.

    The following table shows a summary of available relationships for Hunting ruleset objects.

    | Relationship         | Return object type                                |
    | :------------------- | :------------------------------------------------ |
    | hunting_notification_files | Files that matched with the ruleset filters |

    Args:
      ruleset_id (required): Hunting ruleset identifier.
      relationship_name (required): Relationship name.
      limit: Limit the number of entities to retrieve. 10 by default.
    Returns:
      List of objects related to the Hunting ruleset.
  """
  if relationship_name not in HUNTING_RULESET_RELATIONSHIPS:
    return utils.tool_error_result(  # type: ignore[return-value]
        f"Relationship {relationship_name} does not exist. "
        f"Available relationships are: {','.join(HUNTING_RULESET_RELATIONSHIPS)}"
    )

  try:
    async with vt_client(ctx) as client:
      res = await utils.fetch_object_relationships(
          client,
          "intelligence/hunting_rulesets",
          ruleset_id,
          [relationship_name],
          limit=limit)
  except Exception as e:
    logging.exception("Error fetching relationships for hunting ruleset %s: %s", ruleset_id, e)
    return utils.tool_error_result(f"Failed to fetch hunting ruleset relationships: {e}")  # type: ignore[return-value]
  return utils.sanitize_response(res.get(relationship_name, []))

