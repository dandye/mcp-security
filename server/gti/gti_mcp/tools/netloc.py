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
from ..phase5 import (
    GTI_IOC_VERDICT_URI as _GTI_IOC_VERDICT_URI,
    ui_tool_meta as _ui_tool_meta,
)
from ..server import server, vt_client


DOMAIN_RELATIONSHIPS = [
    "associations",
    "caa_records",
    "campaigns",
    "cname_records",
    "collections",
    "comments",
    "communicating_files",
    "downloaded_files",
    "graphs",
    "historical_ssl_certificates",
    "historical_whois",
    "immediate_parent",
    "malware_families",
    "memory_pattern_parents",
    "mx_records",
    "ns_records",
    "parent",
    "referrer_files",
    "related_comments",
    "related_reports",
    "related_threat_actors",
    "reports",
    "resolutions",
    "siblings",
    "soa_records",
    "software_toolkits",
    "subdomains",
    "urls",
    "user_votes",
    "votes",
    "vulnerabilities",
]

DOMAIN_KEY_RELATIONSHIPS = [
    "associations",
]


IP_RELATIONSHIPS = [
    "associations",
    "campaigns",
    "collections",
    "comments",
    "communicating_files",
    "downloaded_files",
    "graphs",
    "historical_ssl_certificates",
    "historical_whois",
    "malware_families",
    "memory_pattern_parents",
    "referrer_files",
    "related_comments",
    "related_reports",
    "related_threat_actors",
    "reports",
    "resolutions",
    "software_toolkits",
    "urls",
    "user_votes",
    "votes",
    "vulnerabilities",
]

IP_KEY_RELATIONSHIPS = [
    "associations",
]


@server.tool(
    title="Get Domain Threat Report",
    annotations=_ToolAnnotations(
        title="Get Domain Threat Report",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
    meta=_ui_tool_meta(_GTI_IOC_VERDICT_URI),
)
async def get_domain_report(domain: str, ctx: Context) -> dict[str, typing.Any]:
  """Get a comprehensive domain analysis report from Google Threat Intelligence.

  Args:
    domain (required): Domain to analyse.
  Returns:
    Report with insights about the domain.
  """
  try:
    async with vt_client(ctx) as client:
      res = await utils.fetch_object(
          client,
          "domains",
          "domain",
          domain,
          relationships=DOMAIN_KEY_RELATIONSHIPS,
          params={"exclude_attributes": "last_analysis_results"})
  except Exception as e:
    logging.exception("Error fetching domain report for %s: %s", domain, e)
    return utils.tool_error_result(f"Failed to fetch domain report: {e}")  # type: ignore[return-value]
  if utils.is_error_dict(res):
    return utils.tool_error_result_from_dict(res)  # type: ignore[return-value]
  return utils.sanitize_response(res)


@server.tool(
    title="Get Entities Related to Domain",
    annotations=_ToolAnnotations(
        title="Get Entities Related to Domain",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
async def get_entities_related_to_a_domain(
    domain: str, relationship_name: str, descriptors_only: bool, ctx: Context, limit: int = 10
) -> list[dict[str, typing.Any]]:
  """Retrieve entities related to the the given domain.

    The following table shows a summary of available relationships for domain objects.

    | Relationship                | Description                                                | Return type  |
    | --------------------------- | ---------------------------------------------------------- | ------------ |
    | associations                | Domain's associated objects (reports, campaigns, IoC collections, malware families, software toolkits, vulnerabilities, threat-actors), without filtering by the associated object type.                                                             | Everyone. | List of [reports](ref:report-object), [campaigns](ref:campaign-object), [IoC collections](ref:ioc-collection-object), [malware families](ref:malware-family-object), [software toolkits](ref:software-toolkit-object), [vulnerabilities](ref:vulnerability-object), [threat-actors](ref:threat-actor-object) objecs.| collection |
    | caa_records                 | Records CAA for the domain.                                | domain       |
    | campaigns                   | Campaigns associated to the domain.                        | collection   |
    | cname_records               | Records CNAME for the domain.                              | domain       |
    | collections                 | IoC Collections associated to the domain.                  | collection   |
    | comments                    | Community posted comments about the domain.                | comment      |
    | communicating_files         | Files that communicate with the domain.                    | file         |
    | downloaded_files            | Files downloaded from that domain.                         | file         |
    | graphs                      | Graphs including the domain.                               | graph        |
    | historical_ssl_certificates | SSL certificates associated with the domain.               | ssl-cert     |
    | historical_whois            | WHOIS information for the domain.                          | whois        |
    | immediate_parent            | Domain's immediate parent.                                 | domain       |
    | malware_families            | Malware families associated to the domain.                 | collection   |
    | memory_pattern_parents      | Files having a domain as string on memory during sandbox execution. | file |
    | mx_records                  | Records MX for the domain.                                 | domain       |
    | ns_records                  | Records NS for the domain.                                 | domain       |
    | parent                      | Domain's top parent.                                       | domain       |
    | referrer_files              | Files containing the domain.                               | file         |
    | related_comments            | Community posted comments in the domain's related objects. | comment      |
    | related_reports             | Reports that are directly and indirectly related to the domain. | collection |
    | related_threat_actors       | Threat actors related to the domain.                       | collection   |
    | reports                     | Reports directly associated to the domain.                 | collection   |
    | resolutions                 | DNS resolutions for the domain.                            | resolution   |
    | siblings                    | Domain's sibling domains.                                  | domain       |
    | soa_records                 | Records SOA for the domain.                                | domain       |
    | software_toolkits           | Software and Toolkits associated to the domain.            | collection   |
    | subdomains                  | Domain's subdomains.                                       | domain       |
    | urls                        | URLs having this domain.                                   | url          |
    | user_votes                  | Current user's votes.                                      | vote         |
    | votes                       | Domain's votes.                                            | vote         |
    | vulnerabilities             | Vulnerabilities associated to the domain.                  | collection   |

    Args:
      domain (required): Domain to analyse.
      relationship_name (required): Relationship name.
      descriptors_only (required): Bool. Must be True when the target object type is one of file, domain, url, ip_address or collection.
      limit: Limit the number of entities to retrieve. 10 by default.
    Returns:
      List of entities related to the domain.
  """
  if relationship_name not in DOMAIN_RELATIONSHIPS:
    return utils.tool_error_result(  # type: ignore[return-value]
        f"Relationship {relationship_name} does not exist. "
        f"Available relationships are: {','.join(DOMAIN_RELATIONSHIPS)}"
    )

  try:
    async with vt_client(ctx) as client:
      res = await utils.fetch_object_relationships(
          client,
          "domains",
          domain,
          relationships=[relationship_name],
          descriptors_only=descriptors_only,
          limit=limit)
  except Exception as e:
    logging.exception("Error fetching relationships for domain %s: %s", domain, e)
    return utils.tool_error_result(f"Failed to fetch domain relationships: {e}")  # type: ignore[return-value]
  return utils.sanitize_response(res.get(relationship_name, []))


@server.tool(
    title="Get IP Address Threat Report",
    annotations=_ToolAnnotations(
        title="Get IP Address Threat Report",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
    meta=_ui_tool_meta(_GTI_IOC_VERDICT_URI),
)
async def get_ip_address_report(ip_address: str, ctx: Context) -> dict[str, typing.Any]:
  """Get a comprehensive IP Address analysis report from Google Threat Intelligence.

  Args:
    ip_address (required): IP Address to analyze. It can be IPv4 or IPv6.
  Returns:
    Report with insights about the IP address.
  """
  try:
    async with vt_client(ctx) as client:
      res = await utils.fetch_object(
          client,
          "ip_addresses",
          "ip",
          ip_address,
          relationships=IP_KEY_RELATIONSHIPS,
          params={"exclude_attributes": "last_analysis_results"})
  except Exception as e:
    logging.exception("Error fetching IP address report for %s: %s", ip_address, e)
    return utils.tool_error_result(f"Failed to fetch IP address report: {e}")  # type: ignore[return-value]
  if utils.is_error_dict(res):
    return utils.tool_error_result_from_dict(res)  # type: ignore[return-value]
  return utils.sanitize_response(res)


@server.tool(
    title="Get Entities Related to IP Address",
    annotations=_ToolAnnotations(
        title="Get Entities Related to IP Address",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
async def get_entities_related_to_an_ip_address(
    ip_address: str, relationship_name: str, descriptors_only: bool, ctx: Context, limit: int = 10
) -> list[dict[str, typing.Any]]:
  """Retrieve entities related to the the given IP Address.

    The following table shows a summary of available relationships for IP Address objects.

    | Relationship                | Description                                            | Return type  |
    | --------------------------- | ------------------------------------------------------ | ------------ |
    | associations                | IP's associated objects (reports, campaigns, IoC collections, malware families, software toolkits, vulnerabilities, threat-actors), without filtering by the associated object type. | collection |
    | campaigns                   | Campaigns associated to the IP address.                | collection   |
    | collections                 | IoC Collections associated to the IP address.          | collection   |
    | comments                    | Comments for the IP address.                           | comment      |
    | communicating_files         | Files that communicate with the IP address.            | file         |
    | downloaded_files            | Files downloaded from the IP address.                  | file         |
    | graphs                      | Graphs including the IP address.                       | graph        |
    | historical_ssl_certificates | SSL certificates associated with the IP.               | ssl-cert     |
    | historical_whois            | WHOIS information for the IP address.                  | whois        |
    | malware_families            | Malware families associated to the IP address.         | collection   |
    | memory_pattern_parents      | Files having an IP as string on memory during sandbox execution. | file |
    | referrer_files              | Files containing the IP address.                       | file         |
    | related_comments            | Community posted comments in the IP's related objects. | comment      |
    | related_reports             | Reports that are directly and indirectly related to the IP. | collection |
    | related_threat_actors       | Threat actors related to the IP address.               | collection   |
    | reports                     | Reports directly associated to the IP.                 | collection   |
    | resolutions                 | IP address' resolutions                                | resolution   |
    | software_toolkits           | Software and Toolkits associated to the IP address.    | collection   |
    | urls                        | URLs related to the IP address.                        | url          |
    | user_votes                  | IP's votes made by current signed-in user.             | vote         |
    | votes                       | IP's votes.                                            | vote         |
    | vulnerabilities             | Vulnerabilities associated to the IP address.          | collection   |

    Args:
      ip_address (required): IP Addres to analyse.
      relationship_name (required): Relationship name.
      descriptors_only (required): Bool. Must be True when the target object type is one of file, domain, url, ip_address or collection.
      limit: Limit the number of entities to retrieve. 10 by default.
    Returns:
      List of entities related to the IP Address.
  """
  if relationship_name not in IP_RELATIONSHIPS:
    return utils.tool_error_result(  # type: ignore[return-value]
        f"Relationship {relationship_name} does not exist. "
        f"Available relationships are: {','.join(IP_RELATIONSHIPS)}"
    )

  try:
    async with vt_client(ctx) as client:
      res = await utils.fetch_object_relationships(
          client,
          "ip_addresses",
          ip_address,
          relationships=[relationship_name],
          descriptors_only=descriptors_only,
          limit=limit)
  except Exception as e:
    logging.exception("Error fetching relationships for IP %s: %s", ip_address, e)
    return utils.tool_error_result(f"Failed to fetch IP relationships: {e}")  # type: ignore[return-value]
  return utils.sanitize_response(res.get(relationship_name, []))
