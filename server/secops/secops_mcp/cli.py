# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
CLI interface for SecOps tools using Typer.
This provides a unified command-line interface for all the deduplicated logic functions.
"""

import json
import logging
from typing import List, Optional

import typer
from typing_extensions import Annotated

from secops_mcp.tools.alerts_logic import (
    do_update_security_alert_impl,
    get_security_alert_by_id_impl,
    get_security_alerts_impl,
)
from secops_mcp.tools.data_table_logic import (
    add_rows_to_data_table_impl,
    create_data_table_impl,
    delete_data_table_rows_impl,
    list_data_table_rows_impl,
)
from secops_mcp.tools.entity_logic import lookup_entity_impl
from secops_mcp.tools.feed_logic import (
    create_feed_impl,
    delete_feed_impl,
    disable_feed_impl,
    enable_feed_impl,
    generate_feed_secret_impl,
    get_feed_impl,
    list_feeds_impl,
    update_feed_impl,
)
from secops_mcp.tools.ioc_logic import get_ioc_matches_impl
from secops_mcp.tools.log_ingestion_logic import (
    get_available_log_types_impl,
    ingest_raw_log_impl,
    ingest_udm_events_impl,
)
from secops_mcp.tools.parser_logic import (
    activate_parser_impl,
    create_parser_impl,
    deactivate_parser_impl,
    get_parser_impl,
    run_parser_against_sample_logs_impl,
)
from secops_mcp.tools.reference_list_logic import (
    create_reference_list_impl,
    get_reference_list_impl,
    update_reference_list_impl,
)
from secops_mcp.tools.rules_logic import (
    create_rule_impl,
    get_detection_rule_impl,
    get_rule_detections_impl,
    list_rule_errors_impl,
    list_rules_impl,
    search_security_rules_impl,
    test_rule_impl,
    validate_rule_impl,
)
from secops_mcp.tools.search_logic import search_udm_impl
from secops_mcp.tools.security_events_logic import search_security_events_impl
from secops_mcp.tools.threat_intel_logic import get_threat_intel_impl
from secops_mcp.tools.udm_search_logic import (
    export_udm_search_csv_impl,
    find_udm_field_values_impl,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secops-cli")

app = typer.Typer(help="Google SecOps CLI")

# Sub-applications for grouping commands
rules_app = typer.Typer(help="Manage security detection rules")
alerts_app = typer.Typer(help="Manage and retrieve security alerts")
events_app = typer.Typer(help="Search and investigate security events")
entities_app = typer.Typer(help="Entity enrichment and lookup")
ioc_app = typer.Typer(help="IoC matching and intelligence")
intel_app = typer.Typer(help="Threat intelligence queries")
ingest_app = typer.Typer(help="Ingest logs and UDM events")
parser_app = typer.Typer(help="Manage log parsers")
tables_app = typer.Typer(help="Manage data tables")
lists_app = typer.Typer(help="Manage reference lists")
feeds_app = typer.Typer(help="Manage data feeds")

app.add_typer(rules_app, name="rules")
app.add_typer(alerts_app, name="alerts")
app.add_typer(events_app, name="events")
app.add_typer(entities_app, name="entities")
app.add_typer(ioc_app, name="ioc")
app.add_typer(intel_app, name="intel")
app.add_typer(ingest_app, name="ingest")
app.add_typer(parser_app, name="parsers")
app.add_typer(tables_app, name="tables")
app.add_typer(lists_app, name="lists")
app.add_typer(feeds_app, name="feeds")


# --- Rules Commands ---

@rules_app.command("list")
def list_rules(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    page_size: int = 100,
    page_token: Optional[str] = None,
):
    """List security detection rules."""
    result = list_rules_impl(project_id, customer_id, region, page_size, page_token)
    typer.echo(json.dumps(result, indent=2))

@rules_app.command("search")
def search_rules(
    query: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Search security detection rules using regex."""
    result = search_security_rules_impl(query, project_id, customer_id, region)
    typer.echo(json.dumps(result, indent=2))

@rules_app.command("get")
def get_rule(
    rule_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Get details of a detection rule."""
    result = get_detection_rule_impl(rule_id, project_id, customer_id, region)
    typer.echo(json.dumps(result, indent=2))

@rules_app.command("create")
def create_rule(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Create a new detection rule."""
    result = create_rule_impl(rule_text, project_id, customer_id, region)
    typer.echo(result)

@rules_app.command("test")
def test_rule(
    rule_text: str,
    hours_back: int = 168,
    max_results: int = 100,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Test a detection rule against historical data."""
    result = test_rule_impl(rule_text, project_id, customer_id, region, hours_back, max_results)
    typer.echo(result)

@rules_app.command("validate")
def validate_rule(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Validate detection rule syntax."""
    result = validate_rule_impl(rule_text, project_id, customer_id, region)
    typer.echo(result)

# --- Alerts Commands ---

@alerts_app.command("list")
def list_alerts(
    hours_back: int = 24,
    max_alerts: int = 10,
    status_filter: str = 'feedback_summary.status != "CLOSED"',
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Get security alerts."""
    result = get_security_alerts_impl(project_id, customer_id, hours_back, max_alerts, status_filter, region)
    typer.echo(result)

@alerts_app.command("get")
def get_alert(
    alert_id: str,
    include_detections: bool = True,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Get security alert by ID."""
    result = get_security_alert_by_id_impl(project_id, customer_id, region, alert_id, include_detections)
    typer.echo(result)

# --- Events Commands ---

@events_app.command("search-nl")
def search_events_nl(
    text: str,
    hours_back: int = 24,
    max_events: int = 100,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Search security events using natural language."""
    result = search_security_events_impl(text, project_id, customer_id, hours_back, max_events=max_events, region=region)
    typer.echo(json.dumps(result, indent=2))

@events_app.command("search-udm")
def search_events_udm(
    query: str,
    hours_back: int = 24,
    max_events: int = 100,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Search events using raw UDM query."""
    result = search_udm_impl(query, hours_back, max_events=max_events, project_id=project_id, customer_id=customer_id, region=region)
    typer.echo(json.dumps(result, indent=2))

# --- Entities Commands ---

@entities_app.command("lookup")
def lookup_entity(
    value: str,
    hours_back: int = 24,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Lookup an entity (IP, domain, user, etc.)."""
    result = lookup_entity_impl(value, project_id, customer_id, hours_back, region)
    typer.echo(result)

# --- IoC Commands ---

@ioc_app.command("matches")
def get_matches(
    hours_back: int = 24,
    max_matches: int = 20,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Get IoC matches."""
    result = get_ioc_matches_impl(project_id, customer_id, hours_back, max_matches, region)
    typer.echo(result)

# --- Threat Intel Commands ---

@intel_app.command("ask")
def ask_intel(
    query: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Ask Gemini for threat intelligence."""
    result = get_threat_intel_impl(query, project_id, customer_id, region)
    typer.echo(result)

# --- Ingestion Commands ---

@ingest_app.command("log")
def ingest_log(
    log_type: str,
    log_message: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """Ingest a raw log."""
    result = ingest_raw_log_impl(log_type, log_message, project_id, customer_id, region)
    typer.echo(result)

@ingest_app.command("types")
def list_log_types(
    search_term: Optional[str] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
):
    """List available log types."""
    result = get_available_log_types_impl(project_id, customer_id, region, search_term)
    typer.echo(result)

# --- Entry Point ---

def main():
    """Main entry point for the CLI."""
    app()

if __name__ == "__main__":
    main()
