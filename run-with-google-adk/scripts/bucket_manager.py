#!/usr/bin/env python3
"""
Bucket Manager for Google MCP Security Agent

This script manages GCS bucket operations including verification and creation
for ADK deployment staging.
"""

import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))
from scripts.env_manager import EnvManager

app = typer.Typer(
    add_completion=False,
    help="Manage GCS buckets for ADK deployment staging.",
)


class BucketManager:
    """Manages GCS bucket operations."""

    def __init__(self, env_file: Path):
        """Initialize the bucket manager."""
        self.env_manager = EnvManager(env_file)
        self.env_vars = self.env_manager.env_vars

    def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if a GCS bucket exists."""
        try:
            result = subprocess.run(
                ["gsutil", "ls", bucket_name],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            typer.secho(f"Error checking bucket: {e}", fg=typer.colors.RED)
            return False

    def create_bucket(self, bucket_name: str, project: str) -> bool:
        """Create a GCS bucket."""
        try:
            result = subprocess.run(
                ["gsutil", "mb", "-p", project, bucket_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                typer.secho(
                    f"✅ Successfully created bucket: {bucket_name}",
                    fg=typer.colors.GREEN,
                )
                return True
            else:
                typer.secho(
                    f"❌ Failed to create bucket: {result.stderr}",
                    fg=typer.colors.RED,
                )
                return False
        except Exception as e:
            typer.secho(f"Error creating bucket: {e}", fg=typer.colors.RED)
            return False

    def generate_bucket_name(self) -> Optional[str]:
        """Generate a bucket name based on project and timestamp."""
        project = self.env_vars.get("GOOGLE_CLOUD_PROJECT")
        if not project:
            typer.secho(
                "❌ Error: GOOGLE_CLOUD_PROJECT not set in environment",
                fg=typer.colors.RED,
            )
            return None
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"gs://agent-deploy-{project}-{timestamp}"

    def verify_or_create_bucket(
        self, bucket_name: Optional[str] = None, interactive: bool = True
    ) -> bool:
        """Verify bucket exists or optionally create it."""
        # Get bucket name from parameter, env, or generate
        if not bucket_name:
            bucket_name = self.env_vars.get("GCS_STAGING_BUCKET")

        if not bucket_name:
            bucket_name = self.generate_bucket_name()
            if not bucket_name:
                return False
            typer.echo(f"Generated staging bucket name: {bucket_name}")
            # Update env file with generated name
            self.env_manager.update_env("GCS_STAGING_BUCKET", bucket_name)

        # Check if bucket exists
        typer.echo(f"Checking if bucket exists: {bucket_name}")
        if self.check_bucket_exists(bucket_name):
            typer.secho(
                f"✅ Staging bucket exists: {bucket_name}", fg=typer.colors.GREEN
            )
            return True

        typer.secho(
            f"❌ Staging bucket does not exist: {bucket_name}", fg=typer.colors.RED
        )

        # Get project for bucket creation
        project = self.env_vars.get("GOOGLE_CLOUD_PROJECT")
        if not project:
            typer.secho(
                "❌ Error: GOOGLE_CLOUD_PROJECT not set", fg=typer.colors.RED
            )
            return False

        # Handle creation
        if interactive:
            create = typer.confirm("\nWould you like to create it now?")
            if create:
                return self.create_bucket(bucket_name, project)
            else:
                typer.echo(f"\nTo create the bucket manually, run:")
                typer.echo(f"  gsutil mb -p {project} {bucket_name}")
                return False
        else:
            typer.echo(f"\nTo create the bucket, run:")
            typer.echo(f"  gsutil mb -p {project} {bucket_name}")
            return False


@app.command()
def check(
    bucket: Annotated[
        Optional[str], typer.Option(help="Bucket name to check (overrides env)")
    ] = None,
    env_file: Annotated[
        Path,
        typer.Option(help="Path to the environment file."),
    ] = Path("agents/google_mcp_security_agent/.env"),
) -> None:
    """Check if the configured GCS bucket exists."""
    manager = BucketManager(env_file)

    bucket_name = bucket or manager.env_vars.get("GCS_STAGING_BUCKET")
    if not bucket_name:
        typer.secho("❌ Error: No bucket specified", fg=typer.colors.RED)
        raise typer.Exit(1)

    if manager.check_bucket_exists(bucket_name):
        typer.secho(f"✅ Bucket exists: {bucket_name}", fg=typer.colors.GREEN)
    else:
        typer.secho(f"❌ Bucket does not exist: {bucket_name}", fg=typer.colors.RED)
        project = manager.env_vars.get("GOOGLE_CLOUD_PROJECT", "<PROJECT>")
        typer.echo(f"Create with: gsutil mb -p {project} {bucket_name}")
        raise typer.Exit(1)


@app.command()
def verify(
    bucket: Annotated[
        Optional[str], typer.Option(help="Bucket name to verify (overrides env)")
    ] = None,
    no_interactive: Annotated[
        bool,
        typer.Option("--no-interactive", help="Disable interactive prompts"),
    ] = False,
    env_file: Annotated[
        Path,
        typer.Option(help="Path to the environment file."),
    ] = Path("agents/google_mcp_security_agent/.env"),
) -> None:
    """Verify GCS bucket exists or interactively create it."""
    manager = BucketManager(env_file)

    success = manager.verify_or_create_bucket(
        bucket_name=bucket, interactive=not no_interactive
    )
    if not success:
        raise typer.Exit(1)


@app.command()
def create(
    bucket: Annotated[
        Optional[str], typer.Option(help="Bucket name to create (overrides env)")
    ] = None,
    env_file: Annotated[
        Path,
        typer.Option(help="Path to the environment file."),
    ] = Path("agents/google_mcp_security_agent/.env"),
) -> None:
    """Create the configured GCS bucket."""
    manager = BucketManager(env_file)

    bucket_name = bucket or manager.env_vars.get("GCS_STAGING_BUCKET")
    if not bucket_name:
        bucket_name = manager.generate_bucket_name()
        if not bucket_name:
            raise typer.Exit(1)
        typer.echo(f"Generated bucket name: {bucket_name}")
        manager.env_manager.update_env("GCS_STAGING_BUCKET", bucket_name)

    project = manager.env_vars.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        typer.secho(
            "❌ Error: GOOGLE_CLOUD_PROJECT not set", fg=typer.colors.RED
        )
        raise typer.Exit(1)

    if manager.create_bucket(bucket_name, project):
        typer.secho(f"✅ Successfully created: {bucket_name}", fg=typer.colors.GREEN)
    else:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()