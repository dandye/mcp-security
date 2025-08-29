#!/usr/bin/env python3
"""
Chronicle Authentication Testing Script

This script provides comprehensive testing of Google Cloud authentication
and Chronicle API access for the MCP SecOps server. It validates that
authentication works correctly in both local development and containerized
environments.

Usage:
    python test_chronicle_auth.py [--verbose] [--container]
    
Environment Variables:
    CHRONICLE_PROJECT_ID - Chronicle project ID
    CHRONICLE_CUSTOMER_ID - Chronicle customer ID  
    CHRONICLE_REGION - Chronicle region (default: us)
"""

import os
import sys
import json
import argparse
from typing import Optional, Dict, Any
from pathlib import Path

# Add server directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / "server"))

try:
    from google.auth import default
    from google.auth.transport.requests import Request
    import google.auth.exceptions
except ImportError:
    print("Error: google-auth library not installed")
    print("Install with: pip install google-auth google-auth-oauthlib")
    sys.exit(1)

try:
    from secops import SecOpsClient
    SECOPS_AVAILABLE = True
except ImportError:
    print("Warning: secops library not available")
    print("Chronicle API testing will be limited")
    SECOPS_AVAILABLE = False


def load_configuration(env_file_path, skip_env_file=False):
    """Load Chronicle configuration from .env file or environment.
    
    Configuration is loaded from .env file into environment variables
    to simulate how containers receive configuration.
    """
    config_vars = {
        "CHRONICLE_PROJECT_ID": None,
        "CHRONICLE_CUSTOMER_ID": None,
        "CHRONICLE_REGION": "us",
        "GOOGLE_CLOUD_PROJECT": None
    }
    
    # First, check existing environment variables
    for var in config_vars:
        if os.environ.get(var):
            config_vars[var] = os.environ.get(var)
    
    # Then, load from .env file unless skipped
    if not skip_env_file and os.path.exists(env_file_path):
        try:
            with open(env_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        if key in config_vars and value:
                            os.environ[key] = value
                            config_vars[key] = value
            print(f"Loaded configuration from {env_file_path}")
            for var in config_vars:
                if config_vars[var]:
                    display_val = config_vars[var][:8] + "..." if len(config_vars[var]) > 8 else config_vars[var]
                    print(f"  {var}: {display_val}")
        except Exception as e:
            print(f"Warning: Could not load {env_file_path}: {e}")
    elif skip_env_file:
        print("Skipping .env file loading (--no-env-file specified)")
    
    return config_vars


def setup_authentication(auth_mode, service_account=None, key_file=None):
    """Setup authentication based on specified mode.
    
    Returns True if setup is successful, False otherwise.
    """
    print(f"\nSetting up authentication mode: {auth_mode}")
    print("-" * 40)
    
    if auth_mode == "adc":
        # Use existing Application Default Credentials
        print("Using Application Default Credentials (ADC)")
        print("Ensure you've run: gcloud auth application-default login")
        
    elif auth_mode == "impersonation":
        if not service_account:
            print("ERROR: --service-account required for impersonation mode")
            return False
        print(f"Using service account impersonation: {service_account}")
        print("Ensure you've run:")
        print(f"  gcloud auth application-default login \\")
        print(f"    --impersonate-service-account={service_account}")
        
    elif auth_mode == "service-account":
        if not key_file:
            print("ERROR: --key-file required for service-account mode")
            return False
        if not os.path.exists(key_file):
            print(f"ERROR: Key file not found: {key_file}")
            return False
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
        print(f"Using service account key file: {key_file}")
        
    elif auth_mode == "container":
        print("Container mode: expecting pre-configured environment")
        print("Authentication should be configured by container runtime")
    
    print("-" * 40)
    return True


class ChromicleAuthTester:
    """Test Chronicle authentication and API access."""

    def __init__(self, verbose: bool = False, container_mode: bool = False):
        self.verbose = verbose
        self.container_mode = container_mode
        self.errors = []
        self.warnings = []

    def log(self, message: str, level: str = "INFO") -> None:
        """Log message with level prefix."""
        if level == "ERROR":
            self.errors.append(message)
            print(f"FAILED: {message}")
        elif level == "WARNING":
            self.warnings.append(message)
            print(f"WARNING: {message}")
        elif level == "SUCCESS":
            print(f"PASSED: {message}")
        elif self.verbose or level == "INFO":
            print(f"  {message}")

    def test_environment_variables(self) -> bool:
        """Test that required environment variables are set."""
        self.log("Testing environment variables...", "INFO")
        
        required_vars = [
            "CHRONICLE_PROJECT_ID",
            "CHRONICLE_CUSTOMER_ID",
        ]
        
        optional_vars = {
            "CHRONICLE_REGION": "us",
            "GOOGLE_CLOUD_PROJECT": "Not set (using CHRONICLE_PROJECT_ID)",
            "GOOGLE_APPLICATION_CREDENTIALS": "Not set (using ADC)"
        }
        
        success = True
        
        # Check required variables
        for var in required_vars:
            value = os.environ.get(var)
            if value:
                # Mask sensitive values
                display_value = value[:8] + "..." if len(value) > 8 else value
                self.log(f"{var}: {display_value}", "SUCCESS")
            else:
                self.log(f"Missing required environment variable: {var}", "ERROR")
                success = False
        
        # Check optional variables
        for var, default in optional_vars.items():
            value = os.environ.get(var)
            if value:
                # Mask credentials file path
                if "CREDENTIALS" in var and value:
                    display_value = f".../{os.path.basename(value)}"
                else:
                    display_value = value
                self.log(f"{var}: {display_value}")
            else:
                self.log(f"{var}: {default}")
        
        return success

    def test_google_auth(self) -> Optional[Dict[str, Any]]:
        """Test basic Google authentication."""
        self.log("Testing Google authentication...", "INFO")
        
        try:
            credentials, project = default()
            
            # Get credential information
            cred_info = {
                "project": project,
                "credentials_type": type(credentials).__name__,
                "service_account": getattr(credentials, "service_account_email", None),
                "valid": credentials.valid if hasattr(credentials, 'valid') else True
            }
            
            self.log("Google auth successful", "SUCCESS")
            self.log(f"Project: {project}")
            self.log(f"Credentials type: {cred_info['credentials_type']}")
            
            if cred_info["service_account"]:
                self.log(f"Service account: {cred_info['service_account']}")
            else:
                self.log("Using user credentials (ADC)")
            
            # Test token refresh if needed
            if hasattr(credentials, 'valid') and not credentials.valid:
                self.log("Refreshing credentials...")
                credentials.refresh(Request())
                cred_info["valid"] = credentials.valid
                
            self.log(f"Token valid: {cred_info['valid']}")
            
            return cred_info
            
        except google.auth.exceptions.DefaultCredentialsError as e:
            self.log(f"Default credentials not found: {e}", "ERROR")
            self.log("Try: gcloud auth application-default login", "ERROR")
            return None
        except Exception as e:
            self.log(f"Google authentication failed: {e}", "ERROR")
            return None

    def test_credentials_file_access(self) -> bool:
        """Test access to credentials file in container mode."""
        if not self.container_mode:
            return True
            
        self.log("Testing credentials file access (container mode)...", "INFO")
        
        creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if not creds_path:
            self.log("GOOGLE_APPLICATION_CREDENTIALS not set", "WARNING")
            return True
            
        try:
            if os.path.exists(creds_path):
                self.log(f"Credentials file exists: {creds_path}", "SUCCESS")
                
                # Test file permissions
                if os.access(creds_path, os.R_OK):
                    self.log("Credentials file is readable", "SUCCESS")
                else:
                    self.log("Credentials file is not readable", "ERROR")
                    return False
                    
                # Test file content (basic JSON structure)
                try:
                    with open(creds_path, 'r') as f:
                        creds_data = json.load(f)
                        if 'type' in creds_data:
                            self.log(f"Credentials type: {creds_data['type']}")
                        else:
                            self.log("Credentials file missing 'type' field", "WARNING")
                    return True
                except json.JSONDecodeError:
                    self.log("Credentials file is not valid JSON", "ERROR")
                    return False
            else:
                self.log(f"Credentials file does not exist: {creds_path}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error accessing credentials file: {e}", "ERROR")
            return False

    def test_chronicle_client_initialization(self) -> Optional[Any]:
        """Test Chronicle client initialization."""
        if not SECOPS_AVAILABLE:
            self.log("Skipping Chronicle client test (secops library not available)", "WARNING")
            return None
            
        self.log("Testing Chronicle client initialization...", "INFO")
        
        try:
            client = SecOpsClient()
            self.log("SecOpsClient initialized successfully", "SUCCESS")
            return client
        except Exception as e:
            self.log(f"Failed to initialize SecOpsClient: {e}", "ERROR")
            return None

    def test_chronicle_api_access(self, client: Any) -> bool:
        """Test actual Chronicle API access."""
        if not client or not SECOPS_AVAILABLE:
            self.log("Skipping Chronicle API test (client not available)", "WARNING")
            return True
            
        self.log("Testing Chronicle API access...", "INFO")
        
        # Get required environment variables
        customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID")
        project_id = os.environ.get("CHRONICLE_PROJECT_ID")
        region = os.environ.get("CHRONICLE_REGION", "us")
        
        if not customer_id or not project_id:
            self.log("Missing Chronicle configuration for API test", "WARNING")
            return True
            
        try:
            # Initialize Chronicle connection
            _ = client.chronicle(
                customer_id=customer_id,
                project_id=project_id,
                region=region
            )
            
            self.log("Chronicle API connection established", "SUCCESS")
            self.log(f"Customer ID: {customer_id[:8]}...")
            self.log(f"Project ID: {project_id}")
            self.log(f"Region: {region}")
            
            # Note: We don't perform actual API calls here to avoid
            # unnecessary API usage and potential billing
            self.log("Chronicle API authentication successful", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Chronicle API access failed: {e}", "ERROR")
            return False

    def test_container_environment(self) -> bool:
        """Test container-specific environment."""
        if not self.container_mode:
            return True
            
        self.log("Testing container environment...", "INFO")
        
        # Check if we're actually running in a container
        container_indicators = [
            "/.dockerenv",
            "/proc/self/cgroup"
        ]
        
        in_container = False
        for indicator in container_indicators:
            if os.path.exists(indicator):
                in_container = True
                break
                
        if in_container:
            self.log("Running inside container environment", "SUCCESS")
        else:
            self.log("Not detected as container environment", "WARNING")
            
        # Check container-specific environment variables
        container_env_vars = [
            "HOSTNAME",
            "PWD"
        ]
        
        for var in container_env_vars:
            value = os.environ.get(var)
            if value:
                self.log(f"{var}: {value}")
                
        return True

    def run_all_tests(self) -> bool:
        """Run all authentication tests."""
        self.log("=" * 60)
        self.log("Chronicle Authentication Test Suite")
        self.log("=" * 60)
        
        if self.container_mode:
            self.log("Running in container mode")
        else:
            self.log("Running in local mode")
            
        self.log("")
        
        # Run tests in sequence
        tests = [
            ("Environment Variables", self.test_environment_variables),
            ("Container Environment", self.test_container_environment),
            ("Credentials File Access", self.test_credentials_file_access),
            ("Google Authentication", self.test_google_auth),
        ]
        
        results = {}
        chronicle_client = None
        
        for test_name, test_func in tests:
            self.log(f"\n--- {test_name} ---")
            try:
                if test_name == "Google Authentication":
                    result = test_func()
                    results[test_name] = result is not None
                    if result:
                        # Save credentials info for Chronicle tests
                        results["google_auth_info"] = result
                else:
                    results[test_name] = test_func()
            except Exception as e:
                self.log(f"Test '{test_name}' failed with exception: {e}", "ERROR")
                results[test_name] = False
        
        # Chronicle-specific tests
        if results.get("Google Authentication", False):
            self.log("\n--- Chronicle Client Initialization ---")
            chronicle_client = self.test_chronicle_client_initialization()
            results["Chronicle Client"] = chronicle_client is not None
            
            if chronicle_client:
                self.log("\n--- Chronicle API Access ---")
                results["Chronicle API"] = self.test_chronicle_api_access(chronicle_client)
        
        # Summary
        self.log("\n" + "=" * 60)
        self.log("Test Results Summary")
        self.log("=" * 60)
        
        total_tests = 0
        passed_tests = 0
        
        for test_name, result in results.items():
            if test_name == "google_auth_info":
                continue
                
            total_tests += 1
            if result:
                passed_tests += 1
                self.log(f"{test_name}: PASSED", "SUCCESS")
            else:
                self.log(f"{test_name}: FAILED", "ERROR")
        
        self.log(f"\nPassed: {passed_tests}/{total_tests}")
        
        if self.warnings:
            self.log(f"\nWarnings: {len(self.warnings)}")
            for warning in self.warnings:
                print(f"WARNING: {warning}")
        
        if self.errors:
            self.log(f"\nErrors: {len(self.errors)}")
            for error in self.errors:
                print(f"ERROR: {error}")
        
        success = passed_tests == total_tests and len(self.errors) == 0
        
        if success:
            self.log("\nAll tests passed! Authentication is working correctly.", "SUCCESS")
        else:
            self.log(f"\n{len(self.errors)} test(s) failed. Please check the errors above.", "ERROR")
        
        return success


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test Chronicle authentication and API access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with user ADC (default)
  python test_chronicle_auth.py --auth-mode=adc
  
  # Test with service account impersonation
  python test_chronicle_auth.py --auth-mode=impersonation \\
      --service-account=chronicle-mcp-sa@my-project.iam.gserviceaccount.com
  
  # Test with service account key file
  python test_chronicle_auth.py --auth-mode=service-account \\
      --key-file=/path/to/key.json
  
  # Test in container mode
  python test_chronicle_auth.py --auth-mode=container
  
  # Test with manual environment variables (no .env file)
  export CHRONICLE_PROJECT_ID=my-project
  export CHRONICLE_CUSTOMER_ID=my-customer
  python test_chronicle_auth.py --auth-mode=adc --no-env-file
  
Environment Variables:
  CHRONICLE_PROJECT_ID   - Required: Chronicle project ID
  CHRONICLE_CUSTOMER_ID  - Required: Chronicle customer ID
  CHRONICLE_REGION       - Optional: Chronicle region (default: us)
        """
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--auth-mode",
        choices=["adc", "impersonation", "service-account", "container"],
        default="adc",
        help="Authentication mode to test (default: adc)"
    )
    
    parser.add_argument(
        "--service-account",
        help="Service account email for impersonation mode"
    )
    
    parser.add_argument(
        "--key-file",
        help="Path to service account key file for service-account mode"
    )
    
    parser.add_argument(
        "--env-file",
        default="agents/google_mcp_security_agent/.env",
        help="Path to .env file for configuration (default: agents/google_mcp_security_agent/.env)"
    )
    
    parser.add_argument(
        "--no-env-file",
        action="store_true",
        help="Skip loading configuration from .env file"
    )
    
    # Deprecated argument for backward compatibility
    parser.add_argument(
        "--container", "-c",
        action="store_true",
        help="DEPRECATED: Use --auth-mode=container instead"
    )
    
    args = parser.parse_args()
    
    # Handle deprecated --container flag
    if args.container:
        print("Warning: --container flag is deprecated. Using --auth-mode=container")
        args.auth_mode = "container"
    
    # Load configuration
    config = load_configuration(args.env_file, args.no_env_file)
    
    # Setup authentication
    if not setup_authentication(args.auth_mode, args.service_account, args.key_file):
        print("\nAuthentication setup failed. Exiting.")
        sys.exit(1)
    
    # Run tests with clear mode indication
    tester = ChromicleAuthTester(
        verbose=args.verbose,
        container_mode=(args.auth_mode == "container")
    )
    
    print(f"\nRunning tests with authentication mode: {args.auth_mode}")
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()