#!/usr/bin/env python3
"""
Quick test script to verify Chronicle authentication with service account.
Run this after setting up service account impersonation.
"""

import os
import sys
from google.auth import default
from google.auth.transport.requests import Request

def test_google_auth():
    """Test basic Google authentication"""
    try:
        credentials, project = default()
        print(f"Google auth successful")
        print(f"   Project: {project}")
        print(f"   Service account: {getattr(credentials, 'service_account_email', 'N/A')}")
        
        # Test token refresh
        if not credentials.valid:
            credentials.refresh(Request())
        
        print(f"   Token valid: {credentials.valid}")
        return True
    except Exception as e:
        print(f"Google auth failed: {e}")
        return False

def test_chronicle_client():
    """Test Chronicle client initialization"""
    try:
        from secops import SecOpsClient
        
        client = SecOpsClient()
        print("SecOps client created successfully")
        
        # Get environment variables
        project_id = os.environ.get('CHRONICLE_PROJECT_ID')
        customer_id = os.environ.get('CHRONICLE_CUSTOMER_ID') 
        region = os.environ.get('CHRONICLE_REGION', 'us')
        
        if not project_id or not customer_id:
            print("Missing required environment variables:")
            print(f"   CHRONICLE_PROJECT_ID: {project_id}")
            print(f"   CHRONICLE_CUSTOMER_ID: {customer_id}")
            return False
            
        # Try to create Chronicle client
        chronicle = client.chronicle(
            customer_id=customer_id,
            project_id=project_id,
            region=region
        )
        print("Chronicle client initialized successfully")
        print(f"   Customer ID: {customer_id}")
        print(f"   Project ID: {project_id}")
        print(f"   Region: {region}")
        
        return True
        
    except ImportError:
        print("SecOps library not found. Install with: pip install secops")
        return False
    except Exception as e:
        print(f"Chronicle client failed: {e}")
        return False

def main():
    print("Testing Chronicle Authentication")
    print("=" * 50)
    
    # Test 1: Basic Google auth
    print("\n1. Testing Google Authentication...")
    auth_ok = test_google_auth()
    
    # Test 2: Chronicle client
    print("\n2. Testing Chronicle Client...")
    chronicle_ok = test_chronicle_client()
    
    # Summary
    print("\n" + "=" * 50)
    if auth_ok and chronicle_ok:
        print("All tests passed! Service account authentication is working.")
        print("\nYou can now run: make local-dev-run")
    else:
        print("Some tests failed. Check the errors above.")
        print("\nTroubleshooting:")
        print("1. Ensure you're using service account impersonation:")
        print("   gcloud auth application-default login --impersonate-service-account=chronicle-mcp-sa@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com")
        print("2. Set required environment variables:")
        print("   export CHRONICLE_PROJECT_ID=your-project-id")
        print("   export CHRONICLE_CUSTOMER_ID=your-customer-id")
        print("   export CHRONICLE_REGION=us")

if __name__ == "__main__":
    main()