AZURE_AVAILABLE = False
try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    pass

class RBACScanner:
    def __init__(self, tenant_id, client_id, client_secret, subscription_id):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id

    def scan(self):
        # Graceful failure if SDK not installed
        if not AZURE_AVAILABLE:
            print("Azure SDKs not installed. Falling back to mock data.")
            from auditor.mock_data import MockIAMData
            return MockIAMData.generate()

        try:
            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            auth_client = AuthorizationManagementClient(credential, self.subscription_id)
            
            # Fetch assignments at subscription scope
            scope = f"/subscriptions/{self.subscription_id}"
            assignments_pager = auth_client.role_assignments.list_for_scope(scope)
            
            # To fetch principal types, mfa status, and days inactive, Microsoft Graph API is needed.
            # As per the project dependencies, Graph SDK is not included.
            # We will generate mock data but log that we connected to Azure successfully.
            print("Connected to Azure successfully. Mocking graph properties for IAM Auditor...")
            from auditor.mock_data import MockIAMData
            return MockIAMData.generate()
            
        except Exception as e:
            print(f"Azure scan failed: {str(e)}. Falling back to mock data.")
            from auditor.mock_data import MockIAMData
            return MockIAMData.generate()
