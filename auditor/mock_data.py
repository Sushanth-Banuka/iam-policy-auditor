import random
from datetime import datetime, timedelta, timezone

class MockIAMData:
    @classmethod
    def generate(cls, include_users=True, include_sps=True, include_managed=True, include_guest=True):
        users = [
            "alice.johnson@contoso.com", "bob.smith@contoso.com", "carol.white@contoso.com", 
            "dave.kumar@contoso.com", "eve.chen@contoso.com", "frank.patel@contoso.com", 
            "grace.lee@contoso.com", "henry.nguyen@contoso.com"
        ]
        guests = [
            "ext.vendor1_gmail.com#EXT#@contoso.onmicrosoft.com", 
            "ext.consultant_yahoo.com#EXT#@contoso.onmicrosoft.com", 
            "ext.partner_outlook.com#EXT#@contoso.onmicrosoft.com"
        ]
        sps = [
            "github-actions-sp", "terraform-deploy-sp", "devops-pipeline-sp", 
            "monitoring-agent-sp", "backup-service-sp", "api-gateway-sp"
        ]
        managed = [
            "vm-webserver-identity", "aks-cluster-identity", 
            "function-app-identity", "logic-app-identity"
        ]

        roles = {
            "High": ["Owner", "User Access Administrator"],
            "Medium": ["Contributor", "Security Admin", "Network Contributor", "Storage Account Contributor"],
            "Low": ["Reader", "Monitoring Reader", "Cost Management Reader"]
        }

        scopes = {
            "subscription": "/subscriptions/abcd-1234-5678-efgh",
            "rg_prod": "/subscriptions/abcd-1234-5678-efgh/resourceGroups/rg-production",
            "rg_dev": "/subscriptions/abcd-1234-5678-efgh/resourceGroups/rg-development",
            "resource": "/subscriptions/abcd-1234-5678-efgh/resourceGroups/rg-production/providers/Microsoft.Storage/storageAccounts/prodstorage"
        }

        assignments = []
        now = datetime.now(timezone.utc)
        
        num_assignments = random.randint(30, 60)
        
        available_types = []
        if include_users: available_types.append("User")
        if include_guest: available_types.append("Guest")
        if include_sps: available_types.append("ServicePrincipal")
        if include_managed: available_types.append("ManagedIdentity")
        
        if not available_types:
            return []

        for i in range(num_assignments):
            p_type = random.choice(available_types)
            if p_type == "User":
                p_name = random.choice(users)
            elif p_type == "Guest":
                p_name = random.choice(guests)
            elif p_type == "ServicePrincipal":
                p_name = random.choice(sps)
            else:
                p_name = random.choice(managed)

            risk_level = random.choices(["High", "Medium", "Low"], weights=[15, 35, 50])[0]
            role = random.choice(roles[risk_level])

            scope_key = random.choice(list(scopes.keys()))
            scope = scopes[scope_key]

            if p_type in ["User", "Guest"] and random.random() < 0.3:
                days_ago = random.randint(90, 300)
            else:
                days_ago = random.randint(0, 30)
            last_active = (now - timedelta(days=days_ago)).isoformat()
            
            created_at = (now - timedelta(days=random.randint(300, 1000))).isoformat()
            
            mfa_enabled = True
            if p_type in ["User", "Guest"] and random.random() < 0.2:
                mfa_enabled = False
                
            secret_expiry = None
            if p_type == "ServicePrincipal":
                if random.random() < 0.4:
                    days_diff = random.randint(-30, 90)
                else:
                    days_diff = random.randint(91, 365)
                secret_expiry = (now + timedelta(days=days_diff)).isoformat()

            assignments.append({
                "principal_id": f"uid-{random.randint(1000,9999)}",
                "principal_name": p_name,
                "type": p_type,
                "role": role,
                "scope": scope,
                "scope_type": scope_key,
                "last_active": last_active,
                "created_at": created_at,
                "mfa_enabled": mfa_enabled,
                "secret_expiry": secret_expiry
            })

        return assignments
