from datetime import datetime, timezone

class RiskEngine:
    MITRE_MAP = {
        "Over-Privileged Role":          {"id": "T1078",     "name": "Valid Accounts",       "tactic": "Privilege Escalation"},
        "Subscription-Scope Assignment": {"id": "T1098",     "name": "Account Manipulation", "tactic": "Persistence"},
        "Privileged Guest Account":      {"id": "T1078.004", "name": "Cloud Accounts",        "tactic": "Initial Access"},
        "Service Principal Owner":       {"id": "T1552.001", "name": "Credentials in Files", "tactic": "Credential Access"},
        "Stale Account":                 {"id": "T1078.004", "name": "Cloud Accounts",        "tactic": "Defense Evasion"},
        "MFA Not Enabled":               {"id": "T1556",     "name": "Modify Auth Process",  "tactic": "Credential Access"},
        "Expired SP Secret":             {"id": "T1552.004", "name": "Private Keys",          "tactic": "Credential Access"},
        "Expiring SP Secret":            {"id": "T1552.004", "name": "Private Keys",          "tactic": "Credential Access"},
    }

    SEV_WEIGHT = {"Critical": 20, "High": 10, "Medium": 4, "Low": 1}

    def analyze(self, assignments):
        findings = []
        principals_dict = {}
        now = datetime.now(timezone.utc)

        for a in assignments:
            p_name = a["principal_name"]
            p_type = a["type"]
            role = a["role"]
            scope = a["scope"]
            short_scope = scope.split("/")[-1] if "/" in scope else scope
            mfa = a.get("mfa_enabled", True)
            last_active_str = a.get("last_active")
            secret_expiry_str = a.get("secret_expiry")

            last_active = datetime.fromisoformat(last_active_str) if last_active_str else now
            stale_days = (now - last_active).days

            if p_name not in principals_dict:
                principals_dict[p_name] = {
                    "name": p_name,
                    "type": p_type,
                    "role": role,
                    "scope": short_scope,
                    "risk_level": "Low",
                    "findings_count": 0,
                    "mfa_enabled": str(mfa) if p_type in ["User", "Guest"] else "N/A",
                    "last_active": last_active_str.split("T")[0] if last_active_str else "Unknown"
                }

            def add_finding(sev, f_type, desc, rec, rem_cli):
                mitre = self.MITRE_MAP[f_type]
                findings.append({
                    "severity": sev,
                    "type": f_type,
                    "principal": p_name,
                    "role": role,
                    "scope": short_scope,
                    "description": desc,
                    "recommendation": rec,
                    "mitre_id": mitre["id"],
                    "mitre_name": mitre["name"],
                    "mitre_tactic": mitre["tactic"],
                    "remediation_cli": rem_cli
                })
                principals_dict[p_name]["findings_count"] += 1
                current_risk = principals_dict[p_name]["risk_level"]
                if self.SEV_WEIGHT[sev] > self.SEV_WEIGHT.get(current_risk, 0):
                    principals_dict[p_name]["risk_level"] = sev

            # 1. Over-Privileged Role (Critical)
            if role in ["Owner", "User Access Administrator"]:
                add_finding(
                    "Critical", "Over-Privileged Role",
                    f"{p_type} '{p_name}' has '{role}' role which grants full access.",
                    "Review and downgrade to a least-privilege role.",
                    f"# Remove {role} finding\naz role assignment delete --assignee {a['principal_id']} --role '{role}' --scope '{scope}'\n# Assign safer role\naz role assignment create --assignee {a['principal_id']} --role 'Reader' --scope '{scope}'"
                )
            
            # 2. Subscription-Scope Assignment (High)
            is_high_med_role = role in ["Owner", "User Access Administrator", "Contributor", "Security Admin", "Network Contributor", "Storage Account Contributor"]
            if "resourceGroups" not in scope and is_high_med_role:
                add_finding(
                    "High", "Subscription-Scope Assignment",
                    f"High/Medium privileged role '{role}' is assigned at the subscription scope.",
                    "Move the assignment to a specific resource group or resource.",
                    f"# Delete subscription assignment\naz role assignment delete --assignee {a['principal_id']} --role '{role}' --scope '{scope}'\n# Please manually create at RG scope"
                )

            # 3. Privileged Guest Account (Critical)
            if p_type == "Guest" and is_high_med_role:
                add_finding(
                    "Critical", "Privileged Guest Account",
                    f"Guest account '{p_name}' has privileged role '{role}'.",
                    "Remove privileged access from external guests.",
                    f"# Remove guest role\naz role assignment delete --assignee {a['principal_id']} --role '{role}' --scope '{scope}'"
                )

            # 4. Service Principal Owner (Critical)
            if p_type == "ServicePrincipal" and role == "Owner":
                add_finding(
                    "Critical", "Service Principal Owner",
                    f"Service Principal '{p_name}' is assigned Owner.",
                    "Use custom roles with narrow permissions for automated pipelines.",
                    f"# Delete SP owner role\naz role assignment delete --assignee {a['principal_id']} --role 'Owner' --scope '{scope}'"
                )

            # 5. Stale Account (High)
            if p_type in ["User", "Guest"] and stale_days >= 90:
                add_finding(
                    "High", "Stale Account",
                    f"Account has not been active for {stale_days} days.",
                    "Disable or delete the stale account.",
                    f"# Delete assignments\naz role assignment delete --assignee {a['principal_id']} --scope '{scope}'\n# Disable user\naz ad user update --id {p_name} --account-enabled false"
                )

            # 6. MFA Not Enabled (Medium)
            if p_type in ["User", "Guest"] and not mfa:
                add_finding(
                    "Medium", "MFA Not Enabled",
                    f"MFA is not enabled for account '{p_name}'.",
                    "Enforce MFA using Conditional Access.",
                    "# Remediation requires Conditional Access Policy\n# Go to Entra ID > Security > Conditional Access\n# Create a policy requiring MFA for all users"
                )

            # 7. Expired/Expiring SP Secret
            if p_type == "ServicePrincipal" and secret_expiry_str:
                expiry_dt = datetime.fromisoformat(secret_expiry_str)
                days_to_expire = (expiry_dt - now).days
                
                if days_to_expire < 0:
                    add_finding(
                        "High", "Expired SP Secret",
                        f"Secret for SP '{p_name}' expired {abs(days_to_expire)} days ago.",
                        "Rotate the expired credential immediately.",
                        f"# Reset SP credentials\naz ad app credential reset --id {a['principal_id']} --years 1"
                    )
                elif days_to_expire <= 30:
                    add_finding(
                        "Medium", "Expiring SP Secret",
                        f"Secret expires in {days_to_expire} days.",
                        "Rotate credential before expiration.",
                        f"# Reset SP credentials\naz ad app credential reset --id {a['principal_id']} --years 1"
                    )

        penalty = sum(self.SEV_WEIGHT[f["severity"]] for f in findings)
        max_possible = len(assignments) * self.SEV_WEIGHT["Critical"] * 2
        score = max(0, round(100 - (penalty / max(max_possible, 1)) * 100))

        if score >= 90:
            grade = ("A", "#00FF00", "Excellent")
        elif score >= 75:
            grade = ("B", "#ADFF2F", "Good")
        elif score >= 60:
            grade = ("C", "#FFA500", "Needs Attention")
        elif score >= 40:
            grade = ("D", "#FF4500", "Poor")
        else:
            grade = ("F", "#FF0000", "Critical Risk")

        summary = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
            "security_score": score,
            "score_grade": grade,
            "principals_scanned": len(principals_dict)
        }

        return {
            "findings": findings,
            "principals": list(principals_dict.values()),
            "summary": summary,
            "scanned_at": now.isoformat()
        }
