# MIT License — Copyright (c) 2026 cvemula1
# Azure provider — discovers Service Principals, Managed Identities, App Credentials

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity, IdentityType, Provider
from nhinsight.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class AzureProvider(BaseProvider):
    """Discover non-human identities in Azure AD / Entra ID."""

    name = "azure"

    def __init__(self, config: NHInsightConfig):
        super().__init__(config)
        self._credential = None
        self._graph_client = None
        self._auth_client = None
        self._tenant_id: Optional[str] = None
        self._subscription_id: Optional[str] = None

    def _get_credential(self):
        """Get Azure credential using DefaultAzureCredential."""
        from azure.identity import DefaultAzureCredential

        if self._credential is None:
            self._credential = DefaultAzureCredential()
        return self._credential

    def _get_graph_token(self) -> str:
        """Get an access token for Microsoft Graph API."""
        token = self._get_credential().get_token("https://graph.microsoft.com/.default")
        return token.token

    def _graph_get(self, path: str) -> dict:
        """Make a GET request to Microsoft Graph API."""
        import requests

        headers = {"Authorization": f"Bearer {self._get_graph_token()}"}
        url = f"https://graph.microsoft.com/v1.0{path}"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _graph_get_all(self, path: str) -> list:
        """Get all pages from a Microsoft Graph API list endpoint."""
        import requests

        headers = {"Authorization": f"Bearer {self._get_graph_token()}"}
        url = f"https://graph.microsoft.com/v1.0{path}"
        results = []

        while url:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return results

    def _get_auth_client(self):
        """Get Azure authorization management client for RBAC queries."""
        if self._auth_client is None:
            from azure.mgmt.authorization import AuthorizationManagementClient

            sub_id = self.config.azure_subscription_id or self._get_subscription_id()
            self._auth_client = AuthorizationManagementClient(
                credential=self._get_credential(),
                subscription_id=sub_id,
            )
        return self._auth_client

    def _get_subscription_id(self) -> str:
        """Get default subscription ID from config or az CLI."""
        if self._subscription_id is None:
            if self.config.azure_subscription_id:
                self._subscription_id = self.config.azure_subscription_id
            else:
                # Fall back to az CLI current subscription
                import subprocess
                try:
                    out = subprocess.check_output(
                        ["az", "account", "show", "--query", "id", "-o", "tsv"],
                        text=True, timeout=10,
                    ).strip()
                    self._subscription_id = out
                except Exception:
                    logger.warning("Could not auto-detect subscription. Use --azure-subscription-id.")
        return self._subscription_id or ""

    def is_available(self) -> bool:
        """Check if Azure credentials are available."""
        try:
            self._get_credential()
            return True
        except Exception:
            return False

    def discover(self) -> List[Identity]:
        """Discover Azure AD service principals, managed identities, and app credentials."""
        identities: List[Identity] = []

        try:
            # Get RBAC role assignments for enrichment
            role_map = self._get_role_assignments()

            # Discover service principals (includes app registrations)
            sp_identities = self._discover_service_principals(role_map)
            identities.extend(sp_identities)

            # Discover managed identities
            mi_identities = self._discover_managed_identities(role_map)
            identities.extend(mi_identities)

            # Discover app credentials (secrets + certificates)
            cred_identities = self._discover_app_credentials()
            identities.extend(cred_identities)

        except ImportError:
            logger.error(
                "Azure SDK not installed. Run: "
                "pip install azure-identity azure-mgmt-authorization msgraph-core"
            )
        except Exception as e:
            logger.error("Azure discovery failed: %s", e)

        logger.info("Found %d Azure identities", len(identities))
        return identities

    def _discover_service_principals(
        self, role_map: Dict[str, List[str]]
    ) -> List[Identity]:
        """Discover Azure AD Service Principals."""
        identities: List[Identity] = []

        try:
            sps = self._graph_get_all("/servicePrincipals?$top=999")

            for sp in sps:
                sp_id = sp.get("id", "")
                app_id = sp.get("appId", "")
                display_name = sp.get("displayName", "")
                sp_type = sp.get("servicePrincipalType", "")
                created = sp.get("createdDateTime")
                app_owner_org = sp.get("appOwnerOrganizationId", "")
                tags = sp.get("tags", [])
                enabled = sp.get("accountEnabled", True)

                # Skip Microsoft first-party apps
                if app_owner_org == "f8cdef31-a31e-4b4a-93e4-5f571e91255a":
                    continue

                # Determine identity type
                if sp_type == "ManagedIdentity":
                    continue  # handled separately
                identity_type = IdentityType.AZURE_SP

                # Parse creation time
                created_at = None
                if created:
                    from datetime import datetime
                    try:
                        created_at = datetime.fromisoformat(
                            created.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                # Get role assignments for this SP
                roles = role_map.get(sp_id, [])

                ident = Identity(
                    id=f"azure:sp:{app_id}",
                    name=display_name,
                    provider=Provider.AZURE,
                    identity_type=identity_type,
                    created_at=created_at,
                    policies=roles,
                    raw={
                        "app_id": app_id,
                        "object_id": sp_id,
                        "sp_type": sp_type,
                        "enabled": enabled,
                        "tags": tags,
                        "app_owner_org": app_owner_org,
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.warning("Failed to list service principals: %s", e)

        logger.info("Found %d service principals", len(identities))
        return identities

    def _discover_managed_identities(
        self, role_map: Dict[str, List[str]]
    ) -> List[Identity]:
        """Discover Azure Managed Identities (user-assigned + system-assigned)."""
        identities: List[Identity] = []

        try:
            mis = self._graph_get_all(
                "/servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'"
                "&$top=999"
            )

            for mi in mis:
                sp_id = mi.get("id", "")
                app_id = mi.get("appId", "")
                display_name = mi.get("displayName", "")
                created = mi.get("createdDateTime")
                tags = mi.get("tags", [])

                # Determine if system-assigned or user-assigned
                alt_names = mi.get("alternativeNames", [])
                mi_type = "system-assigned"
                resource_id = ""
                for alt in alt_names:
                    if alt.startswith("isExplicit="):
                        mi_type = (
                            "user-assigned"
                            if alt == "isExplicit=True"
                            else "system-assigned"
                        )
                    elif "/" in alt:
                        resource_id = alt

                created_at = None
                if created:
                    from datetime import datetime
                    try:
                        created_at = datetime.fromisoformat(
                            created.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                roles = role_map.get(sp_id, [])

                ident = Identity(
                    id=f"azure:mi:{app_id}",
                    name=display_name,
                    provider=Provider.AZURE,
                    identity_type=IdentityType.AZURE_MANAGED_IDENTITY,
                    created_at=created_at,
                    policies=roles,
                    raw={
                        "app_id": app_id,
                        "object_id": sp_id,
                        "mi_type": mi_type,
                        "resource_id": resource_id,
                        "tags": tags,
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.warning("Failed to list managed identities: %s", e)

        logger.info("Found %d managed identities", len(identities))
        return identities

    def _discover_app_credentials(self) -> List[Identity]:
        """Discover App Registration credentials (client secrets + certificates)."""
        identities: List[Identity] = []

        try:
            apps = self._graph_get_all(
                "/applications?$select=id,appId,displayName,"
                "passwordCredentials,keyCredentials&$top=999"
            )

            for app in apps:
                app_id = app.get("appId", "")
                app_name = app.get("displayName", "")

                # Client secrets
                for cred in app.get("passwordCredentials", []):
                    cred_id = cred.get("keyId", "")
                    hint = cred.get("hint", cred.get("displayName", ""))
                    end_date = cred.get("endDateTime")
                    start_date = cred.get("startDateTime")

                    created_at = None
                    if start_date:
                        from datetime import datetime
                        try:
                            created_at = datetime.fromisoformat(
                                start_date.replace("Z", "+00:00")
                            )
                        except (ValueError, TypeError):
                            pass

                    expires_at = None
                    if end_date:
                        from datetime import datetime
                        try:
                            expires_at = datetime.fromisoformat(
                                end_date.replace("Z", "+00:00")
                            )
                        except (ValueError, TypeError):
                            pass

                    ident = Identity(
                        id=f"azure:app_secret:{app_id}:{cred_id}",
                        name=f"{app_name}/secret:{hint or cred_id[:8]}",
                        provider=Provider.AZURE,
                        identity_type=IdentityType.AZURE_APP_SECRET,
                        created_at=created_at,
                        owner=app_name,
                        raw={
                            "app_id": app_id,
                            "app_name": app_name,
                            "cred_id": cred_id,
                            "hint": hint,
                            "expires_at": expires_at.isoformat() if expires_at else None,
                        },
                    )
                    identities.append(ident)

                # Certificates
                for cert in app.get("keyCredentials", []):
                    cred_id = cert.get("keyId", "")
                    cert_name = cert.get("displayName", "")
                    end_date = cert.get("endDateTime")
                    start_date = cert.get("startDateTime")
                    usage = cert.get("usage", "")

                    created_at = None
                    if start_date:
                        from datetime import datetime
                        try:
                            created_at = datetime.fromisoformat(
                                start_date.replace("Z", "+00:00")
                            )
                        except (ValueError, TypeError):
                            pass

                    expires_at = None
                    if end_date:
                        from datetime import datetime
                        try:
                            expires_at = datetime.fromisoformat(
                                end_date.replace("Z", "+00:00")
                            )
                        except (ValueError, TypeError):
                            pass

                    ident = Identity(
                        id=f"azure:app_cert:{app_id}:{cred_id}",
                        name=f"{app_name}/cert:{cert_name or cred_id[:8]}",
                        provider=Provider.AZURE,
                        identity_type=IdentityType.AZURE_APP_CERT,
                        created_at=created_at,
                        owner=app_name,
                        raw={
                            "app_id": app_id,
                            "app_name": app_name,
                            "cred_id": cred_id,
                            "cert_name": cert_name,
                            "usage": usage,
                            "expires_at": expires_at.isoformat() if expires_at else None,
                        },
                    )
                    identities.append(ident)

        except Exception as e:
            logger.warning("Failed to list app credentials: %s", e)

        logger.info("Found %d app credentials", len(identities))
        return identities

    def _get_role_assignments(self) -> Dict[str, List[str]]:
        """Get RBAC role assignments mapped by principal ID."""
        role_map: Dict[str, List[str]] = {}

        try:
            auth = self._get_auth_client()

            sub_scope = f"/subscriptions/{self._get_subscription_id()}"

            # Build role definition name cache
            role_defs = {}
            for rd in auth.role_definitions.list(scope=sub_scope):
                role_defs[rd.id] = rd.role_name

            # List all role assignments at subscription level
            for ra in auth.role_assignments.list_for_subscription():
                principal_id = ra.principal_id
                role_name = role_defs.get(ra.role_definition_id, ra.role_definition_id)
                scope = ra.scope or ""
                role_map.setdefault(principal_id, []).append(
                    f"{role_name} @ {scope}"
                )

        except Exception as e:
            logger.warning("Failed to list role assignments: %s", e)

        return role_map
