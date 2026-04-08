"""Helpers for formatting and caching Cloudflare group permissions."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple


class GroupPermissionService:
    """Collects and formats member and group permission data."""

    @staticmethod
    def dedupe_names(values: List[str]) -> List[str]:
        """Return the first occurrence of each non-empty name."""
        unique: List[str] = []
        seen = set()

        for value in values:
            cleaned = (value or "").strip()
            if not cleaned:
                continue
            key = cleaned.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(cleaned)

        return unique

    def extract_group_permission_names(self, group_detail: dict) -> List[str]:
        """Pull the distinct permission names out of a Cloudflare group payload."""
        policies = group_detail.get("policies", []) or []
        if not policies:
            return []

        found: List[str] = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            for field in ("permission_groups", "permissions", "roles"):
                items = policy.get(field, []) or []
                for item in items:
                    if isinstance(item, dict):
                        name = (
                            item.get("name")
                            or item.get("label")
                            or item.get("permission")
                            or item.get("id")
                            or ""
                        ).strip()
                    else:
                        name = str(item).strip()

                    if name:
                        found.append(name)

        return self.dedupe_names(found)

    def format_group_permissions(self, group_detail: dict) -> str:
        """Return a shortened permission summary for card-style UI rows."""
        unique = self.extract_group_permission_names(group_detail)

        if not unique:
            return "No permissions assigned"
        if len(unique) <= 5:
            return ", ".join(unique)
        return ", ".join(unique[:5]) + f" +{len(unique) - 5} more"

    def format_full_group_permissions(self, group_detail: dict) -> str:
        """Return the full permission list for a group."""
        unique = self.extract_group_permission_names(group_detail)
        if not unique:
            return "No permissions assigned"
        return ", ".join(unique)

    def build_group_permissions_cache(
        self,
        account_id: str,
        members: List[dict],
        client_factory: Callable[[str], Any],
        max_workers: int = 6,
    ) -> Tuple[Dict[str, List[str]], List[str]]:
        """Fetch each distinct group's permissions once and cache the results by group id."""
        group_ids: List[str] = []
        seen = set()

        for member in members:
            for group in member.get("user_groups") or []:
                if not isinstance(group, dict):
                    continue
                group_id = (group.get("id") or "").strip()
                if not group_id or group_id in seen:
                    continue
                seen.add(group_id)
                group_ids.append(group_id)

        if not group_ids:
            return {}, []

        group_permissions_by_id: Dict[str, List[str]] = {}
        errors: List[str] = []

        def load_group_permissions(group_id: str) -> Tuple[str, List[str]]:
            """Load and normalize the permissions for one Cloudflare group."""
            client = client_factory("groups_read")
            resp = client.get_user_group(account_id, group_id)
            group_detail = resp.get("result") or {}
            return group_id, self.extract_group_permission_names(group_detail)

        worker_count = min(max_workers, len(group_ids))
        if worker_count <= 1:
            for group_id in group_ids:
                try:
                    gid, permissions = load_group_permissions(group_id)
                    group_permissions_by_id[gid] = permissions
                except Exception as err:
                    errors.append(f"Failed to load permissions for group {group_id}: {err}")
            return group_permissions_by_id, errors

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_group = {
                executor.submit(load_group_permissions, group_id): group_id
                for group_id in group_ids
            }
            for future in as_completed(future_to_group):
                group_id = future_to_group[future]
                try:
                    gid, permissions = future.result()
                    group_permissions_by_id[gid] = permissions
                except Exception as err:
                    errors.append(f"Failed to load permissions for group {group_id}: {err}")

        return group_permissions_by_id, errors

    def get_full_member_permissions(
        self,
        account_id: str,
        member: dict,
        client_factory: Callable[[str], Any],
        group_permissions_by_id: Optional[Dict[str, List[str]]] = None,
    ) -> str:
        """Return the member's direct roles plus any user-group permissions."""
        roles = member.get("roles") or []
        role_names = [role.get("name", "") for role in roles if isinstance(role, dict)]

        permission_names: List[str] = []
        fallback_client: Optional[Any] = None

        for group in member.get("user_groups") or []:
            if not isinstance(group, dict):
                continue

            group_id = (group.get("id") or "").strip()
            if not group_id:
                continue

            if group_permissions_by_id is not None:
                permission_names.extend(group_permissions_by_id.get(group_id, []))
                continue

            if fallback_client is None:
                fallback_client = client_factory("groups_read")

            resp = fallback_client.get_user_group(account_id, group_id)
            group_detail = resp.get("result") or {}
            permission_names.extend(self.extract_group_permission_names(group_detail))

        combined_permissions = self.dedupe_names(role_names + permission_names)
        return ", ".join(combined_permissions) or "(no roles)"
