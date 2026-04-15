"""Helpers for formatting and caching Cloudflare group permissions."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


class GroupPermissionService:
    """Collects and formats member and group permission data."""

    @staticmethod
    def _policy_item_name(item: Any) -> str:
        """Return the most human-friendly name for a policy item."""
        if isinstance(item, dict):
            return (
                item.get("name")
                or item.get("label")
                or item.get("permission")
                or item.get("id")
                or ""
            ).strip()
        return str(item).strip()

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

    def extract_policy_entries(self, group_detail: dict) -> List[Dict[str, Any]]:
        """Return normalized policy entries while preserving their source field."""
        policies = group_detail.get("policies", []) or []
        if not policies:
            return []

        entries: List[Dict[str, Any]] = []
        seen = set()

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            for field in ("permission_groups", "permissions", "roles"):
                items = policy.get(field, []) or []
                for item in items:
                    name = self._policy_item_name(item)
                    item_id = ""

                    if isinstance(item, dict):
                        item_id = (item.get("id") or "").strip()

                    if not name and not item_id:
                        continue

                    dedupe_key = item_id.lower() if item_id else f"{field}:{name.lower()}"
                    if dedupe_key in seen:
                        continue

                    seen.add(dedupe_key)
                    entries.append(
                        {
                            "field": field,
                            "id": item_id or None,
                            "name": name or item_id,
                            "raw_item": dict(item) if isinstance(item, dict) else item,
                        }
                    )

        return entries

    def extract_group_permission_names(self, group_detail: dict) -> List[str]:
        """Pull the distinct permission names out of a Cloudflare group payload."""
        return self.dedupe_names(
            [
                entry.get("name", "").strip()
                for entry in self.extract_policy_entries(group_detail)
                if entry.get("name")
            ]
        )

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
        cached_permissions_by_id: Optional[Dict[str, List[str]]] = None,
        max_workers: int = 4,
    ) -> Tuple[Dict[str, List[str]], List[str]]:
        """Fetch missing group permissions once and reuse any cached group results."""
        referenced_group_ids: List[str] = []
        seen = set()

        for member in members:
            for group in member.get("user_groups") or []:
                if not isinstance(group, dict):
                    continue
                group_id = (group.get("id") or "").strip()
                if not group_id or group_id in seen:
                    continue
                seen.add(group_id)
                referenced_group_ids.append(group_id)

        if not referenced_group_ids:
            return {}, []

        cached_permissions_by_id = cached_permissions_by_id or {}
        group_permissions_by_id: Dict[str, List[str]] = {
            group_id: list(cached_permissions_by_id.get(group_id, []))
            for group_id in referenced_group_ids
            if group_id in cached_permissions_by_id
        }
        group_ids = [group_id for group_id in referenced_group_ids if group_id not in group_permissions_by_id]
        errors: List[str] = []

        if not group_ids:
            return group_permissions_by_id, errors

        def load_group_permissions(group_id: str) -> Tuple[str, List[str]]:
            """Load and normalize the permissions for one Cloudflare group."""
            client = client_factory("groups_read")
            resp = client.get_user_group(account_id, group_id)
            group_detail = resp.get("result") or {}
            return group_id, self.extract_group_permission_names(group_detail)

        def retry_failed_groups(group_ids_to_retry: List[str]) -> List[str]:
            """Retry failed group permission fetches once in a slower serial pass."""
            if not group_ids_to_retry:
                return []

            time.sleep(1.0)
            retry_errors: List[str] = []

            for group_id in group_ids_to_retry:
                try:
                    gid, permissions = load_group_permissions(group_id)
                    group_permissions_by_id[gid] = permissions
                except Exception as err:
                    retry_errors.append(f"Failed to load permissions for group {group_id}: {err}")

            return retry_errors

        worker_count = min(max_workers, len(group_ids))
        failed_group_ids: List[str] = []

        if worker_count <= 1:
            for group_id in group_ids:
                try:
                    gid, permissions = load_group_permissions(group_id)
                    group_permissions_by_id[gid] = permissions
                except Exception as err:
                    failed_group_ids.append(group_id)
                    errors.append(f"Failed to load permissions for group {group_id}: {err}")
            return group_permissions_by_id, retry_failed_groups(failed_group_ids)

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
                    failed_group_ids.append(group_id)
                    errors.append(f"Failed to load permissions for group {group_id}: {err}")

        if failed_group_ids:
            errors = retry_failed_groups(failed_group_ids)

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
