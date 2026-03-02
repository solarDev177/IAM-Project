# Cloudflare IAM Explorer
# Client

import requests
from api_handler import CloudflareAPIError

BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareClient:
    def __init__(self, token: str, timeout: int = 30):
        self.token = token.strip()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, params=None, json=None):
        url = f"{BASE_URL}{path}"
        resp = self.session.request(
            method,
            url,
            params=params,
            json=json,
            timeout=self.timeout
        )

        try:
            data = resp.json()
        except ValueError:
            raise CloudflareAPIError(
                f"Non-JSON response ({resp.status_code}): {resp.text[:200]}"
            )

        if not resp.ok or not data.get("success", False):
            raise CloudflareAPIError(
                f"HTTP {resp.status_code} {path}\n"
                f"errors={data.get('errors')}\n"
                f"messages={data.get('messages')}"
            )

        return data

    # ---------------- Token / account ----------------

    def verify_token_for_account(self, account_id: str):
        return self._request("GET", f"/accounts/{account_id}/tokens/verify")

    def get_account(self, account_id: str):
        return self._request("GET", f"/accounts/{account_id}")

    def list_accounts(self, page: int = 1, per_page: int = 50):
        return self._request(
            "GET",
            "/accounts",
            params={"page": page, "per_page": per_page}
        )

    # ---------------- Members ----------------

    def list_members(self, account_id: str, page: int = 1, per_page: int = 50):
        return self._request(
            "GET",
            f"/accounts/{account_id}/members",
            params={"page": page, "per_page": per_page}
        )

    def get_member(self, account_id: str, member_id: str):
        return self._request(
            "GET",
            f"/accounts/{account_id}/members/{member_id}"
        )

    def add_member(self, account_id: str, email: str, role_ids: list[str]):
        payload = {
            "email": email,
            "roles": [{"id": rid} for rid in role_ids],
        }
        return self._request(
            "POST",
            f"/accounts/{account_id}/members",
            json=payload
        )

    def delete_member(self, account_id: str, member_id: str):
        return self._request(
            "DELETE",
            f"/accounts/{account_id}/members/{member_id}"
        )

    def update_member_roles(self, account_id: str, member_id: str, role_ids: list[str]):
        payload = {
            "roles": [{"id": rid} for rid in role_ids]
        }
        return self._request(
            "PUT",
            f"/accounts/{account_id}/members/{member_id}",
            json=payload
        )

    # ---------------- Roles ----------------

    def list_roles(self, account_id: str, page: int = 1, per_page: int = 50):
        return self._request(
            "GET",
            f"/accounts/{account_id}/roles",
            params={"page": page, "per_page": per_page}
        )

    # ---------------- IAM User Groups ----------------

    def list_user_groups(self, account_id: str, page: int = 1, per_page: int = 50):
        return self._request(
            "GET",
            f"/accounts/{account_id}/iam/user_groups",
            params={"page": page, "per_page": per_page}
        )

    def get_user_group(self, account_id: str, group_id: str):
        return self._request(
            "GET",
            f"/accounts/{account_id}/iam/user_groups/{group_id}"
        )

    def update_user_group(self, account_id: str, group_id: str, name: str, policies=None):
        payload = {"name": name}

        if policies is not None:
            payload["policies"] = policies

        return self._request(
            "PUT",
            f"/accounts/{account_id}/iam/user_groups/{group_id}",
            json=payload
        )

    def create_user_group(self, account_id: str, name: str):
        return self._request(
            "POST",
            f"/accounts/{account_id}/iam/user_groups",
            json={"name": name}
        )

    def delete_user_group(self, account_id: str, group_id: str):
        return self._request(
            "DELETE",
            f"/accounts/{account_id}/iam/user_groups/{group_id}"
        )

    def list_user_group_members(self, account_id: str, group_id: str, page: int = 1, per_page: int = 50):
        return self._request(
            "GET",
            f"/accounts/{account_id}/iam/user_groups/{group_id}/members",
            params={"page": page, "per_page": per_page}
        )

    def add_members_to_user_group(self, account_id: str, group_id: str, member_ids: list[str]):
        payload = [{"id": mid} for mid in member_ids]
        return self._request(
            "POST",
            f"/accounts/{account_id}/iam/user_groups/{group_id}/members",
            json=payload
        )

    def replace_user_group_members(self, account_id: str, group_id: str, member_ids: list[str]):
        payload = [{"id": mid} for mid in member_ids]
        return self._request(
            "PUT",
            f"/accounts/{account_id}/iam/user_groups/{group_id}/members",
            json=payload
        )

    def remove_member_from_user_group(self, account_id: str, group_id: str, member_id: str):
        return self._request(
            "DELETE",
            f"/accounts/{account_id}/iam/user_groups/{group_id}/members/{member_id}"
        )

    def list_permission_groups(self, account_id: str, page: int = 1, per_page: int = 100):
        return self._request(
            "GET",
            f"/accounts/{account_id}/iam/permission_groups",
            params={"page": page, "per_page": per_page}
        )

    def list_resource_groups(self, account_id: str):
        return self._request(
            "GET",
            f"/accounts/{account_id}/iam/resource_groups"
        )
