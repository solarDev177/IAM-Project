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

    def _request_all_pages(self, path: str, params=None, per_page: int = 100):
        """Load every page for a paginated Cloudflare list endpoint."""
        merged_params = dict(params or {})
        page = int(merged_params.pop("page", 1) or 1)
        per_page = int(merged_params.pop("per_page", per_page) or per_page)
        results = []
        last_response = None

        while True:
            page_params = dict(merged_params)
            page_params.update({"page": page, "per_page": per_page})
            data = self._request("GET", path, params=page_params)
            last_response = data

            page_results = data.get("result") or []
            if not isinstance(page_results, list):
                return data

            results.extend(page_results)

            result_info = data.get("result_info") or {}
            total_pages = int(result_info.get("total_pages") or 0)
            count = int(result_info.get("count") or len(page_results))

            if total_pages and page >= total_pages:
                break
            if not page_results or count < per_page:
                break

            page += 1

        if last_response is None:
            return {"result": results, "success": True}

        last_response["result"] = results
        return last_response

    # ---------------- Token / account ----------------

    def verify_token_for_account(self, account_id: str):
        return self._request("GET", f"/accounts/{account_id}/tokens/verify")

    def get_account(self, account_id: str):
        return self._request("GET", f"/accounts/{account_id}")

    def list_accounts(self, page: int = 1, per_page: int = 50):
        return self._request_all_pages("/accounts", params={"page": page, "per_page": per_page})

    # ---------------- Members ----------------

    def list_members(self, account_id: str, page: int = 1, per_page: int = 50):
        return self._request_all_pages(
            f"/accounts/{account_id}/members",
            params={"page": page, "per_page": per_page},
        )

    def get_member(self, account_id: str, member_id: str):
        return self._request(
            "GET",
            f"/accounts/{account_id}/members/{member_id}"
        )

    def add_member(self, account_id: str, email: str, role_ids: list[str]):
        payload = {
            "email": email,
            "roles": role_ids if isinstance(role_ids, list) else [role_ids],
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
        return self._request_all_pages(
            f"/accounts/{account_id}/roles",
            params={"page": page, "per_page": per_page},
        )

    # ---------------- IAM User Groups ----------------

    def list_user_groups(self, account_id: str, page: int = 1, per_page: int = 50):
        return self._request_all_pages(
            f"/accounts/{account_id}/iam/user_groups",
            params={"page": page, "per_page": per_page},
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
        return self._request_all_pages(
            f"/accounts/{account_id}/iam/user_groups/{group_id}/members",
            params={"page": page, "per_page": per_page},
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
        return self._request_all_pages(
            f"/accounts/{account_id}/iam/permission_groups",
            params={"page": page, "per_page": per_page},
        )

    def list_resource_groups(self, account_id: str):
        return self._request(
            "GET",
            f"/accounts/{account_id}/iam/resource_groups"
        )
