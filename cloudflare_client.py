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
        resp = self.session.request(method, url, params=params, json=json, timeout=self.timeout)

        try:
            data = resp.json()
        except ValueError:
            raise CloudflareAPIError(f"Non-JSON response ({resp.status_code}): {resp.text[:200]}")

        # Cloudflare returns { success, errors, messages, result, result_info }
        if not resp.ok or not data.get("success", False):
            raise CloudflareAPIError(
                f"HTTP {resp.status_code} {path}\n"
                f"errors={data.get('errors')}\nmessages={data.get('messages')}"
            )
        return data


    def verify_token(self):
        ACCOUNT_ID = "3ef9aca3e663821dd1413c72b4ae0db8"
        return self._request("GET", f"/accounts/{ACCOUNT_ID}/tokens/verify")

    def list_accounts(self, page=1, per_page=50):
        return self._request("GET", "/accounts", params={"page": page, "per_page": per_page})

    def list_members(self, account_id: str, page=1, per_page=50):
        return self._request("GET", f"/accounts/{account_id}/members", params={"page": page, "per_page": per_page})

    def list_user_groups(self, account_id: str, page=1, per_page=50):
        return self._request("GET", f"/accounts/{account_id}/iam/user_groups",
                             params={"page": page, "per_page": per_page})
