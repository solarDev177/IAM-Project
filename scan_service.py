"""Helpers for batching, parsing, and normalizing IAM risk scan results."""

import json
import re
import time
from typing import Any, Callable, Dict, List, Optional

import g4f

from permission_service import GroupPermissionService


class RiskScanService:
    """Runs Cloudflare IAM risk scans and stabilizes their results."""

    def __init__(self):
        """Initialize the local helpers used to normalize scan output."""
        self.permission_service = GroupPermissionService()

    @staticmethod
    def coerce_scan_response_text(result: Any) -> str:
        """Convert a g4f response object into plain text."""
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            if isinstance(result.get("text"), str):
                return result["text"]

            choices = result.get("choices")
            if isinstance(choices, list) and choices:
                first = choices[0]
                if isinstance(first, dict):
                    message = first.get("message")
                    if isinstance(message, dict) and isinstance(message.get("content"), str):
                        return message["content"]
                    if isinstance(first.get("text"), str):
                        return first["text"]

            message = result.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]

        content = getattr(result, "content", None)
        if isinstance(content, str):
            return content

        text = getattr(result, "text", None)
        if isinstance(text, str):
            return text

        return str(result)

    @staticmethod
    def normalize_scan_response_text(result: Any) -> str:
        """Strip common markdown wrappers from a scan response."""
        text = RiskScanService.coerce_scan_response_text(result)
        text = text.replace("\r\n", "\n")
        text = re.sub(r"^\s*[*-]\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"^\s*#+\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"^\s*\*\*(.*?)\*\*\s*$", r"\1", text, flags=re.MULTILINE)
        return text.strip()

    @staticmethod
    def extract_scan_section(result: str, label: str) -> str:
        """Return the text that belongs to one named scan section."""
        escaped_label = re.escape(label)
        pattern = (
            rf"(?:^|\n)\s*(?:\*\*)?{escaped_label}(?:\*\*)?\s*[:\-]\s*(.*?)(?=\n\s*(?:\*\*)?"
            rf"(?:Overall Risk Level|Reason|Low Risk Roles?|Medium Risk Roles?|High Risk Roles?|Critical Risk Roles?)"
            rf"(?:\*\*)?\s*[:\-]|\Z)"
        )
        match = re.search(pattern, result or "", re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        return match.group(1).strip()

    @staticmethod
    def parse_risk_items(result: str, label: str) -> List[str]:
        """Parse a named list of risky permissions from the response text."""
        raw_items = RiskScanService.extract_scan_section(result, label)
        if not raw_items:
            return []

        raw_items = raw_items.strip().strip("()[]")
        lowered = raw_items.lower()
        if lowered in {
            "none",
            "n/a",
            "na",
            "no roles",
            "no permissions",
            "no high risk roles",
            "no critical risk roles",
            "none identified",
        }:
            return []

        items = []
        seen = set()
        for part in re.split(r",|\n|;", raw_items):
            cleaned = re.sub(r"^\s*(?:[*-]|\d+\.)\s*", "", part)
            cleaned = cleaned.strip().strip(".").strip()
            cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", cleaned).strip()
            if not cleaned or cleaned.lower() in {"none", "n/a", "na"}:
                continue
            key = cleaned.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append(cleaned)

        return items

    @staticmethod
    def infer_overall_risk_level(high_items: List[str], critical_items: List[str], result: str) -> str:
        """Infer a fallback overall severity when the model omits it."""
        if critical_items:
            return "Critical"
        if high_items:
            return "High"

        normalized = (result or "").lower()
        if "medium risk" in normalized:
            return "Medium"
        if "low risk" in normalized:
            return "Low"
        return ""

    @staticmethod
    def parse_overall_risk_level(result: str) -> str:
        """Parse the overall severity label from the response text."""
        section = RiskScanService.extract_scan_section(result, "Overall Risk Level")
        if not section:
            match = re.search(
                r"overall\s+risk\s+level\s*[:\-]?\s*(critical|high|medium|low)",
                result or "",
                re.IGNORECASE,
            )
            if not match:
                return ""
            return match.group(1).strip().title()

        line = section.splitlines()[0].strip()
        line = re.sub(r"^\s*(?:[*-]|\d+\.)\s*", "", line)
        line = line.strip(". ").title()
        if line.lower() in {"critical", "high", "medium", "low"}:
            return line
        return ""

    def parse_member_scan_result(self, result: str) -> dict:
        """Parse one raw scan response into the app's normalized risk shape."""
        normalized_result = self.normalize_scan_response_text(result)
        high_items = self.parse_risk_items(normalized_result, "High Risk Roles")
        critical_items = self.parse_risk_items(normalized_result, "Critical Risk Roles")
        overall = self.parse_overall_risk_level(normalized_result)
        if not overall:
            overall = self.infer_overall_risk_level(high_items, critical_items, normalized_result)

        return self.apply_local_risk_overrides({
            "raw": normalized_result,
            "overall": overall,
            "high": high_items,
            "critical": critical_items,
        })

    @staticmethod
    def default_scan_result(raw: str = "", overall: str = "Unknown") -> dict:
        """Return the default risk payload used for missing or invalid scan data."""
        return {
            "raw": raw,
            "overall": overall,
            "high": [],
            "critical": [],
        }

    @staticmethod
    def extract_json_payload(text: str) -> str:
        """Extract the first complete JSON payload from a noisy model response."""
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text or "", re.IGNORECASE | re.DOTALL)
        if fenced:
            text = fenced.group(1).strip()
        else:
            text = (text or "").strip()

        decoder = json.JSONDecoder()
        for opener in ("{", "["):
            start = text.find(opener)
            if start == -1:
                continue
            candidate = text[start:].lstrip()
            try:
                _parsed, end_index = decoder.raw_decode(candidate)
                return candidate[:end_index].strip()
            except json.JSONDecodeError:
                continue

        return text

    @staticmethod
    def normalize_risk_level_value(value: Any) -> str:
        """Normalize a free-form severity value into one of the app's four levels."""
        normalized = str(value or "").strip().lower()
        if normalized in {"critical", "high", "medium", "low"}:
            return normalized.title()
        return ""

    @staticmethod
    def coerce_risk_list(values: Any) -> List[str]:
        """Normalize a JSON value into a deduplicated list of permissions."""
        if values is None:
            return []
        if isinstance(values, str):
            values = [part.strip() for part in re.split(r",|\n|;", values) if part.strip()]
        elif not isinstance(values, list):
            values = [str(values).strip()]

        cleaned: List[str] = []
        seen = set()
        for value in values:
            item = str(value).strip().strip(".")
            if not item or item.lower() in {"none", "n/a", "na"}:
                continue
            key = item.lower()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(item)

        return cleaned

    def coerce_batch_scan_entry(self, entry: Any) -> dict:
        """Convert one batch-scan JSON record into the app's normalized risk shape."""
        if isinstance(entry, str):
            return self.parse_member_scan_result(entry)

        if not isinstance(entry, dict):
            return self.default_scan_result(str(entry or ""))

        raw = json.dumps(entry, ensure_ascii=False)
        high_items = self.coerce_risk_list(entry.get("high") or entry.get("high_risk") or entry.get("high_risk_roles"))
        critical_items = self.coerce_risk_list(
            entry.get("critical") or entry.get("critical_risk") or entry.get("critical_risk_roles")
        )
        overall = self.normalize_risk_level_value(
            entry.get("overall") or entry.get("overall_risk") or entry.get("overall_risk_level")
        )
        if not overall:
            overall = self.infer_overall_risk_level(high_items, critical_items, raw)

        return self.apply_local_risk_overrides({
            "raw": raw,
            "overall": overall or "Unknown",
            "high": high_items,
            "critical": critical_items,
        })

    @staticmethod
    def risk_rank(level: str) -> int:
        """Map a severity label to a sortable integer rank."""
        ranks = {
            "unknown": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return ranks.get((level or "").strip().lower(), 0)

    @staticmethod
    def override_permission_severity(permission: str) -> str:
        """Return a deterministic severity override for sensitive admin-class permissions."""
        normalized = (permission or "").strip().lower()
        if not normalized:
            return ""

        critical_markers = (
            "super administrator",
            "super admin",
            "super-administrator",
            "super-admin",
            "account owner",
            "owner",
        )
        if any(marker in normalized for marker in critical_markers):
            return "Critical"

        high_markers = (
            "administrator",
            "admin",
        )
        if any(marker in normalized for marker in high_markers):
            return "High"

        return ""

    def apply_local_risk_overrides(self, parsed_result: dict) -> dict:
        """Normalize the model output with deterministic local severity rules."""
        high_items = self.permission_service.dedupe_names(list(parsed_result.get("high") or []))
        critical_items = self.permission_service.dedupe_names(list(parsed_result.get("critical") or []))

        promoted_to_critical: List[str] = []
        retained_high: List[str] = []

        for permission in high_items:
            override = self.override_permission_severity(permission)
            if override == "Critical":
                promoted_to_critical.append(permission)
            else:
                retained_high.append(permission)

        for permission in critical_items:
            override = self.override_permission_severity(permission)
            if override == "High":
                retained_high.append(permission)
            else:
                promoted_to_critical.append(permission)

        normalized_critical = self.permission_service.dedupe_names(promoted_to_critical)
        normalized_high = [
            permission for permission in self.permission_service.dedupe_names(retained_high)
            if permission.lower() not in {item.lower() for item in normalized_critical}
        ]

        overall = parsed_result.get("overall") or "Unknown"
        if normalized_critical and self.risk_rank(overall) < self.risk_rank("Critical"):
            overall = "Critical"
        elif normalized_high and self.risk_rank(overall) < self.risk_rank("High"):
            overall = "High"

        return {
            "raw": parsed_result.get("raw", ""),
            "overall": overall,
            "high": normalized_high,
            "critical": normalized_critical,
        }

    @staticmethod
    def risk_tag_for_level(level: str) -> str:
        """Map a severity level to the UI tag used for colored text."""
        normalized = (level or "").strip().lower()
        if normalized == "critical":
            return "risk_critical"
        if normalized == "high":
            return "risk_high"
        if normalized == "medium":
            return "risk_medium"
        if normalized == "low":
            return "risk_low"
        return "scan_muted"

    @staticmethod
    def scan_profile_key(group_name: str, roles_text: str) -> str:
        """Return the cache key for one group and permission profile."""
        return f"{group_name}|{roles_text}"

    def is_rate_limited(self, result: Any) -> bool:
        """Detect whether a scan response is really a throttle message."""
        normalized = self.normalize_scan_response_text(result).lower()
        if not normalized:
            return False

        markers = (
            "rate limit",
            "too many requests",
            "temporarily restricted",
            "temporarily limited",
            "try again in",
            "request limit",
            "该请求过多已被暂时限制",
            "请求过多已被暂时限制",
            "两分钟后再试",
            "每小时60次",
        )
        return any(marker in normalized for marker in markers)

    def scan_member_risk(
        self,
        member_roles: str,
        member_group: str,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Run one direct scan request for a single permission profile."""
        prompt = (
            f"For a cloudflare role of {member_group} can you provide me with an overall risk level "
            f"of low, medium, high, and critical if they were properly trained: {member_roles}. "
            f"At the end, also provide an overall risk level of all the roles combined together.\n\n"
            f"Rule: any Super Administrator or Super Admin permission must be treated as Critical.\n"
            f"Format (Do not include any other words other than the actual permission themselves:\n"
            f"Overall Risk Level:\n"
            f"Reason:\n"
            f"Low Risk Roles: (Role, Role, Role...)\n"
            f"Medium Risk Roles: (Role, Role, Role...)\n"
            f"High Risk Roles: (Role, Role, Role...)\n"
            f"Critical Risk Roles: (Role, Role, Role...)"
        )

        delays = [0, 10, 20]

        for attempt, delay_seconds in enumerate(delays, start=1):
            if delay_seconds:
                if status_callback is not None:
                    status_callback(
                        f"Rate limited by the risk scanner. Waiting {delay_seconds}s before retry {attempt}/{len(delays)}..."
                    )
                time.sleep(delay_seconds)

            response = g4f.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )

            if not self.is_rate_limited(response):
                return response

        raise RuntimeError("Risk scanner rate limited after multiple retries.")

    def scan_member_risks_batch(
        self,
        scan_requests: Dict[str, dict],
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, dict]:
        """Run one batched scan request for every uncached profile."""
        if not scan_requests:
            return {}

        if status_callback is not None:
            status_callback(f"Sending 1 batched risk scan request for {len(scan_requests)} profiles...")

        profiles = []
        for profile_id, request in scan_requests.items():
            profiles.append(
                {
                    "id": profile_id,
                    "group": request["group_name"],
                    "permissions": request["roles_text"],
                }
            )

        prompt = (
            "Evaluate the Cloudflare IAM risk for each profile below.\n"
            "Return ONLY valid JSON with this exact shape:\n"
            "{\n"
            '  "profiles": {\n'
            '    "<id>": {\n'
            '      "overall": "Low|Medium|High|Critical",\n'
            '      "high": ["permission", "..."],\n'
            '      "critical": ["permission", "..."]\n'
            "    }\n"
            "  }\n"
            "}\n"
            "Rules:\n"
            "- Do not include markdown or code fences.\n"
            "- Use empty arrays when there are no high or critical permissions.\n"
            "- Every profile id must appear exactly once.\n"
            "- Any Super Administrator or Super Admin permission must be classified as Critical.\n"
            "- Only include permissions that belong in the high or critical list.\n\n"
            f"Profiles:\n{json.dumps(profiles, ensure_ascii=False)}"
        )

        response = g4f.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )

        if self.is_rate_limited(response):
            raise RuntimeError("Risk scanner rate limited for the batched request.")

        raw_text = self.coerce_scan_response_text(response)
        payload_text = self.extract_json_payload(raw_text)

        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as err:
            raise RuntimeError(f"Could not parse batched risk response: {err}") from err

        profile_map = payload.get("profiles", payload) if isinstance(payload, dict) else {}
        if not isinstance(profile_map, dict):
            raise RuntimeError("Batched risk response did not include a profiles object.")

        parsed_results: Dict[str, dict] = {}
        for profile_id in scan_requests:
            entry = profile_map.get(profile_id)
            if entry is None:
                parsed_results[profile_id] = self.default_scan_result(
                    raw=f"Missing batched result for {profile_id}",
                    overall="Unknown",
                )
                continue
            parsed_results[profile_id] = self.coerce_batch_scan_entry(entry)

        return parsed_results
