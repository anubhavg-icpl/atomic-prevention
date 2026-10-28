"""Small, read-only UEC API client used for QA correlation.

The client intentionally supports only the endpoints needed to correlate an
Atomic Prevention run with endpoint telemetry. Credentials stay in backend
settings and are never placed in a playbook export or sent to Claude.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from backend.app.core.config import settings


class UecUnavailable(RuntimeError):
    pass


def _validate_https_or_local(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise UecUnavailable("UEC base URL must use http or https")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise UecUnavailable("Non-local UEC URLs must use https")
    return url.rstrip("/")


class UecClient:
    def __init__(
        self,
        base_url: str | None = None,
        tenant: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float | None = None,
    ):
        self.base_url = _validate_https_or_local(base_url or settings.uec_base_url)
        tenant = tenant or settings.uec_tenant
        if "/t/" not in self.base_url:
            self.base_url = f"{self.base_url}/t/{tenant}"
        self.token = token or settings.uec_token
        self.username = username or settings.uec_username
        self.password = password or settings.uec_password
        self.timeout = timeout or settings.uec_timeout_seconds
        self._login_attempted = False

    @property
    def configured(self) -> bool:
        return settings.uec_enabled and bool(self.token or (self.username and self.password))

    async def _login(self) -> str:
        if self.token:
            return self.token
        if not self.username or not self.password or self._login_attempted:
            raise UecUnavailable("UEC credentials are not configured")
        self._login_attempted = True
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/v1/Auth/login",
                    json={"email": self.username, "password": self.password},
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise UecUnavailable("UEC login failed") from exc
        except ValueError as exc:
            raise UecUnavailable("UEC login returned invalid JSON") from exc

        token = None
        if isinstance(payload, dict):
            nested = payload.get("data")
            token = (
                payload.get("accessToken")
                or payload.get("access_token")
                or payload.get("token")
                or (nested.get("accessToken") if isinstance(nested, dict) else None)
            )
        if not isinstance(token, str) or not token:
            raise UecUnavailable("UEC login response did not contain an access token")
        self.token = token
        return token

    async def _request(
        self, method: str, path: str, params: dict[str, Any] | None = None, json_body: dict[str, Any] | None = None
    ) -> Any:
        if not self.configured:
            raise UecUnavailable("UEC token is not configured")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers={"Authorization": f"Bearer {await self._login()}"},
                    params=params,
                    json=json_body,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise UecUnavailable(f"UEC request failed: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise UecUnavailable("UEC returned an invalid JSON response") from exc

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def health(self) -> dict[str, Any]:
        data = await self._get("/api/v1/about")
        return data if isinstance(data, dict) else {"result": data}

    async def find_device(self, hostname: str) -> dict[str, Any] | None:
        data = await self._get(
            "/api/v1/devices", {"search": hostname, "page": 1, "pageSize": 20}
        )
        items = _items(data)
        lowered = hostname.lower()
        for item in items:
            for key in ("hostName", "hostname", "deviceName", "name"):
                if str(item.get(key, "")).lower() == lowered:
                    return item
        for item in items:
            for key in ("hostName", "hostname", "deviceName", "name"):
                value = str(item.get(key, "")).lower()
                if value and lowered in value:
                    return item
        return None

    async def event_logs(
        self,
        *,
        hostname: str,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        device_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        completed = _utc(completed_at or datetime.now(timezone.utc))
        started = _utc(started_at or (completed - timedelta(hours=1)))
        params: dict[str, Any] = {
            "startDate": started.isoformat(),
            "endDate": completed.isoformat(),
            "pageSize": max(1, min(limit, 200)),
            "withTotal": "true",
        }
        if device_id:
            params["deviceId"] = device_id
        elif hostname:
            params["deviceName"] = hostname
        data = await self._get("/api/v1/event-logs", params)
        return _sanitize_page(data, limit)

    async def threat_findings(
        self,
        *,
        device_id: str | None = None,
        days: int = 1,
        limit: int = 100,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"days": days, "limit": max(1, min(limit, 200))}
        if device_id:
            params["deviceId"] = device_id
        data = await self._get("/api/v1/threat-detection/findings", params)
        return _sanitize_page(data, limit, started_at=started_at, completed_at=completed_at)

    async def device_detection_state(self, device_id: str) -> dict[str, Any]:
        data = await self._get(
            f"/api/v1/threat-detection/devices/{quote(str(device_id), safe='')}/state"
        )
        return data if isinstance(data, dict) else {"result": data}


def _items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("items", "results", "data", "findings"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _sanitize_page(
    payload: Any,
    limit: int,
    *,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> dict[str, Any]:
    start = _utc(started_at) if started_at else None
    end = _utc(completed_at) if completed_at else None
    items = []
    for raw in _items(payload):
        item = _clean_event(raw)
        timestamp = _parse_datetime(
            item.get("timeGenerated") or item.get("occurredAt") or item.get("timestamp")
        )
        if start and (not timestamp or timestamp < start - timedelta(minutes=1)):
            continue
        if end and (not timestamp or timestamp > end + timedelta(minutes=5)):
            continue
        items.append(item)
        if len(items) >= limit:
            break
    return {
        "items": items,
        "total": payload.get("total") if isinstance(payload, dict) else len(items),
        "has_more": bool(payload.get("hasMore")) if isinstance(payload, dict) else False,
    }


def _clean_event(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {"value": str(item)[:1000]}
    keys = (
        "id", "alertId", "deviceId", "deviceName", "timeGenerated", "timestamp",
        "occurredAt", "eventType",
        "eventId", "message", "fileName", "filePath", "fileHash", "processName",
        "userName", "policyName", "severity", "severityId", "isBlocked",
        "blockReason", "technique", "tactic", "control", "framework", "title",
        "techniques", "tactics", "ruleUid", "description", "status", "confidence",
    )
    result = {key: item.get(key) for key in keys if key in item}
    result.setdefault("id", "")
    result.setdefault("timeGenerated", item.get("occurredAt") or item.get("timestamp"))
    result.setdefault("message", item.get("description") or item.get("title"))
    return result


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (TypeError, ValueError):
        return None
