"""GitLab REST API adapter. Credentials are read only from backend settings."""

from typing import Any
from urllib.parse import quote, urlparse

import httpx

from backend.app.core.config import settings


class GitlabUnavailable(RuntimeError):
    pass


class GitlabClient:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = (base_url or settings.gitlab_url).rstrip("/")
        self.token = token or settings.gitlab_token
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            raise GitlabUnavailable("GitLab URL must use https")

    @property
    def configured(self) -> bool:
        return settings.gitlab_enabled and bool(self.token)

    async def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        if not self.configured:
            raise GitlabUnavailable("GitLab token is not configured")
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.request(
                    method,
                    f"{self.base_url}/api/v4{path}",
                    headers={"PRIVATE-TOKEN": self.token},
                    params=params,
                    json=json_body,
                )
            if response.status_code >= 400:
                raise GitlabUnavailable(f"GitLab API returned HTTP {response.status_code}")
            if response.status_code == 204:
                return None
            return response.json()
        except httpx.HTTPError as exc:
            raise GitlabUnavailable(f"GitLab request failed: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise GitlabUnavailable("GitLab returned invalid JSON") from exc

    async def search_projects(self, search: str, limit: int = 20) -> list[dict[str, Any]]:
        data = await self._request(
            "/projects",
            params={
                "search": search,
                "membership": "true",
                "simple": "true",
                "order_by": "last_activity_at",
                "per_page": max(1, min(limit, 100)),
            },
        )
        if not isinstance(data, list):
            return []
        return [
            {
                "id": str(item.get("id", "")),
                "name": item.get("name", ""),
                "path_with_namespace": item.get("path_with_namespace", ""),
                "web_url": item.get("web_url", ""),
                "last_activity_at": item.get("last_activity_at"),
                "open_issues_count": item.get("open_issues_count", 0),
            }
            for item in data
            if isinstance(item, dict)
        ]

    async def get_project(self, project_id_or_path: str) -> dict[str, Any]:
        item = await self._request(f"/projects/{quote(str(project_id_or_path), safe='')}")
        if not isinstance(item, dict):
            raise GitlabUnavailable("GitLab project response was invalid")
        return item

    async def find_issue_by_marker(self, project_id: str, marker: str) -> dict[str, Any] | None:
        data = await self._request(
            f"/projects/{quote(str(project_id), safe='')}/issues",
            params={"search": marker, "in": "description", "state": "opened", "per_page": 20},
        )
        if not isinstance(data, list):
            return None
        for issue in data:
            if isinstance(issue, dict) and marker in str(issue.get("description", "")):
                return issue
        return None

    async def create_issue(
        self,
        *,
        project_id: str,
        title: str,
        description: str,
        labels: list[str] | None = None,
        marker: str | None = None,
    ) -> dict[str, Any]:
        if marker:
            existing = await self.find_issue_by_marker(project_id, marker)
            if existing:
                return {
                    "created": False,
                    "issue": existing,
                    "project_id": str(project_id),
                }

        safe_labels = sorted({
            label.strip()
            for label in (labels or [])
            if label.strip() and len(label.strip()) <= 64 and "\n" not in label
        })[:10]
        issue = await self._request(
            f"/projects/{quote(str(project_id), safe='')}/issues",
            method="POST",
            json_body={
                "title": title[:255],
                "description": description[:1_000_000],
                "labels": safe_labels,
            },
        )
        if not isinstance(issue, dict):
            raise GitlabUnavailable("GitLab issue response was invalid")
        return {"created": True, "issue": issue, "project_id": str(project_id)}
