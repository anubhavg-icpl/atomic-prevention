from fastapi import APIRouter, Query

from backend.app.core.config import settings
from backend.app.services.claude_client import ClaudeClient
from backend.app.services.gitlab_client import GitlabClient
from backend.app.services.uec_client import UecClient

router = APIRouter()


@router.get("/status")
async def integration_status():
    return {
        "claude": {
            "enabled": settings.claude_enabled,
            "configured": settings.claude_enabled and bool(settings.anthropic_api_key),
            "model": settings.anthropic_model,
        },
        "gitlab": {
            "enabled": settings.gitlab_enabled,
            "configured": settings.gitlab_enabled and bool(settings.gitlab_token),
            "url": settings.gitlab_url,
            "default_project": settings.gitlab_default_project,
        },
        "uec": {
            "enabled": settings.uec_enabled,
            "configured": UecClient().configured,
            "url": settings.uec_base_url,
            "tenant": settings.uec_tenant,
            "correlation_enabled": settings.uec_correlation_enabled,
        },
    }


@router.get("/gitlab/projects")
async def gitlab_projects(search: str = Query(min_length=2, max_length=160)):
    client = GitlabClient()
    projects = await client.search_projects(search)
    return {"projects": projects}
