"""Anthropic Messages API adapter with strict server-side secret handling."""

import asyncio
import json
import re
from typing import Any

import httpx

from backend.app.core.config import settings


class ClaudeUnavailable(RuntimeError):
    pass


class ClaudeClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        api_version: str | None = None,
        max_tokens: int | None = None,
    ):
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.anthropic_model
        self.api_version = api_version or settings.anthropic_version
        self.max_tokens = max_tokens or settings.anthropic_max_tokens

    @property
    def configured(self) -> bool:
        return settings.claude_enabled and bool(self.api_key)

    async def analyze_json(self, system: str, prompt: str) -> dict[str, Any]:
        if not self.configured:
            raise ClaudeUnavailable("Anthropic API key is not configured")

        body = {
            "model": self.model,
            # 42+ findings need ~2900 output tokens even condensed; 4000 truncated it mid-JSON
            "max_tokens": max(256, min(self.max_tokens, 8000)),
            # no "temperature": Sonnet 5.x rejects it with HTTP 400 ("deprecated for this model")
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if re.match(r"claude-[a-z]+-5", self.model):
            # 5.x models think by default and spend max_tokens on it (truncating the JSON);
            # older models reject this field, hence the guard.
            body["thinking"] = {"type": "between_tools"}
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.api_version,
            "content-type": "application/json",
        }

        last_error = "Anthropic request failed"
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=45.0) as client:
                    response = await client.post(
                        "https://api.anthropic.com/v1/messages", headers=headers, json=body
                    )
                if response.status_code in (429, 500, 502, 503, 529) and attempt == 0:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                if response.status_code >= 400:
                    # Only the API's error message; never response headers or the API key.
                    try:
                        detail = str(response.json().get("error", {}).get("message", ""))[:200]
                    except ValueError:
                        detail = ""
                    raise ClaudeUnavailable(
                        f"Anthropic API returned HTTP {response.status_code}"
                        + (f": {detail}" if detail else "")
                    )
                payload = response.json()
                text = "".join(
                    block.get("text", "")
                    for block in payload.get("content", [])
                    if isinstance(block, dict) and block.get("type") == "text"
                )
                parsed = _extract_json(text)
                if not isinstance(parsed, dict):
                    raise ClaudeUnavailable("Anthropic response was not a JSON object")
                parsed["_usage"] = {
                    "input_tokens": payload.get("usage", {}).get("input_tokens", 0),
                    "output_tokens": payload.get("usage", {}).get("output_tokens", 0),
                }
                return parsed
            except httpx.HTTPError as exc:
                last_error = f"Anthropic request failed: {type(exc).__name__}"
                if attempt == 0:
                    await asyncio.sleep(0.5)
                    continue
        raise ClaudeUnavailable(last_error)


def _extract_json(text: str) -> Any:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass
    return None
