"""Shared bounded redaction for agent output and endpoint logs."""

import re
from typing import Any

_TRUNCATED = "...[truncated]"

_PATTERNS = [
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|token)\s+)\S+"),
    re.compile(r"(?i)(private-token\s*[:=]\s*)\S+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*)\S+"),
    re.compile(r"(?i)https?://[^/@:\s]+:[^/@\s]+@"),
]

_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "client_secret", "authorization", "x-api-key", "private-token",
}


def redact_text(value: Any, char_limit: int = 16_000) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = "".join(char if char in "\n\r\t" or char >= " " else " " for char in text)
    for pattern in _PATTERNS:
        if pattern.groups:
            text = pattern.sub(r"\1<redacted>", text)
        else:
            text = pattern.sub("<redacted>", text)
    if len(text) > char_limit:
        keep = max(0, char_limit - len(_TRUNCATED))
        text = text[:keep] + _TRUNCATED
    return text


def sanitize_log_item(
    value: Any,
    *,
    max_chars: int = 8_000,
    max_depth: int = 8,
) -> Any:
    """Recursively redact and bound one log entry without serializing secrets."""
    return _sanitize(value, max_chars, max_depth, 0)


def sanitize_log_items(
    values: list[Any] | Any,
    *,
    max_entries: int = 500,
    max_chars: int = 8_000,
    max_total_chars: int = 1_000_000,
) -> list[Any]:
    if not isinstance(values, list):
        return []
    cleaned: list[Any] = []
    total = 0
    for item in values[:max_entries]:
        safe_item = sanitize_log_item(item, max_chars=max_chars)
        size = len(str(safe_item))
        if total + size > max_total_chars:
            remaining = max(0, max_total_chars - total)
            if remaining <= len(_TRUNCATED):
                break
            cleaned.append({
                "level": "warning",
                "message": _TRUNCATED,
            })
            break
        cleaned.append(safe_item)
        total += size
    return cleaned


def _sanitize(value: Any, max_chars: int, max_depth: int, depth: int) -> Any:
    if depth >= max_depth:
        return _TRUNCATED
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:100]:
            safe_key = redact_text(key, 256) or ""
            if safe_key.strip().lower() in _SENSITIVE_KEYS:
                result[safe_key] = "<redacted>"
                continue
            result[safe_key] = _sanitize(item, max_chars, max_depth, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [
            _sanitize(item, max_chars, max_depth, depth + 1)
            for item in list(value)[:100]
        ]
    if isinstance(value, str):
        return redact_text(value, max_chars)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value, max_chars)
