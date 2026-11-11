"""Adapters for results that cross the worker-process boundary.

Worker responses are plain JSON-compatible dicts; the original HTML templates
were written against the dataclasses in :mod:`app.diagnostics` and use
attribute access (``c.subject``). :class:`AttrDict` restores that behaviour
without rebuilding the full object graph (and without touching the core
diagnostics module).
"""

from __future__ import annotations

from typing import Any


class AttrDict(dict):
    """Dict with attribute access; nested dicts/lists are adapted lazily."""

    def __getattr__(self, name: str) -> Any:
        try:
            value = self[name]
        except KeyError as exc:  # pragma: no cover - mirrors attribute semantics
            raise AttributeError(name) from exc
        return _wrap(value)


def _wrap(value: Any) -> Any:
    if isinstance(value, dict):
        return AttrDict(value)
    if isinstance(value, list):
        return [_wrap(item) for item in value]
    return value


def wrap_result(result: dict) -> AttrDict:
    """Adapt a serialised DiagnosticResult dict for the HTML templates."""
    return AttrDict(result)
