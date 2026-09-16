"""Provider-observed and estimated LLM cost correlation."""

from __future__ import annotations

import threading
from typing import Any, cast

from strix.report.pricing import resolve_litellm_model


def openrouter_stream_cost(usage: Any) -> float | None:
    """Total OpenRouter-reported cost from a raw stream ``usage`` block, or None.

    Non-BYOK responses bill everything to ``usage.cost``. BYOK responses put the
    OpenRouter fee in ``usage.cost`` (often 0) and the provider charge in
    ``usage.cost_details.upstream_inference_cost``, so BYOK totals sum the two.
    """
    if not isinstance(usage, dict):
        return None
    total = 0.0
    cost = usage.get("cost")
    if isinstance(cost, int | float) and cost > 0:
        total += float(cost)
    if bool(usage.get("is_byok")):
        details = usage.get("cost_details")
        upstream = details.get("upstream_inference_cost") if isinstance(details, dict) else None
        if isinstance(upstream, int | float) and upstream > 0:
            total += float(upstream)
    return total if total > 0 else None


def _response_id(completion_response: Any) -> str | None:
    response_id = getattr(completion_response, "id", None)
    if response_id is None:
        response_id = getattr(completion_response, "response_id", None)
    if response_id is None and isinstance(completion_response, dict):
        response_id = cast("dict[str, Any]", completion_response).get("id")
    return response_id if isinstance(response_id, str) and response_id else None


class StreamedOpenRouterCosts:
    """Correlates OpenRouter's per-stream cost from the parser to the cost callback.

    LiteLLM rebuilds streamed responses from token-only chunks and drops the
    ``usage.cost`` OpenRouter reports in its final stream chunk (its non-streamed
    path preserves it; streaming snapshots hidden params at stream start). Every
    scan streams, so the OpenRouter streaming handler (see strix.config.models)
    records the cost here keyed by response id, and the callback takes it back out
    for the matching rebuilt response. Entries are removed on read; ``clear()``
    runs per scan so nothing accumulates across runs.
    """

    def __init__(self) -> None:
        self._costs: dict[str, float] = {}
        self._lock = threading.Lock()

    def remember(self, response_id: Any, usage: Any) -> None:
        cost = openrouter_stream_cost(usage)
        if cost is None or not (isinstance(response_id, str) and response_id):
            return
        with self._lock:
            self._costs[response_id] = cost
            if len(self._costs) > 1024:
                self._costs.pop(next(iter(self._costs)))

    def take(self, completion_response: Any) -> float | None:
        response_id = _response_id(completion_response)
        if response_id is None:
            return None
        with self._lock:
            return self._costs.pop(response_id, None)

    def clear(self) -> None:
        with self._lock:
            self._costs.clear()


streamed_openrouter_costs = StreamedOpenRouterCosts()


def litellm_cost_callback(
    kwargs: Any,
    completion_response: Any,
    _start_time: Any = None,
    _end_time: Any = None,
) -> None:
    """Correlate provider-observed cost for the run hook that owns the response."""
    cost: float | None = None
    raw = kwargs.get("response_cost") if isinstance(kwargs, dict) else None
    if isinstance(raw, int | float) and raw > 0:
        cost = float(raw)

    if cost is None:
        hidden = getattr(completion_response, "_hidden_params", None) or {}
        candidate = hidden.get("response_cost") if isinstance(hidden, dict) else None
        if isinstance(candidate, int | float) and candidate > 0:
            cost = float(candidate)
        else:
            headers = hidden.get("additional_headers") or {} if isinstance(hidden, dict) else {}
            raw = (
                headers.get("llm_provider-x-litellm-response-cost")
                if isinstance(headers, dict)
                else None
            )
            try:
                value = float(raw) if raw is not None else None
            except (TypeError, ValueError):
                value = None
            if value is not None and value > 0:
                cost = value

    if cost is None:
        cost = _usage_reported_cost(completion_response)

    # Recover the exact OpenRouter cost the streaming handler stashed for this
    # response — LiteLLM drops it from streamed usage, so nothing above sees it.
    if cost is None:
        cost = streamed_openrouter_costs.take(completion_response)

    if cost is None:
        cost = _estimate_response_cost(kwargs, completion_response)

    if cost is None or cost <= 0:
        return
    streamed_openrouter_costs.remember(_response_id(completion_response), {"cost": cost})


def _usage_reported_cost(completion_response: Any) -> float | None:
    """Provider-reported cost from the ``usage`` block (e.g. OpenRouter).

    Non-BYOK responses charge everything to ``usage.cost``. BYOK responses
    charge only the OpenRouter fee to ``usage.cost`` (often 0) and report the
    provider charge in ``usage.cost_details.upstream_inference_cost``, so the
    true BYOK total is the sum of the two.
    """
    usage: Any = getattr(completion_response, "usage", None)
    if usage is None and isinstance(completion_response, dict):
        usage = cast("dict[str, Any]", completion_response).get("usage")
    if usage is None:
        return None

    def _field(container: Any, name: str) -> Any:
        if isinstance(container, dict):
            return cast("dict[str, Any]", container).get(name)
        return getattr(container, name, None)

    total = 0.0
    usage_cost = _field(usage, "cost")
    if isinstance(usage_cost, int | float) and usage_cost > 0:
        total += float(usage_cost)

    if bool(_field(usage, "is_byok")):
        upstream = _field(_field(usage, "cost_details"), "upstream_inference_cost")
        if isinstance(upstream, int | float) and upstream > 0:
            total += float(upstream)

    return total if total > 0 else None


def _estimate_response_cost(kwargs: Any, completion_response: Any) -> float | None:
    """Best-effort LiteLLM cost-map estimate when no provider-reported cost exists.

    LiteLLM strips provider cost fields when rebuilding streamed responses and
    returns no ``response_cost`` for models missing from its cost map, so try
    the provider-prefixed name, the raw name, and the bare model name.
    """
    # Delay LiteLLM's large import until cost fallback is actually needed.
    from litellm import completion_cost  # noqa: PLC0415

    model = kwargs.get("model") if isinstance(kwargs, dict) else None
    if not isinstance(model, str) or not model:
        if isinstance(completion_response, dict):
            model = cast("dict[str, Any]", completion_response).get("model")
        else:
            model = getattr(completion_response, "model", None)
    if not isinstance(model, str) or not model:
        return None

    provider = None
    litellm_params = kwargs.get("litellm_params") if isinstance(kwargs, dict) else None
    if isinstance(litellm_params, dict):
        provider = litellm_params.get("custom_llm_provider")

    usage_payload = _usage_payload(completion_response)
    if usage_payload is None:
        return None

    candidates: list[str] = []
    if isinstance(provider, str) and provider and not model.startswith(f"{provider}/"):
        candidates.append(f"{provider}/{model}")
    candidates.append(model)
    if "/" in model:
        candidates.append(model.rsplit("/", 1)[-1])

    for candidate in candidates:
        resolved = resolve_litellm_model(candidate)
        if not resolved:
            continue
        try:
            value = completion_cost(
                completion_response={"model": resolved, "usage": usage_payload},
                model=resolved,
            )
        except Exception:  # nosec B112  # noqa: BLE001, S112
            continue
        if isinstance(value, int | float) and value > 0:
            return float(value)
    return None


def _usage_payload(completion_response: Any) -> dict[str, Any] | None:
    """Token counts as a plain dict, detached from the response's provider metadata."""
    usage: Any = getattr(completion_response, "usage", None)
    if usage is None and isinstance(completion_response, dict):
        usage = cast("dict[str, Any]", completion_response).get("usage")
    if usage is None:
        return None
    if hasattr(usage, "model_dump"):
        usage = usage.model_dump()
    if not isinstance(usage, dict):
        return None
    payload = cast("dict[str, Any]", usage)
    if not payload.get("total_tokens") and not (
        payload.get("prompt_tokens") or payload.get("completion_tokens")
    ):
        return None
    return payload
