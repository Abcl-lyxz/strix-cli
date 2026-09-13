"""Scan bootstrap shared by the CLI entry point and the TUI setup flow.

Target resolution, run preparation, model preflight, and start-of-run
telemetry live here so ``strix.interface.main`` (the CLI) and
``strix.interface.tui.runtime`` (interactive setup) depend on one module
instead of each other. Everything raises ordinary exceptions; rendering
errors and exiting the process is the caller's job.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from strix.config import Settings, codex, load_settings
from strix.core.paths import run_dir_for
from strix.interface.utils import (
    assign_workspace_subdirs,
    clone_repository,
    collect_local_sources,
    dedupe_local_targets,
    derive_local_base_name,
    generate_run_name,
    infer_target_type,
    read_target_list_file,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    stage_api_specs,
    write_fetched_collection,
)
from strix.utils.api_spec import (
    SpecParseError,
    fetch_postman_collection,
    fetch_postman_environment,
    load_spec,
    spec_base_urls,
    spec_title,
)


if TYPE_CHECKING:
    import argparse

logger = logging.getLogger(__name__)

HOST_GATEWAY_HOSTNAME = "host.docker.internal"


class ModelConnectionError(RuntimeError):
    """An ordinary model preflight failure, annotated with its model route."""

    def __init__(self, model_name: str, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.model_name = model_name


async def preflight_model_connection(
    model_name: str,
    *,
    settings: Settings | None = None,
    selected_routes: list[str] | None = None,
    check_tools: bool = False,
) -> None:
    """Verify the configured model route using the run's real transport mode."""
    from agents.model_settings import ModelSettings
    from agents.models.interface import ModelTracing

    from strix.config.models import StrixProvider, configure_sdk_model_defaults
    from strix.config.routes import load_routes
    from strix.core.inputs import make_model_settings
    from strix.routing import RoutedModel, RoutePool

    resolved_settings = load_settings() if settings is None else settings
    configure_sdk_model_defaults(resolved_settings)
    route_pool = None
    try:
        routes = load_routes(resolved_settings, selected=selected_routes)
    except (AttributeError, TypeError, ValueError):
        # Tests and embedders may pass a minimal settings object with no route
        # section. The direct single-model preflight remains supported.
        routes = []
    matching = [route for route in routes if not model_name or route.model == model_name]
    if matching:
        route_pool = RoutePool(
            matching,
            wait_timeout=min(float(resolved_settings.llm.timeout), 45.0),
        )
    model = (
        RoutedModel(route_pool) if route_pool is not None else StrixProvider().get_model(model_name)
    )
    request_settings = make_model_settings(
        None,
        model_name=model_name,
        request_timeout=resolved_settings.llm.timeout,
        prompt_cache=False,
        extra_headers=resolved_settings.llm.extra_headers,
        has_tools=False,
    ).resolve(ModelSettings(max_tokens=32))
    request: dict[str, Any] = {
        "system_instructions": "You are a helpful assistant.",
        "input": "Reply with just 'OK'.",
        "model_settings": request_settings,
        "tools": [],
        "output_schema": None,
        "handoffs": [],
        "tracing": ModelTracing.DISABLED,
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }

    if check_tools:
        from agents.tool import FunctionTool

        async def probe(_context: Any, _arguments: str) -> str:
            return "OK"

        request["tools"] = [
            FunctionTool(
                name="strix_connection_test",
                description="Confirm tool calling is supported",
                params_json_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                on_invoke_tool=probe,
            )
        ]
        request["input"] = "Call strix_connection_test with ok set to true."
        request["model_settings"] = request_settings.resolve(
            ModelSettings(max_tokens=128, tool_choice="strix_connection_test")
        )
    observed_tool = False

    def observe(response: Any) -> None:
        nonlocal observed_tool
        from strix.llm.tool_arguments import parse_tool_arguments

        for output in getattr(response, "output", []) or []:
            if (
                getattr(output, "type", "") == "function_call"
                and getattr(output, "name", "") == "strix_connection_test"
            ):
                observed_tool = parse_tool_arguments(output.arguments).get("ok") is True

    async def perform_check() -> None:
        if resolved_settings.llm.disable_streaming:
            observe(await model.get_response(**request))
            return
        # Match the transport used by a normal scan. Some OpenAI-compatible
        # gateways support streaming reliably but leave non-streaming requests
        # open indefinitely, so a non-streaming-only preflight rejects a route
        # that the agent itself can use.
        async for event in model.stream_response(**request):
            if getattr(event, "type", "") == "response.completed":
                observe(getattr(event, "response", None))

    timeout = min(float(resolved_settings.llm.timeout), 45.0)
    try:
        try:
            await asyncio.wait_for(perform_check(), timeout=timeout)
            if check_tools and not observed_tool:
                raise ValueError(
                    "The model did not return the requested tool call. "
                    "Choose a model with tool support."
                )
        except TimeoutError as exc:
            raise TimeoutError(f"model connection check timed out after {timeout:g}s") from exc
    finally:
        if route_pool is not None:
            await route_pool.close()


def build_targets_info(args: argparse.Namespace) -> None:
    """Populate ``args.targets_info`` from target/target-list inputs.

    Raises :class:`ValueError` with a user-facing message on any bad input so
    callers can surface it via ``parser.error`` (CLI) or a console panel (home
    page).
    """
    args.targets_info = []
    targets = list(args.target or [])
    for target_list_path in args.target_list or []:
        targets.extend(read_target_list_file(target_list_path))

    for target in targets:
        try:
            target_type, target_dict = infer_target_type(target)
        except ValueError as e:
            raise ValueError(f"Invalid target '{target}': {e}") from None

        if target_type == "local_code":
            display_target = target_dict.get("target_path", target)
        else:
            display_target = target

        if target_type == "api_spec":
            _resolve_api_spec(target, target_dict)

        args.targets_info.append(
            {"type": target_type, "details": target_dict, "original": display_target}
        )

    args.targets_info = dedupe_local_targets(args.targets_info)

    assign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)


def _resolve_api_spec(target: str, details: dict[str, Any]) -> None:
    """Read the spec up front so bad input fails before the run starts.

    Records the declared base URLs (the only thing scope authorization can take
    from a spec) and, for a ``postman://`` target, downloads the collection to a
    local file so the sandbox never needs the Postman API key.
    """
    try:
        if details.get("source") == "postman_api":
            collection_uid = str(details["collection_uid"])
            api_key = load_settings().integrations.postman_api_key or ""
            raw = fetch_postman_collection(collection_uid, api_key)
            environment_uid = str(details.get("environment_uid") or "")
            extra_variables = (
                fetch_postman_environment(environment_uid, api_key) if environment_uid else None
            )
            details["target_spec"] = write_fetched_collection(raw, collection_uid)
        else:
            raw = load_spec(str(details["target_spec"]))
            extra_variables = None
        base_urls = spec_base_urls(raw, extra_variables=extra_variables)
    except SpecParseError as exc:
        raise ValueError(f"Invalid API spec '{target}': {exc}") from None

    details["spec_title"] = spec_title(raw)
    details["base_urls"] = base_urls


def prepare_run(args: argparse.Namespace) -> None:
    """Resolve the run name, clone repos, compute diff-scope, and persist state.

    Shared by the CLI startup path and the interactive TUI setup phase (once the
    user has supplied a target via ``/target``). Mutates *args* in place and
    raises :class:`ValueError` on any preparation failure.
    """
    args.run_name = args.resume or generate_run_name(args.targets_info)

    if args.resume:
        return

    for target_info in args.targets_info:
        if target_info["type"] == "repository":
            repo_url = target_info["details"]["target_repo"]
            dest_name = target_info["details"].get("workspace_subdir")
            cloned_path = clone_repository(repo_url, args.run_name, dest_name)
            target_info["details"]["cloned_repo_path"] = cloned_path

    from strix.interface.attachments import describe_attachment

    for target in args.targets_info:
        if target["type"] == "local_file":
            if target["details"].get("workspace_path"):
                continue
            item = describe_attachment(target["details"]["target_path"], role="target")
            target["details"]["workspace_path"] = item["workspace_path"]
            args.workspace_files = list(getattr(args, "workspace_files", []) or []) + item["files"]
    args.local_sources = collect_local_sources(args.targets_info)
    args.local_sources.extend(stage_api_specs(args.targets_info, args.run_name))
    diff_scope = resolve_diff_scope_context(
        local_sources=args.local_sources,
        scope_mode=args.scope_mode,
        diff_base=args.diff_base,
        non_interactive=args.non_interactive,
    )
    args.diff_scope = diff_scope.metadata
    if diff_scope.instruction_block:
        if args.instruction:
            args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
        else:
            args.instruction = diff_scope.instruction_block

    attach_workspace_mount(args)
    _persist_run_record(args)


def attach_workspace_mount(args: argparse.Namespace) -> None:
    """Expose ``args.workspace_mount`` to the sandbox without making it a target.

    A workspace mount is a directory the agent works in, not something to test:
    it stays out of ``targets_info``, so it carries no authorized scope, and it
    is attached after diff-scope resolution so it contributes no diff context.
    The instruction is the only source of truth for what to do with it.
    """
    mount = getattr(args, "workspace_mount", None)
    if not mount:
        return
    args.workspace_subdir = derive_local_base_name(mount)
    local_sources = list(getattr(args, "local_sources", None) or [])
    local_sources.append(
        {
            "source_path": mount,
            "workspace_subdir": args.workspace_subdir,
            "protect_metadata": True,
        }
    )
    args.local_sources = local_sources


def _persist_run_record(args: argparse.Namespace) -> None:
    from strix.report.writer import write_run_record

    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "auth_mode": codex.auth_mode(load_settings().llm.model),
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        # Kept apart from instruction, which carries the diff-scope preamble: the
        # transcript replays this as the user's opening message.
        "user_instruction": getattr(args, "user_instruction", None),
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        # Persisted so --resume places the same workspace files again.
        "workspace_files": getattr(args, "workspace_files", []),
        # Persisted so --resume can remount the workspace: it is not a target,
        # so it cannot be rebuilt from targets_info.
        "workspace_mount": getattr(args, "workspace_mount", None),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
    }
    write_run_record(run_dir, run_record)
