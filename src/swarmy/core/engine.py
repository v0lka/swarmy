"""Engine: the typed wrapper around the L0 deep-agent assembly (arch §9.1,
roadmap T3.1.3).

This module is the **only** place where swarmy touches the untyped surface
of ``create_deep_agent`` (G3; the per-file ruff/ty relaxations exist for it
alone). Everything else in ``swarmy`` stays fully typed.

Responsibilities:

* assemble the orchestrator deep-agent: model, the static system prompt
  (:func:`~swarmy.core.prompts.build_orchestrator_prompt`), the platform
  orchestrator toolset, the loaded subagent dicts, the middleware stack
  (``GuardrailMiddleware`` + ``ProjectorMiddleware`` + ``CorrelationMiddleware``
  — the orchestrator carries the same guardrail/projector pair as every
  subagent, arch §9.1), the HITL ``interrupt_on`` matrix (profile x mode x
  registry) and the SQLite checkpointer writing into the session's
  ``memory.sqlite`` (arch §7.1);
* keep the effective ``interrupt_on`` mapping for the approval-queue origin
  derivation (profile vs mode vs module entries);
* :meth:`recompile` — rebuild the graph with a different profile or
  autonomy mode on the same checkpointer: the documented L0 operation for
  on-the-fly strictness changes (arch §7.2, T3.3.1/T3.3.4).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from deepagents import create_deep_agent
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from swarmy.core.hitl import (
    ALLOWED_DECISIONS,
    AutonomyMode,
    StrictnessProfile,
    build_interrupt_config,
)
from swarmy.guardrails.pipeline import GuardrailMiddleware, GuardrailPipeline
from swarmy.modules.loader import PLATFORM_TOOL_BUDGET_CLASSES
from swarmy.tools.errors import ToolErrorFeedbackMiddleware
from swarmy.tools.projector import ProjectorMiddleware

if TYPE_CHECKING:
    from aiosqlite import Connection as AioConnection
    from langchain.agents.middleware import InterruptOnConfig
    from langchain_core.language_models.chat_models import BaseChatModel
    from langgraph.graph.state import CompiledStateGraph

    from swarmy.core.runtime import CorrelationMiddleware
    from swarmy.modules.registry import ModuleRegistry
    from swarmy.tools.registry import ToolRegistry


class Engine:
    """The compiled orchestrator graph and its assembly facts (arch §9.1).

    Built once by :meth:`build` during ``Session.open`` (and rebuilt in
    place by :meth:`recompile`); the graph and the checkpointer connection
    live for the whole session. The engine owns no session components
    itself — it borrows the session's (arch §2.2: one owner).
    """

    __slots__ = (
        "_checkpointer_connection",
        "graph",
        "interrupt_config",
        "middleware",
        "modules",
    )

    def __init__(
        self,
        graph: CompiledStateGraph,
        modules: ModuleRegistry,
        interrupt_config: dict[str, bool | InterruptOnConfig],
        checkpointer_connection: AioConnection,
        middleware: list[object],
    ) -> None:
        """Store the compiled graph, the module registry and the gate facts."""
        self.graph = graph
        self.modules = modules
        self.interrupt_config = interrupt_config
        self._checkpointer_connection = checkpointer_connection
        self.middleware = middleware

    @classmethod
    def build(
        cls,
        *,
        system_prompt: str,
        orchestrator_tools: Sequence[Any],
        subagents: Sequence[dict[str, object]],
        pipeline: GuardrailPipeline,
        projector: Any,
        correlation_middleware: CorrelationMiddleware,
        tool_registry: ToolRegistry,
        profile: StrictnessProfile,
        mode: AutonomyMode,
        significant_tools: Sequence[str],
        model: str | BaseChatModel | None,
        checkpointer_connection: AioConnection,
        modules: ModuleRegistry,
        module_overrides: Mapping[str, bool | InterruptOnConfig] | None = None,
    ) -> Engine:
        """Assemble the orchestrator deep-agent (arch §9.1).

        The orchestrator receives the **same middleware pair** as the
        subagents (``GuardrailMiddleware`` over ``pipeline`` and
        ``ProjectorMiddleware`` over ``projector``) plus the correlation
        middleware wrapping ``task()`` calls; its tools pass the guardrail
        pipeline on equal terms (arch §9.1). The checkpointer is the L0
        ``AsyncSqliteSaver`` over the session database's dedicated
        connection — checkpoints live in ``memory.sqlite`` (arch §7.1).

        Args:
            system_prompt: the assembled orchestrator prompt.
            orchestrator_tools: the platform tool callables (``session_info``,
                ``memory_*``, ``emit_event``).
            subagents: the loaded ``SubAgent`` dicts (loader output).
            pipeline: the orchestrator's guardrail pipeline (invariants +
                engine rules + judge band, no module rules).
            projector: the session projector (§6.8).
            correlation_middleware: the delegation-correlation middleware
                (T3.2.3).
            tool_registry: the session registry (source of risk classes).
            profile: the strictness profile (arch §7.2).
            mode: the autonomy mode (arch §9.5).
            significant_tools: tools ``interactive`` gates as significant
                forks.
            model: the orchestrator model — an L0 model id string or a
                ``BaseChatModel`` instance (test seam); ``None`` defers to
                the L0 default selection.
            checkpointer_connection: the session database's checkpointer
                connection (AD-6).
            modules: the loaded module registry (kept for recompile).
            module_overrides: explicit module ``interrupt_on`` entries for
                the orchestrator's own tools (rare; normally the subagents
                carry overrides).

        Returns:
            The compiled engine.
        """
        interrupt_config = cls._interrupt_matrix(
            tool_registry, profile, mode, significant_tools, module_overrides
        )
        middleware: list[object] = [
            # The session projector also sanitizes deny feedback inside
            # GuardrailMiddleware (deny bypasses the inner projector, #39);
            # the tool-class map applies the §6.8 budgets to HTTP tool
            # envelopes (#58 ↔ F-6).
            GuardrailMiddleware(pipeline, projector=projector),
            ProjectorMiddleware(projector, tool_classes=PLATFORM_TOOL_BUDGET_CLASSES),
            correlation_middleware,
            # Innermost: recoverable tool-body failures reach the model as
            # error feedback instead of aborting the run (see
            # swarmy.tools.errors).
            ToolErrorFeedbackMiddleware(),
        ]
        graph = cls._compile(
            model=model,
            system_prompt=system_prompt,
            orchestrator_tools=orchestrator_tools,
            subagents=subagents,
            middleware=middleware,
            interrupt_config=interrupt_config,
            checkpointer_connection=checkpointer_connection,
        )
        return cls(
            graph=graph,
            modules=modules,
            interrupt_config=interrupt_config,
            checkpointer_connection=checkpointer_connection,
            middleware=middleware,
        )

    def recompile(
        self,
        *,
        profile: StrictnessProfile,
        mode: AutonomyMode,
        system_prompt: str,
        orchestrator_tools: Sequence[Any],
        subagents: Sequence[dict[str, object]],
        pipeline: GuardrailPipeline,
        projector: Any,
        correlation_middleware: CorrelationMiddleware,
        tool_registry: ToolRegistry,
        significant_tools: Sequence[str],
        model: str | BaseChatModel | None,
        module_overrides: Mapping[str, bool | InterruptOnConfig] | None = None,
    ) -> None:
        """Rebuild the graph for a new profile/mode (arch §7.2, T3.3.1/§9.5).

        The documented L0 operation for on-the-fly strictness changes: a new
        ``interrupt_on`` matrix is built and the graph is compiled again
        **on the same checkpointer connection**, so the thread state (and
        every pending interrupt) survives the recompilation.
        """
        interrupt_config = self._interrupt_matrix(
            tool_registry, profile, mode, significant_tools, module_overrides
        )
        middleware: list[object] = [
            GuardrailMiddleware(pipeline, projector=projector),
            ProjectorMiddleware(projector, tool_classes=PLATFORM_TOOL_BUDGET_CLASSES),
            correlation_middleware,
            # Innermost: recoverable tool-body failures reach the model as
            # error feedback instead of aborting the run (see
            # swarmy.tools.errors).
            ToolErrorFeedbackMiddleware(),
        ]
        self.graph = self._compile(
            model=model,
            system_prompt=system_prompt,
            orchestrator_tools=orchestrator_tools,
            subagents=subagents,
            middleware=middleware,
            interrupt_config=interrupt_config,
            checkpointer_connection=self._checkpointer_connection,
        )
        self.interrupt_config = interrupt_config
        self.middleware = middleware

    @staticmethod
    def _interrupt_matrix(
        tool_registry: ToolRegistry,
        profile: StrictnessProfile,
        mode: AutonomyMode,
        significant_tools: Sequence[str],
        module_overrides: Mapping[str, bool | InterruptOnConfig] | None,
    ) -> dict[str, bool | InterruptOnConfig]:
        """Render the arch §7.2 gates over the session registry (T3.3.1)."""
        return build_interrupt_config(
            profile,
            tool_registry.risk_classes(),
            mode=mode,
            significant_tools=significant_tools,
            module_overrides=module_overrides,
        )

    @staticmethod
    def _normalize_subagent_gates(
        subagents: Sequence[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Restrict every subagent gate to the swarmy decision set (Issue #60).

        The loader emits plain ``True`` entries per tool (the manifest's
        ``interrupt_on`` map is bool-typed); in langchain's HITL middleware a
        ``True`` entry enables the *default* decision set — which includes
        the L0 ``respond`` decision the platform deliberately does not offer
        (arch §7.2: operator feedback rides ``reject``/``edit`` payloads,
        never a synthetic answer). Each ``True`` entry is rewritten as an
        ``InterruptOnConfig`` offering exactly :data:`ALLOWED_DECISIONS`,
        mirroring the orchestrator matrix; explicit dict entries keep their
        shape but never offer ``respond``. ``False`` passes through.

        Args:
            subagents: the loaded ``SubAgent`` dicts (loader output).

        Returns:
            Copies with normalized ``interrupt_on`` entries (inputs untouched).
        """
        normalized: list[dict[str, object]] = []
        for subagent in subagents:
            gates = subagent.get("interrupt_on")
            if not isinstance(gates, Mapping) or not gates:
                normalized.append(dict(subagent))
                continue
            rewritten: dict[str, object] = {}
            for tool_name, entry in gates.items():
                if entry is True:
                    rewritten[str(tool_name)] = {
                        "allowed_decisions": list(ALLOWED_DECISIONS),
                        "description": (
                            f"Tool {tool_name!r} requires operator approval (module-declared gate)."
                        ),
                    }
                elif isinstance(entry, Mapping):
                    config_entry: dict[str, object] = dict(entry)
                    decisions = config_entry.get("allowed_decisions")
                    if isinstance(decisions, list) and "respond" in decisions:
                        config_entry["allowed_decisions"] = [
                            item for item in decisions if item != "respond"
                        ]
                    rewritten[str(tool_name)] = config_entry
                else:
                    rewritten[str(tool_name)] = entry
            normalized.append({**subagent, "interrupt_on": rewritten})
        return normalized

    @staticmethod
    def _compile(
        *,
        model: str | BaseChatModel | None,
        system_prompt: str,
        orchestrator_tools: Sequence[Any],
        subagents: Sequence[dict[str, object]],
        middleware: list[object],
        interrupt_config: dict[str, bool | InterruptOnConfig],
        checkpointer_connection: AioConnection,
    ) -> CompiledStateGraph:
        """The single L0 call of the whole codebase (G3).

        The casts mark exactly the untyped seams of ``create_deep_agent``
        (SubAgent dicts, middleware list, model id): swarmy-side values are
        validated by the loader/pipeline before they reach this point.
        """
        return create_deep_agent(
            model=model,
            system_prompt=system_prompt,
            tools=list(orchestrator_tools),
            subagents=Engine._normalize_subagent_gates(list(subagents)),  # ty: ignore[invalid-argument-type]
            middleware=middleware,  # ty: ignore[invalid-argument-type]
            interrupt_on=interrupt_config,
            checkpointer=AsyncSqliteSaver(checkpointer_connection),
        )


__all__ = ["Engine"]
