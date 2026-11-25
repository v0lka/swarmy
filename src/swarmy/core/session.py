"""Session: the composition root of one run (arch §3.3, §13.1, T3.1.2).

A session is a portable folder (``session.yaml`` audit snapshot, ``secrets.yaml``
mode 600, ``memory.sqlite``, ``evidence/``). :meth:`Session.open` builds every
component **on one Database**, in the arch §13.1 startup order — Database →
Journal/Bus/Scope/Limiter/ToolRegistry → MemoryStore+SearchIndex →
ModuleLoader → Engine → ``TargetSet`` — and owns them all: nobody creates a
component "by itself" (arch §2.2). :meth:`Session.resume` is the separate
restart path (arch §13.1): migrations are skipped when the schema version
matches, the journal tail is re-read, and the interrupted approvals are
restored into the FIFO (T3.2.4/T3.3.3). :meth:`Session.close` checkpoints the
WAL and closes every connection, so a copied session folder opens "on another
machine".

Boundary (T3.1.2 AC): nothing under ``swarmy.core`` imports ``swarmy.tui`` —
the TUI arrives at milestone M4 through a ``SessionView`` facade; the headless
M3 session is complete without it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, TypeVar

import yaml

from swarmy.core.config import (
    SESSION_CONFIG_FILENAME,
    SecretsConfig,
    SessionConfig,
    load_secrets,
    snapshot_yaml,
)
from swarmy.core.database import Database
from swarmy.core.engine import Engine
from swarmy.core.hitl import (
    SIGNIFICANT_FORK_TOOLS,
    ApprovalDecision,
    ApprovalQueue,
)
from swarmy.core.prompts import build_orchestrator_prompt
from swarmy.core.runtime import (
    CorrelationMiddleware,
    OrchestratorRuntime,
    current_correlation_id,
    resolve_policies,
)
from swarmy.events.bus import EventBus
from swarmy.events.emit import EmitEventTool, make_emit_tool
from swarmy.events.journal import JournalReader, JournalWriter
from swarmy.events.models import EventSource, TargetSetPayload
from swarmy.guardrails.invariants import InvariantLayer, session_invariants
from swarmy.guardrails.judge import LlmJudge
from swarmy.guardrails.pipeline import GuardrailPipeline, tool_args_digest
from swarmy.memory.models import ReportStatistics
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore
from swarmy.modules.loader import ModuleLoader
from swarmy.tools.http.client import (
    HttpClientEvents,
    OutboundSecretWarn,
    SwarmyHttpClient,
)
from swarmy.tools.http.evidence import EvidenceRecorder
from swarmy.tools.http.tools import make_http_tools
from swarmy.tools.limits import ResourceLimiter
from swarmy.tools.platform import make_memory_tools, make_session_info_tool
from swarmy.tools.projector import ContextProjector
from swarmy.tools.registry import BUILTIN_SOURCE, PLATFORM_OWNER, ToolRegistry, ToolSpec
from swarmy.tools.scope import ScopeEntries, ScopeRegistry

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from langchain_core.language_models.chat_models import BaseChatModel

    from swarmy.events.models import GuardrailBlockedPayload
    from swarmy.guardrails.models import BlockedFeedback, RiskClass, Verdict
    from swarmy.guardrails.pipeline import JudgeBand
    from swarmy.modules.registry import ModuleRegistry


class _JudgeBandAdapter:
    """Structural :class:`~swarmy.guardrails.pipeline.JudgeBand` over one judge.

    The session builds one adapter per pipeline (orchestrator, every
    subagent) binding that pipeline's tool-name → risk-class map onto the
    shared :class:`~swarmy.guardrails.judge.LlmJudge` (§6.7 wiring, T3.4.x).
    """

    __slots__ = ("_gate_for", "_precall")

    def __init__(
        self,
        gate_for: Callable[[str], tuple[Verdict, BlockedFeedback | None] | None],
        precall: Callable[
            [str, Mapping[str, object], str],
            Awaitable[tuple[Verdict, BlockedFeedback | None] | None],
        ],
    ) -> None:
        """Bind the two closures the session builder produced."""
        self._gate_for = gate_for
        self._precall = precall

    def gate_for(self, tool_name: str) -> tuple[Verdict, BlockedFeedback | None] | None:
        """Standing class verdict for the tool, or ``None`` when clear."""
        return self._gate_for(tool_name)

    async def precall(
        self, tool_name: str, tool_args: Mapping[str, object], args_digest: str
    ) -> tuple[Verdict, BlockedFeedback | None] | None:
        """Judge one deterministically-allowed call (arch §6.7)."""
        return await self._precall(tool_name, tool_args, args_digest)



def _prepare_session_dir(session_dir: Path) -> None:
    """Create the session folder and refuse an existing session database.

    Blocking filesystem work lives in a sync helper (ASYNC240): the checks
    are tiny and run once per session start, before any event-loop work.
    """
    session_dir.mkdir(parents=True, exist_ok=True)
    if (session_dir / "memory.sqlite").exists():
        msg = (
            f"session directory {session_dir} already contains memory.sqlite; "
            "open a fresh directory or use resume"
        )
        raise SessionError(msg)


def _require_resumable(session_dir: Path) -> None:
    """Refuse to resume a folder without a session database (arch §13.1)."""
    if not (session_dir / "memory.sqlite").exists():
        msg = f"no session to resume in {session_dir}: memory.sqlite not found"
        raise SessionError(msg)


def _write_snapshot(session_dir: Path, text: str) -> None:
    """Write the ``session.yaml`` audit snapshot (arch §3.3, §12.2)."""
    (session_dir / SESSION_CONFIG_FILENAME).write_text(text, encoding="utf-8")


#: Journal tail window the report statistics are computed over (arch §11).
_REPORT_STATISTICS_TAIL: Final[int] = 10_000


class ReportToolFactory(Protocol):
    """Structural type of the injected ``generate_report`` builder (RD-7).

    arch §2.5: ``swarmy.core`` never imports ``swarmy.report`` — the
    composition root (``cli.py``, L2) supplies the report package's
    :func:`swarmy.report.generator.make_generate_report_tool` through this
    protocol; :class:`Session` only binds its arguments. Omitting the
    factory (tests, library use) simply builds the engine without the
    report tool.
    """

    def __call__(
        self,
        *,
        store: MemoryStore,
        session_dir: Path,
        base_url: str,
        scope_labels: Sequence[str],
        statistics: Callable[[], Awaitable[ReportStatistics]],
    ) -> Callable[..., object]: ...


def _read_text(path: Path) -> str:
    """Read one UTF-8 text file (sync helper for the ASYNC240 boundary)."""
    return path.read_text(encoding="utf-8")


_T = TypeVar("_T")


class SessionError(Exception):
    """A session could not be opened/resumed/closed (fail-fast, arch §4.5)."""


class Session:
    """Owner of every component of one session run (arch §2.2, §13.1).

    Build it only through :meth:`open` / :meth:`resume`; :meth:`close`
    releases everything. The attributes below are the composition surface the
    CLI (M4+) and the integration tests consume.
    """

    def __init__(self, *, config: SessionConfig, session_dir: Path) -> None:
        """Store the resolved config and the session folder (components land in open)."""
        self.config = config
        self.session_dir = session_dir
        self.secrets: SecretsConfig | None = None
        self.database: Database | None = None
        self.journal: JournalWriter | None = None
        self.reader: JournalReader | None = None
        self.bus: EventBus | None = None
        self.scope: ScopeRegistry | None = None
        self.limiter: ResourceLimiter | None = None
        self.tool_registry: ToolRegistry | None = None
        self.search: Fts5SearchIndex | None = None
        self.memory: MemoryStore | None = None
        self.projector: ContextProjector | None = None
        self.http_client: SwarmyHttpClient | None = None
        self.judge: LlmJudge | None = None
        self.modules: ModuleRegistry | None = None
        self.engine: Engine | None = None
        self.approvals: ApprovalQueue | None = None
        self.runtime: OrchestratorRuntime | None = None
        self._emit: EmitEventTool | None = None
        self._orchestrator_tools: dict[str, Callable[..., object]] = {}
        self._closed = False

    # ---- open / resume / close ----

    @classmethod
    async def open(
        cls,
        *,
        config: SessionConfig,
        session_dir: Path,
        secrets: SecretsConfig | None = None,
        model: str | BaseChatModel | None = None,
        judge_model: BaseChatModel | None = None,
        report_tool_factory: ReportToolFactory | None = None,
    ) -> Session:
        """Compose a brand-new session (arch §13.1 startup order).

        Args:
            config: the fully resolved session config (``SessionConfig.load``).
            session_dir: the portable session folder; created when missing.
                An existing ``memory.sqlite`` in it is an error — resuming is
                the separate :meth:`resume` path.
            secrets: operator secrets (``load_secrets`` result); ``None`` is
                a valid no-secrets session.
            model: the orchestrator model override (L0 id string or
                ``BaseChatModel`` instance — the test seam); ``None`` uses
                ``config.model`` / the L0 default selection.
            judge_model: the judge chat model override (test seam for the
                ``judge.model`` band); ``None`` resolves the configured
                ``provider:model`` id through ``init_chat_model``.
            report_tool_factory: the ``generate_report`` builder injected by
                the composition root (``cli.py`` passes the report package's
                factory, RD-7 — arch §2.5 keeps core report-free); ``None``
                builds the engine without the report tool.

        Returns:
            The open session (all components on one Database, ``TargetSet``
            published).

        Raises:
            SessionError: the folder already holds a session database.
        """
        _prepare_session_dir(session_dir)
        session = cls(config=config, session_dir=session_dir)
        session.secrets = secrets
        await session._compose(
            fresh=True,
            model=model,
            judge_model=judge_model,
            report_tool_factory=report_tool_factory,
        )
        _write_snapshot(session_dir, snapshot_yaml(config, secrets))
        return session

    @classmethod
    async def resume(
        cls,
        *,
        session_dir: Path,
        model: str | BaseChatModel | None = None,
        report_tool_factory: ReportToolFactory | None = None,
    ) -> Session:
        """Resume a session folder after a restart (arch §13.1, T3.2.4).

        The audit snapshot ``session.yaml`` is the config source of truth
        (its ``secrets`` reference map is dropped before validation — raw
        values live only in ``secrets.yaml``); migrations are skipped when
        the schema version matches; the journal tail is replayed through the
        policy pipeline and the interrupted approvals are restored into the
        FIFO.

        Raises:
            SessionError: no session database in the folder, or the snapshot
                does not validate.
        """
        _require_resumable(session_dir)
        config = cls._config_from_snapshot(session_dir / SESSION_CONFIG_FILENAME)
        secrets_path = session_dir / "secrets.yaml"
        secrets: SecretsConfig | None = None
        if secrets_path.is_file():
            secrets = load_secrets(secrets_path)
        session = cls(config=config, session_dir=session_dir)
        session.secrets = secrets
        await session._compose(
            fresh=False,
            model=model,
            judge_model=None,
            report_tool_factory=report_tool_factory,
        )
        runtime = session.runtime
        reader = session.reader
        assert runtime is not None, "runtime composed"
        assert reader is not None, "reader composed"
        await runtime.restore(reader.range)
        return session

    async def close(self) -> None:
        """Checkpoint the WAL and close every connection (arch §3.3, T3.1.2).

        Idempotent. Order: bus subscriptions first (no more deliveries),
        then the truncating WAL checkpoint (the side files fold into the
        portable folder), then the database closes every subsystem
        connection — including the checkpointer's (AD-6).
        """
        if self._closed:
            return
        self._closed = True
        if self.bus is not None:
            await self.bus.close()
        database = self.database
        if database is not None:
            await database.checkpoint()
            await database.close()

    # ---- operator actions (arch §9.5, §12.2) ----

    async def set_mode(
        self, mode: str, *, model: str | BaseChatModel | None = None
    ) -> None:
        """Switch the autonomy mode on the fly (arch §9.5, T3.3.4).

        Rebuilds the ``interrupt_on`` matrix and recompiles the graph **on
        the same checkpointer** (documented L0 operation); journals the
        operator decision and swaps the runtime onto the new graph.
        """
        engine = self._require(self.engine)
        runtime = self._require(self.runtime)
        emit = self._require_emit()
        if mode not in ("interactive", "mission"):
            msg = f"unknown autonomy mode {mode!r}; allowed: interactive, mission"
            raise ValueError(msg)
        engine.recompile(
            profile=self.config.profile,
            mode=mode,  # type: ignore[arg-type]
            system_prompt=self._orchestrator_prompt(),
            orchestrator_tools=list(self._orchestrator_tools.values()),
            subagents=self._require(self.modules).subagent_dicts(),
            pipeline=self._orchestrator_pipeline(),
            projector=self._require(self.projector),
            correlation_middleware=self._correlation_middleware(),
            tool_registry=self._require(self.tool_registry),
            significant_tools=sorted(SIGNIFICANT_FORK_TOOLS),
            model=model if model is not None else self._model_value(),
        )
        runtime.swap_graph(engine.graph)
        await emit(
            "OperatorDecision",
            {
                "request_id": f"mode-switch:{mode}",
                "decision": "approve",
                "edited_args_digest": None,
            },
        )

    # ---- composition internals ----

    async def _compose(
        self,
        *,
        fresh: bool,
        model: str | BaseChatModel | None,
        judge_model: BaseChatModel | None,
        report_tool_factory: ReportToolFactory | None = None,
    ) -> None:
        """The arch §13.1 startup sequence, shared by open and resume."""
        # 1. Database (WAL, migrations; resume skips applied versions).
        database = Database(self.session_dir / "memory.sqlite", MIGRATIONS)
        await database.open()
        self.database = database
        # 2. Journal / bus / scope / limiter / tool registry.
        self.journal = JournalWriter(await database.connection("events"))
        self.reader = JournalReader(await database.connection("events"))
        self.bus = EventBus()
        self.scope = ScopeRegistry(self.config.scope)
        self.limiter = ResourceLimiter(self.config.limits)
        self.tool_registry = ToolRegistry()
        # 3. Memory + search + projector (§6.8: config budgets + secrets).
        self.search = Fts5SearchIndex(await database.connection("search"))
        self.memory = MemoryStore(database, self.search)
        self.projector = ContextProjector(
            budgets=self.config.context.budgets,
            secrets=self.secrets.secret_values() if self.secrets is not None else None,
        )
        emit = make_emit_tool(
            journal=self.journal,
            bus=self.bus,
            source=EventSource.PLATFORM,
            source_detail="core.session",
            correlation_provider=current_correlation_id,
        )
        self._emit = emit
        # 4. Judge + approval queue (P3.4/RD-2 wiring; §7.3). The judge chat
        # model comes from ``judge_model`` (test seam) or ``init_chat_model``
        # over the configured ``provider:model`` id (fail-fast at start).
        self.judge = self._build_judge(emit, judge_model)
        self.approvals = ApprovalQueue(
            journal=self.journal,
            emit=make_emit_tool(
                journal=self.journal,
                bus=self.bus,
                source=EventSource.PLATFORM,
                source_detail="core.hitl",
            ),
            sanitizer=lambda args: tool_args_digest(args, self._require(self.projector)),
        )
        # 5. HTTP perimeter (client shared by every delegation — D19).
        self.http_client = SwarmyHttpClient(
            scope=self._require(self.scope),
            limiter=self._require(self.limiter),
            pipeline=GuardrailPipeline(
                invariants=InvariantLayer(
                    session_invariants(self._require(self.scope), self._require(self.limiter))
                ),
                engine_rules_enabled=self.config.guardrails.engine_rules,
                projector=self._require(self.projector),
                blocked_sink=self._guardrail_blocked_sink(emit),
            ),
            projector=self._require(self.projector),
            secrets=self.secrets if self.secrets is not None else SecretsConfig(),
            evidence=EvidenceRecorder(
                evidence_dir=self.session_dir / "evidence",
                store=self._require(self.memory),
                max_body_bytes=self.config.limits.max_body_bytes,
            ),
            events=self._http_events(emit),
            correlation_provider=current_correlation_id,
        )
        # 6. Module loading (fail-fast over all modules, arch §8.3).
        loader = ModuleLoader(
            user_dirs=[Path(item) for item in self.config.agents_dirs],
            strictness=self.config.profile,
            platform_toolset_factory=self._module_platform_toolset,
            tool_registry=self._require(self.tool_registry),
            projector_factory=lambda _name: self._require(self.projector),
            engine_rules_enabled=self.config.guardrails.engine_rules,
            judge_band_factory=self._judge_band_factory(),
        )
        self.modules = loader.load()
        # 7. Orchestrator toolset + registry (non-colliding names only —
        # the loader already registered the module-level platform names).
        self._orchestrator_tools = self._build_orchestrator_tools(
            emit, report_tool_factory=report_tool_factory
        )
        for name, fn in sorted(self._orchestrator_tools.items()):
            if name not in self._require(self.tool_registry):
                self._require(self.tool_registry).register(
                    ToolSpec(name=name, fn=fn, owner=PLATFORM_OWNER, source=BUILTIN_SOURCE)
                )
        # 8. Engine (create_deep_agent + SQLite checkpointer, arch §9.1).
        checkpointer_connection = await database.connection("checkpointer")
        self.engine = Engine.build(
            system_prompt=self._orchestrator_prompt(),
            orchestrator_tools=list(self._orchestrator_tools.values()),
            subagents=self._require(self.modules).subagent_dicts(),
            pipeline=self._orchestrator_pipeline(),
            projector=self._require(self.projector),
            correlation_middleware=self._correlation_middleware(),
            tool_registry=self._require(self.tool_registry),
            profile=self.config.profile,
            mode=self.config.mode,
            significant_tools=sorted(SIGNIFICANT_FORK_TOOLS),
            model=model if model is not None else self._model_value(),
            checkpointer_connection=checkpointer_connection,
            modules=self._require(self.modules),
        )
        # 9. Runtime (single-writer contours) + bus subscription.
        self.runtime = OrchestratorRuntime(
            graph=self.engine.graph,
            emit=emit,
            policies=resolve_policies(self.config.policies),
            projector=self._require(self.projector),
            approvals=self._require(self.approvals),
            thread_id="orchestrator",
        )
        self.runtime.subscribe(self._require(self.bus).subscribe)
        # 10. Fresh sessions only: target row + TargetSet event (arch §13.1).
        if fresh:
            store = self._require(self.memory)
            target = await store.save_target(str(self.config.target.base_url))
            await emit(
                "TargetSet",
                TargetSetPayload(
                    target_id=target.id, base_url=self.config.target.base_url
                ).model_dump(mode="json"),
            )

    # ---- wiring helpers ----

    @staticmethod
    def _require(component: _T | None) -> _T:
        """Non-null view of a composed component (composition invariant)."""
        if component is None:
            msg = "session component accessed before _compose() finished"
            raise SessionError(msg)
        return component

    def _require_emit(self) -> EmitEventTool:
        """Non-null view of the platform emit callable."""
        return self._require(self._emit)

    def _model_value(self) -> str | BaseChatModel | None:
        """The config model (an L0 id string) or ``None`` (L0 default)."""
        return self.config.model

    def _orchestrator_prompt(self) -> str:
        """Assemble the orchestrator prompt over the loaded modules (§9.6)."""
        modules = self._require(self.modules)
        roster = {module.manifest.name: module.manifest.description for module in modules.modules()}
        return build_orchestrator_prompt(roster)

    def _orchestrator_pipeline(self) -> GuardrailPipeline:
        """The orchestrator pipeline: invariants + engine + judge (§9.1)."""
        return GuardrailPipeline(
            invariants=InvariantLayer(
                session_invariants(self._require(self.scope), self._require(self.limiter))
            ),
            engine_rules_enabled=self.config.guardrails.engine_rules,
            projector=self._require(self.projector),
            blocked_sink=self._guardrail_blocked_sink(self._require_emit()),
            judge_band=self._judge_band() if self.judge is not None else None,
        )

    def _correlation_middleware(self) -> CorrelationMiddleware:
        """The delegation-correlation middleware over the platform emit."""
        return CorrelationMiddleware(self._require_emit())

    def _build_judge(
        self, emit: EmitEventTool, judge_model: BaseChatModel | None
    ) -> LlmJudge | None:
        """Build the LLM judge when ``judge.model`` is configured (§6.7).

        The judge sink journals flag/escalation notes as ``GuardrailBlocked``
        payloads (``layer="judge"``, ``rule_id="judge:<verdict>"`` — the
        §5.5-anticipated channel); the escalation hook enqueues the
        ``origin="judge"`` approval request whose decision resolves the
        registry gate (T3.4.x).
        """
        judge_config = self.config.judge
        if judge_config.model is None:
            return None
        model: BaseChatModel = judge_model if judge_model is not None else _chat_model(
            judge_config.model
        )

        async def sink(feedback: BlockedFeedback, subject: str) -> None:
            await emit(
                "GuardrailBlocked",
                {
                    "tool_name": subject,
                    "rule_id": feedback.rule_id,
                    "layer": feedback.layer,
                    "reason": feedback.reason,
                    "tool_args_digest": "",
                },
            )

        async def on_escalation(tool_class: str, reason: str) -> None:
            queue = self._require(self.approvals)
            registry = self.judge.escalation_registry if self.judge else None
            escalation_id = registry.escalation_id_for(tool_class) if registry else None

            async def resolve(decision: ApprovalDecision) -> None:
                if registry is not None and escalation_id is not None:
                    registry.resolve(escalation_id, decision)

            await queue.enqueue_external(
                tool=tool_class,
                args_digest=reason,
                origin="judge",
                rule_or_profile="judge:escalate_hitl",
                resolver=resolve,
            )

        return LlmJudge(
            model=model,
            tool_classes=judge_config.tools,
            confidence_threshold=judge_config.confidence_threshold,
            timeout_s=judge_config.timeout_s,
            sink=sink,
            on_escalation=on_escalation,
        )

    def _judge_band_factory(
        self,
    ) -> Callable[[Mapping[str, RiskClass]], JudgeBand] | None:
        """The per-pipeline judge-band factory for the loader (§6.7 wiring).

        ``None`` when the judge is switched off — pipelines keep the
        reserved slot empty (deterministic-only).
        """
        if self.judge is None:
            return None
        return lambda _risk_classes: self._judge_band()

    def _judge_band(self) -> JudgeBand:
        """Build the pipeline judge band over the global registry (§6.7).

        One adapter serves the orchestrator and every subagent pipeline: the
        global ``ToolRegistry`` is a superset of each pipeline's tools, so a
        tool unknown to a pipeline is simply never judged there. Called only
        when the judge is configured (T3.4.x wiring).
        """
        assert self.judge is not None, "judge configured"
        judge = self.judge
        risk_classes = dict(self._require(self.tool_registry).risk_classes())

        def gate_for(tool_name: str) -> tuple[Verdict, BlockedFeedback | None] | None:
            risk = risk_classes.get(tool_name)
            return None if risk is None else judge.gate_for(risk.value)

        async def precall(
            tool_name: str, _tool_args: Mapping[str, object], args_digest: str
        ) -> tuple[Verdict, BlockedFeedback | None] | None:
            risk = risk_classes.get(tool_name)
            if risk is None or not judge.serves_class(risk.value):
                return None
            return await judge.precall(tool_name, risk.value, args_digest)

        return _JudgeBandAdapter(gate_for, precall)

    def _module_platform_toolset(
        self, module_name: str, declared_events: frozenset[str]
    ) -> dict[str, Callable[..., object]]:
        """The per-module platform toolset (arch §6.1, §8.5 wiring).

        ``memory_*`` + ``update_finding_status`` (emit bound to the module's
        declared events and identity), the four HTTP tools (the shared
        session client — global limits, D19) and ``emit_event``.
        """
        platform_emit = make_emit_tool(
            journal=self._require(self.journal),
            bus=self._require(self.bus),
            source=EventSource.PLATFORM,
            source_detail=f"platform.memory:{module_name}",
            correlation_provider=current_correlation_id,
        )
        memory_tools = make_memory_tools(self._require(self.memory), platform_emit)
        http_tools = make_http_tools(self._require(self.http_client))
        toolset: dict[str, Callable[..., object]] = {**memory_tools, **http_tools}
        if declared_events:
            toolset["emit_event"] = make_emit_tool(
                journal=self._require(self.journal),
                bus=self._require(self.bus),
                source=EventSource.MODULE,
                source_detail=module_name,
                correlation_provider=current_correlation_id,
                allowed_types=declared_events,
            )
        return toolset

    def _build_orchestrator_tools(
        self,
        emit: EmitEventTool,
        *,
        report_tool_factory: ReportToolFactory | None = None,
    ) -> dict[str, Callable[..., object]]:
        """The orchestrator's platform toolset (arch §9.1: session_info + memory).

        ``report_tool_factory`` (RD-7) is injected by the composition root —
        core stays report-import-free (arch §2.5); without it the engine
        simply has no ``generate_report`` tool.
        """
        config = self.config
        orchestrator_emit = make_emit_tool(
            journal=self._require(self.journal),
            bus=self._require(self.bus),
            source=EventSource.ORCHESTRATOR,
            source_detail="orchestrator",
        )
        memory_tools = make_memory_tools(self._require(self.memory), orchestrator_emit)
        tools: dict[str, Callable[..., object]] = {
            **memory_tools,
            "session_info": make_session_info_tool(
                base_url=str(config.target.base_url),
                scope_entries=config.scope,
                limiter=self._require(self.limiter),
                profile=config.profile,
                mode=config.mode,
                store=self._require(self.memory),
            ),
            "emit_event": orchestrator_emit,
        }
        if report_tool_factory is not None:
            # RD-7: the report tool joins the engine toolset via the injected
            # factory (core never imports swarmy.report — arch §2.5).
            tools["generate_report"] = report_tool_factory(
                store=self._require(self.memory),
                session_dir=self.session_dir,
                base_url=str(config.target.base_url),
                scope_labels=self._scope_labels(config.scope),
                statistics=self._report_statistics,
            )
        return tools

    @staticmethod
    def _scope_labels(scope: ScopeEntries) -> list[str]:
        """Render the config scope allowlist for the report summary."""
        labels = [f"domain={item}" for item in scope.domains]
        labels += [f"ip_subnet={item}" for item in scope.ip_subnets]
        labels += [f"port={item}" for item in scope.ports]
        labels += [f"scheme={item}" for item in scope.schemes]
        return labels

    async def _report_statistics(self) -> ReportStatistics:
        """Journal-derived report statistics (arch §11: статистика журнала)."""
        tail = await self._require(self.reader).tail(_REPORT_STATISTICS_TAIL)
        counts: dict[str, int] = {}
        for envelope in tail:
            counts[envelope.type] = counts.get(envelope.type, 0) + 1
        return ReportStatistics(
            events_total=len(tail),
            events_by_type=counts,
            period_start=tail[0].ts.isoformat() if tail else "n/a",
            period_end=tail[-1].ts.isoformat() if tail else "n/a",
        )

    def _guardrail_blocked_sink(
        self, emit: EmitEventTool
    ) -> Callable[[GuardrailBlockedPayload], Awaitable[None]]:
        """The pipeline sink: journal-first ``GuardrailBlocked`` (arch §5.3)."""

        async def sink(payload: GuardrailBlockedPayload) -> None:
            await emit("GuardrailBlocked", payload.model_dump(mode="json"))

        return sink

    def _http_events(self, emit: EmitEventTool) -> HttpClientEvents:
        """The ``HttpClientEvents`` wiring over the session journal + bus.

        ``GuardrailBlocked`` rides the registered taxonomy (journal-first);
        the outbound-secret warn has no v0.1 journal type (see the T1.4
        notes) and is appended journal-only for audit.
        """
        session = self

        class _SessionHttpEvents:
            """Journal-first publisher of the client's platform events."""

            async def guardrail_blocked(self, payload: GuardrailBlockedPayload) -> None:
                await emit("GuardrailBlocked", payload.model_dump(mode="json"))

            async def outbound_secret_warn(self, payload: OutboundSecretWarn) -> None:
                await session._require(session.journal).append(
                    type="OutboundSecretWarn",
                    source=EventSource.PLATFORM,
                    source_detail="http-client",
                    correlation_id=current_correlation_id(),
                    payload=payload,
                )

        return _SessionHttpEvents()

    @classmethod
    def _config_from_snapshot(cls, path: Path) -> SessionConfig:
        """Validate the audit snapshot back into a config (resume path).

        The ``secrets`` reference map (AD-5) is dropped before validation —
        the snapshot records secret *names*, the model forbids them.
        """
        try:
            raw: object = yaml.safe_load(_read_text(path))
        except OSError as exc:
            msg = f"session snapshot {path} is unreadable: {exc}"
            raise SessionError(msg) from exc
        if not isinstance(raw, dict):
            msg = f"session snapshot {path}: top level must be a mapping"
            raise SessionError(msg)
        document = {str(key): value for key, value in raw.items() if key != "secrets"}
        try:
            return SessionConfig.model_validate(document)
        except Exception as exc:
            msg = f"session snapshot {path} does not match SessionConfig: {exc}"
            raise SessionError(msg) from exc


def _chat_model(model_id: str) -> BaseChatModel:
    """Instantiate the judge chat model from a ``provider:model`` id (D1)."""
    from langchain.chat_models import init_chat_model

    return init_chat_model(model_id)


__all__ = ["Session", "SessionError"]
