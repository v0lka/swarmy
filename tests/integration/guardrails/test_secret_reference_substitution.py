"""Issue #11 acceptance: by-name operator secrets flow through HTTP tools.

The documented workflow — agents address operator secrets as
``<masked:secret-name>`` references (arch §12.3, §6.8) — is implemented at
the tool boundary (``bind_secret_substitution``): the guardrail pipeline and
every journal digest evaluate the **reference form**, the resolved values
reach the target over the network and the raw **evidence** record (D21),
and the journal never carries the raw value.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from swarmy.core.config import ScopeEntries, SecretsConfig, SessionConfig, TargetConfig
from swarmy.core.session import Session
from tests.helpers.agent_modules import make_module
from tests.helpers.fake_models import ScriptedChatModel, final_reply

pytestmark = pytest.mark.integration

SECRET_NAME = "probe-token"
SECRET_VALUE = "raw-secret-value-123"


class ScriptedJudge(BaseChatModel):
    """An inert judge (never consulted: the session runs without a judge)."""

    @property
    def _llm_type(self) -> str:
        return "scripted-judge"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedJudge:
        return self

    def _generate(self, messages: Any, stop: Any = None, **kwargs: Any) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=_OK))])

    async def _agenerate(self, messages: Any, **kwargs: Any) -> ChatResult:
        return self._generate(messages)


_OK = '{"verdict": "ok", "confidence": 0.9, "reason": "fine"}'


def _call(call_id: str, url: str) -> dict[str, object]:
    return {
        "name": "http_get",
        "args": {
            "url": url,
            "headers": {f"X-{SECRET_NAME.title()}": f"<masked:{SECRET_NAME}>"},
        },
        "id": call_id,
        "type": "tool_call",
    }


@pytest.fixture
async def substitution_session(
    tmp_path: Path, echo_server: Any
) -> Session:
    """A session whose operator secret is addressable by name (Issue #11)."""
    agents = tmp_path / "agents"
    make_module(
        agents, "fetcher", description="Fetching fixture module.",
        prompt="You are fetcher: call `http_get` as instructed, then report.",
        risk="passive",
    )
    echo_port = echo_server.port
    orchestrator = ScriptedChatModel(
        scripts={
            "orchestrator": [
                AIMessage(content="", tool_calls=[{  # type: ignore[list-item]
                    "name": "task",
                    "args": {"description": "fetch", "subagent_type": "fetcher"},
                    "id": "call-f", "type": "tool_call",
                }]),
                final_reply("fetched"),
                final_reply("fetched"),
            ],
            "fetcher": [
                AIMessage(content="", tool_calls=[  # type: ignore[list-item]
                    _call("h1", f"http://127.0.0.1:{echo_port}/echo")
                ]),
                AIMessage(content="", tool_calls=[  # type: ignore[list-item]
                    _call("h2", "http://127.0.0.1:9/out-of-scope/<masked:probe-token>")
                ]),
                final_reply("fetched both"),
            ],
        },
        fallback_reply="done",
    )
    config = SessionConfig(
        target=TargetConfig(base_url=f"http://127.0.0.1:{echo_port}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_port], schemes=["http"]
        ),
        agents_dirs=[str(agents)],
        profile="yolo",  # no HITL pauses: the substitution is what is tested
    )
    session = await Session.open(
        config=config,
        session_dir=tmp_path / "s",
        secrets=SecretsConfig(tokens={SECRET_NAME: SECRET_VALUE}),
        model=orchestrator,
        judge_model=ScriptedJudge(),
    )
    try:
        yield session
    finally:
        await session.close()


class TestSecretReferenceSubstitution:
    """AC: rules see the reference; the target sees the value; raw stays in evidence."""

    async def test_reference_reaches_the_target_and_never_the_journal(
        self, substitution_session: Session, tmp_path: Path, echo_server: Any
    ) -> None:
        session = substitution_session
        session_dir = tmp_path / "s"
        await session.runtime.run_step("fetch both endpoints")

        # 1. The raw value reached the target's raw evidence record (D21:
        # session files stay raw) — substitution happened at the tool
        # boundary, before the client sent the request.
        evidence_files = list((session_dir / "evidence").rglob("*"))
        evidence_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in evidence_files
            if path.is_file()
        )
        assert SECRET_VALUE in evidence_text
        assert f"<masked:{SECRET_NAME}>" not in evidence_text

        # 2. The out-of-scope deny was evaluated on the reference form: the
        # invariant reason quotes the URL with the ``<masked:...>``
        # reference, not the raw value.
        blocked = await session.reader.by_type("GuardrailBlocked")
        reasons = [
            str(envelope.payload.reason)  # type: ignore[union-attr]
            for envelope in blocked
        ]
        assert any(f"<masked:{SECRET_NAME}>" in reason for reason in reasons), reasons
        assert not any(SECRET_VALUE in reason for reason in reasons)

        # 3. The journal never carries the raw value — not in any event.
        envelopes = await session.reader.tail(1000)
        dumped = "".join(
            json.dumps(envelope.payload, default=str) for envelope in envelopes
        )
        assert SECRET_VALUE not in dumped
        assert f"<masked:{SECRET_NAME}>" in dumped  # the reference is auditable
