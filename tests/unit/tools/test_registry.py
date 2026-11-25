"""``ToolRegistry`` tests (roadmap T1.5.1, arch §6.1, AD-7).

Acceptance criteria under test: duplicate names and reserved-prefix violations
are aggregated into ONE error listing every problem; the risk class is read
from the ``swarmy_risk_class`` attribute with the ``passive`` default (AD-7);
owner (``platform`` | module name) and source (``builtin`` | ``module:<dir>``)
are distinguished per entry.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

from swarmy.guardrails.models import RiskClass
from swarmy.tools.registry import (
    BUILTIN_SOURCE,
    PLATFORM_OWNER,
    RESERVED_TOOL_PREFIXES,
    ToolEntry,
    ToolRegistry,
    ToolRegistryError,
    ToolSpec,
    risk_class_of,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _probe(doc: str = "Probe tool: renders its integer argument.") -> Callable[[int], str]:
    """Build one annotated tool function with an LLM-facing docstring."""

    def probe(value: int) -> str:
        """Probe tool: renders its integer argument."""
        return str(value)

    probe.__doc__ = doc
    return probe


def _spec(
    name: str = "probe",
    *,
    owner: str = "some-module",
    source: str = "module:/agents/some-module",
    fn: Callable[..., object] | None = None,
    risk_class: RiskClass | None = None,
) -> ToolSpec:
    """Build a registration spec with sensible module defaults."""
    return ToolSpec(
        name=name,
        fn=fn if fn is not None else _probe(),
        owner=owner,
        source=source,
        risk_class=risk_class,
    )


def test_duplicate_and_reserved_prefix_aggregate_into_one_error() -> None:
    """AC (T1.5.1): duplicate name + reserved prefix yield ONE aggregated error."""
    registry = ToolRegistry()
    registry.register(_spec("memory_probe", owner=PLATFORM_OWNER, source=BUILTIN_SOURCE))
    with pytest.raises(ToolRegistryError) as excinfo:
        registry.register(
            _spec(
                "memory_probe",
                owner="rogue",
                source="module:/agents/rogue",
            )
        )
    problems = excinfo.value.problems
    assert len(problems) == 2
    joined = "\n".join(problems)
    assert "duplicate tool name 'memory_probe'" in joined
    assert "reserved platform prefix 'memory_'" in joined
    assert "arch §6.1" in joined  # the exact reserved-prefix line cites the source
    assert len(registry) == 1  # nothing was inserted


def test_batch_registration_aggregates_problems_across_specs() -> None:
    """Every problem of a batch is reported together; the batch is atomic."""
    registry = ToolRegistry()
    registry.register(_spec("taken"))
    bad_attr = _probe()
    bad_attr.swarmy_risk_class = "bogus"  # type: ignore[assignment]
    with pytest.raises(ToolRegistryError) as excinfo:
        registry.register_many(
            [
                _spec("taken"),  # duplicate against the registry
                _spec("event_sneaky"),  # reserved prefix, unique name
                _spec("fine", fn=_probe()),  # valid
                _spec("also_fine", fn=bad_attr),  # invalid risk attribute
            ]
        )
    problems = excinfo.value.problems
    assert len(problems) == 3
    joined = "\n".join(problems)
    assert "duplicate tool name 'taken'" in joined
    assert "reserved platform prefix 'event_'" in joined
    assert "invalid swarmy_risk_class attribute 'bogus'" in joined
    assert len(registry) == 1  # atomic: nothing inserted on failure


def test_risk_class_from_attribute_with_passive_default() -> None:
    """AC (T1.5.1, AD-7): ``swarmy_risk_class`` wins; missing attribute → passive."""
    registry = ToolRegistry()
    verify_tool = _probe()
    verify_tool.swarmy_risk_class = RiskClass.VERIFY
    string_tool = _probe()
    string_tool.swarmy_risk_class = "destructive"  # string value accepted
    registry.register_many(
        [
            _spec("explicit", fn=verify_tool),
            _spec("string_form", fn=string_tool),
            _spec("defaulted", fn=_probe()),
        ]
    )
    assert registry.entry("explicit").risk_class is RiskClass.VERIFY
    assert registry.entry("string_form").risk_class is RiskClass.DESTRUCTIVE
    assert registry.entry("defaulted").risk_class is RiskClass.PASSIVE


def test_explicit_spec_override_beats_attribute() -> None:
    """A ``tool_classes``-style override passed in the spec wins over the attr."""
    registry = ToolRegistry()
    tool = _probe()
    tool.swarmy_risk_class = RiskClass.VERIFY
    registry.register(_spec("overridden", fn=tool, risk_class=RiskClass.DESTRUCTIVE))
    assert registry.entry("overridden").risk_class is RiskClass.DESTRUCTIVE


def test_owner_and_source_are_distinguished() -> None:
    """AC (T1.5.1): owner ``platform`` vs module name; source builtin vs module:<dir>."""
    registry = ToolRegistry()
    registry.register_many(
        [
            _spec(
                "memory_probe",
                owner=PLATFORM_OWNER,
                source=BUILTIN_SOURCE,
            ),
            _spec("module_tool", owner="crawler", source="module:/agents/crawler"),
        ]
    )
    platform_entry = registry.entry("memory_probe")
    module_entry = registry.entry("module_tool")
    assert isinstance(platform_entry, ToolEntry)
    assert platform_entry.owner == "platform"
    assert platform_entry.source == "builtin"
    assert module_entry.owner == "crawler"
    assert module_entry.source == "module:/agents/crawler"
    assert set(registry.names()) == {"memory_probe", "module_tool"}
    assert "memory_probe" in registry
    assert "nowhere" not in registry


def test_platform_owner_may_use_reserved_prefixes() -> None:
    """The reserved prefixes forbid *module* tools only (arch §6.1)."""
    assert RESERVED_TOOL_PREFIXES == ("memory_", "event_", "session_")
    registry = ToolRegistry()
    for name in ("memory_search", "event_emit", "session_info"):
        registry.register(_spec(name, owner=PLATFORM_OWNER, source=BUILTIN_SOURCE))
    assert len(registry) == 3


def test_duplicate_within_one_batch_is_reported() -> None:
    """Two specs with the same name in one batch collide without a registry entry."""
    registry = ToolRegistry()
    with pytest.raises(ToolRegistryError) as excinfo:
        registry.register_many([_spec("twin", owner="a"), _spec("twin", owner="b")])
    assert "duplicate tool name 'twin' within the batch" in "\n".join(excinfo.value.problems)


def test_risk_class_of_helper() -> None:
    """``risk_class_of`` resolves the attribute with the passive default (AD-7)."""
    plain = _probe()
    assert risk_class_of(plain) is RiskClass.PASSIVE
    marked = _probe()
    marked.swarmy_risk_class = RiskClass.NETWORK_WRITE
    assert risk_class_of(marked) is RiskClass.NETWORK_WRITE
    broken = _probe()
    broken.swarmy_risk_class = "nope"  # type: ignore[assignment]
    with pytest.raises(ToolRegistryError, match="invalid swarmy_risk_class"):
        risk_class_of(broken)


def test_entry_lookup_error_names_registered_tools(tmp_path: Path) -> None:
    """Unknown names fail with the list of registered tools."""
    registry = ToolRegistry()
    registry.register(_spec("known", source=f"module:{tmp_path}"))
    with pytest.raises(KeyError, match="known tool 'missing'") as excinfo:
        registry.entry("missing")
    assert "known" in str(excinfo.value)
