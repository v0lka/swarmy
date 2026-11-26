"""Attack Trees panel: interactive render of AttackNode/AttackEdge (T4.4.1).

Data comes from memory through the facade (RD-9: the panel is accepted on
fixture data; live demo data arrives with P5.3 without a P4.4 dependency).
Nodes expand/collapse like any Textual tree; selecting a ``finding`` node
posts :class:`~swarmy.tui.panels.findings.FindingCardRequested` — the same
node → finding-card transition the findings panel serves (arch §10.1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias

from rich.markup import escape
from textual.containers import Vertical
from textual.widgets import Tree

from swarmy.tui.panels.findings import FindingCardRequested

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult
    from textual.widgets.tree import TreeNode

    from swarmy.memory.models import AttackEdge, AttackNode
    from swarmy.tui.state import SessionView, TuiState

#: Data carried by every tree node: (kind, finding_ref, title).
TreePayload: TypeAlias = tuple[str, int | None, str]

_KIND_MARK: dict[str, str] = {
    "precondition": "[dim]precondition[/]",
    "finding": "[yellow]finding[/]",
    "goal": "[bold red]goal[/]",
}


class TreesPanel(Vertical):
    """One Textual tree over the attack-graph forest (roots = unreferenced nodes)."""

    BORDER_TITLE = "Attack Trees (enter: expand / open finding card)"

    def __init__(self, widget_id: str, masker: Callable[[str], str]) -> None:
        """Start with an empty forest (rebuilt on refresh)."""
        super().__init__(id=widget_id)
        self.masker = masker
        self._by_id: dict[int, AttackNode] = {}

    def compose(self) -> ComposeResult:
        """The forest tree widget."""
        tree: Tree[TreePayload] = Tree("attack trees", id="attack-tree")
        tree.show_root = False
        yield tree

    @property
    def tree_widget(self) -> Tree[TreePayload]:
        """The forest tree."""
        return self.query_one("#attack-tree", Tree)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Finding-kind nodes open the raw finding card (node → finding)."""
        node = event.node
        if node.data is None:
            return
        kind, finding_ref, title = node.data
        if kind == "finding" and finding_ref is not None:
            self.post_message(FindingCardRequested(finding_ref))
            self.border_title = f"Attack Trees — last node: {escape(title)}"

    def refresh_state(self, state: TuiState, view: SessionView) -> None:
        """Rebuild the forest from the snapshot cache (node labels raw)."""
        del view  # the snapshot cache is already pulled; facade unused here
        nodes = state.attack_nodes
        edges = state.attack_edges
        self._by_id = {node.id: node for node in nodes}
        children: dict[int, list[AttackEdge]] = {}
        referenced: set[int] = set()
        for edge in edges:
            children.setdefault(edge.src, []).append(edge)
            referenced.add(edge.dst)
        tree = self.tree_widget
        tree.clear()
        roots = [node for node in nodes if node.id not in referenced]
        for root in roots:
            branch = tree.root.add(self._label(root), data=self._payload(root))
            branch.expand()
            self._attach_children(branch, root.id, children, {root.id}, {root.id})

    def _attach_children(
        self,
        branch: TreeNode[TreePayload],
        node_id: int,
        children: dict[int, list[AttackEdge]],
        visited: set[int],
        path: set[int],
    ) -> None:
        """Attach the typed edges leaving ``node_id`` (requires/enables/leads_to).

        ``visited`` bounds the walk (a node renders at most once per root);
        ``path`` is the current ancestor chain. Attack edges are LLM-authored
        and the store imposes no acyclicity constraint, so a back-edge into
        ``path`` is a cycle and a cross-branch repeat is a diamond — both are
        rendered as marker lines instead of descending again (Issue #15:
        unguarded recursion used to end in ``RecursionError`` on every
        refresh).
        """
        for edge in children.get(node_id, ()):
            target = self._by_id.get(edge.dst)
            if target is None:  # pragma: no cover - store guarantees both rows
                continue
            kind = escape(edge.kind)
            if target.id in path:
                branch.add(
                    f"[dim]{kind} → cycle: node #{target.id}[/]", data=self._payload(target)
                )
                continue
            if target.id in visited:
                branch.add(
                    f"[dim]{kind} → repeat: see node #{target.id} above[/]",
                    data=self._payload(target),
                )
                continue
            visited.add(target.id)
            path.add(target.id)
            child = branch.add(
                f"[dim]{kind}[/] → {self._label(target)}", data=self._payload(target)
            )
            self._attach_children(child, target.id, children, visited, path)
            path.discard(target.id)

    @staticmethod
    def _payload(node: AttackNode) -> TreePayload:
        """Tree-node data: (kind, finding_ref, title) for the selection handler."""
        return (node.kind, node.finding_ref, node.title)

    def _label(self, node: AttackNode) -> str:
        """One node label (target data; secrets masked like every panel)."""
        return f"{_KIND_MARK.get(node.kind, escape(node.kind))} {escape(self.masker(node.title))}"
