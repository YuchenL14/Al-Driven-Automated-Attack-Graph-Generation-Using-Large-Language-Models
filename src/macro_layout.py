from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import networkx as nx

from layout_ir import LayoutIR


MacroKind = Literal[
    "isolated",
    "chain",
    "fork",
    "merge",
    "merge_fork",
]


class MacroLayoutValidationError(ValueError):
    """Raised when macro modules cannot reproduce the atomic block DAG."""


@dataclass(frozen=True)
class MacroModule:
    """One maximal non-branching sequence of atomic blocks."""

    id: str
    kind: MacroKind
    component_index: int
    rank: int
    block_ids: tuple[str, ...]
    parent_module_ids: tuple[str, ...]
    child_module_ids: tuple[str, ...]
    entry_state_ids: tuple[str, ...]
    exit_state_ids: tuple[str, ...]


@dataclass(frozen=True)
class MacroLayout:
    """Immutable macro projection of a :class:`layout_ir.LayoutIR`."""

    modules: tuple[MacroModule, ...]
    block_to_module: tuple[tuple[str, str], ...]
    edges: tuple[tuple[str, str], ...]


def atomic_block_graph(layout_ir: LayoutIR) -> nx.DiGraph:
    """Return the exact atomic-block DAG encoded by ``layout_ir``."""

    graph = nx.DiGraph()
    graph.add_nodes_from(block.id for block in layout_ir.atomic_blocks)
    for block in layout_ir.atomic_blocks:
        graph.add_edges_from(
            (parent_id, block.id) for parent_id in block.parent_block_ids
        )
    if not nx.is_directed_acyclic_graph(graph):
        raise MacroLayoutValidationError(
            "macro layout requires an acyclic atomic-block graph"
        )
    return graph


def _component_indices(
    graph: nx.DiGraph,
    block_order: dict[str, int],
) -> dict[str, int]:
    components = sorted(
        nx.weakly_connected_components(graph),
        key=lambda component: min(block_order[node] for node in component),
    )
    return {
        block_id: index
        for index, component in enumerate(components)
        for block_id in component
    }


def _module_paths(
    graph: nx.DiGraph,
    block_order: dict[str, int],
) -> list[tuple[str, ...]]:
    """Return maximal paths whose internal vertices have degree one.

    A branch or merge vertex starts a new module.  This makes the boundary
    explicit and prevents a long spine heuristic from absorbing one branch
    while leaving its siblings as visually secondary appendages.
    """

    starts = [
        block_id
        for block_id in graph.nodes
        if (
            graph.in_degree(block_id) != 1
            or graph.out_degree(next(iter(graph.predecessors(block_id)))) != 1
        )
    ]
    starts.sort(key=block_order.get)

    assigned: set[str] = set()
    paths: list[tuple[str, ...]] = []
    for start in starts:
        if start in assigned:
            continue
        path = [start]
        assigned.add(start)
        current = start
        while graph.out_degree(current) == 1:
            child = next(iter(graph.successors(current)))
            if graph.in_degree(child) != 1 or child in assigned:
                break
            path.append(child)
            assigned.add(child)
            current = child
        paths.append(tuple(path))

    for block_id in sorted(graph.nodes, key=block_order.get):
        if block_id not in assigned:
            paths.append((block_id,))
            assigned.add(block_id)
    paths.sort(key=lambda path: min(block_order[item] for item in path))
    return paths


def _longest_path_ranks(graph: nx.DiGraph) -> dict[str, int]:
    ranks: dict[str, int] = {}
    for node_id in nx.topological_sort(graph):
        parents = tuple(graph.predecessors(node_id))
        ranks[node_id] = (
            0 if not parents else max(ranks[parent] for parent in parents) + 1
        )
    return ranks


def _kind(
    parent_count: int,
    child_count: int,
    block_count: int,
) -> MacroKind:
    if parent_count == 0 and child_count == 0 and block_count == 1:
        return "isolated"
    if parent_count > 1 and child_count > 1:
        return "merge_fork"
    if parent_count > 1:
        return "merge"
    if child_count > 1:
        return "fork"
    return "chain"


def analyze_macro_layout(layout_ir: LayoutIR) -> MacroLayout:
    """Collapse atomic blocks into stable causal modules."""

    graph = atomic_block_graph(layout_ir)
    block_order = {
        block.id: index for index, block in enumerate(layout_ir.atomic_blocks)
    }
    block_by_id = {block.id: block for block in layout_ir.atomic_blocks}
    component_index = _component_indices(graph, block_order)
    paths = _module_paths(graph, block_order)

    module_ids = [f"module_{index:03d}" for index in range(len(paths))]
    block_to_module = {
        block_id: module_id
        for module_id, path in zip(module_ids, paths)
        for block_id in path
    }
    module_graph = nx.DiGraph()
    module_graph.add_nodes_from(module_ids)
    for source, target in graph.edges:
        source_module = block_to_module[source]
        target_module = block_to_module[target]
        if source_module != target_module:
            module_graph.add_edge(source_module, target_module)
    if not nx.is_directed_acyclic_graph(module_graph):
        raise MacroLayoutValidationError(
            "collapsing atomic blocks unexpectedly created a module cycle"
        )
    ranks = _longest_path_ranks(module_graph)

    producer_by_state = {
        state_id: block.id
        for block in layout_ir.atomic_blocks
        for state_id in block.result_state_ids
    }
    consumers_by_state: dict[str, set[str]] = {}
    for block in layout_ir.atomic_blocks:
        for state_id in block.input_state_ids:
            consumers_by_state.setdefault(state_id, set()).add(block.id)

    modules: list[MacroModule] = []
    for module_id, path in zip(module_ids, paths):
        path_set = set(path)
        parents = tuple(sorted(
            module_graph.predecessors(module_id),
            key=module_ids.index,
        ))
        children = tuple(sorted(
            module_graph.successors(module_id),
            key=module_ids.index,
        ))
        entry_states: list[str] = []
        exit_states: list[str] = []
        for block_id in path:
            block = block_by_id[block_id]
            for state_id in block.input_state_ids:
                producer = producer_by_state.get(state_id)
                if producer not in path_set and state_id not in entry_states:
                    entry_states.append(state_id)
            for state_id in block.result_state_ids:
                consumers = consumers_by_state.get(state_id, set())
                if (
                    not consumers
                    or any(consumer not in path_set for consumer in consumers)
                ):
                    if state_id not in exit_states:
                        exit_states.append(state_id)
        modules.append(MacroModule(
            id=module_id,
            kind=_kind(len(parents), len(children), len(path)),
            component_index=component_index[path[0]],
            rank=ranks[module_id],
            block_ids=path,
            parent_module_ids=parents,
            child_module_ids=children,
            entry_state_ids=tuple(entry_states),
            exit_state_ids=tuple(exit_states),
        ))

    macro = MacroLayout(
        modules=tuple(modules),
        block_to_module=tuple(
            (block_id, block_to_module[block_id])
            for block_id in sorted(block_to_module, key=block_order.get)
        ),
        edges=tuple(module_graph.edges),
    )
    validate_macro_layout(layout_ir, macro)
    return macro


def validate_macro_layout(layout_ir: LayoutIR, macro: MacroLayout) -> None:
    """Prove that the macro projection covers and preserves the block DAG."""

    expected_graph = atomic_block_graph(layout_ir)
    expected_blocks = set(expected_graph.nodes)
    listed_blocks = [
        block_id
        for module in macro.modules
        for block_id in module.block_ids
    ]
    if (
        len(listed_blocks) != len(set(listed_blocks))
        or set(listed_blocks) != expected_blocks
    ):
        raise MacroLayoutValidationError(
            "macro modules must cover every atomic block exactly once"
        )

    mapping_items = list(macro.block_to_module)
    if (
        len(mapping_items) != len(expected_blocks)
        or len({block_id for block_id, _ in mapping_items})
        != len(expected_blocks)
    ):
        raise MacroLayoutValidationError(
            "block-to-module mapping must be total and unique"
        )
    mapping = dict(mapping_items)
    known_module_ids = {module.id for module in macro.modules}
    if set(mapping.values()) - known_module_ids:
        raise MacroLayoutValidationError(
            "block-to-module mapping references an unknown module"
        )

    expected_module_edges = {
        (mapping[source], mapping[target])
        for source, target in expected_graph.edges
        if mapping[source] != mapping[target]
    }
    if set(macro.edges) != expected_module_edges:
        raise MacroLayoutValidationError(
            "macro edges do not reproduce cross-module atomic edges"
        )

    module_graph = nx.DiGraph()
    module_graph.add_nodes_from(known_module_ids)
    module_graph.add_edges_from(macro.edges)
    if not nx.is_directed_acyclic_graph(module_graph):
        raise MacroLayoutValidationError("macro module graph must be acyclic")

