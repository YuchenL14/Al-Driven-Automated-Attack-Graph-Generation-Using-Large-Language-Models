"""Artifact-level reproducibility for professional graph generation.

Hosted language models can vary between otherwise identical requests, even
when sampling is configured conservatively.  This module therefore separates
an *independent sample* from an exact replay of a previously validated graph.
The cache key covers every semantic input that can legitimately change the
graph and the adjacent manifest records what happened for later audit.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from schema import AttackGraph


CACHE_FORMAT_VERSION = 1
DECODING_PROFILE = {
    "temperature": 0,
    "thinking": "disabled",
}
_SEMANTIC_CODE_FILES = (
    "requirements.lock",
    "src/extract.py",
    "src/schema.py",
    "src/attack_lookup.py",
)
_RENDER_CODE_FILES = (
    "src/attack_graph.py",
    "src/causal_split.py",
    "src/layout_ir.py",
    "src/layout_planner.py",
    "src/layout_renderer.py",
    "src/layout_svg.py",
    "src/visual_aggregation.py",
    "src/visual_syntax.py",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _file_sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _files_fingerprint(root: Path, names: tuple[str, ...]) -> str:
    records = []
    for name in names:
        path = root / name
        records.append({"path": name, "sha256": _file_sha256(path)})
    return _sha256_text(_canonical_json(records))


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass(frozen=True)
class ReproducibilitySpec:
    """All inputs that define one reusable semantic graph."""

    format_version: int
    source_text_sha256: str
    ruleset: str
    ruleset_sha256: str
    attack_catalogue_sha256: str
    semantic_code_sha256: str
    provider: str
    model: str
    pipeline: str
    decoding: dict[str, Any]

    @property
    def cache_key(self) -> str:
        return _sha256_text(_canonical_json(asdict(self)))


def build_reproducibility_spec(
    root: Path,
    report_text: str,
    ruleset: str,
    provider: str,
    model: str,
    *,
    pipeline: str = "hierarchical",
) -> ReproducibilitySpec:
    """Build the content-addressed identity of a professional extraction."""

    rules_path = root / "rules" / f"ruleset_{ruleset}.md"
    catalogue_path = root / "data" / "attack_lookup.json"
    return ReproducibilitySpec(
        format_version=CACHE_FORMAT_VERSION,
        source_text_sha256=_sha256_text(report_text),
        ruleset=ruleset,
        ruleset_sha256=_file_sha256(rules_path),
        attack_catalogue_sha256=_file_sha256(catalogue_path),
        semantic_code_sha256=_files_fingerprint(
            root, _SEMANTIC_CODE_FILES),
        provider=provider,
        model=model,
        pipeline=pipeline,
        decoding=dict(DECODING_PROFILE),
    )


def renderer_fingerprint(root: Path) -> str:
    """Identify the deterministic rendering implementation used for a run."""

    return _files_fingerprint(root, _RENDER_CODE_FILES)


def graph_sha256(graph: AttackGraph) -> str:
    """Hash the canonical validated graph, independent of JSON indentation."""

    return _sha256_text(_canonical_json(graph.model_dump(mode="json")))


def cache_path(cache_dir: Path, cache_key: str) -> Path:
    return cache_dir / f"{cache_key}.json"


def load_validated_graph(
    cache_dir: Path,
    spec: ReproducibilitySpec,
) -> AttackGraph | None:
    """Return an exact validated replay, or ``None`` for any unsafe entry."""

    path = cache_path(cache_dir, spec.cache_key)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("format_version") != CACHE_FORMAT_VERSION:
            return None
        if payload.get("spec") != asdict(spec):
            return None
        graph = AttackGraph.model_validate(payload["graph"])
        if payload.get("graph_sha256") != graph_sha256(graph):
            return None
        return graph
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        # A partial, stale or manually edited cache entry must never bypass the
        # normal validated extraction path.
        return None


def store_validated_graph(
    cache_dir: Path,
    spec: ReproducibilitySpec,
    graph: AttackGraph,
) -> Path:
    """Atomically freeze one validated graph without replacing an existing one."""

    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_path(cache_dir, spec.cache_key)
    if destination.exists():
        return destination
    payload = {
        "format_version": CACHE_FORMAT_VERSION,
        "spec": asdict(spec),
        "graph_sha256": graph_sha256(graph),
        "graph": graph.model_dump(mode="json"),
    }
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=cache_dir,
            prefix=f".{spec.cache_key}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        try:
            # Linking is an atomic create-if-absent operation.  It preserves
            # the first validated reference if two workers finish the same
            # request concurrently; ``replace`` would silently overwrite it.
            os.link(temporary_name, destination)
        except FileExistsError:
            pass
    finally:
        if temporary_name:
            temporary = Path(temporary_name)
            if temporary.exists():
                temporary.unlink()
    return destination


def write_run_manifest(
    output_path: Path,
    root: Path,
    spec: ReproducibilitySpec,
    graph: AttackGraph,
    *,
    cache_hit: bool,
    independent_sample: bool,
    pages: int,
) -> Path:
    """Write an auditable explanation of how this particular run was made."""

    mode = (
        "independent_sample"
        if independent_sample
        else "validated_replay" if cache_hit else "new_frozen_reference"
    )
    payload = {
        "format_version": CACHE_FORMAT_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "cache_key": spec.cache_key,
        "cache_hit": cache_hit,
        "independent_sample": independent_sample,
        "spec": asdict(spec),
        "renderer_sha256": renderer_fingerprint(root),
        "graph_sha256": graph_sha256(graph),
        "preconditions": len(graph.preconditions),
        "events": len(graph.events),
        "pages": pages,
    }
    path = output_path.with_suffix(".reproducibility.json")
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
