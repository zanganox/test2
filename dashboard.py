
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leak2Path relationship graph injected into the HTML dashboard."""

from __future__ import annotations

import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if not path.is_file():
        return rows

    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
            except json.JSONDecodeError:
                continue

    return rows


def _escape(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _linked_candidates(record: Dict[str, Any]) -> Set[str]:
    values = record.get("linked_identity_candidates", []) or []

    if isinstance(values, str):
        values = [values]

    return {
        str(value).strip().lower()
        for value in values
        if value
    }


def _localpart(value: str) -> str:
    return value.split("@", 1)[0].strip().lower()


def _relationship_graph(
    target: str,
    records: List[Dict[str, Any]],
    max_nodes: int = 36,
) -> str:
    corporate_ids = {
        str(record.get("identity", "")).strip().lower()
        for record in records
        if record.get("is_corporate_identity")
        and record.get("identity")
    }

    alias_map: Dict[str, Set[str]] = defaultdict(set)

    for identity in corporate_ids:
        alias_map[_localpart(identity)].add(identity)

    services: Dict[str, Dict[str, Any]] = {}

    for record in records:
        host = str(
            record.get("service_domain", "")
        ).strip().lower().rstrip(".")

        scope = str(
            record.get("service_scope", "unknown")
        )

        identity = str(
            record.get("identity", "")
        ).strip().lower()

        if not host or scope not in {"corporate", "third_party"}:
            continue

        linked = _linked_candidates(record)
        direct_corporate = bool(
            record.get("is_corporate_identity")
            or identity in corporate_ids
        )

        if not direct_corporate:
            linked.update(alias_map.get(identity, set()))

        if scope == "corporate":
            include = True
        else:
            include = bool(
                direct_corporate or (linked & corporate_ids)
            )

        if not include:
            continue

        key = scope + "|" + host

        item = services.setdefault(key, {
            "host": host,
            "scope": scope,
            "identities": set(),
            "evidence_ids": set(),
            "records": 0,
        })

        if identity:
            item["identities"].add(identity)

        item["evidence_ids"].update(
            record.get("evidence_ids", []) or []
        )

        if record.get("evidence_id"):
            item["evidence_ids"].add(record["evidence_id"])

        item["records"] += 1

    ordered = sorted(
        services.values(),
        key=lambda item: (
            0 if item["scope"] == "corporate" else 1,
            -len(item["evidence_ids"]),
            item["host"],
        ),
    )

    total_nodes = len(ordered)
    visible = ordered[:max_nodes]
    omitted = max(0, total_nodes - len(visible))

    width = 1120
    row_height = 82
    top = 70
    height = max(280, top + row_height * max(1, len(visible)) + 60)
    center_y = height // 2

    svg_parts = [
        f'<svg viewBox="0 0 {width} {height}" '
        'role="img" aria-label="Relaciones observadas entre dominio y servicios">',
        '<defs><marker id="l2pArrow" markerWidth="10" markerHeight="10" '
        'refX="8" refY="3" orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L0,6 L9,3 z" fill="#6f8cac"/></marker></defs>',
    ]

    # Domain node remains central to the graph.
    domain_x = 22
    domain_y = center_y - 48
    domain_w = 250
    domain_h = 96

    for index, item in enumerate(visible):
        y = top + index * row_height
        y_center = y + 26

        scope = item["scope"]
        host = item["host"]

        color = "#48b4a2" if scope == "corporate" else "#7e91ef"

        svg_parts.append(
            f'<path d="M {domain_x + domain_w} {center_y} '
            f'C 360 {center_y}, 390 {y_center}, 475 {y_center}" '
            'fill="none" stroke="#6f8cac" stroke-width="1.6" '
            'marker-end="url(#l2pArrow)" opacity="0.8"/>'
        )

        svg_parts.append(
            f'<rect x="475" y="{y}" width="600" height="54" rx="10" '
            f'fill="#17243a" stroke="{color}" stroke-width="1.3"/>'
        )

        svg_parts.append(
            f'<text x="493" y="{y + 22}" font-size="14" '
            'font-family="Segoe UI,Arial" fill="#edf3fb">'
            f'{_escape(host)}</text>'
        )

        svg_parts.append(
            f'<text x="493" y="{y + 42}" font-size="11" '
            'font-family="Segoe UI,Arial" fill="#aabbd0">'
            f'{_escape(scope)} · '
            f'{len(item["identities"])} identidad(es) · '
            f'{len(item["evidence_ids"])} evidencia(s)</text>'
        )

    svg_parts.extend([
        f'<rect x="{domain_x}" y="{domain_y}" width="{domain_w}" '
        f'height="{domain_h}" rx="14" fill="#182c46" stroke="#51a6d8" '
        'stroke-width="2"/>',
        f'<text x="{domain_x + domain_w / 2}" y="{domain_y + 38}" '
        'text-anchor="middle" font-size="13" font-family="Segoe UI,Arial" '
        'fill="#a9d8fa">TARGET DOMAIN</text>',
        f'<text x="{domain_x + domain_w / 2}" y="{domain_y + 62}" '
        'text-anchor="middle" font-size="14" font-weight="600" '
        'font-family="Segoe UI,Arial" fill="#ffffff">'
        f'{_escape(target)}</text>',
        '</svg>',
    ])

    if total_nodes == 0:
        graph_message = (
            "No se encontraron relaciones de servicio que cumplan "
            "los criterios del gráfico."
        )
    else:
        graph_message = (
            f"{total_nodes} servicios relacionados; "
            f"{len(visible)} mostrados en el gráfico."
        )

    omitted_html = (
        f'<p class="l2p-graph-note">{omitted} servicios adicionales '
        "omitidos en la vista gráfica.</p>"
        if omitted else ""
    )

    table_rows = []

    for item in ordered:
        table_rows.append(
            "<tr>"
            f"<td>{_escape(item['host'])}</td>"
            f"<td>{_escape(item['scope'])}</td>"
            f"<td>{len(item['identities'])}</td>"
            f"<td>{len(item['evidence_ids'])}</td>"
            "</tr>"
        )

    table_html = (
        "<table class=\"l2p-graph-table\"><thead><tr>"
        "<th>Servicio</th><th>Alcance</th><th>Identidades</th>"
        "<th>Evidencias</th></tr></thead><tbody>"
        + "".join(table_rows)
        + "</tbody></table>"
    )

    return f"""
<section id="l2p-relationship-graph" class="l2p-graph-section">
  <h2>Domain–Service Relationship Map</h2>
  <p class="l2p-graph-note">
    {graph_message} Las conexiones representan observaciones correlacionadas,
    no accesos confirmados.
  </p>
  <div class="l2p-graph-viewport">
    {''.join(svg_parts)}
  </div>
  {omitted_html}
  <details>
    <summary>Ver inventario de relaciones</summary>
    {table_html}
  </details>
</section>
<style>
.l2p-graph-section {{
  margin: 28px 0;
  padding: 22px;
  border: 1px solid #2b3d57;
  border-radius: 14px;
  background: #101a2b;
  color: #edf3fb;
}}
.l2p-graph-section h2 {{
  margin: 0 0 12px;
  color: #f3f6fc;
}}
.l2p-graph-note {{
  color: #9fb1c7;
  font-size: 13px;
  line-height: 1.6;
}}
.l2p-graph-viewport {{
  overflow: auto;
  max-height: 850px;
  border: 1px solid #263751;
  border-radius: 10px;
  background: #0c1524;
}}
.l2p-graph-viewport svg {{
  display: block;
  width: 100%;
  min-width: 760px;
  height: auto;
}}
.l2p-graph-section details {{
  margin-top: 18px;
}}
.l2p-graph-section summary {{
  cursor: pointer;
  color: #9ecdf5;
}}
.l2p-graph-table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  font-size: 12px;
}}
.l2p-graph-table th,
.l2p-graph-table td {{
  text-align: left;
  padding: 9px;
  border-bottom: 1px solid #263751;
}}
.l2p-graph-table th {{
  color: #9ecdf5;
}}
</style>
"""


def inject_relationship_graph(
    report_path: Path,
    target: str,
    normalized_records_path: Path,
) -> None:
    """Add the relationship graph to the dashboard generated by the core."""
    report_path = Path(report_path)
    records = read_jsonl(Path(normalized_records_path))

    if not report_path.is_file():
        return

    document = report_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    # The base HTML generator creates a fresh dashboard each run.
    # Avoid inserting the section twice if called more than once.
    marker = '<section id="l2p-relationship-graph"'

    if marker in document:
        return

    section = _relationship_graph(target, records)

    if "</main>" in document:
        document = document.replace(
            "</main>",
            section + "\n</main>",
            1,
        )
    elif "</body>" in document:
        document = document.replace(
            "</body>",
            section + "\n</body>",
            1,
        )
    else:
        document += "\n" + section

    report_path.write_text(
        document,
        encoding="utf-8",
        newline="\n",
    )
