
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leak2Path v5.3.1 - incremental ingestion + scope observation rules.

Dependencias en la misma carpeta:
  - leak2path_v5_3.py  (v5.3.0 incremental layer)
  - leak2path_v5_2.py  (v5.2.0 deterministic engine)

El parser, la normalización, el dashboard y el procesamiento incremental
se delegan a las versiones base validadas.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

VERSION = "5.3.1"
BASE_V53_VERSION = "5.3.0"

BASE_V53_PATH = Path(__file__).resolve().with_name("leak2path_v5_3.py")

if not BASE_V53_PATH.is_file():
    raise SystemExit(
        "[!] No se encontró leak2path_v5_3.py junto a este archivo. "
        "Coloca la v5.3.0 y la v5.2.0 en la misma carpeta."
    )

_spec = importlib.util.spec_from_file_location(
    "leak2path_v53_incremental_base",
    BASE_V53_PATH,
)

if _spec is None or _spec.loader is None:
    raise SystemExit("[!] No se pudo cargar Leak2Path v5.3.0.")

pipeline = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pipeline
_spec.loader.exec_module(pipeline)

if getattr(pipeline, "VERSION", None) != BASE_V53_VERSION:
    raise SystemExit(
        f"[!] Se esperaba la capa v{BASE_V53_VERSION}, pero se encontró "
        f"v{getattr(pipeline, 'VERSION', 'desconocida')}."
    )

engine = pipeline.engine

if getattr(engine, "VERSION", None) != BASE_V53_VERSION:
    raise SystemExit(
        "[!] La capa incremental no cargó el motor v5.2.0 esperado."
    )

if not callable(getattr(engine, "derive_findings", None)):
    raise SystemExit("[!] El motor base no contiene derive_findings().")

if not callable(getattr(engine, "build_triage_decisions", None)):
    raise SystemExit(
        "[!] El motor base no contiene build_triage_decisions()."
    )

# Publicar v5.3.1 en la consola, el dashboard y los metadatos.
pipeline.VERSION = VERSION
engine.VERSION = VERSION

BASE_DERIVE_FINDINGS = engine.derive_findings
BASE_BUILD_TRIAGE = engine.build_triage_decisions
BASE_RUN_PIPELINE = pipeline._ORIGINAL_RUN_PIPELINE
BASE_BUILD_DELTA = pipeline._build_delta


# ============================================================
# CATÁLOGO DE REGLAS NUEVAS
# ============================================================

RULE_CATALOGUE_ADDITIONS: Dict[str, Dict[str, str]] = {
    "SVC-001": {
        "family": "R06_in_scope_service_observations",
        "name": "External email observed on an in-scope service",
        "condition": (
            "An external email identity is observed in a normalized record "
            "whose service_scope is corporate and whose service hostname is known."
        ),
        "limitation": (
            "Does not establish account ownership, business relationship, "
            "credential validity, authorization or access. Informational correlation only."
        ),
    },
    "SVC-002": {
        "family": "R06_in_scope_service_observations",
        "name": "Non-email identifier observed on an in-scope service",
        "condition": (
            "A non-email identifier is observed in a normalized record "
            "whose service_scope is corporate and whose service hostname is known."
        ),
        "limitation": (
            "The identifier is not proof of a corporate account, employee, "
            "privilege or ownership. Informational correlation only."
        ),
    },
    "AUTH-002": {
        "family": "R07_federated_authentication_observations",
        "name": "External email observed on a corporate AD FS endpoint",
        "condition": (
            "An external email identity is observed on an in-scope corporate "
            "service whose hostname or path contains an AD FS indicator."
        ),
        "limitation": (
            "Does not prove successful authentication, federation, account validity, "
            "domain access or an operational attack path."
        ),
    },
}


# ============================================================
# HELPERS
# ============================================================

def _record_evidence_ids(record: Dict[str, Any]) -> List[str]:
    """Obtener referencias de evidencia mediante el helper de v5.2.0."""
    helper = getattr(engine, "record_evidence_ids", None)

    if callable(helper):
        return sorted(set(helper(record)))

    values = record.get("evidence_ids") or []

    if not values and record.get("evidence_id"):
        values = [record["evidence_id"]]

    return sorted({
        str(value)
        for value in values
        if value
    })


def _is_external_email_on_in_scope_service(
    record: Dict[str, Any],
) -> bool:
    identity = str(
        record.get("identity", "")
    ).strip().lower()

    return bool(
        record.get("identity_type")
        == "external_email_on_corporate_service"
        and not record.get("is_corporate_identity")
        and "@" in identity
        and record.get("service_scope") == "corporate"
        and record.get("service_domain")
        and record.get("service_origin_known")
    )


def _is_non_email_identifier_on_in_scope_service(
    record: Dict[str, Any],
) -> bool:
    identity = str(
        record.get("identity", "")
    ).strip()

    return bool(
        record.get("identity_type") == "corporate_identifier"
        and not record.get("is_corporate_identity")
        and identity
        and "@" not in identity
        and record.get("service_scope") == "corporate"
        and record.get("service_domain")
        and record.get("service_origin_known")
    )


def _is_adfs_record(record: Dict[str, Any]) -> bool:
    host = str(
        record.get("service_domain", "")
    ).strip().lower().rstrip(".")

    path = str(
        record.get("service_path", "")
    ).strip().lower()

    return bool(
        re.search(r"(?:^|[.-])adfs(?:[.-]|$)", host)
        or re.search(r"(?:^|/)adfs(?:/|$)", path)
    )


def _source_files(
    rows: Sequence[Dict[str, Any]],
) -> List[str]:
    files: Set[str] = set()

    for row in rows:
        files.update(
            str(value)
            for value in row.get("source_files", [])
            if value
        )

        for occurrence in row.get("source_occurrences", []) or []:
            source_file = occurrence.get("source_file")

            if source_file:
                files.add(str(source_file))

        if row.get("source_file"):
            files.add(str(row["source_file"]))

    return sorted(files, key=str.casefold)


# ============================================================
# NUEVOS HALLAZGOS
# ============================================================

def _add_grouped_scope_findings(
    findings: List[Dict[str, Any]],
    rule_id: str,
    rows: Sequence[Dict[str, Any]],
) -> None:
    """
    Agregar un hallazgo por identidad, servicio y regla.
    Conserva todas las referencias de evidencia de ese grupo.
    """
    if not rows:
        return

    identity = str(
        rows[0].get("identity", "")
    ).strip().lower()

    service_key = str(
        rows[0].get("service_key", "")
    )

    services = sorted({
        str(
            row.get("service_observed")
            or row.get("service_domain")
            or service_key
        )
        for row in rows
        if (
            row.get("service_observed")
            or row.get("service_domain")
            or service_key
        )
    })

    hosts = sorted({
        str(row.get("service_domain", "")).lower()
        for row in rows
        if row.get("service_domain")
    })

    paths = sorted({
        str(row.get("service_path", ""))
        for row in rows
        if row.get("service_path")
    })

    evidence_ids = sorted({
        evidence_id
        for row in rows
        for evidence_id in _record_evidence_ids(row)
    })

    if not evidence_ids:
        return

    material_types = sorted({
        str(row.get("credential_material_type", "unknown"))
        for row in rows
    })

    # No se incluyen contraseñas ni valores de credenciales.
    details = {
        "identity_type": str(
            rows[0].get("identity_type", "unknown")
        ),
        "service_scope": str(
            rows[0].get("service_scope", "unknown")
        ),
        "service_key": service_key,
        "observed_services": services,
        "service_hosts": hosts,
        "service_paths": paths,
        "credential_material_types": material_types,
        "unique_normalized_observations": len(rows),
        "raw_occurrence_count": sum(
            int(row.get("occurrence_count", 1) or 1)
            for row in rows
        ),
        "source_files": _source_files(rows),
        "ownership_confirmed": False,
        "credential_validity_confirmed": False,
    }

    if rule_id == "SVC-001":
        title = "External email observed on an in-scope service"
        pattern = "external_identity_on_corporate_service"
        confidence = "low"

        hypothesis = (
            "An email address from outside the target domain was observed "
            "in a record associated with an in-scope service. It may belong "
            "to a client, supplier, test user or another legitimate relationship."
        )

        limitations = (
            "This association does not establish account ownership, a business "
            "dependency, credential validity, authorization or access."
        )

        validation = (
            "Confirm the service purpose and account relationship with the "
            "authorized service owner. Validate only within the approved scope."
        )

    elif rule_id == "SVC-002":
        title = "Non-email identifier observed on an in-scope service"
        pattern = "non_email_identifier_on_corporate_service"
        confidence = "low"

        hypothesis = (
            "A username or other identifier that is not an email address was "
            "observed in a record associated with an in-scope service."
        )

        limitations = (
            "The observation does not establish that the identifier belongs "
            "to the organization, a current employee, a privileged account or a person."
        )

        validation = (
            "Resolve the identifier with the authorized service owner and "
            "inventory. Do not infer ownership from the service scope alone."
        )

    elif rule_id == "AUTH-002":
        title = "External email observed on a corporate AD FS endpoint"
        pattern = "external_identity_on_corporate_adfs"
        confidence = "low"

        hypothesis = (
            "An external email identity appears in an observed record associated "
            "with an in-scope AD FS endpoint. The association merits contextual review."
        )

        limitations = (
            "Does not prove that the identity is federated, can authenticate, "
            "has domain access or represents an exploitable path."
        )

        validation = (
            "Confirm the endpoint and identity relationship with the authorized "
            "identity owner. Perform live authentication validation only when explicitly authorized."
        )

        details["adfs_indicator"] = True

    else:
        return

    engine.add_finding(
        findings,
        rule_id,
        pattern,
        title,
        identity,
        evidence_ids,
        confidence,
        "observed",
        hypothesis,
        limitations,
        validation,
        details,
    )


def _derive_findings_v531(
    records: List[Dict[str, Any]],
    corporate_identities: Set[str],
    alias_records_by_identity: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    # Preservar íntegramente las reglas existentes de v5.2.0.
    findings = BASE_DERIVE_FINDINGS(
        records,
        corporate_identities,
        alias_records_by_identity,
    )

    grouped: Dict[
        Tuple[str, str, str],
        List[Dict[str, Any]],
    ] = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        identity = str(
            record.get("identity", "")
        ).strip().lower()

        service_key = str(
            record.get("service_key", "")
        )

        if not identity or not service_key:
            continue

        external_in_scope = (
            _is_external_email_on_in_scope_service(record)
        )

        identifier_in_scope = (
            _is_non_email_identifier_on_in_scope_service(record)
        )

        if external_in_scope:
            grouped.setdefault(
                ("SVC-001", identity, service_key),
                [],
            ).append(record)

            if _is_adfs_record(record):
                grouped.setdefault(
                    ("AUTH-002", identity, service_key),
                    [],
                ).append(record)

        if identifier_in_scope:
            grouped.setdefault(
                ("SVC-002", identity, service_key),
                [],
            ).append(record)

    for key in sorted(grouped):
        rule_id = key[0]
        _add_grouped_scope_findings(
            findings,
            rule_id,
            grouped[key],
        )

    return sorted(
        findings,
        key=lambda finding: (
            finding.get("triage_pattern", ""),
            finding.get("subject_identity", ""),
            finding.get("rule_id", ""),
            finding.get("finding_id", ""),
        ),
    )


# ============================================================
# EXPLICACIONES DE TRIAGE
# ============================================================

def _fix_triage_explanations(
    decisions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    for decision in decisions:
        if decision.get("decision") != "no_actionable_pattern":
            continue

        matched = set(
            decision.get("matched_rule_ids", [])
        )

        identity_type = decision.get(
            "identity_type", "unknown"
        )

        service_scope = decision.get(
            "service_scope", "unknown"
        )

        if "BASE-000" in matched:
            explanation = (
                "No se identificó otra regla accionable para esta identidad "
                "corporativa. BASE-000 es un registro informativo; no representa "
                "por sí mismo una exposición accionable."
            )

        elif (
            identity_type == "external_email_on_corporate_service"
            and service_scope == "corporate"
        ):
            explanation = (
                "La identidad parece ser un correo externo asociado a un servicio "
                "dentro del alcance, pero no se vinculó un hallazgo SVC-001. "
                "Revise el registro normalizado y el catálogo de reglas."
            )

        elif (
            identity_type == "corporate_identifier"
            and service_scope == "corporate"
        ):
            explanation = (
                "Se observó un identificador no basado en correo en un servicio "
                "dentro del alcance, pero no se vinculó un hallazgo SVC-002. "
                "La asociación no confirma propiedad corporativa. Revise el registro normalizado."
            )

        else:
            explanation = (
                "La observación fue normalizada, pero ninguna regla configurada "
                "generó un hallazgo para esta evidencia. No se generó BASE-000 "
                "para esta observación. Revise el contexto y el catálogo de reglas."
            )

        decision["decision_explanation"] = explanation

    return decisions


def _build_triage_decisions_v531(
    unique_groups: List[Dict[str, Any]],
    line_records: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    decisions_all, decisions_unique = BASE_BUILD_TRIAGE(
        unique_groups,
        line_records,
        findings,
    )

    return (
        _fix_triage_explanations(decisions_all),
        _fix_triage_explanations(decisions_unique),
    )


# ============================================================
# COMPATIBILIDAD DEL ESTADO INCREMENTAL
# ============================================================

def _build_delta_compatible(
    input_dir: Path,
    target: str,
    current: Dict[str, Dict[str, int]],
    previous: Optional[Dict[str, Any]],
    force_rebuild: bool,
) -> Dict[str, Any]:
    """
    Reutilizar el inventario v5.3.0 al cambiar solamente las reglas.
    El motor sigue reconstruyendo globalmente la normalización y los hallazgos.
    """
    compatible_previous = previous

    if (
        previous
        and previous.get("version") == BASE_V53_VERSION
        and isinstance(previous.get("files"), dict)
    ):
        compatible_previous = dict(previous)
        compatible_previous["version"] = VERSION

    return BASE_BUILD_DELTA(
        input_dir,
        target,
        current,
        compatible_previous,
        force_rebuild,
    )


# ============================================================
# ACTUALIZACIÓN DEL CATÁLOGO
# ============================================================

def _write_rule_catalogue_additions(
    output_dir: Path,
) -> None:
    catalogue_path = (
        output_dir / "findings" / "rule_catalogue.json"
    )

    if not catalogue_path.is_file():
        return

    try:
        with catalogue_path.open(
            "r",
            encoding="utf-8",
        ) as source:
            catalogue = json.load(source)

        if not isinstance(catalogue, dict):
            raise ValueError(
                "rule_catalogue.json no contiene un objeto JSON"
            )

        catalogue.update(RULE_CATALOGUE_ADDITIONS)

        temp_path = catalogue_path.with_suffix(".json.tmp")

        with temp_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output:
            json.dump(
                catalogue,
                output,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            output.write("\n")

        temp_path.replace(catalogue_path)

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(
            f"[!] No se pudo actualizar el catálogo de reglas: {exc}"
        )


def _run_pipeline_with_catalogue(
    *args: Any,
    **kwargs: Any,
) -> int:
    status = BASE_RUN_PIPELINE(*args, **kwargs)

    if status == 0:
        output_dir = kwargs.get("output_dir")

        if output_dir is None and len(args) >= 3:
            output_dir = args[2]

        if output_dir is not None:
            _write_rule_catalogue_additions(
                Path(output_dir)
            )

    return status


# ============================================================
# INSTALACIÓN DE LAS MEJORAS
# ============================================================

engine.derive_findings = _derive_findings_v531
engine.build_triage_decisions = _build_triage_decisions_v531

pipeline._build_delta = _build_delta_compatible
pipeline._ORIGINAL_RUN_PIPELINE = _run_pipeline_with_catalogue


def main() -> int:
    print(
        "[+] Leak2Path v5.3.1 rules loaded: "
        "SVC-001, SVC-002, AUTH-002"
    )
    return pipeline.main()


if __name__ == "__main__":
    raise SystemExit(main())
