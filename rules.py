
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leak2Path rule catalogue and deterministic extension rules."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Set, Tuple


VERSION = "5.4.0"
_TARGET_DOMAIN = ""


RULE_CATALOGUE: Dict[str, Dict[str, str]] = {
    "SVC-001": {
        "family": "R06_in_scope_service_observations",
        "name": "External email observed on an in-scope service",
        "condition": (
            "An external email identity is observed on a service inside "
            "the target domain scope."
        ),
        "limitation": (
            "Does not establish account ownership, account validity, "
            "authorization or access."
        ),
    },
    "SVC-002": {
        "family": "R06_in_scope_service_observations",
        "name": "Non-email identifier observed on an in-scope service",
        "condition": (
            "A non-email identifier is observed on a service within "
            "the target domain scope."
        ),
        "limitation": (
            "Does not establish that the identifier belongs to an employee "
            "or is an active or privileged account."
        ),
    },
    "AUTH-002": {
        "family": "R07_federated_authentication_observations",
        "name": "External email observed on a corporate AD FS endpoint",
        "condition": (
            "An external email identity is observed on an in-scope "
            "AD FS endpoint."
        ),
        "limitation": (
            "Does not prove federation, successful authentication, "
            "account validity or domain access."
        ),
    },
    "APP-001": {
        "family": "R08_in_scope_application_lifecycle",
        "name": "Corporate identity observed on an in-scope application",
        "condition": (
            "A corporate identity or exact linked alias is observed "
            "in a record associated with an in-scope service."
        ),
        "limitation": (
            "Does not prove current access, employment status, "
            "persistent access or a valid session."
        ),
    },
    "ID-003": {
        "family": "R02_account_naming",
        "name": "Numeric username family candidate",
        "condition": (
            "A relevant identifier has a numeric suffix of two or more "
            "digits, such as usr1526 or usr1526@target-domain."
        ),
        "limitation": (
            "A numeric suffix is a naming heuristic. It does not prove "
            "that an account is generic or temporary."
        ),
    },
    "ID-004": {
        "family": "R02_account_naming",
        "name": "Generic or temporary non-email identifier",
        "condition": (
            "A non-email identifier in scope contains a configured "
            "generic, temporary or service-account token."
        ),
        "limitation": (
            "Naming alone does not establish account function, "
            "ownership, privilege or validity."
        ),
    },
}


GENERIC_TOKENS = {
    "admin", "administrator", "support", "soporte", "helpdesk",
    "service", "servicio", "shared", "generic", "common",
    "root", "operator", "operador", "help", "system",
}

TEMPORARY_TOKENS = {
    "temp", "tmp", "temporary", "temporal", "test", "testing",
    "prueba", "demo", "trial", "dev", "staging", "uat",
    "qa", "sandbox",
}

SERVICE_TOKENS = {
    "svc", "service", "servicio", "daemon", "bot", "robot",
    "api", "system",
}


def set_target_domain(target: str) -> None:
    global _TARGET_DOMAIN
    _TARGET_DOMAIN = (target or "").strip().lower().rstrip(".")


def _evidence_ids(
    record: Dict[str, Any],
    record_evidence_ids: Callable[[Dict[str, Any]], List[str]],
) -> List[str]:
    return sorted(set(record_evidence_ids(record)))


def _service_is_in_scope(record: Dict[str, Any]) -> bool:
    return bool(
        record.get("service_scope") == "corporate"
        and record.get("service_domain")
        and record.get("service_origin_known")
    )


def _is_adfs(record: Dict[str, Any]) -> bool:
    host = str(record.get("service_domain", "")).lower()
    path = str(record.get("service_path", "")).lower()

    return bool(
        re.search(r"(?:^|[.-])adfs(?:[.-]|$)", host)
        or re.search(r"(?:^|/)adfs(?:/|$)", path)
    )


def _source_files(rows: Sequence[Dict[str, Any]]) -> List[str]:
    values: Set[str] = set()

    for row in rows:
        if row.get("source_file"):
            values.add(str(row["source_file"]))

        for source in row.get("source_files", []) or []:
            if source:
                values.add(str(source))

    return sorted(values, key=str.casefold)


def _make_details(
    rows: Sequence[Dict[str, Any]],
    record_evidence_ids: Callable[[Dict[str, Any]], List[str]],
) -> Dict[str, Any]:
    return {
        "service_keys": sorted({
            str(row.get("service_key", ""))
            for row in rows
            if row.get("service_key")
        }),
        "observed_services": sorted({
            str(row.get("service_domain", ""))
            for row in rows
            if row.get("service_domain")
        }),
        "observed_service_paths": sorted({
            str(row.get("service_path", ""))
            for row in rows
            if row.get("service_path")
        }),
        "identity_types": sorted({
            str(row.get("identity_type", "unknown"))
            for row in rows
        }),
        "material_types": sorted({
            str(
                row.get("credential_material_type")
                or row.get("material_type")
                or "unknown"
            )
            for row in rows
        }),
        "evidence_ids": sorted({
            evidence_id
            for row in rows
            for evidence_id in _evidence_ids(
                row, record_evidence_ids
            )
        }),
        "source_files": _source_files(rows),
        "observation_count": len(rows),
        "ownership_confirmed": False,
        "credential_validity_confirmed": False,
        "account_lifecycle_confirmed": False,
    }


def _emit_group(
    findings: List[Dict[str, Any]],
    rule_id: str,
    subject: str,
    rows: Sequence[Dict[str, Any]],
    add_finding: Callable[..., None],
    record_evidence_ids: Callable[[Dict[str, Any]], List[str]],
) -> None:
    if not rows:
        return

    details = _make_details(rows, record_evidence_ids)
    evidence = details["evidence_ids"]

    if not evidence:
        return

    if rule_id == "SVC-001":
        add_finding(
            findings,
            rule_id,
            "external_identity_on_corporate_service",
            "External email observed on an in-scope service",
            subject,
            evidence,
            "low",
            "observed",
            (
                "An external email address was observed in a record "
                "associated with an in-scope service."
            ),
            (
                "This does not establish account ownership, a business "
                "relationship, valid credentials or access."
            ),
            (
                "Verify the service and account relationship with the "
                "authorized service owner."
            ),
            details,
        )

    elif rule_id == "SVC-002":
        add_finding(
            findings,
            rule_id,
            "non_email_identifier_on_corporate_service",
            "Non-email identifier observed on an in-scope service",
            subject,
            evidence,
            "low",
            "observed",
            (
                "A non-email identifier was observed in a record "
                "associated with an in-scope service."
            ),
            (
                "The identifier's presence does not establish employee "
                "status, privileges or successful access."
            ),
            (
                "Correlate the identifier with an approved application "
                "or identity inventory."
            ),
            details,
        )

    elif rule_id == "AUTH-002":
        details["adfs_indicator"] = True
        add_finding(
            findings,
            rule_id,
            "external_identity_on_corporate_adfs",
            "External email observed on a corporate AD FS endpoint",
            subject,
            evidence,
            "low",
            "observed",
            (
                "An external email identity was observed in a record "
                "associated with an in-scope AD FS endpoint."
            ),
            (
                "This does not establish federation, valid credentials, "
                "successful authentication or domain access."
            ),
            (
                "Confirm the endpoint and identity relationship with "
                "the authorized identity owner."
            ),
            details,
        )

    elif rule_id == "APP-001":
        add_finding(
            findings,
            rule_id,
            "in_scope_application_identity_lifecycle_review",
            "Corporate identity observed on an in-scope application",
            subject,
            evidence,
            "low",
            "observed",
            (
                "A corporate identity or linked identifier appears in a "
                "record associated with an application within the target "
                "domain scope. This may be relevant to account-lifecycle "
                "and offboarding review."
            ),
            (
                "No conclusion is made about former employment, current "
                "access, account status or persistent access."
            ),
            (
                "Verify the identity and application relationship with "
                "the application owner and the authorized identity inventory."
            ),
            details,
        )

    elif rule_id == "ID-003":
        details["username_shape"] = subject
        details["observed_identifiers"] = sorted({
            str(row.get("identity", ""))
            for row in rows
            if row.get("identity")
        })
        add_finding(
            findings,
            rule_id,
            "numeric_username_family",
            "Numeric username family candidate",
            subject,
            evidence,
            "low",
            "candidate",
            (
                "One or more relevant identifiers have a numeric-suffix "
                "pattern. Related accounts may exist, but their presence "
                "and role must be established from authorized evidence."
            ),
            (
                "A matching shape does not prove the accounts exist, "
                "belong to the same person or are generic test accounts."
            ),
            (
                "Compare the observed identifier family with an approved "
                "identity or application inventory. Do not infer access "
                "from a generated username variant."
            ),
            details,
        )

    elif rule_id == "ID-004":
        details["naming_tokens"] = sorted(set(
            token
            for row in rows
            for token in re.findall(
                r"[a-z0-9]+",
                str(row.get("identity", "")).lower(),
            )
            if token in (
                GENERIC_TOKENS | TEMPORARY_TOKENS | SERVICE_TOKENS
            )
        ))
        add_finding(
            findings,
            rule_id,
            "generic_temporary_identifier",
            "Generic or temporary non-email identifier",
            subject,
            evidence,
            "low",
            "candidate",
            (
                "The identifier contains a configured generic, temporary "
                "or service-account naming token."
            ),
            (
                "This is a naming hypothesis only; the account role and "
                "ownership have not been confirmed."
            ),
            (
                "Validate the account type with an authorized application "
                "inventory or service owner."
            ),
            details,
        )


def apply_additional_findings(
    records: List[Dict[str, Any]],
    existing_findings: List[Dict[str, Any]],
    corporate_identities: Set[str],
    alias_records_by_identity: Dict[str, List[Dict[str, Any]]],
    add_finding: Callable[..., None],
    record_evidence_ids: Callable[[Dict[str, Any]], List[str]],
) -> List[Dict[str, Any]]:
    """
    Apply new observation rules. The existing v5.2.0 rules run first.
    No password plaintext is copied to the finding details.
    """
    groups: Dict[
        Tuple[str, str, str],
        List[Dict[str, Any]],
    ] = defaultdict(list)

    corp_ids = {
        str(identity).strip().lower()
        for identity in corporate_identities
    }

    for record in records:
        identity = str(record.get("identity", "")).strip().lower()
        service_key = str(record.get("service_key", ""))

        if not identity or not _service_is_in_scope(record):
            continue

        is_corporate = bool(record.get("is_corporate_identity"))
        id_type = str(record.get("identity_type", ""))
        linked = {
            str(value).strip().lower()
            for value in record.get("linked_identity_candidates", []) or []
        }
        is_adfs_record = _is_adfs(record)
        is_external_email = (
            "@" in identity
            and not is_corporate
            and (
                id_type == "external_email_on_corporate_service"
                or id_type == "external_email"
            )
        )

        # Case 3: an in-scope application may merit an account-lifecycle
        # review, without inferring that the employee has left.
        if is_corporate and not is_adfs_record:
            groups[(
                "APP-001", identity, service_key
            )].append(record)

        for corporate_id in sorted(linked & corp_ids):
            if not is_adfs_record:
                groups[(
                    "APP-001", corporate_id, service_key
                )].append(record)

        # SVC-001: external email associated with an in-scope application.
        if is_external_email:
            groups[(
                "SVC-001", identity, service_key
            )].append(record)

            if is_adfs_record:
                groups[(
                    "AUTH-002", identity, service_key
                )].append(record)

        # SVC-002: non-email identifier associated with an in-scope service.
        if (
            "@" not in identity
            and id_type == "corporate_identifier"
        ):
            groups[(
                "SVC-002", identity, service_key
            )].append(record)

            # Generic/temp rules apply to service-linked identifiers as
            # well as email local-parts.
            tokens = set(re.findall(r"[a-z0-9]+", identity))
            if tokens & (
                GENERIC_TOKENS | TEMPORARY_TOKENS | SERVICE_TOKENS
            ):
                groups[(
                    "ID-004", identity, service_key
                )].append(record)

        # ID-003: numeric suffix pattern. Limit it to target-related
        # identities or identifiers observed on an in-scope service.
        relevant = (
            is_corporate
            or identity in corp_ids
            or id_type == "corporate_identifier"
            or bool(linked & corp_ids)
        )

        local_part = identity.split("@", 1)[0]
        numeric_suffix = bool(
            re.search(r"[a-z][a-z0-9._-]*\d{2,}$", local_part)
        )

        if relevant and numeric_suffix:
            shape = re.sub(r"\d+", "#", local_part)
            domain = (
                str(record.get("identity_domain", "")).lower()
                or str(record.get("service_domain", "")).lower()
            )
            groups[(
                "ID-003",
                f"{shape}@{domain}" if domain else shape,
                service_key,
            )].append(record)

    for (rule_id, subject, _service), rows in sorted(groups.items()):
        # For a numeric family, aggregate observations even when multiple
        # exact identifiers share the normalized name shape.
        if rule_id == "ID-003":
            family_rows = [
                row for row in records
                if (
                    str(row.get("identity", "")).strip().lower()
                    .split("@", 1)[0]
                    and re.sub(
                        r"\d+",
                        "#",
                        str(row.get("identity", ""))
                        .strip().lower().split("@", 1)[0],
                    ) == subject.split("@", 1)[0]
                    and _service_is_in_scope(row)
                )
            ]
            if family_rows:
                rows = family_rows

        _emit_group(
            existing_findings,
            rule_id,
            subject,
            rows,
            add_finding,
            record_evidence_ids,
        )

    # An actionable finding added by this module supersedes BASE-000 for
    # the same subject. Do not leave contradictory "informational only"
    # findings beside a new observation finding.
    actionable_subjects = {
        finding.get("subject_identity", "")
        for finding in existing_findings
        if finding.get("rule_id") != "BASE-000"
    }

    result = [
        finding
        for finding in existing_findings
        if not (
            finding.get("rule_id") == "BASE-000"
            and finding.get("subject_identity", "") in actionable_subjects
        )
    ]

    # Avoid duplicate findings with identical rule, subject and evidence.
    deduplicated: Dict[Tuple[str, str, Tuple[str, ...]], Dict[str, Any]] = {}

    for finding in result:
        key = (
            str(finding.get("rule_id", "")),
            str(finding.get("subject_identity", "")),
            tuple(sorted(finding.get("evidence_ids", []))),
        )
        deduplicated[key] = finding

    return sorted(
        deduplicated.values(),
        key=lambda finding: (
            str(finding.get("subject_identity", "")),
            str(finding.get("rule_id", "")),
        ),
    )


def extend_attack_paths(
    existing_paths: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    stable_id: Callable[..., str],
) -> List[Dict[str, Any]]:
    """Build unvalidated path hypotheses from the new observation rules."""
    rule_to_path = {
        "SVC-001": (
            "external_identity_to_in_scope_application",
            "External identity observed on an in-scope application",
            "An external email was observed in a record associated with an "
            "in-scope application. The relationship is not proof of access.",
        ),
        "SVC-002": (
            "identifier_to_in_scope_application",
            "Identifier observed on an in-scope application",
            "A non-email identifier was observed in a record associated with "
            "an in-scope application. Its ownership and account status are unknown.",
        ),
        "APP-001": (
            "corporate_identity_to_in_scope_application",
            "Corporate identity observed on an in-scope application",
            "An identity or linked alias was observed on an in-scope application. "
            "This can inform lifecycle review but does not establish stale access.",
        ),
        "AUTH-002": (
            "external_identity_to_corporate_adfs",
            "External identity observed on corporate AD FS",
            "An external email was observed on an in-scope AD FS endpoint. "
            "No successful authentication or domain access has been established.",
        ),
    }

    groups: Dict[
        Tuple[str, str],
        Dict[str, Any],
    ] = {}

    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))

        if rule_id not in rule_to_path:
            continue

        path_type, title, narrative = rule_to_path[rule_id]
        identity = str(finding.get("subject_identity", ""))
        details = finding.get("details", {}) or {}

        key = (path_type, identity)
        group = groups.setdefault(key, {
            "path_type": path_type,
            "identity": identity,
            "title": title,
            "narrative": narrative,
            "services": set(),
            "evidence_ids": set(),
            "finding_ids": set(),
            "rules": set(),
        })

        for service in details.get("observed_services", []) or []:
            if service:
                group["services"].add(str(service))

        for service_key in details.get("service_keys", []) or []:
            if service_key:
                group["services"].add(str(service_key))

        group["evidence_ids"].update(
            finding.get("evidence_ids", []) or []
        )
        group["finding_ids"].add(
            str(finding.get("finding_id", ""))
        )
        group["rules"].add(rule_id)

    paths = list(existing_paths)

    for (path_type, identity), group in sorted(groups.items()):
        services = sorted(group["services"])
        evidence_ids = sorted(group["evidence_ids"])

        if not services or not evidence_ids:
            continue

        paths.append({
            "path_id": stable_id(
                "|".join([
                    _TARGET_DOMAIN,
                    identity,
                    path_type,
                    *services,
                ])
            ),
            "identity": identity,
            "path_type": path_type,
            "title": group["title"],
            "narrative": group["narrative"],
            "steps": [
                {
                    "step": 1,
                    "type": "target_domain",
                    "value": _TARGET_DOMAIN,
                    "evidence_status": "scope_context",
                },
                {
                    "step": 2,
                    "type": "observed_identity",
                    "value": identity,
                    "evidence_status": "observed",
                },
                {
                    "step": 3,
                    "type": "in_scope_application",
                    "value": services,
                    "evidence_status": "observed",
                },
            ],
            "services": services,
            "evidence_ids": evidence_ids,
            "evidence_ref_count": len(evidence_ids),
            "finding_ids": sorted(group["finding_ids"]),
            "rule_ids": sorted(group["rules"]),
            "evidence_status": "hypothesis_not_validated",
            "not_validated": True,
            "confidence": "low",
            "limitations": (
                "This is an evidence-based relationship hypothesis, not "
                "proof of valid credentials, successful authentication, "
                "current account activity or operational access."
            ),
            "recommended_validation": (
                "Corroborate with an authorized service owner and application "
                "inventory. Validate access only when explicitly in scope."
            ),
        })

    unique: Dict[str, Dict[str, Any]] = {}

    for path in paths:
        unique[str(path.get("path_id", ""))] = path

    return sorted(
        unique.values(),
        key=lambda path: (
            str(path.get("identity", "")),
            str(path.get("path_type", "")),
            path.get("services", []),
        ),
    )


def fix_triage_explanations(
    decisions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    for item in decisions:
        if item.get("decision") != "no_actionable_pattern":
            continue

        matched = set(item.get("matched_rule_ids", []) or [])
        identity_type = str(item.get("identity_type", "unknown"))
        scope = str(item.get("service_scope", "unknown"))

        if "BASE-000" in matched:
            item["decision_explanation"] = (
                "No se identificó otra regla aplicable a esta identidad "
                "corporativa. BASE-000 es informativa y no representa por "
                "sí misma un hallazgo accionable."
            )
        elif (
            identity_type == "external_email_on_corporate_service"
            and scope == "corporate"
        ):
            item["decision_explanation"] = (
                "Correo externo observado en un servicio dentro del alcance, "
                "pero ninguna regla generó un hallazgo para esta evidencia. "
                "Revisar el registro normalizado y las condiciones de las reglas."
            )
        elif (
            identity_type == "corporate_identifier"
            and scope == "corporate"
        ):
            item["decision_explanation"] = (
                "Identificador no basado en correo observado en un servicio "
                "dentro del alcance, sin una regla aplicable a esta evidencia. "
                "La observación no confirma propiedad corporativa."
            )
        else:
            item["decision_explanation"] = (
                "La observación fue normalizada, pero ninguna regla generó "
                "un hallazgo asociado. No se generó BASE-000 para esta evidencia."
            )

    return decisions


def merge_rule_catalogue(output_dir: Path) -> None:
    catalogue_path = (
        Path(output_dir) / "findings" / "rule_catalogue.json"
    )

    if not catalogue_path.is_file():
        return

    try:
        with catalogue_path.open("r", encoding="utf-8") as source:
            catalogue = json.load(source)

        if not isinstance(catalogue, dict):
            return

        catalogue.update(RULE_CATALOGUE)

        temp_path = catalogue_path.with_suffix(".json.tmp")
        with temp_path.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(
                catalogue,
                output,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            output.write("\n")

        temp_path.replace(catalogue_path)

    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] No se pudo actualizar rule_catalogue.json: {exc}")
