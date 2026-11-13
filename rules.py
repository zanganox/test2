
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leak2Path rule catalogue and deterministic extension rules."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Set, Tuple


VERSION = "5.4.1"
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
        if not isinstance(record, dict):
            continue

        identity = str(
            record.get("identity", "")
        ).strip().lower()

        service_key = str(
            record.get("service_key", "")
        )

        if not identity:
            continue

        is_corporate = bool(
            record.get("is_corporate_identity")
        )

        id_type = str(
            record.get("identity_type", "")
        )

        linked_raw = (
            record.get("linked_identity_candidates") or []
        )

        if isinstance(linked_raw, str):
            linked_raw = [linked_raw]

        linked = {
            str(value).strip().lower()
            for value in linked_raw
            if value
        }

        is_adfs_record = _is_adfs(record)
        in_scope_service = _service_is_in_scope(record)

        is_external_email = (
            "@" in identity
            and not is_corporate
            and (
                id_type == "external_email_on_corporate_service"
                or id_type == "external_email"
            )
        )

        # --------------------------------------------------------
        # ID-003: evaluate before the in-scope service-only rules.
        # External-service evidence is eligible only when the
        # identity itself is corporate or explicitly linked to one.
        # --------------------------------------------------------
        linked_corporate = linked & corp_ids

        numeric_identity_relevant = bool(
            is_corporate
            or identity in corp_ids
            or linked_corporate
            or (
                id_type == "corporate_identifier"
                and in_scope_service
            )
        )

        local_part = identity.split("@", 1)[0]

        numeric_suffix = bool(
            re.search(
                r"[a-z][a-z0-9._-]*\d{2,}$",
                local_part,
            )
        )

        if numeric_identity_relevant and numeric_suffix:
            # Prefer the exact corporate identity domain or a domain
            # from an explicitly linked corporate email.
            family_domain = ""

            if (
                (is_corporate or identity in corp_ids)
                and "@" in identity
            ):
                family_domain = identity.rsplit("@", 1)[1].lower()

            if not family_domain:
                linked_domains = sorted({
                    item.rsplit("@", 1)[1].lower()
                    for item in linked_corporate
                    if "@" in item
                })

                if linked_domains:
                    family_domain = linked_domains[0]

            if not family_domain:
                observed_domain = str(
                    record.get("identity_domain", "")
                ).strip().lower().rstrip(".")

                target_domain = _TARGET_DOMAIN.strip().lower().rstrip(".")

                if observed_domain and (
                    observed_domain == target_domain
                    or observed_domain.endswith("." + target_domain)
                ):
                    family_domain = observed_domain

            if not family_domain:
                family_domain = _TARGET_DOMAIN.strip().lower().rstrip(".")

            shape = re.sub(r"\d+", "#", local_part)

            family_subject = (
                f"{shape}@{family_domain}"
                if family_domain
                else shape
            )

            # Use one group per username family. This allows evidence
            # from multiple services to be consolidated together.
            groups[
                ("ID-003", family_subject, "*")
            ].append(record)

        # All remaining rules retain their original scope requirements.
        if not in_scope_service:
            continue

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



    for (rule_id, subject, _service), rows in sorted(groups.items()):
        # For a numeric family, aggregate observations only when
        # the normalized identity and corporate domain match.
        if rule_id == "ID-003":
            family_shape, separator, family_domain = (
                subject.partition("@")
            )

            family_rows = []

            def _domain_matches_family(
                candidate_domain: str,
                expected_domain: str,
            ) -> bool:
                candidate_domain = (
                    candidate_domain.strip().lower().rstrip(".")
                )
                expected_domain = (
                    expected_domain.strip().lower().rstrip(".")
                )

                if not candidate_domain or not expected_domain:
                    return False

                return (
                    candidate_domain == expected_domain
                    or candidate_domain.endswith(
                        "." + expected_domain
                    )
                    or expected_domain.endswith(
                        "." + candidate_domain
                    )
                )

            for row in records:
                if not isinstance(row, dict):
                    continue

                row_identity = str(
                    row.get("identity", "")
                ).strip().lower()

                if not row_identity:
                    continue

                row_local_part = row_identity.split("@", 1)[0]

                row_shape = re.sub(
                    r"\d+",
                    "#",
                    row_local_part,
                )

                if row_shape != family_shape:
                    continue

                row_type = str(
                    row.get("identity_type", "")
                )

                row_is_corporate = bool(
                    row.get("is_corporate_identity")
                    or row_identity in corp_ids
                )

                row_linked_raw = (
                    row.get("linked_identity_candidates") or []
                )

                if isinstance(row_linked_raw, str):
                    row_linked_raw = [row_linked_raw]

                row_linked = {
                    str(value).strip().lower()
                    for value in row_linked_raw
                    if value
                }

                row_linked_corporate = row_linked & corp_ids

                row_in_scope = _service_is_in_scope(row)

                row_relevant = bool(
                    row_is_corporate
                    or row_linked_corporate
                    or (
                        row_type == "corporate_identifier"
                        and row_in_scope
                    )
                )

                if not row_relevant:
                    continue

                row_domains = set()

                # Domain of a directly corporate email identity.
                if row_is_corporate and "@" in row_identity:
                    row_domains.add(
                        row_identity.rsplit("@", 1)[1].lower()
                    )

                # Domains of explicit linked corporate email anchors.
                row_domains.update(
                    linked_identity.rsplit("@", 1)[1].lower()
                    for linked_identity in row_linked_corporate
                    if "@" in linked_identity
                )

                # A directly corporate record can also provide its
                # normalized identity domain.
                row_identity_domain = str(
                    row.get("identity_domain", "")
                ).strip().lower().rstrip(".")

                if row_is_corporate and row_identity_domain:
                    row_domains.add(row_identity_domain)

                # For a non-email corporate identifier on a service
                # inside the target scope, use the configured target.
                if (
                    not row_domains
                    and row_type == "corporate_identifier"
                    and row_in_scope
                    and _TARGET_DOMAIN
                ):
                    row_domains.add(_TARGET_DOMAIN.lower())

                same_domain = any(
                    _domain_matches_family(
                        candidate,
                        family_domain,
                    )
                    for candidate in row_domains
                )

                if same_domain:
                    family_rows.append(row)

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
    """Generate aggregated, unvalidated Attack Path hypotheses."""

    rule_to_path = {
        "SVC-001": (
            "external_identity_to_in_scope_application",
            "External identity observed on an in-scope application",
            "An external email was observed in a record associated with an "
            "in-scope application. This relationship is not proof of access.",
        ),
        "SVC-002": (
            "identifier_to_in_scope_application",
            "Identifier observed on an in-scope application",
            "A non-email identifier was observed in a record associated with "
            "an in-scope application. Ownership and account status are unknown.",
        ),
        "APP-001": (
            "corporate_identity_to_in_scope_application",
            "Corporate identity observed on an in-scope application",
            "A corporate identity or linked alias was observed on an in-scope "
            "application. This does not establish current or persistent access.",
        ),
        "AUTH-002": (
            "external_identity_to_corporate_adfs",
            "External identity observed on corporate AD FS",
            "An external email was observed on an in-scope AD FS endpoint. "
            "Successful authentication and domain access have not been established.",
        ),

        # New Attack Path: create a path if either PWD-001 or PWD-002
        # has been matched. Both rules are consolidated into one path
        # per identity, with the matched rule IDs retained in the output.
        "PWD-001": (
            "password_pattern_reuse_across_services",
            "Credential reuse or password-pattern variation across services",
            "Evidence indicates exact credential-material reuse or a shared "
            "numeric password-pattern family across explicitly identified services. "
            "This does not establish current credential validity or successful access.",
        ),
        "PWD-002": (
            "password_pattern_reuse_across_services",
            "Credential reuse or password-pattern variation across services",
            "Evidence indicates exact credential-material reuse or a shared "
            "numeric password-pattern family across explicitly identified services. "
            "This does not establish current credential validity or successful access.",
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
        identity = str(
            finding.get("subject_identity", "")
        ).strip()

        if not identity:
            continue

        details = finding.get("details", {}) or {}
        key = (path_type, identity)

        group = groups.setdefault(
            key,
            {
                "path_type": path_type,
                "identity": identity,
                "title": title,
                "narrative": narrative,
                "services": set(),
                "evidence_ids": set(),
                "finding_ids": set(),
                "rules": set(),
                "pattern_types": set(),
            },
        )

        # The PWD findings use distinct_services. Other rules may use
        # observed_services or service_keys. Support all three schemas.
        for field in (
            "observed_services",
            "service_keys",
            "distinct_services",
        ):
            values = details.get(field, []) or []

            if isinstance(values, str):
                values = [values]

            for service in values:
                if service:
                    group["services"].add(str(service))

        group["evidence_ids"].update(
            str(value)
            for value in finding.get("evidence_ids", []) or []
            if value
        )

        finding_id = finding.get("finding_id")
        if finding_id:
            group["finding_ids"].add(str(finding_id))

        group["rules"].add(rule_id)

        pattern_type = details.get("pattern_type")
        if pattern_type:
            group["pattern_types"].add(str(pattern_type))

    paths = list(existing_paths)

    for (path_type, identity), group in sorted(groups.items()):
        services = sorted(group["services"])
        evidence_ids = sorted(group["evidence_ids"])

        # A path must have explicit service context and evidence.
        if not services or not evidence_ids:
            continue

        is_password_path = (
            path_type == "password_pattern_reuse_across_services"
        )

        if is_password_path:
            limitations = (
                "A match indicates observed reuse or pattern similarity only. "
                "It does not prove that a credential is current or usable. "
                "Do not infer unobserved password variants."
            )

            recommended_validation = (
                "When credential validation is explicitly in scope, use only "
                "credential material actually present in the evidence and only "
                "against the specifically authorized endpoints. Do not generate "
                "or test guessed variants."
            )
        else:
            limitations = (
                "This is an evidence-based relationship hypothesis, not proof "
                "of valid credentials, successful authentication, current account "
                "activity or operational access."
            )

            recommended_validation = (
                "Validate only against endpoints and accounts explicitly "
                "included in the authorized engagement scope."
            )

        path_id = stable_id(
            "|".join([
                _TARGET_DOMAIN,
                identity,
                path_type,
                *services,
            ])
        )

        paths.append({
            "path_id": path_id,
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
                    "type": (
                        "credential_pattern_evidence"
                        if is_password_path
                        else "observed_service_relationship"
                    ),
                    "value": (
                        sorted(group["pattern_types"])
                        if is_password_path
                        else services
                    ),
                    "evidence_status": "observed",
                },
                {
                    "step": 4,
                    "type": "authorized_validation",
                    "value": (
                        "Credential-material validation on explicitly "
                        "in-scope endpoints"
                    ),
                    "evidence_status": "hypothesis_not_validated",
                },
            ],
            "services": services,
            "evidence_ids": evidence_ids,
            "evidence_ref_count": len(evidence_ids),
            "finding_ids": sorted(group["finding_ids"]),
            "rule_ids": sorted(group["rules"]),
            "pattern_types": sorted(group["pattern_types"]),
            "evidence_status": "hypothesis_not_validated",
            "not_validated": True,
            "confidence": "low",
            "limitations": limitations,
            "recommended_validation": recommended_validation,
        })

    # Stable deduplication: if PWD-001 and PWD-002 match for the same
    # identity and services, keep a single aggregated path.
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
