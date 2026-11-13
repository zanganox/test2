
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leak2Path v5.4.1 - bilingual report and Identity Correlation views."""

from __future__ import annotations

import html
import json
import re
from urllib.parse import urlsplit
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    import rules
except ImportError:
    rules = None


VERSION = "5.4.1"


# ============================================================
# REPORT LANGUAGE
# ============================================================

UI = {
    "es": {
        "eyebrow": "MOTOR DE INTELIGENCIA DETERMINISTA",
        "subtitle": "Stealer Logs → Correlación de identidades → Hipótesis de rutas de ataque",
        "generated": "Generado",
        "search": "Búsqueda",
        "nav": "Índice del reporte",
        "nav_summary": "Resumen",
        "nav_domain": "Vista centrada en dominio",
        "nav_identity": "Correlación centrada en identidad",
        "nav_recurrence": "Recurrencia y temporalidad",
        "nav_rules": "Índice de reglas",
        "nav_findings": "Hallazgos",
        "nav_paths": "Hipótesis de rutas de ataque",
        "raw_occurrences": "Ocurrencias RAW",
        "unique_lines": "Líneas RAW únicas",
        "parsed_lines": "Líneas únicas procesadas",
        "normalized_records": "Registros normalizados",
        "corporate_identities": "Identidades corporativas",
        "findings": "Hallazgos",
        "attack_paths": "Hipótesis de rutas de ataque",
        "rule_distribution": "Distribución de reglas",
        "rule_distribution_note": (
            "El número representa hallazgos generados por regla, no identidades "
            "únicas. Una misma identidad o evidencia puede estar asociada a más "
            "de una regla. Selecciona una regla para consultar su definición."
        ),
        "occurrence_decisions": "Decisiones de triage",
        "deterministic_findings": "Hallazgos deterministas",
        "rule_index": "Índice de reglas",
        "rule_index_note": (
            "Referencia de las reglas aplicadas. Las condiciones son "
            "deterministas; la interpretación describe lo que puede concluirse "
            "y lo que no demuestra por sí sola cada regla."
        ),
        "rule_id": "Regla",
        "rule_family": "Familia",
        "rule_name": "Significado",
        "rule_condition": "Cuándo se activa",
        "rule_limitation": "Limitaciones e interpretación",
        "finding": "Hallazgo",
        "identity": "Identidad",
        "confidence": "Confianza",
        "status": "Estado",
        "evidence_refs": "Referencias de evidencia",
        "no_findings": "No se generaron hallazgos.",
        "no_decisions": "No hay decisiones de triage.",
        "domain_graph": "Vista centrada en dominio",
        "domain_graph_note": (
            "Las conexiones del dominio a las identidades corporativas muestran "
            "el contexto del objetivo. Las líneas continuas conectan identidades "
            "con servicios observados; las discontinuas indican correlaciones "
            "candidatas. No representan acceso confirmado."
        ),
        "identity_graph": "Mapa de correlación centrado en identidad",
        "identity_graph_note": (
            "Cada arista representa una relación observada o una correlación "
            "candidata. Una coincidencia de alias no confirma que dos cuentas "
            "pertenezcan a la misma persona."
        ),
        "recurrence": "Recurrencia por identidad",
        "recurrence_note": (
            "Ordenado por la cantidad de observaciones normalizadas. La "
            "recurrencia aumenta la prioridad de revisión, pero no demuestra "
            "que la cuenta siga activa."
        ),
        "temporal": "Metadatos temporales de los archivos fuente",
        "temporal_note": (
            "La fecha representa metadatos disponibles del archivo de origen, "
            "no la fecha confirmada de exposición ni de actividad de la cuenta."
        ),
        "profile_table": "Matriz de correlación de identidades",
        "profile_note": (
            "Consolidación de servicios, evidencias y archivos por identificador "
            "observado. Un identificador no equivale necesariamente a una persona."
        ),
        "service": "Servicio",
        "scope": "Alcance",
        "services": "Servicios",
        "evidence": "Evidencias",
        "occurrences": "Ocurrencias",
        "source_files": "Archivos fuente",
        "source_metadata": "Metadatos de origen",
        "observed": "Observado",
        "candidate": "Candidato",
        "corporate": "Dentro del alcance",
        "third_party": "Tercero",
        "unknown": "Desconocido",
        "no_graph_data": "No hay datos suficientes para generar esta visualización.",
        "no_temporal_data": (
            "No hay fechas utilizables en los metadatos del corpus."
        ),
        "identity_type": "Tipo de identidad",
        "services_count": "Cantidad de servicios",
        "evidence_count": "Cantidad de evidencias",
        "source_count": "Archivos fuente",
        "start_date": "Primer metadato",
        "end_date": "Último metadato",
        "attack_path": "Hipótesis",
        "path_identity": "Identidad observada",
        "path_service": "Servicio o endpoint",
        "path_description": "Ruta propuesta y escenario de Red Team",
        "proposed_route": "Ruta propuesta",
        "what_to_prove": "Qué se busca demostrar",
        "potential_impact": "Posible escenario de impacto",
        "validation_conditions": "Condiciones de validación",
        "interpretation": "Interpretación",
        "limitations": "Limitaciones",
        "validation": "Validación recomendada",
        "warning": (
            "Los hallazgos y las rutas son observaciones o hipótesis; no "
            "demuestran contraseñas válidas, cuentas activas, situación laboral "
            "ni acceso operativo. El reporte no contiene contraseñas en claro. "
            "Los archivos RAW pueden contener credenciales y deben protegerse."
        ),
        "footer": "Leak2Path · Reglas deterministas en Python · Reporte local",
        "not_proven": "No confirmado",
        "high": "Alta",
        "medium": "Media",
        "low": "Baja",
        "informational": "Informativa",
        "finding_status": "Hallazgo",
        "unparsed": "No procesado",
        "hypothesis_not_validated": "Hipótesis no validada",
        "candidate_not_validated": "Candidato no validado",
        "scope_edge": "Contexto de alcance",
        "observed_edge": "Relación observada",
        "candidate_edge": "Relación candidata",
    },
    "en": {
        "eyebrow": "DETERMINISTIC INTELLIGENCE ENGINE",
        "subtitle": "Stealer Logs → Identity Correlation → Attack-Path Hypotheses",
        "generated": "Generated",
        "search": "Search",
        "nav": "Report index",
        "nav_summary": "Summary",
        "nav_domain": "Domain-centric view",
        "nav_identity": "Identity-centric correlation",
        "nav_recurrence": "Recurrence and temporality",
        "nav_rules": "Rule index",
        "nav_findings": "Findings",
        "nav_paths": "Attack-path hypotheses",
        "raw_occurrences": "RAW occurrences",
        "unique_lines": "Unique RAW lines",
        "parsed_lines": "Processed unique lines",
        "normalized_records": "Normalized records",
        "corporate_identities": "Corporate identities",
        "findings": "Findings",
        "attack_paths": "Attack-path hypotheses",
        "rule_distribution": "Rule distribution",
        "rule_distribution_note": (
            "The count represents findings generated per rule, not unique "
            "identities. One identity or piece of evidence may be associated "
            "with multiple rules. Select a rule to read its definition."
        ),
        "occurrence_decisions": "Triage decisions",
        "deterministic_findings": "Deterministic findings",
        "rule_index": "Rule index",
        "rule_index_note": (
            "Reference for the configured rules. Conditions are deterministic; "
            "the interpretation explains what each rule does and does not prove."
        ),
        "rule_id": "Rule",
        "rule_family": "Family",
        "rule_name": "Meaning",
        "rule_condition": "Trigger condition",
        "rule_limitation": "Limitations and interpretation",
        "finding": "Finding",
        "identity": "Identity",
        "confidence": "Confidence",
        "status": "Status",
        "evidence_refs": "Evidence references",
        "no_findings": "No findings were generated.",
        "no_decisions": "No triage decisions available.",
        "domain_graph": "Domain-centric view",
        "domain_graph_note": (
            "Domain-to-corporate-identity connectors show target context. Solid "
            "lines connect identities to observed services; dashed lines indicate "
            "candidate correlations. None of these relationships proves access."
        ),
        "identity_graph": "Identity-centric correlation map",
        "identity_graph_note": (
            "Each edge represents an observed relationship or a candidate "
            "correlation. A matching alias does not confirm that two accounts "
            "belong to the same person."
        ),
        "recurrence": "Recurrence by identity",
        "recurrence_note": (
            "Ranked by the number of normalized observations. Recurrence helps "
            "prioritize review but does not prove that an account is active."
        ),
        "temporal": "Source-file temporal metadata",
        "temporal_note": (
            "Dates represent available source-file metadata, not a confirmed "
            "exposure date or account-activity timestamp."
        ),
        "profile_table": "Identity correlation matrix",
        "profile_note": (
            "Services, evidence and source files consolidated by observed "
            "identifier. An identifier does not necessarily represent one person."
        ),
        "service": "Service",
        "scope": "Scope",
        "services": "Services",
        "evidence": "Evidence",
        "occurrences": "Occurrences",
        "source_files": "Source files",
        "source_metadata": "Source metadata",
        "observed": "Observed",
        "candidate": "Candidate",
        "corporate": "In scope",
        "third_party": "Third party",
        "unknown": "Unknown",
        "no_graph_data": "There is not enough data to generate this visualization.",
        "no_temporal_data": "No usable dates were found in source-file metadata.",
        "identity_type": "Identity type",
        "services_count": "Service count",
        "evidence_count": "Evidence count",
        "source_count": "Source files",
        "start_date": "Earliest metadata",
        "end_date": "Latest metadata",
        "attack_path": "Hypothesis",
        "path_identity": "Observed identity",
        "path_service": "Service or endpoint",
        "path_description": "Proposed Red Team path and impact scenario",
        "proposed_route": "Proposed route",
        "what_to_prove": "What the test should demonstrate",
        "potential_impact": "Potential impact scenario",
        "validation_conditions": "Validation conditions",
        "interpretation": "Interpretation",
        "limitations": "Limitations",
        "validation": "Recommended validation",
        "warning": (
            "Findings and paths are observations or hypotheses; they do not prove "
            "valid passwords, active accounts, employment status or operational "
            "access. The report excludes plaintext passwords. RAW evidence files "
            "may contain credentials and must be protected."
        ),
        "footer": "Leak2Path · Deterministic Python rules · Local report",
        "not_proven": "Not confirmed",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "finding_status": "Finding",
        "unparsed": "Unparsed",
        "hypothesis_not_validated": "Unvalidated hypothesis",
        "candidate_not_validated": "Unvalidated candidate",
        "scope_edge": "Scope context",
        "observed_edge": "Observed relationship",
        "candidate_edge": "Candidate relationship",
    },
}


# Each rule entry: name, trigger condition, interpretation/limitation.
RULE_TEXT = {
    "PWD-001": {
        "es": (
            "Reutilización exacta de material de contraseña",
            "Misma identidad corporativa, mismo fingerprint HMAC y al menos "
            "dos hosts de servicio explícitos distintos.",
            "No demuestra que la contraseña siga vigente ni que la autenticación "
            "haya tenido éxito.",
        ),
        "en": (
            "Exact credential-material reuse",
            "Same corporate identity, same HMAC fingerprint, and at least two "
            "distinct explicitly identified service hosts.",
            "Does not prove that the password is current or that authentication succeeded.",
        ),
    },
    "PWD-002": {
        "es": (
            "Variación numérica del patrón de contraseña",
            "Misma identidad corporativa y forma de contraseña equivalente tras "
            "sustituir secuencias numéricas, con múltiples fingerprints y servicios.",
            "Es una heurística. Formas parecidas pueden aparecer por coincidencia; "
            "no se muestra ni se infiere aquí la contraseña en claro.",
        ),
        "en": (
            "Numeric password-pattern variation",
            "Same corporate identity and equivalent password shape after numeric "
            "runs are normalized, with multiple fingerprints and services.",
            "This is a heuristic. Similar shapes may occur by chance; plaintext "
            "passwords are neither shown nor inferred.",
        ),
    },
    "ID-002": {
        "es": (
            "Nomenclatura genérica, temporal, de servicio o privilegiada",
            "El identificador corporativo contiene tokens de nomenclatura "
            "incluidos en los diccionarios configurados.",
            "El nombre por sí solo no demuestra función, privilegio, propiedad "
            "ni actividad de la cuenta.",
        ),
        "en": (
            "Generic, temporary, service, or privileged-style naming",
            "The corporate identifier contains a configured naming token.",
            "The name alone does not prove account function, privilege, ownership, "
            "or activity.",
        ),
    },
    "ID-003": {
        "es": (
            "Candidato a familia de usuarios con sufijo numérico",
            "Identificador relevante que termina en una secuencia numérica "
            "de dos o más dígitos.",
            "El patrón no demuestra que existan cuentas vecinas, que sean de "
            "prueba o que pertenezcan a la misma persona.",
        ),
        "en": (
            "Numeric-suffix username family candidate",
            "A relevant identifier ends in a numeric suffix of two or more digits.",
            "The pattern does not prove that neighboring accounts exist, are test "
            "accounts, or belong to the same person.",
        ),
    },
    "ID-004": {
        "es": (
            "Identificador genérico o temporal",
            "Identificador no basado en correo con tokens genéricos, temporales "
            "o de servicio configurados.",
            "La nomenclatura es un indicio para revisar, no una confirmación "
            "del rol, titularidad o privilegios.",
        ),
        "en": (
            "Generic or temporary identifier",
            "Non-email identifier with configured generic, temporary, or "
            "service-account tokens.",
            "Naming is a review clue, not confirmation of role, ownership, "
            "or privileges.",
        ),
    },
    "LIFE-001": {
        "es": (
            "Indicador histórico vinculado a servicios externos",
            "Identificador corporativo con un marcador histórico configurado y "
            "evidencia directa o asociada en un servicio de terceros.",
            "No demuestra desvinculación laboral, cuenta residual ni acceso persistente.",
        ),
        "en": (
            "Historical marker linked to third-party service evidence",
            "Corporate identifier has a configured historical marker and direct "
            "or linked evidence on a third-party service.",
            "Does not prove employment termination, a residual account, or persistent access.",
        ),
    },
    "EXT-001": {
        "es": (
            "Identidad corporativa observada en servicio de terceros",
            "Correo corporativo exacto observado asociado a un hostname externo válido.",
            "No demuestra que la dependencia esté aprobada, que la cuenta siga activa "
            "ni que las credenciales sean válidas.",
        ),
        "en": (
            "Corporate identity observed on a third-party service",
            "Exact corporate email identity observed with a valid external hostname.",
            "Does not prove an approved dependency, an active account, or valid credentials.",
        ),
    },
    "EXT-002": {
        "es": (
            "Posible cuenta externa vinculada por parte local",
            "Usuario no basado en correo coincide exactamente con la parte local "
            "de un correo corporativo único y el servicio es externo.",
            "La coincidencia es candidata; no prueba identidad humana común ni "
            "credenciales compartidas.",
        ),
        "en": (
            "Candidate external account linked by local-part",
            "Non-email username exactly matches the local-part of a unique "
            "corporate email and the service is external.",
            "This is a candidate link; it does not prove the same person or shared credentials.",
        ),
    },
    "CORR-001": {
        "es": (
            "Identificador corporativo recurrente",
            "Al menos dos líneas RAW únicas, con varios hosts o varios archivos "
            "fuente para el identificador corporativo.",
            "La recurrencia no demuestra una única persona ni una cuenta vigente.",
        ),
        "en": (
            "Recurring corporate identifier",
            "At least two unique RAW lines, with multiple service hosts or source "
            "files for a corporate identifier.",
            "Recurrence does not prove a unique person or a current account.",
        ),
    },
    "CORR-002": {
        "es": (
            "Relación candidata entre identidades",
            "Un usuario observado coincide exactamente con la parte local de un "
            "correo corporativo único.",
            "No fusiona identidades ni demuestra titularidad.",
        ),
        "en": (
            "Candidate identity relationship",
            "An observed username exactly matches the local-part of a unique "
            "corporate email.",
            "Does not merge identities or establish ownership.",
        ),
    },
    "CRED-001": {
        "es": (
            "Par de credenciales corporativas sin servicio identificado",
            "Identidad de correo corporativo y material candidato a contraseña "
            "sin un servicio explícito en el registro fuente.",
            "No permite atribuir el origen a una aplicación ni demuestra vigencia "
            "o autenticación exitosa.",
        ),
        "en": (
            "Corporate credential pair with unknown source service",
            "Corporate email identity and candidate password material, with no "
            "explicit service in the source record.",
            "Does not identify the application or prove validity or successful authentication.",
        ),
    },
    "HASH-001": {
        "es": (
            "Posible hash de contraseña sin servicio identificado",
            "Identidad corporativa y valor que coincide con una heurística de "
            "formato de hash, sin servicio de origen identificado.",
            "No confirma algoritmo, recuperación del secreto ni vigencia.",
        ),
        "en": (
            "Possible password hash with unknown source service",
            "Corporate identity and a value matching a hash-format heuristic, "
            "with no known source service.",
            "Does not confirm the algorithm, recoverability, or current validity.",
        ),
    },
    "AUTH-001": {
        "es": (
            "Registro de credenciales corporativas asociado a AD FS",
            "Identidad corporativa, material candidato a contraseña y endpoint "
            "AD FS explícito dentro del alcance.",
            "No demuestra autenticación exitosa, acceso al dominio ni movimiento lateral.",
        ),
        "en": (
            "Corporate credential record associated with AD FS",
            "Corporate identity, candidate password material, and an explicit "
            "in-scope AD FS endpoint.",
            "Does not prove successful authentication, domain access, or lateral movement.",
        ),
    },
    "SVC-001": {
        "es": (
            "Correo externo observado en un servicio dentro del alcance",
            "Correo externo asociado a un servicio cuyo hostname está dentro "
            "del alcance del dominio objetivo.",
            "No demuestra titularidad, autorización, validez de credenciales ni acceso.",
        ),
        "en": (
            "External email observed on an in-scope service",
            "External email associated with a service hostname inside the target scope.",
            "Does not prove ownership, authorization, credential validity, or access.",
        ),
    },
    "SVC-002": {
        "es": (
            "Identificador no basado en correo en un servicio dentro del alcance",
            "Usuario u otro identificador no basado en correo observado en "
            "un servicio dentro del alcance.",
            "No demuestra que pertenezca a un empleado ni que sea una cuenta "
            "activa o privilegiada.",
        ),
        "en": (
            "Non-email identifier observed on an in-scope service",
            "Username or other non-email identifier observed on an in-scope service.",
            "Does not prove that it belongs to an employee or is an active or privileged account.",
        ),
    },
    "AUTH-002": {
        "es": (
            "Correo externo observado en endpoint corporativo AD FS",
            "Correo externo observado en un servicio dentro del alcance con "
            "indicadores de AD FS.",
            "No demuestra federación, autenticación exitosa, cuenta válida "
            "ni acceso al dominio.",
        ),
        "en": (
            "External email observed on a corporate AD FS endpoint",
            "External email observed on an in-scope service with AD FS indicators.",
            "Does not prove federation, successful authentication, account validity, "
            "or domain access.",
        ),
    },
    "APP-001": {
        "es": (
            "Identidad corporativa observada en una aplicación dentro del alcance",
            "Identidad corporativa o alias exacto relacionado observado en un "
            "servicio dentro del alcance.",
            "No demuestra actividad actual, desvinculación laboral ni acceso persistente.",
        ),
        "en": (
            "Corporate identity observed on an in-scope application",
            "Corporate identity or exact linked alias observed on an in-scope service.",
            "Does not prove current activity, employment termination, or persistent access.",
        ),
    },
    "BASE-000": {
        "es": (
            "Sin otra regla accionable configurada",
            "Una identidad corporativa no tiene otros hallazgos según el catálogo actual.",
            "Es un registro informativo. Que no haya una regla coincidente no "
            "demuestra ausencia de riesgo.",
        ),
        "en": (
            "No other configured actionable rule",
            "A corporate identity has no other findings under the current rule catalogue.",
            "Informational only. No matching rule does not establish absence of risk.",
        ),
    },
}


RULE_FAMILIES = {
    "R01_password_patterns": {
        "es": "Patrones de contraseña",
        "en": "Password patterns",
    },
    "R02_account_naming": {
        "es": "Nomenclatura de cuentas",
        "en": "Account naming",
    },
    "R03_historical_identity": {
        "es": "Contexto histórico de identidad",
        "en": "Historical identity context",
    },
    "R04_third_party_dependency": {
        "es": "Dependencias de terceros",
        "en": "Third-party dependencies",
    },
    "R05_identity_correlation": {
        "es": "Correlación de identidades",
        "en": "Identity correlation",
    },
    "R06_unscoped_credential_material": {
        "es": "Material de credenciales sin servicio",
        "en": "Credential material without source service",
    },
    "R06_in_scope_service_observations": {
        "es": "Observaciones de servicios dentro del alcance",
        "en": "In-scope service observations",
    },
    "R07_corporate_authentication_endpoint": {
        "es": "Endpoint corporativo de autenticación",
        "en": "Corporate authentication endpoint",
    },
    "R07_federated_authentication_observations": {
        "es": "Observaciones de autenticación federada",
        "en": "Federated authentication observations",
    },
    "R08_in_scope_application_lifecycle": {
        "es": "Identidades y ciclo de vida de aplicaciones",
        "en": "Application identity lifecycle",
    },
    "informational_baseline": {
        "es": "Referencia informativa",
        "en": "Informational baseline",
    },
}


FINDING_TITLES = {
    "PWD-001": {"es": "Reutilización exacta de material de contraseña",
                "en": "Exact credential-material reuse"},
    "PWD-002": {"es": "Variación de patrón numérico de contraseña",
                "en": "Numeric password-pattern variation"},
    "ID-002": {"es": "Nomenclatura genérica, temporal o de servicio",
               "en": "Generic, temporary, or service-account naming"},
    "ID-003": {"es": "Candidato a familia de usuarios con sufijo numérico",
               "en": "Numeric-suffix username family candidate"},
    "ID-004": {"es": "Identificador genérico o temporal",
               "en": "Generic or temporary identifier"},
    "LIFE-001": {"es": "Indicador histórico vinculado a servicio externo",
                 "en": "Historical marker linked to external-service evidence"},
    "EXT-001": {"es": "Identidad corporativa observada en servicio de terceros",
                "en": "Corporate identity observed on a third-party service"},
    "EXT-002": {"es": "Posible cuenta externa vinculada por parte local",
                "en": "Candidate external account linked by local-part"},
    "CORR-001": {"es": "Identificador corporativo recurrente",
                 "en": "Recurring corporate identifier"},
    "CORR-002": {"es": "Relación candidata entre identidades",
                 "en": "Candidate identity relationship"},
    "CRED-001": {"es": "Par de credenciales sin servicio de origen identificado",
                 "en": "Credential pair with unknown source service"},
    "HASH-001": {"es": "Posible hash de contraseña sin servicio identificado",
                 "en": "Possible password hash with unknown source service"},
    "AUTH-001": {"es": "Registro de credenciales asociado a AD FS",
                 "en": "Credential record associated with AD FS"},
    "SVC-001": {"es": "Correo externo observado en un servicio dentro del alcance",
                 "en": "External email observed on an in-scope service"},
    "SVC-002": {"es": "Identificador no basado en correo en servicio dentro del alcance",
                 "en": "Non-email identifier observed on an in-scope service"},
    "AUTH-002": {"es": "Correo externo observado en endpoint AD FS",
                 "en": "External email observed on AD FS"},
    "APP-001": {"es": "Identidad observada en una aplicación dentro del alcance",
                 "en": "Identity observed on an in-scope application"},
    "BASE-000": {"es": "Sin otra regla accionable configurada",
                 "en": "No other configured actionable rule"},
}


PATH_TEXT = {
    "observed_corporate_identity_to_external_service": {
        "es": (
            "Potencial exposición de identidad corporativa en servicio de terceros",
            "Se observó una relación entre {identity} y el servicio externo {services}. "
            "La evidencia permite priorizar la revisión de la dependencia.",
            "No se ha confirmado vigencia de credenciales, autenticación exitosa, "
            "reutilización ni acceso corporativo.",
            "Corroborar el servicio y el contexto de la cuenta con el responsable. "
            "Validar autenticación solo si está expresamente autorizada.",
        ),
        "en": (
            "Corporate identity observed on a third-party service",
            "A relationship between {identity} and external service {services} was observed. "
            "The evidence can help prioritize dependency review.",
            "Credential validity, successful authentication, reuse and corporate access "
            "have not been confirmed.",
            "Corroborate the service and account context with its owner. Validate "
            "authentication only when explicitly authorized.",
        ),
    },
    "candidate_localpart_alias_to_external_service": {
        "es": (
            "Posible cuenta externa vinculada por alias",
            "El identificador relacionado con {identity} aparece asociado a {services}. "
            "La coincidencia de parte local es una correlación candidata.",
            "No demuestra que ambas cuentas pertenezcan a la misma persona ni que "
            "compartan credenciales.",
            "Corroborar la relación mediante un inventario autorizado o con el "
            "responsable de la aplicación.",
        ),
        "en": (
            "Candidate external account linked by alias",
            "An identifier associated with {identity} appears on {services}. "
            "The local-part match is a candidate correlation.",
            "It does not prove that the accounts belong to the same person or share credentials.",
            "Corroborate the relationship through an authorized inventory or application owner.",
        ),
    },
    "potential_corporate_credential_on_adfs": {
        "es": (
            "Posible credencial corporativa asociada a AD FS",
            "Se observó un registro de {identity} relacionado con el endpoint {services}.",
            "No confirma credenciales válidas, autenticación exitosa, acceso al dominio "
            "ni movimiento lateral.",
            "Corroborar la relación con el responsable de identidad. Cualquier validación "
            "debe tener autorización explícita.",
        ),
        "en": (
            "Potential corporate credential associated with AD FS",
            "A record for {identity} was observed in association with endpoint {services}.",
            "Does not prove valid credentials, successful authentication, domain access, "
            "or lateral movement.",
            "Corroborate the relationship with the identity owner. Any validation requires "
            "explicit authorization.",
        ),
    },
    "external_identity_to_in_scope_application": {
        "es": (
            "Identidad externa observada en aplicación dentro del alcance",
            "Se observó la identidad {identity} en un registro de un servicio dentro "
            "del alcance: {services}.",
            "No demuestra que la identidad pertenezca a la organización, que tenga "
            "privilegios ni que haya obtenido acceso.",
            "Confirmar el contexto de la cuenta con el responsable autorizado de la aplicación.",
        ),
        "en": (
            "External identity observed on an in-scope application",
            "Identity {identity} appeared in a record associated with in-scope service "
            "{services}.",
            "Does not establish organizational ownership, privileges, or successful access.",
            "Confirm the account context with the authorized application owner.",
        ),
    },
    "identifier_to_in_scope_application": {
        "es": (
            "Identificador observado en aplicación dentro del alcance",
            "El identificador {identity} aparece en un registro relacionado con {services}.",
            "No se ha confirmado su titularidad ni el estado de la cuenta.",
            "Corroborar el identificador con el responsable y el inventario autorizado de la aplicación.",
        ),
        "en": (
            "Identifier observed on an in-scope application",
            "Identifier {identity} appeared in a record associated with {services}.",
            "Ownership and account status have not been confirmed.",
            "Corroborate the identifier with the authorized application inventory and owner.",
        ),
    },
    "corporate_identity_to_in_scope_application": {
        "es": (
            "Identidad corporativa observada en aplicación dentro del alcance",
            "La identidad {identity} aparece relacionada con la aplicación {services}. "
            "La relación puede aportar contexto para revisar su ciclo de vida.",
            "No demuestra actividad actual, desvinculación laboral ni acceso persistente.",
            "Confirmar la relación con el responsable de la aplicación y el inventario de identidades.",
        ),
        "en": (
            "Corporate identity observed on an in-scope application",
            "Identity {identity} is associated with application {services}. This may "
            "provide context for an account-lifecycle review.",
            "Does not prove current activity, employment termination, or persistent access.",
            "Confirm the relationship with the application owner and identity inventory.",
        ),
    },
    "external_identity_to_corporate_adfs": {
        "es": (
            "Identidad externa observada en endpoint corporativo AD FS",
            "Se observó la identidad externa {identity} en un registro asociado a {services}.",
            "No demuestra federación, autenticación exitosa ni acceso al dominio.",
            "Confirmar el contexto con el responsable de identidad; validar acceso solo "
            "dentro de una autorización explícita.",
        ),
        "en": (
            "External identity observed on corporate AD FS",
            "External identity {identity} appeared in a record associated with {services}.",
            "Does not prove federation, successful authentication, or domain access.",
            "Confirm the context with the identity owner; validate access only under "
            "explicit authorization.",
        ),
    },
}


PATH_SCENARIOS = {
    # --------------------------------------------------------
    # Corporate identity observed on a third-party application
    # --------------------------------------------------------
    "observed_corporate_identity_to_external_service": {
        "es": {
            "route": (
                "Registro ULP → identidad corporativa {identity} → "
                "aplicación de terceros {services} → identificación del "
                "mecanismo de autenticación y del propietario del servicio "
                "→ validación autorizada mediante cuenta de prueba o "
                "procedimiento aprobado → revisión de roles, funciones y "
                "datos accesibles → evaluación de dependencias adicionales "
                "dentro del alcance."
            ),
            "objective": (
                "Determinar si la relación entre identidad y aplicación es "
                "correcta, si existe una cuenta vigente y qué funciones, datos "
                "y permisos están disponibles bajo las condiciones autorizadas."
            ),
            "impact": (
                "Si se confirma una cuenta utilizable con permisos excesivos "
                "o controles de autorización insuficientes, podrían quedar "
                "expuestos datos o funciones de la aplicación de terceros. "
                "No se presupone reutilización de credenciales en otros servicios."
            ),
            "validation": (
                "Corroborar la relación con el responsable del servicio. "
                "Usar una cuenta de prueba o un procedimiento aprobado. "
                "Validar reutilización entre servicios solo si forma parte "
                "del alcance autorizado."
            ),
        },
        "en": {
            "route": (
                "ULP record → corporate identity {identity} → third-party "
                "application {services} → identify the authentication "
                "mechanism and service owner → authorized validation through "
                "a test account or approved procedure → review roles, "
                "functions and accessible data → assess additional dependencies "
                "within the authorized scope."
            ),
            "objective": (
                "Determine whether the identity/application relationship is "
                "correct, whether an account is current, and which functions, "
                "data and permissions are available under authorized conditions."
            ),
            "impact": (
                "If a usable account with excessive permissions or insufficient "
                "authorization controls is confirmed, application data or "
                "functions could be exposed. Credential reuse across services "
                "is not assumed."
            ),
            "validation": (
                "Corroborate the relationship with the service owner. Use a "
                "test account or approved procedure. Validate cross-service "
                "reuse only when it is explicitly within scope."
            ),
        },
    },

    # --------------------------------------------------------
    # Candidate username alias on a third-party application
    # --------------------------------------------------------
    "candidate_localpart_alias_to_external_service": {
        "es": {
            "route": (
                "Registro ULP → identidad corporativa {identity} → alias "
                "candidato {aliases} → corroboración con inventario autorizado "
                "o responsable de la aplicación → identificación del mecanismo "
                "de autenticación → validación autorizada mediante cuenta de "
                "prueba → revisión de roles, datos y dependencias aprobadas."
            ),
            "objective": (
                "Determinar si el alias corresponde realmente a una cuenta "
                "relacionada con la identidad corporativa, sin asumir que ambas "
                "cuentas pertenecen a la misma persona."
            ),
            "impact": (
                "Si la relación se confirma y la aplicación presenta permisos "
                "excesivos o una autorización débil, una cuenta externa podría "
                "acceder a funciones o datos fuera de su propósito previsto."
            ),
            "validation": (
                "Confirmar la correlación con el responsable de la aplicación. "
                "No fusionar identidades ni probar credenciales extraídas sin "
                "autorización explícita."
            ),
        },
        "en": {
            "route": (
                "ULP record → corporate identity {identity} → candidate alias "
                "{aliases} → corroboration against an authorized inventory or "
                "application owner → identify the authentication mechanism → "
                "authorized validation using a test account → review roles, "
                "data and approved dependencies."
            ),
            "objective": (
                "Determine whether the alias truly maps to an account related "
                "to the corporate identity without assuming both accounts "
                "belong to the same person."
            ),
            "impact": (
                "If the relationship is confirmed and the application has "
                "excessive permissions or weak authorization, an external "
                "account could access functions or data beyond its intended purpose."
            ),
            "validation": (
                "Confirm the correlation with the application owner. Do not merge "
                "identities or test recovered credentials without explicit authorization."
            ),
        },
    },

    # --------------------------------------------------------
    # Corporate identity associated with an AD FS endpoint
    # --------------------------------------------------------
    "potential_corporate_credential_on_adfs": {
        "es": {
            "route": (
                "Registro ULP → identidad corporativa {identity} → endpoint "
                "AD FS {services} → confirmación del tenant y la relación "
                "de federación → revisión autorizada de MFA, políticas de "
                "autenticación, claims y asignaciones → validación controlada "
                "mediante cuenta de prueba o procedimiento aprobado → revisión "
                "de recursos accesibles y permisos efectivos."
            ),
            "objective": (
                "Determinar si la identidad y el endpoint pertenecen al mismo "
                "contexto de autenticación, y evaluar los controles de federación "
                "y autorización aplicables."
            ),
            "impact": (
                "Si existe una identidad utilizable y los controles de "
                "autenticación o federación son insuficientes, podría producirse "
                "acceso no previsto a aplicaciones federadas, sujeto a las "
                "políticas y asignaciones efectivas."
            ),
            "validation": (
                "Corroborar el contexto con el responsable de identidad. Priorizar "
                "configuración, registros y cuentas de prueba; cualquier prueba "
                "de autenticación requiere autorización explícita."
            ),
        },
        "en": {
            "route": (
                "ULP record → corporate identity {identity} → AD FS endpoint "
                "{services} → confirm the tenant and federation relationship "
                "→ authorized review of MFA, authentication policies, claims "
                "and assignments → controlled validation using a test account "
                "or approved procedure → review accessible resources and effective permissions."
            ),
            "objective": (
                "Determine whether the identity and endpoint belong to the same "
                "authentication context and assess the applicable federation "
                "and authorization controls."
            ),
            "impact": (
                "If a usable identity exists and authentication or federation "
                "controls are insufficient, unintended access to federated "
                "applications may be possible, depending on effective policies and assignments."
            ),
            "validation": (
                "Corroborate the context with the identity owner. Prefer "
                "configuration, logs and test accounts; authentication testing "
                "requires explicit authorization."
            ),
        },
    },

    # --------------------------------------------------------
    # External email observed on an in-scope application
    # --------------------------------------------------------
    "external_identity_to_in_scope_application": {
        "es": {
            "route": (
                "Registro ULP → identidad externa {identity} → aplicación "
                "dentro del alcance {services} → identificación del mecanismo "
                "de autenticación y el propósito de la cuenta → confirmación "
                "con el responsable de la aplicación → validación autorizada "
                "con cuenta de prueba → revisión de roles, autorización, "
                "separación de datos y funciones expuestas."
            ),
            "objective": (
                "Determinar si se espera esa identidad externa en la aplicación "
                "y si los controles de acceso limitan sus funciones y datos "
                "al propósito autorizado."
            ),
            "impact": (
                "Una cuenta externa con asignaciones excesivas o una aplicación "
                "con controles de autorización débiles podría permitir acceso "
                "a registros o funciones que no corresponden a esa identidad."
            ),
            "validation": (
                "Confirmar con el propietario si la cuenta externa es legítima. "
                "Usar una cuenta de prueba o evidencia administrativa aprobada "
                "para evaluar permisos y aislamiento de datos."
            ),
        },
        "en": {
            "route": (
                "ULP record → external identity {identity} → in-scope "
                "application {services} → identify the authentication "
                "mechanism and account purpose → confirm with the application "
                "owner → authorized validation using a test account → review "
                "roles, authorization, data separation and exposed functions."
            ),
            "objective": (
                "Determine whether the external identity is expected on the "
                "application and whether access controls restrict functions "
                "and data to the authorized purpose."
            ),
            "impact": (
                "An external account with excessive assignments or weak "
                "application authorization could access records or functions "
                "outside the identity's intended scope."
            ),
            "validation": (
                "Confirm with the owner whether the external account is legitimate. "
                "Use a test account or approved administrative evidence to assess "
                "permissions and data isolation."
            ),
        },
    },

    # --------------------------------------------------------
    # Non-email identifier observed on an in-scope application
    # --------------------------------------------------------
    "identifier_to_in_scope_application": {
        "es": {
            "route": (
                "Registro ULP → identificador observado {identity} → aplicación "
                "dentro del alcance {services} → resolución de la cuenta en el "
                "inventario autorizado → identificación del mecanismo de "
                "autenticación → validación autorizada de su tipo y estado → "
                "revisión de roles, autorización y acceso a datos."
            ),
            "objective": (
                "Determinar si el identificador corresponde a una cuenta "
                "reconocida por la aplicación y qué controles regulan sus "
                "funciones y acceso a información."
            ),
            "impact": (
                "Si el identificador corresponde a una cuenta compartida, de "
                "servicio o con permisos excesivos, podría existir exposición "
                "de funciones o datos que no corresponden a su propósito."
            ),
            "validation": (
                "Corroborar el tipo y titularidad con el responsable de la "
                "aplicación. No asumir que el identificador pertenece a un "
                "empleado ni que la cuenta esté activa."
            ),
        },
        "en": {
            "route": (
                "ULP record → observed identifier {identity} → in-scope "
                "application {services} → resolve the account against an "
                "authorized inventory → identify the authentication mechanism "
                "→ authorized validation of its type and status → review roles, "
                "authorization and data access."
            ),
            "objective": (
                "Determine whether the identifier maps to a recognized "
                "application account and which controls govern its functions "
                "and access to information."
            ),
            "impact": (
                "If the identifier maps to a shared, service or overprivileged "
                "account, functions or data beyond its intended purpose could "
                "be exposed."
            ),
            "validation": (
                "Corroborate account type and ownership with the application "
                "owner. Do not assume that the identifier belongs to an employee "
                "or that the account is active."
            ),
        },
    },

    # --------------------------------------------------------
    # Corporate identity observed on an in-scope application
    # --------------------------------------------------------
    "corporate_identity_to_in_scope_application": {
        "es": {
            "route": (
                "Registro ULP → identidad corporativa {identity} → aplicación "
                "dentro del alcance {services} → confirmación de la cuenta y "
                "del mecanismo de autenticación → revisión de roles y permisos "
                "efectivos → validación autorizada con cuenta de prueba o "
                "procedimiento aprobado → evaluación de autorización, datos "
                "accesibles y dependencias de la aplicación."
            ),
            "objective": (
                "Determinar si la identidad mantiene una relación legítima con "
                "la aplicación y si los privilegios y controles de autorización "
                "corresponden al propósito de la cuenta."
            ),
            "impact": (
                "Una cuenta vigente con privilegios excesivos o controles de "
                "autorización insuficientes podría acceder a funciones, registros "
                "o dependencias que exceden su propósito. La observación no "
                "demuestra que la identidad sea histórica ni que su titular "
                "haya dejado la organización."
            ),
            "validation": (
                "Corroborar el estado y la relación con el inventario autorizado "
                "y el responsable de la aplicación. No inferir desvinculación "
                "laboral a partir de registros ULP."
            ),
        },
        "en": {
            "route": (
                "ULP record → corporate identity {identity} → in-scope "
                "application {services} → confirm the account and authentication "
                "mechanism → review effective roles and permissions → authorized "
                "validation using a test account or approved procedure → assess "
                "authorization, accessible data and application dependencies."
            ),
            "objective": (
                "Determine whether the identity has a legitimate relationship "
                "with the application and whether effective privileges and "
                "authorization controls match the account's purpose."
            ),
            "impact": (
                "A current account with excessive privileges or insufficient "
                "authorization controls could access functions, records or "
                "dependencies beyond its intended purpose. The observation "
                "does not establish historical identity status or employment termination."
            ),
            "validation": (
                "Corroborate account status and relationship with the authorized "
                "inventory and application owner. Do not infer offboarding from ULP records."
            ),
        },
    },

    # --------------------------------------------------------
    # External identity observed on corporate AD FS
    # --------------------------------------------------------
    "external_identity_to_corporate_adfs": {
        "es": {
            "route": (
                "Registro ULP → identidad externa {identity} → endpoint "
                "corporativo AD FS {services} → confirmación de si corresponde "
                "a una identidad externa o federada esperada → revisión de "
                "trusts, claims y políticas de autenticación → validación "
                "autorizada con cuenta de prueba → evaluación del alcance de "
                "los recursos que esa identidad podría recibir."
            ),
            "objective": (
                "Determinar si la presencia de la identidad externa es esperada "
                "y si la configuración de federación limita correctamente las "
                "identidades, claims y recursos asociados."
            ),
            "impact": (
                "Una relación de federación demasiado amplia o asignaciones "
                "inadecuadas podrían permitir que una identidad externa recibiera "
                "acceso no previsto. La evidencia por sí sola no demuestra acceso."
            ),
            "validation": (
                "Verificar configuración y contexto con el responsable de "
                "identidad. Cualquier prueba de autenticación debe estar "
                "expresamente autorizada."
            ),
        },
        "en": {
            "route": (
                "ULP record → external identity {identity} → corporate AD FS "
                "endpoint {services} → confirm whether it is an expected "
                "external or federated identity → review trusts, claims and "
                "authentication policies → authorized validation with a test "
                "account → assess the scope of resources the identity could receive."
            ),
            "objective": (
                "Determine whether the external identity is expected and whether "
                "federation configuration correctly restricts associated "
                "identities, claims and resources."
            ),
            "impact": (
                "Overly broad federation relationships or inappropriate "
                "assignments could grant an external identity unintended access. "
                "The evidence alone does not demonstrate access."
            ),
            "validation": (
                "Verify configuration and context with the identity owner. "
                "Authentication testing must be explicitly authorized."
            ),
        },
    },

    # --------------------------------------------------------
    # Specific Microsoft identity endpoint scenario
    # --------------------------------------------------------
    "microsoft_identity_authentication": {
        "es": {
            "title": "Identidad corporativa asociada al inicio de sesión de Microsoft",
            "route": (
                "Registro ULP → identidad corporativa {identity} → endpoint "
                "{services} → confirmación de la cuenta en el tenant autorizado "
                "→ identificación de aplicaciones, asignaciones y roles "
                "asociados → revisión de MFA, Acceso Condicional y políticas "
                "de autenticación → validación autorizada con cuenta de prueba "
                "o procedimiento aprobado → evaluación de privilegios y recursos "
                "disponibles → revisión de dependencias adicionales dentro del alcance."
            ),
            "objective": (
                "Determinar si la identidad existe en el tenant autorizado, "
                "qué aplicaciones y asignaciones le corresponden y si MFA, "
                "Acceso Condicional y los permisos efectivos limitan el acceso."
            ),
            "impact": (
                "Una identidad vigente con controles de autenticación o "
                "asignaciones de aplicaciones inadecuados podría acceder a "
                "recursos adicionales de Microsoft 365 o Entra ID, dependiendo "
                "de las políticas y permisos efectivos."
            ),
            "validation": (
                "Confirmar la identidad y las asignaciones mediante registros "
                "administrativos autorizados. Para validar acceso, usar una "
                "cuenta de prueba o procedimiento aprobado; no asumir que una "
                "coincidencia ULP confirma una sesión válida."
            ),
        },
        "en": {
            "title": "Corporate identity associated with Microsoft sign-in",
            "route": (
                "ULP record → corporate identity {identity} → endpoint "
                "{services} → confirm the account in the authorized tenant "
                "→ identify associated applications, assignments and roles "
                "→ review MFA, Conditional Access and authentication policies "
                "→ authorized validation using a test account or approved "
                "procedure → assess privileges and accessible resources "
                "→ review additional dependencies within scope."
            ),
            "objective": (
                "Determine whether the identity exists in the authorized tenant, "
                "which applications and assignments are associated with it, "
                "and whether MFA, Conditional Access and effective permissions "
                "restrict access."
            ),
            "impact": (
                "A current identity with unsuitable authentication controls "
                "or application assignments could access additional Microsoft "
                "365 or Entra ID resources, depending on effective policies and permissions."
            ),
            "validation": (
                "Confirm the identity and assignments through authorized "
                "administrative records. Use a test account or approved "
                "procedure for access validation; a ULP match does not "
                "confirm a valid session."
            ),
        },
    },

    # --------------------------------------------------------
    # Fallback for future path types
    # --------------------------------------------------------
    "generic": {
        "es": {
            "route": (
                "Registro ULP → identidad o identificador {identity} → "
                "servicio observado {services} → corroboración de la relación "
                "con el responsable → identificación de autenticación y "
                "autorización → validación aprobada dentro del alcance."
            ),
            "objective": (
                "Determinar si la relación observada corresponde a una cuenta "
                "o dependencia legítima y qué controles efectivos la gobiernan."
            ),
            "impact": (
                "El impacto dependerá de la cuenta, los privilegios y las "
                "debilidades que puedan confirmarse durante la evaluación."
            ),
            "validation": (
                "Revisar evidencia y configuración con el responsable autorizado. "
                "No inferir acceso operativo a partir de una correlación."
            ),
        },
        "en": {
            "route": (
                "ULP record → observed identity or identifier {identity} → "
                "observed service {services} → corroborate the relationship "
                "with its owner → identify authentication and authorization "
                "controls → approved validation within scope."
            ),
            "objective": (
                "Determine whether the observed relationship maps to a legitimate "
                "account or dependency and which effective controls govern it."
            ),
            "impact": (
                "Impact depends on the account, privileges and weaknesses "
                "that may be confirmed during the assessment."
            ),
            "validation": (
                "Review evidence and configuration with the authorized owner. "
                "Do not infer operational access from correlation alone."
            ),
        },
    },
}


# ============================================================
# DATA HELPERS
# ============================================================

def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if not path.is_file():
        return rows

    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
            except json.JSONDecodeError:
                continue

    return rows


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _record_evidence(record: Dict[str, Any]) -> Set[str]:
    values = record.get("evidence_ids") or []
    if isinstance(values, str):
        values = [values]

    single = record.get("evidence_id")
    result = {str(value) for value in values if value}

    if single:
        result.add(str(single))

    return result


def _display(value: Any, lang: str) -> str:
    text = str(value or "")

    aliases = {
        "corporate_email": {"es": "Correo corporativo", "en": "Corporate email"},
        "external_email_on_corporate_service": {
            "es": "Correo externo en servicio dentro del alcance",
            "en": "External email on in-scope service",
        },
        "external_email": {"es": "Correo externo", "en": "External email"},
        "corporate_identifier": {
            "es": "Identificador en servicio dentro del alcance",
            "en": "Identifier on in-scope service",
        },
        "username_only": {"es": "Usuario sin correo", "en": "Username without email"},
        "unparsed": {"es": "No procesado", "en": "Unparsed"},
        "corporate": {"es": "Dentro del alcance", "en": "In scope"},
        "third_party": {"es": "Tercero", "en": "Third party"},
        "unknown": {"es": "Desconocido", "en": "Unknown"},
        "observed": {"es": "Observado", "en": "Observed"},
        "candidate": {"es": "Candidato", "en": "Candidate"},
        "hypothesis_not_validated": {
            "es": "Hipótesis no validada",
            "en": "Unvalidated hypothesis",
        },
        "candidate_not_validated": {
            "es": "Candidato no validado",
            "en": "Unvalidated candidate",
        },
        "low": {"es": "Baja", "en": "Low"},
        "medium": {"es": "Media", "en": "Medium"},
        "high": {"es": "Alta", "en": "High"},
        "informational": {"es": "Informativa", "en": "Informational"},
    }

    return aliases.get(text, {}).get(lang, text)


def _load_catalogue(output_dir: Path) -> Dict[str, Dict[str, Any]]:
    catalogue = _read_json(
        output_dir / "findings" / "rule_catalogue.json"
    )

    if rules is not None:
        additions = getattr(rules, "RULE_CATALOGUE", {})
        if isinstance(additions, dict):
            catalogue.update(additions)

    return {
        str(rule_id): value
        for rule_id, value in catalogue.items()
        if isinstance(value, dict)
    }


def _rule_text(
    rule_id: str,
    meta: Dict[str, Any],
    lang: str,
) -> Tuple[str, str, str]:
    localized = RULE_TEXT.get(rule_id, {}).get(lang)

    if localized:
        return localized

    name = str(meta.get("name") or rule_id)
    condition = str(meta.get("condition") or "")
    limitation = str(meta.get("limitation") or "")

    return name, condition, limitation


def _family_name(family: str, lang: str) -> str:
    return RULE_FAMILIES.get(
        family, {}
    ).get(lang, family.replace("_", " "))


def _rule_index(
    catalogue: Dict[str, Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    rows = []

    for rule_id in sorted(catalogue):
        meta = catalogue[rule_id]
        name, condition, limitation = _rule_text(rule_id, meta, lang)
        family = _family_name(str(meta.get("family", "")), lang)

        rows.append(
            f'<tr id="rule-{_e(rule_id)}">'
            f'<td><b>{_e(rule_id)}</b></td>'
            f'<td>{_e(family)}</td>'
            f'<td>{_e(name)}</td>'
            f'<td>{_e(condition)}</td>'
            f'<td>{_e(limitation)}</td>'
            "</tr>"
        )

    return (
        '<section class="panel report-section" id="rule-index">'
        f'<h2>{_e(ui["rule_index"])}</h2>'
        f'<p class="muted">{_e(ui["rule_index_note"])}</p>'
        '<div class="tablewrap"><table class="rule-table">'
        "<thead><tr>"
        f'<th>{_e(ui["rule_id"])}</th>'
        f'<th>{_e(ui["rule_family"])}</th>'
        f'<th>{_e(ui["rule_name"])}</th>'
        f'<th>{_e(ui["rule_condition"])}</th>'
        f'<th>{_e(ui["rule_limitation"])}</th>'
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></section>"
    )


def _rule_distribution(
    counts: Dict[str, int],
    catalogue: Dict[str, Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    max_count = max(counts.values(), default=1)
    if max_count < 1:
        max_count = 1

    bars = []

    for rule_id, count in sorted(counts.items()):
        width = max(2, int(int(count) / max_count * 100))
        label = rule_id

        if rule_id in catalogue:
            name, _, _ = _rule_text(rule_id, catalogue[rule_id], lang)
            label = f"{rule_id} · {name}"

        bars.append(
            '<div class="bar">'
            f'<a href="#rule-{_e(rule_id)}" title="{_e(label)}">'
            f'{_e(rule_id)}</a>'
            f'<b>{int(count)}</b>'
            f'<i><em style="width:{width}%"></em></i>'
            "</div>"
        )

    return (
        f'<section class="panel" id="rule-distribution">'
        f'<h2>{_e(ui["rule_distribution"])}</h2>'
        f'<p class="muted">{_e(ui["rule_distribution_note"])}</p>'
        + (
            "".join(bars)
            if bars else f'<p class="muted">{_e(ui["no_findings"])}</p>'
        )
        + "</section>"
    )


# ============================================================
# RULE/FINDING/PATH PRESENTATION TRANSLATION
# ============================================================

def _finding_title(finding: Dict[str, Any], lang: str) -> str:
    rule_id = str(finding.get("rule_id", ""))
    localized = FINDING_TITLES.get(rule_id, {}).get(lang)

    return localized or str(
        finding.get("title") or rule_id or "—"
    )


def _finding_rows(
    findings: Sequence[Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    rows = []

    for finding in findings[:500]:
        rows.append(
            "<tr>"
            f'<td><a href="#rule-{_e(finding.get("rule_id", ""))}">'
            f'{_e(finding.get("rule_id", ""))}</a></td>'
            f"<td>{_e(_finding_title(finding, lang))}</td>"
            f"<td>{_e(finding.get('subject_identity', ''))}</td>"
            f"<td>{_e(_display(finding.get('confidence', ''), lang))}</td>"
            f"<td>{_e(_display(finding.get('evidence_status', ''), lang))}</td>"
            f"<td>{len(finding.get('evidence_ids', []) or [])}</td>"
            "</tr>"
        )

    if not rows:
        return f'<tr><td colspan="6">{_e(ui["no_findings"])}</td></tr>'

    return "".join(rows)



def _service_label(value: Any) -> str:
    """Remove internal scope prefixes from a service display label."""
    label = str(value or "").strip()

    if "|" in label:
        prefix, remainder = label.split("|", 1)

        if prefix.strip().lower() in {
            "corporate",
            "third_party",
            "unknown",
        }:
            label = remainder.strip()

    return label or "—"


def _path_copy(
    path: Dict[str, Any],
    lang: str,
) -> Tuple[str, str, str, str, str]:
    path_type = str(path.get("path_type", ""))
    language = lang if lang in UI else "es"

    raw_services = path.get("services") or []

    if isinstance(raw_services, str):
        raw_services = [raw_services]

    if not raw_services:
        for step in path.get("steps", []) or []:
            if step.get("type") in {
                "external_service",
                "corporate_authentication_endpoint",
                "in_scope_application",
            }:
                value = step.get("value", [])
                raw_services.extend(
                    value if isinstance(value, list) else [value]
                )

    services = sorted({
        _service_label(value)
        for value in raw_services
        if value
    })

    services_text = ", ".join(services) or "—"
    identity = str(path.get("identity") or "—")

    aliases = path.get("candidate_usernames") or []

    if isinstance(aliases, str):
        aliases = [aliases]

    aliases_text = ", ".join(
        str(value)
        for value in aliases
        if value
    ) or (
        "alias no determinado" if language == "es"
        else "alias not identified"
    )

    # Preserve the established titles in PATH_TEXT where available.
    title_entry = PATH_TEXT.get(path_type, {}).get(language)

    if title_entry:
        title = title_entry[0]
    else:
        title = str(
            path.get("title") or UI[language]["attack_path"]
        )

    scenario_key = path_type
    service_hosts = {
        _graph_hostname({"service_key": value})
        for value in raw_services
        if value
    }

    microsoft_identity_hosts = {
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.windows.net",
        "sts.windows.net",
    }

    # Specialize the corporate external-service path when the observed
    # service is a Microsoft identity sign-in endpoint.
    if (
        path_type == "observed_corporate_identity_to_external_service"
        and (service_hosts & microsoft_identity_hosts)
    ):
        scenario_key = "microsoft_identity_authentication"
        title = PATH_SCENARIOS[scenario_key][language]["title"]

    scenario = PATH_SCENARIOS.get(
        scenario_key,
        PATH_SCENARIOS["generic"],
    ).get(
        language,
        PATH_SCENARIOS["generic"]["es"],
    )

    values = {
        "identity": identity,
        "services": services_text,
        "aliases": aliases_text,
    }

    return (
        title,
        scenario["route"].format(**values),
        scenario["objective"].format(**values),
        scenario["impact"].format(**values),
        scenario["validation"].format(**values),
    )


def _path_rows(
    paths: Sequence[Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    rows = []

    for path in paths[:500]:
        (
            title,
            proposed_route,
            objective,
            impact,
            validation,
        ) = _path_copy(path, lang)

        services = path.get("services") or []

        if isinstance(services, str):
            services = [services]

        if not services:
            for step in path.get("steps", []) or []:
                if step.get("type") in {
                    "external_service",
                    "corporate_authentication_endpoint",
                    "in_scope_application",
                }:
                    value = step.get("value", [])
                    services.extend(
                        value if isinstance(value, list) else [value]
                    )

        services_text = ", ".join(
            _service_label(value)
            for value in services
            if value
        ) or "—"

        path_type = str(path.get("path_type", ""))
        identity = str(path.get("identity", "—"))
        status = _display(path.get("evidence_status", ""), lang)

        # All content originating from the corpus is HTML-escaped.
        scenario_html = (
            '<div class="path-scenario">'
            '<div class="scenario-block route-block">'
            f'<b>{_e(ui["proposed_route"])}:</b>'
            f'<p class="route-chain">{_e(proposed_route)}</p>'
            '</div>'
            '<div class="scenario-block">'
            f'<b>{_e(ui["what_to_prove"])}:</b> '
            f'{_e(objective)}'
            '</div>'
            '<div class="scenario-block">'
            f'<b>{_e(ui["potential_impact"])}:</b> '
            f'{_e(impact)}'
            '</div>'
            '<div class="scenario-block validation-block">'
            f'<b>{_e(ui["validation_conditions"])}:</b> '
            f'{_e(validation)}'
            '</div>'
            '</div>'
        )

        rows.append(
            "<tr>"
            f"<td>{_e(title)}<br><small>{_e(path_type)}</small></td>"
            f"<td>{_e(identity)}</td>"
            f"<td>{_e(services_text)}</td>"
            f'<td class="path-copy">{scenario_html}</td>'
            f"<td>{_e(status)}</td>"
            "</tr>"
        )

    if not rows:
        return (
            f'<tr><td colspan="5">{_e(ui["no_findings"])}</td></tr>'
        )

    return "".join(rows)



# ============================================================
# IDENTITY/SERVICE GRAPH MODEL
# ============================================================

def _graph_hostname(record: Dict[str, Any]) -> str:
    """Return the primary hostname for graph aggregation.

    URL paths, query strings, fragments and ports do not create separate
    service nodes. The graph represents the hostname/subdomain as the
    primary application relationship.
    """
    raw = str(
        record.get("service_domain")
        or record.get("service_key")
        or ""
    ).strip()

    if not raw:
        return ""

    # Some service keys may include a scope prefix, for example:
    # third_party|bancaporinternet.interbank.pe/login
    if "|" in raw and "://" not in raw:
        prefix, remainder = raw.split("|", 1)

        if prefix.strip().lower() in {
            "corporate",
            "third_party",
            "unknown",
        }:
            raw = remainder.strip()

    # urlsplit needs a scheme or a leading // to parse a hostname.
    parse_value = (
        raw if "://" in raw
        else "//" + raw.lstrip("/")
    )

    try:
        parsed = urlsplit(parse_value)
        hostname = parsed.hostname or ""
    except ValueError:
        hostname = ""

    if not hostname:
        # Conservative fallback for malformed service values.
        hostname = (
            raw.split("/", 1)[0]
            .split("?", 1)[0]
            .split("#", 1)[0]
        )

        if "@" in hostname:
            hostname = hostname.rsplit("@", 1)[-1]

        if ":" in hostname and not hostname.startswith("["):
            hostname = hostname.split(":", 1)[0]

    return hostname.strip().lower().rstrip(".")


def _graph_model(
    records: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a domain/identity/service graph from normalized records.

    Observed edges represent source-record associations.
    Candidate edges represent possible alias correlations only.
    Neither edge type proves account ownership or successful access.
    """

    # 1. Collect corporate identity anchors.
    corporate_ids: Set[str] = {
        str(record.get("identity", "")).strip().lower()
        for record in records
        if isinstance(record, dict)
        and record.get("is_corporate_identity")
        and record.get("identity")
    }

    # 2. Build a local-part -> corporate email map for candidate aliases.
    alias_map: Dict[str, Set[str]] = defaultdict(set)

    for corporate_identity in corporate_ids:
        if "@" not in corporate_identity:
            continue

        local_part = corporate_identity.split("@", 1)[0].strip().lower()

        if local_part:
            alias_map[local_part].add(corporate_identity)

    identity_meta: Dict[str, Dict[str, Any]] = {}
    service_meta: Dict[str, Dict[str, Any]] = {}
    edge_evidence: Dict[
        Tuple[str, str, str],
        Set[str],
    ] = defaultdict(set)

    # 3. Build observed identity/service relationships.
    for record in records:
        if not isinstance(record, dict):
            continue

        identity = str(
            record.get("identity", "")
        ).strip().lower()
		
        host = _graph_hostname(record)

        # FIX 1: initialize scope before using it.
        scope = str(
            record.get("service_scope", "unknown")
        ).strip().lower()

        if not identity or not host:
            continue

        if scope not in {"corporate", "third_party"}:
            continue

        # FIX 2: initialize linked candidates before they are referenced.
        linked_raw = (
            record.get("linked_identity_candidates") or []
        )

        if isinstance(linked_raw, str):
            linked_raw = [linked_raw]

        linked: Set[str] = {
            str(value).strip().lower()
            for value in linked_raw
            if value
        }

        # FIX 3: determine whether this record directly refers to a
        # corporate identity. Do not infer this from service_scope.
        direct_corporate = bool(
            record.get("is_corporate_identity")
            or identity in corporate_ids
        )

        # A non-email username may match a unique corporate email's
        # local-part. Represent this as a candidate relationship.
        if not direct_corporate:
            linked.update(
                alias_map.get(identity, set())
            )

        # Keep in-scope observations. Third-party services are included
        # only when there is a direct or candidate corporate relationship.
        if scope == "corporate":
            include = True
        else:
            include = bool(
                direct_corporate
                or (linked & corporate_ids)
            )

        if not include:
            continue


        # 4. Aggregate URLs by hostname/subdomain.
        # Different paths on the same host become one graph node.
        service_path = str(
            record.get("service_path", "")
        ).strip()

        service_port = str(
            record.get("service_port", "") or ""
        ).strip()

        # The port/path are retained as metadata for traceability,
        # but are deliberately excluded from the graph-node key.
        service_key = f"{scope}|{host}"

        evidence_ids = _record_evidence(record)

        service = service_meta.setdefault(
            service_key,
            {
                "key": service_key,
                "host": host,
                "domain": host,
                "port": "",
                "path": "",
                "paths": set(),
                "ports": set(),
                "scope": scope,
                "identities": set(),
                "evidence": set(),
                "records": 0,
            },
        )

        if service_path and service_path != "/":
            service["paths"].add(service_path)

        if service_port:
            service["ports"].add(service_port)

        service["identities"].add(identity)
        service["evidence"].update(evidence_ids)
        service["records"] += 1


        # 5. Aggregate the observed identity profile.
        ident = identity_meta.setdefault(
            identity,
            {
                "identity": identity,
                "corporate": (
                    identity in corporate_ids or direct_corporate
                ),
                "identity_type": str(
                    record.get("identity_type", "unknown")
                ),
                "services": set(),
                "evidence": set(),
                "source_files": set(),
                "occurrences": 0,
            },
        )

        # Keep corporate status correct if the identity is encountered
        # in more than one record.
        ident["corporate"] = bool(
            ident["corporate"]
            or identity in corporate_ids
            or direct_corporate
        )

        ident["services"].add(service_key)
        ident["evidence"].update(evidence_ids)

        try:
            occurrence_count = int(
                record.get("occurrence_count", 1) or 1
            )
        except (TypeError, ValueError):
            occurrence_count = 1

        ident["occurrences"] += occurrence_count

        source_files = record.get("source_files") or []

        if isinstance(source_files, str):
            source_files = [source_files]

        if record.get("source_file"):
            ident["source_files"].add(
                str(record["source_file"])
            )

        ident["source_files"].update(
            str(source_file)
            for source_file in source_files
            if source_file
        )

        # Direct record-to-service relationship.
        edge_evidence[
            (identity, service_key, "observed")
        ].update(evidence_ids)

        # 6. Represent alias links as candidate edges, not identity merges.
        for candidate in sorted(linked & corporate_ids):
            if candidate == identity:
                continue

            candidate_meta = identity_meta.setdefault(
                candidate,
                {
                    "identity": candidate,
                    "corporate": True,
                    "identity_type": "corporate_email",
                    "services": set(),
                    "evidence": set(),
                    "source_files": set(),
                    "occurrences": 0,
                },
            )

            candidate_meta["corporate"] = True
            candidate_meta["services"].add(service_key)
            candidate_meta["evidence"].update(evidence_ids)

            edge_evidence[
                (candidate, service_key, "candidate")
            ].update(evidence_ids)

    # 7. Convert internal sets into the graph's edge list.
    edges = [
        {
            "identity": identity,
            "service_key": service_key,
            "kind": kind,
            "evidence_count": len(evidence_ids),
        }
        for (
            identity,
            service_key,
            kind,
        ), evidence_ids in edge_evidence.items()
    ]

    return {
        "corporate_ids": corporate_ids,
        "identities": identity_meta,
        "services": service_meta,
        "edges": edges,
    }



def _short(value: str, limit: int = 38) -> str:
    value = str(value)
    if len(value) <= limit:
        return value
    return value[:limit - 1] + "…"



def _svg_domain_graph(
    target: str,
    model: Dict[str, Any],
    lang: str,
    max_nodes: int = 16,
) -> str:
    """Render a connected three-column domain/identity/service graph.

    Left: target domain.
    Center: identities observed or explicitly correlated.
    Right: in-scope and linked third-party services.

    Observed relationships and candidate alias edges are visually distinct.
    The graph does not prove authentication or account ownership.
    """
    ui = UI[lang]
    identities = model["identities"]
    services = model["services"]
    edges = model["edges"]
    corporate_ids = model["corporate_ids"]

    identity_keys = sorted(
        identities,
        key=lambda key: (
            -len(identities[key]["services"]),
            -len(identities[key]["evidence"]),
            key,
        ),
    )[:max_nodes]

    service_keys = sorted(
        services,
        key=lambda key: (
            0 if services[key]["scope"] == "corporate" else 1,
            -len(services[key]["evidence"]),
            services[key]["host"],
        ),
    )[:max_nodes]

    visible_identities = set(identity_keys)
    visible_services = set(service_keys)

    # Three-column geometry:
    # target x=22..246; identities x=340..655; services x=760..1120.
    width = 1160
    row_h = 62
    top = 85

    height = max(
        400,
        top + row_h * max(
            1,
            len(identity_keys),
            len(service_keys),
        ) + 60,
    )

    center_y = height // 2

    target_label = (
        "DOMINIO OBJETIVO" if lang == "es" else "TARGET DOMAIN"
    )

    corporate_label = (
        "Identidad corporativa" if lang == "es"
        else "Corporate identity"
    )

    # Center each card and use the exact same coordinates for its edges.
    identity_y = {
        identity: top + index * row_h + 21
        for index, identity in enumerate(identity_keys)
    }

    service_y = {
        service_key: top + index * row_h + 21
        for index, service_key in enumerate(service_keys)
    }

    parts = [
        f'<svg viewBox="0 0 {width} {height}" '
        'role="img" aria-label="Domain-centric identity and service graph">',
        '<defs>',
        '<marker id="l2pDomainArrow" markerWidth="9" markerHeight="9" '
        'refX="8" refY="3" orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L0,6 L9,3z" fill="#7188a8"/>'
        '</marker>',
        '<marker id="l2pDomainCorporateArrow" markerWidth="9" markerHeight="9" '
        'refX="8" refY="3" orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L0,6 L9,3z" fill="#48b4a2"/>'
        '</marker>',
        '</defs>',
    ]

    # 1. Draw target -> exact corporate identity edges.
    # These edges terminate at the left edge of an actual identity card.
    for identity in identity_keys:
        if identity not in corporate_ids:
            continue

        iy = identity_y[identity]

        parts.append(
            f'<path d="M246 {center_y} '
            f'C280 {center_y}, 300 {iy}, 340 {iy}" '
            'fill="none" stroke="#48b4a2" stroke-width="1.7" '
            'marker-end="url(#l2pDomainCorporateArrow)" opacity="0.9">'
            f'<title>{_e(ui["observed_edge"])}</title>'
            '</path>'
        )

    # 2. Draw identity -> service edges.
    # The node on each side is guaranteed to be visible before the SVG closes.
    for edge in edges:
        identity = edge["identity"]
        service_key = edge["service_key"]
        kind = edge["kind"]

        if (
            identity not in visible_identities
            or service_key not in visible_services
        ):
            continue

        iy = identity_y[identity]
        sy = service_y[service_key]

        if kind == "candidate":
            color = "#d4a76a"
            dash = ' stroke-dasharray="6 5"'
            marker = "url(#l2pDomainArrow)"
            label = ui["candidate_edge"]
        else:
            color = "#7188a8"
            dash = ""
            marker = "url(#l2pDomainArrow)"
            label = ui["observed_edge"]

        parts.append(
            f'<path d="M655 {iy} '
            f'C690 {iy}, 720 {sy}, 760 {sy}" '
            f'fill="none" stroke="{color}" stroke-width="1.7"{dash} '
            f'marker-end="{marker}" opacity="0.9">'
            f'<title>{_e(label)}</title>'
            '</path>'
        )

    # 3. Draw the target-domain card.
    target_x = 22
    target_y = center_y - 46
    target_w = 224
    target_h = 92

    parts.append(
        f'<rect x="{target_x}" y="{target_y}" '
        f'width="{target_w}" height="{target_h}" rx="13" '
        'fill="#182c46" stroke="#51a6d8" stroke-width="2"/>'
        f'<text x="{target_x + target_w / 2}" y="{target_y + 34}" '
        'text-anchor="middle" fill="#a9d8fa" font-size="12">'
        f'{_e(target_label)}</text>'
        f'<text x="{target_x + target_w / 2}" y="{target_y + 60}" '
        'text-anchor="middle" fill="#ffffff" font-size="14" font-weight="600">'
        f'{_e(_short(target, 27))}</text>'
    )

    # 4. Draw every visible identity card.
    # Previously, only connectors were emitted here; the cards themselves
    # were missing, leaving identity-to-service edges floating in the SVG.
    for identity in identity_keys:
        item = identities[identity]
        cy = identity_y[identity]
        y = cy - 21

        is_corporate = bool(
            identity in corporate_ids
            or item.get("corporate")
        )

        border = "#48b4a2" if is_corporate else "#d4a76a"

        if is_corporate:
            type_label = corporate_label
        else:
            type_label = _display(
                item.get("identity_type", "unknown"),
                lang,
            )

        identity_services = len(item.get("services", set()))
        identity_evidence = len(item.get("evidence", set()))

        parts.append(
            f'<rect x="340" y="{y}" width="315" height="43" rx="8" '
            f'fill="#17243a" stroke="{border}" stroke-width="1.3"/>'
            f'<text x="352" y="{y + 17}" fill="#edf3fb" font-size="12">'
            f'{_e(_short(identity, 39))}</text>'
            f'<text x="352" y="{y + 33}" fill="#aabbd0" font-size="10">'
            f'{_e(type_label)} · {identity_services} '
            f'{_e(ui["services"].lower())} · {identity_evidence} '
            f'{_e(ui["evidence"].lower())}</text>'
        )

    # 5. Draw service/endpoint cards.
    for service_key in service_keys:
        item = services[service_key]
        cy = service_y[service_key]
        y = cy - 21

        scope = item.get("scope", "unknown")
        scope_label = _display(scope, lang)

        border = (
            "#48b4a2" if scope == "corporate"
            else "#7e91ef" if scope == "third_party"
            else "#8094b4"
        )

        service_host = str(item.get("host", ""))

        parts.append(
            f'<rect x="760" y="{y}" width="360" height="43" rx="8" '
            f'fill="#17243a" stroke="{border}" stroke-width="1.3"/>'
            f'<text x="773" y="{y + 17}" fill="#edf3fb" font-size="12">'
            f'{_e(_short(service_host, 45))}</text>'
            f'<text x="773" y="{y + 33}" fill="#aabbd0" font-size="10">'
            f'{_e(scope_label)} · {len(item.get("evidence", set()))} '
            f'{_e(ui["evidence"].lower())}</text>'
        )

    parts.append("</svg>")

    if not edges:
        return (
            '<section class="panel report-section" id="l2p-domain-graph">'
            f'<h2>{_e(ui["domain_graph"])}</h2>'
            f'<p class="muted">{_e(ui["no_graph_data"])}</p>'
            '</section>'
        )

    legend = (
        '<div class="legend">'
        f'<span><i class="legend-solid"></i>'
        f'{_e(ui["observed_edge"])}</span>'
        f'<span><i class="legend-candidate"></i>'
        f'{_e(ui["candidate_edge"])}</span>'
        '</div>'
    )

    return (
        '<section class="panel report-section" id="l2p-domain-graph">'
        f'<h2>{_e(ui["domain_graph"])}</h2>'
        f'<p class="muted">{_e(ui["domain_graph_note"])}</p>'
        f'{legend}<div class="graph-viewport">{"".join(parts)}</div>'
        '</section>'
    )



def _svg_identity_graph(
    model: Dict[str, Any],
    lang: str,
    max_nodes: int = 20,
) -> str:
    ui = UI[lang]
    identities = model["identities"]
    services = model["services"]
    edges = model["edges"]

    identity_keys = sorted(
        identities,
        key=lambda key: (
            -len(identities[key]["services"]),
            -len(identities[key]["evidence"]),
            key,
        ),
    )[:max_nodes]

    service_keys = sorted(
        services,
        key=lambda key: (
            -len(services[key]["identities"]),
            -len(services[key]["evidence"]),
            services[key]["host"],
        ),
    )[:max_nodes]

    visible_identities = set(identity_keys)
    visible_services = set(service_keys)
    width = 1130
    row_h = 58
    top = 72
    height = max(
        310,
        top + row_h * max(1, len(identity_keys), len(service_keys)) + 45,
    )

    parts = [
        f'<svg viewBox="0 0 {width} {height}" '
        'role="img" aria-label="Identity-to-service correlation graph">',
        '<defs><marker id="l2pIdentityArrow" markerWidth="9" markerHeight="9" '
        'refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3z" '
        'fill="#7188a8"/></marker></defs>',
    ]

    service_pos = {
        service_key: top + index * row_h + 20
        for index, service_key in enumerate(service_keys)
    }
    identity_pos = {
        identity: top + index * row_h + 20
        for index, identity in enumerate(identity_keys)
    }

    # Draw edges before nodes.
    for edge in edges:
        identity = edge["identity"]
        service_key = edge["service_key"]
        kind = edge["kind"]

        if identity not in visible_identities or service_key not in visible_services:
            continue

        y1 = identity_pos[identity]
        y2 = service_pos[service_key]
        color = "#d4a76a" if kind == "candidate" else "#7188a8"
        dash = ' stroke-dasharray="6 5"' if kind == "candidate" else ""

        parts.append(
            f'<path d="M415 {y1} C520 {y1}, 600 {y2}, 710 {y2}" '
            f'fill="none" stroke="{color}" stroke-width="1.5"{dash} '
            'marker-end="url(#l2pIdentityArrow)" opacity="0.85">'
            f'<title>{_e(ui["candidate_edge"] if kind == "candidate" else ui["observed_edge"])}</title>'
            '</path>'
        )

    for identity in identity_keys:
        item = identities[identity]
        y = identity_pos[identity] - 20
        color = "#48b4a2" if item["corporate"] else "#8094b4"

        parts.append(
            f'<rect x="22" y="{y}" width="393" height="41" rx="8" '
            f'fill="#17243a" stroke="{color}"/>'
            f'<text x="35" y="{y + 17}" fill="#edf3fb" font-size="12">'
            f'{_e(_short(identity, 47))}</text>'
            f'<text x="35" y="{y + 32}" fill="#aabbd0" font-size="10">'
            f'{len(item["services"])} {_e(ui["services"].lower())} · '
            f'{len(item["evidence"])} {_e(ui["evidence"].lower())}</text>'
        )

    for service_key in service_keys:
        item = services[service_key]
        y = service_pos[service_key] - 20
        color = "#48b4a2" if item["scope"] == "corporate" else "#7e91ef"

        parts.append(
            f'<rect x="710" y="{y}" width="394" height="41" rx="8" '
            f'fill="#17243a" stroke="{color}"/>'
            f'<text x="723" y="{y + 17}" fill="#edf3fb" font-size="12">'
            f'{_e(_short(item["host"], 47))}</text>'
            f'<text x="723" y="{y + 32}" fill="#aabbd0" font-size="10">'
            f'{_e(_display(item["scope"], lang))} · '
            f'{len(item["evidence"])} {_e(ui["evidence"].lower())}</text>'
        )

    parts.append("</svg>")

    if not edges:
        return (
            f'<section class="panel report-section" id="l2p-identity-graph">'
            f'<h2>{_e(ui["identity_graph"])}</h2>'
            f'<p class="muted">{_e(ui["no_graph_data"])}</p></section>'
        )

    legend = (
        f'<div class="legend">'
        f'<span><i class="legend-solid"></i>{_e(ui["observed_edge"])}</span>'
        f'<span><i class="legend-candidate"></i>{_e(ui["candidate_edge"])}</span>'
        "</div>"
    )

    return (
        f'<section class="panel report-section" id="l2p-identity-graph">'
        f'<h2>{_e(ui["identity_graph"])}</h2>'
        f'<p class="muted">{_e(ui["identity_graph_note"])}</p>'
        f'{legend}<div class="graph-viewport">{ "".join(parts) }</div>'
        '</section>'
    )


# ============================================================
# RECURRENCE / TEMPORALITY / IDENTITY MATRIX
# ============================================================

def _identity_stats(
    records: Sequence[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}

    for record in records:
        identity = str(record.get("identity", "")).strip()
        if not identity:
            continue

        item = result.setdefault(identity, {
            "identity": identity,
            "identity_type": str(record.get("identity_type", "unknown")),
            "services": set(),
            "evidence": set(),
            "source_files": set(),
            "occurrences": 0,
            "months": set(),
        })

        service = str(
            record.get("service_domain") or record.get("service_key") or ""
        ).strip()

        if service:
            item["services"].add(service)

        item["evidence"].update(_record_evidence(record))
        item["occurrences"] += int(record.get("occurrence_count", 1) or 1)

        if record.get("source_file"):
            item["source_files"].add(str(record["source_file"]))

        source_files = record.get("source_files") or []
        if isinstance(source_files, str):
            source_files = [source_files]

        item["source_files"].update(
            str(source) for source in source_files if source
        )

        # file_created_at is source-file metadata, not an event timestamp.
        date_text = str(record.get("file_created_at", ""))[:10]
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_text):
            item["months"].add(date_text[:7])

    return result


def _bars(
    values: Sequence[Tuple[str, int]],
    lang: str,
    max_rows: int = 14,
) -> str:
    rows = list(values)[:max_rows]
    max_value = max((value for _, value in rows), default=1) or 1

    return "".join(
        '<div class="bar">'
        f'<span class="bar-label" title="{_e(label)}">{_e(_short(label, 34))}</span>'
        f'<b>{int(value)}</b>'
        '<i><em style="width:'
        f'{max(2, int(value / max_value * 100))}%'
        '"></em></i></div>'
        for label, value in rows
    )


def _recurrence_section(
    records: Sequence[Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    stats = _identity_stats(records)

    ranked = sorted(
        (
            (identity, len(item["evidence"]) or item["occurrences"])
            for identity, item in stats.items()
        ),
        key=lambda row: (-row[1], row[0].casefold()),
    )

    return (
        f'<section class="panel report-section" id="l2p-recurrence">'
        f'<h2>{_e(ui["recurrence"])}</h2>'
        f'<p class="muted">{_e(ui["recurrence_note"])}</p>'
        + (
            _bars(ranked, lang)
            if ranked else f'<p class="muted">{_e(ui["no_graph_data"])}</p>'
        )
        + "</section>"
    )


def _temporal_section(
    records: Sequence[Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    counts: Counter[str] = Counter()
    missing = 0

    for record in records:
        value = str(record.get("file_created_at", "")).strip()
        basis = str(record.get("source_timestamp_basis", "")).strip()

        if basis.casefold() in {"", "unavailable", "unknown"}:
            missing += 1
            continue

        match = re.match(r"^(\d{4}-\d{2})", value)
        if match:
            counts[match.group(1)] += 1
        else:
            missing += 1

    values = sorted(counts.items())

    return (
        f'<section class="panel report-section" id="l2p-temporal">'
        f'<h2>{_e(ui["temporal"])}</h2>'
        f'<p class="muted">{_e(ui["temporal_note"])}</p>'
        + (
            _bars(values, lang, max_rows=24)
            if values else f'<p class="muted">{_e(ui["no_temporal_data"])}</p>'
        )
        + (
            f'<p class="muted">{missing} '
            + (
                "observaciones sin metadato temporal utilizable."
                if lang == "es"
                else "observations without usable temporal metadata."
            )
            + "</p>"
        )
        + "</section>"
    )


def _profile_table(
    records: Sequence[Dict[str, Any]],
    lang: str,
) -> str:
    ui = UI[lang]
    stats = _identity_stats(records)

    ranked = sorted(
        stats.values(),
        key=lambda item: (
            -len(item["services"]),
            -len(item["evidence"]),
            item["identity"].casefold(),
        ),
    )[:100]

    rows = []

    for item in ranked:
        services = sorted(item["services"])
        service_text = ", ".join(services[:4])

        if len(services) > 4:
            service_text += f" … (+{len(services) - 4})"

        months = sorted(item["months"])
        first = months[0] if months else "—"
        last = months[-1] if months else "—"

        rows.append(
            "<tr>"
            f"<td>{_e(item['identity'])}</td>"
            f"<td>{_e(_display(item['identity_type'], lang))}</td>"
            f"<td>{len(services)}</td>"
            f"<td>{len(item['evidence']) or item['occurrences']}</td>"
            f"<td>{len(item['source_files'])}</td>"
            f"<td>{_e(service_text or '—')}</td>"
            f"<td>{_e(first)}</td>"
            f"<td>{_e(last)}</td>"
            "</tr>"
        )

    return (
        f'<section class="panel report-section" id="l2p-identity-profiles">'
        f'<h2>{_e(ui["profile_table"])}</h2>'
        f'<p class="muted">{_e(ui["profile_note"])}</p>'
        '<div class="tablewrap"><table>'
        "<thead><tr>"
        f'<th>{_e(ui["identity"])}</th>'
        f'<th>{_e(ui["identity_type"])}</th>'
        f'<th>{_e(ui["services_count"])}</th>'
        f'<th>{_e(ui["evidence_count"])}</th>'
        f'<th>{_e(ui["source_count"])}</th>'
        f'<th>{_e(ui["services"])}</th>'
        f'<th>{_e(ui["start_date"])}</th>'
        f'<th>{_e(ui["end_date"])}</th>'
        "</tr></thead><tbody>"
        + (
            "".join(rows)
            if rows else f'<tr><td colspan="8">{_e(ui["no_graph_data"])}</td></tr>'
        )
        + "</tbody></table></div></section>"
    )


# ============================================================
# DECISION DISTRIBUTION AND COMPLETE HTML REPORT
# ============================================================

def _decision_section(
    decision_counts: Dict[str, int],
    lang: str,
) -> str:
    ui = UI[lang]
    rows = []

    for name, count in sorted(decision_counts.items()):
        label = _display(name, lang)

        if name == "finding":
            label = ui["finding_status"]
        elif name == "no_actionable_pattern":
            label = (
                "Sin patrón accionable" if lang == "es"
                else "No actionable pattern"
            )
        elif name == "unparsed":
            label = ui["unparsed"]

        rows.append(
            f'<div class="decision"><span>{_e(label)}</span>'
            f'<b>{int(count)}</b></div>'
        )

    return (
        f'<section class="panel" id="occurrence-decisions">'
        f'<h2>{_e(ui["occurrence_decisions"])}</h2>'
        + (
            "".join(rows)
            if rows else f'<p class="muted">{_e(ui["no_decisions"])}</p>'
        )
        + "</section>"
    )


def _summary_cards(
    summary: Dict[str, Any],
    lang: str,
) -> str:
    ui = UI[lang]
    cards = [
        (ui["raw_occurrences"], summary.get("raw_evidence_occurrences", 0)),
        (ui["unique_lines"], summary.get("raw_unique_lines", 0)),
        (ui["parsed_lines"], summary.get("normalized_unique_lines", 0)),
        (ui["normalized_records"], summary.get("unique_normalized_records", 0)),
        (ui["corporate_identities"], summary.get("corporate_identity_anchors", 0)),
        (ui["findings"], summary.get("case_findings", 0)),
        (ui["attack_paths"], summary.get("attack_path_hypotheses", 0)),
    ]

    return "".join(
        f'<article><small>{_e(label)}</small><b>{_e(value)}</b></article>'
        for label, value in cards
    )


def _css() -> str:
    return """
:root{
 --bg:#0b1120;--panel:#141e30;--border:#2b3d57;
 --text:#e7eef8;--muted:#9aacc2;--cyan:#38bdf8;--violet:#818cf8
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);
 font-family:Segoe UI,Arial,sans-serif}
main{max-width:1500px;margin:auto;padding:28px 24px 60px}
header{padding:28px;border:1px solid var(--border);border-radius:18px;
 background:linear-gradient(120deg,#14243c,#203653);margin-bottom:18px}
.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:2px;font-weight:800}
h1{font-size:34px;margin:10px 0 4px}
h2{font-size:18px;margin:0 0 14px}
p{line-height:1.55}
.muted,small{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));
 gap:12px;margin:18px 0}
article,.panel{background:var(--panel);border:1px solid var(--border);
 border-radius:14px;padding:17px}
article b{display:block;font-size:28px;margin-top:12px}
.layout{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:15px 0}
.report-section{margin:17px 0;scroll-margin-top:12px}
.bar{margin:12px 0;font-size:12px;display:grid;
 grid-template-columns:minmax(100px,230px) 35px minmax(80px,1fr);
 gap:8px;align-items:center}
.bar a{color:#9ed7fa;text-decoration:none;overflow-wrap:anywhere}
.bar a:hover{text-decoration:underline}
.bar-label{overflow-wrap:anywhere}
.bar i{height:8px;background:#293a52;border-radius:10px;overflow:hidden}
.bar em{height:100%;display:block;
 background:linear-gradient(90deg,var(--cyan),var(--violet))}
.decision{display:flex;justify-content:space-between;padding:11px 0;
 border-bottom:1px solid var(--border);font-size:13px}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:10px;border-bottom:1px solid var(--border);
 text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{color:var(--muted)}
.rule-table{min-width:1040px}
.finding-table,.path-table{min-width:900px}
.path-copy{
  min-width:460px;
  max-width:760px;
  line-height:1.6;
  overflow-wrap:anywhere;
}
.path-scenario{
  display:grid;
  gap:12px;
}
.scenario-block{
  padding:0 0 10px;
  border-bottom:1px solid #263751;
}
.scenario-block:last-child{
  padding-bottom:0;
  border-bottom:0;
}
.scenario-block b{
  color:#9ecdf5;
  font-size:12px;
}
.route-chain{
  margin:7px 0 0;
  color:#e7eef8;
  line-height:1.8;
  overflow-wrap:anywhere;
}
.validation-block{
  color:#b9c8d9;
  font-size:12px;
}
.rule-table tr:target{background:#24354c}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0}
nav a{color:#a9d8fa;text-decoration:none;border:1px solid var(--border);
 background:#121e30;border-radius:7px;padding:8px 10px;font-size:12px}
nav a:hover{background:#203653}
.graph-viewport{overflow:auto;max-height:900px;border:1px solid #263751;
 border-radius:10px;background:#0c1524}
.graph-viewport svg{display:block;width:100%;min-width:880px;height:auto}
.legend{display:flex;flex-wrap:wrap;gap:15px;font-size:11px;
 color:var(--muted);margin:12px 0}
.legend span{display:inline-flex;align-items:center;gap:7px}
.legend i{display:inline-block;width:27px;border-top:2px solid #7188a8}
.legend .legend-dashed{border-top-style:dashed;border-top-color:#48b4a2}
.legend .legend-candidate{border-top-style:dashed;border-top-color:#d4a76a}
.warning{margin-top:18px;padding:15px;border:1px solid #65532f;
 background:#2b251a;color:#f4d99e;border-radius:12px;font-size:12px;line-height:1.6}
footer{border-top:1px solid var(--border);margin-top:24px;padding-top:14px;
 color:var(--muted);font-size:11px}
@media(max-width:850px){main{padding:16px 12px 40px}
 .layout{grid-template-columns:1fr}h1{font-size:28px}}
"""


def write_dashboard(
    path: Path,
    summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    attack_paths: List[Dict[str, Any]],
    language: Optional[str] = None,
) -> None:
    """
    Generate the complete localized HTML report.

    Existing signature remains compatible. The optional language argument
    accepts 'es' or 'en'; report_language in summary is the fallback.
    """
    path = Path(path)
    lang = str(
        language or summary.get("report_language") or "es"
    ).strip().lower()

    if lang not in UI:
        lang = "es"

    ui = UI[lang]
    output_dir = path.parent

    normalized_path = (
        output_dir / "normalized" / "normalized_records.jsonl"
    )
    records = read_jsonl(normalized_path)

    catalogue = _load_catalogue(output_dir)
    model = _graph_model(records)

    # Summary findings and triage values.
    rule_counts = summary.get("finding_counts_by_rule", {}) or {}
    decision_counts = summary.get("triage_decision_counts", {}) or {}

    header = f"""
<header id="report-summary">
  <div class="eyebrow">{_e(ui["eyebrow"])} · V{_e(VERSION)}</div>
  <h1>Leak2Path</h1>
  <b>{_e(summary.get("target", ""))}</b>
  <p class="muted">{_e(ui["subtitle"])}</p>
  <small>{_e(ui["generated"])}: {_e(summary.get("generated_at", ""))}
    · {_e(ui["search"])}: {_e(summary.get("search_engine", ""))}
  </small>
</header>
"""

    nav = f"""
<nav aria-label="{_e(ui['nav'])}">
 <a href="#report-summary">{_e(ui['nav_summary'])}</a>
 <a href="#l2p-domain-graph">{_e(ui['nav_domain'])}</a>
 <a href="#l2p-identity-graph">{_e(ui['nav_identity'])}</a>
 <a href="#l2p-recurrence">{_e(ui['nav_recurrence'])}</a>
 <a href="#rule-index">{_e(ui['nav_rules'])}</a>
 <a href="#findings">{_e(ui['nav_findings'])}</a>
 <a href="#attack-paths">{_e(ui['nav_paths'])}</a>
</nav>
"""

    summary_cards = (
        f'<section class="grid">{_summary_cards(summary, lang)}</section>'
    )

    distribution = _rule_distribution(rule_counts, catalogue, lang)
    decisions = _decision_section(decision_counts, lang)

    finding_table = f"""
<section class="panel report-section" id="findings">
 <h2>{_e(ui['deterministic_findings'])}</h2>
 <div class="tablewrap">
 <table class="finding-table">
  <thead><tr>
   <th>{_e(ui['rule_id'])}</th><th>{_e(ui['finding'])}</th>
   <th>{_e(ui['identity'])}</th><th>{_e(ui['confidence'])}</th>
   <th>{_e(ui['status'])}</th><th>{_e(ui['evidence_refs'])}</th>
  </tr></thead>
  <tbody>{_finding_rows(findings, lang)}</tbody>
 </table>
 </div>
</section>
"""

    paths_table = f"""
<section class="panel report-section" id="attack-paths">
 <h2>{_e(ui['attack_paths'])}</h2>
 <div class="tablewrap">
 <table class="path-table">
  <thead><tr>
   <th>{_e(ui['attack_path'])}</th><th>{_e(ui['path_identity'])}</th>
   <th>{_e(ui['path_service'])}</th><th>{_e(ui['path_description'])}</th>
   <th>{_e(ui['status'])}</th>
  </tr></thead>
  <tbody>{_path_rows(attack_paths, lang)}</tbody>
 </table>
 </div>
</section>
"""

    sections = [
        _svg_domain_graph(str(summary.get("target", "")), model, lang),
        _svg_identity_graph(model, lang),
        _recurrence_section(records, lang),
        _temporal_section(records, lang),
        _profile_table(records, lang),
        distribution,
        decisions,
        _rule_index(catalogue, lang),
        finding_table,
        paths_table,
    ]

    document = f"""<!doctype html>
<html lang="{_e(lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="Leak2Path {VERSION}">
<title>Leak2Path — {_e(summary.get('target', ''))}</title>
<style>{_css()}</style>
</head>
<body>
<main>
{header}
{nav}
{summary_cards}
<div class="layout">
{distribution}
{decisions}
</div>
{''.join(sections[:5])}
{''.join(sections[7:])}
<div class="warning">{_e(ui['warning'])}</div>
<footer>{_e(ui['footer'])} · {_e(VERSION)}</footer>
</main>
</body>
</html>
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8", newline="\n")


def inject_relationship_graph(
    report_path: Path,
    target: str,
    normalized_records_path: Path,
) -> None:
    """
    Compatibility hook for the v5.4.0 integration layer.

    The v5.4.1 report builder already includes both graph sections. If an
    older report is passed in, this function adds the graph sections once.
    """
    report_path = Path(report_path)

    if not report_path.is_file():
        return

    document = report_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    if (
        'id="l2p-domain-graph"' in document
        and 'id="l2p-identity-graph"' in document
    ):
        return

    records = read_jsonl(Path(normalized_records_path))
    model = _graph_model(records)
    match = re.search(r'<html\s+lang="(es|en)"', document, re.I)
    lang = match.group(1).lower() if match else "es"

    sections = (
        _svg_domain_graph(target, model, lang)
        + _svg_identity_graph(model, lang)
        + _recurrence_section(records, lang)
        + _temporal_section(records, lang)
        + _profile_table(records, lang)
    )

    if "</main>" in document:
        document = document.replace(
            "</main>",
            sections + "\n</main>",
            1,
        )
    elif "</body>" in document:
        document = document.replace(
            "</body>",
            sections + "\n</body>",
            1,
        )
    else:
        document += sections

    report_path.write_text(document, encoding="utf-8", newline="\n")
