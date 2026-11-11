#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leak2Path v5.4.1 - deterministic Stealer/ULP intelligence pipeline.

RAW evidence is retained with plaintext exactly as observed (except line terminators
and NUL bytes). All structured outputs exclude password plaintext.

Default production scope is the normalized_corpus directory on G:.
The external tgrep index is explicitly supplied with --index-path.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import rules
import dashboard
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

VERSION = "5.4.1"
REPORT_LANGUAGE = "es"

# Valores portables para distribuir el proyecto en GitHub.
DEFAULT_INPUT_DIR = Path.cwd()
DEFAULT_INDEX_DIR = Path.cwd() / ".tgrep-index"
DEFAULT_TGREP_PATH = r"C:\tgrep\tgrep.exe"

INDEX_MAX_FILESIZE = 64 * 1024 * 1024
MAX_REGEX_CHARS = 18000

EMAIL_RE = re.compile(
    r"(?<![A-Z0-9._%+\-])"
    r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})"
    r"(?![A-Z0-9._%+\-])",
    re.I,
)

TRAILING_NOISE_RE = re.compile(
    r"\s*(?:[:|]\s*)?https?\s*:\s*//t\.me/[^\s|]+\s*$",
    re.I,
)

COMMON_2LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "com.br", "com.mx", "com.ar",
    "com.pe", "net.pe", "org.pe", "gob.pe",
    "co.jp", "ne.jp",
}

GENERIC_TOKENS = {
    "admin", "administrator", "support", "soporte",
    "helpdesk", "service", "servicio", "shared",
    "share", "general", "generic", "common",
    "root", "master", "operator", "operador", "help",
}

TEMP_TOKENS = {
    "temp", "tmp", "temporary", "temporal",
    "test", "testing", "prueba", "demo",
    "trial", "dev", "staging", "uat", "qa", "sandbox",
}

SERVICE_TOKENS = {
    "svc", "service", "servicio", "daemon",
    "bot", "robot", "sa", "api", "system",
}

PRIVILEGED_TOKENS = {
    "admin", "administrator", "root", "superuser",
    "super", "operator", "sys", "security", "sec",
}

FORMER_TOKENS = {
    "former", "exemployee", "exstaff", "alumni",
    "oldstaff", "formeremployee", "inactive", "terminated",
}

# These local-parts are too generic to be useful identity-correlation anchors.
LOCALPART_ALIAS_STOPWORDS = {
    "office365", "o365", "microsoft", "outlook", "email", "mail",
    "mailbox", "correo", "account", "accounts", "user", "users",
    "admin", "administrator", "support", "helpdesk", "info",
    "contact", "service", "shared", "test", "testing", "demo",
    "guest", "root", "operator", "system", "postmaster",
}


# ============================================================
# JSON OUTPUT HELPERS
# ============================================================

def jsonl_write(
    path: Path,
    rows: Iterable[Dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                ) + "\n"
            )


def json_write(
    path: Path,
    obj: Dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(
            obj,
            f,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")


# ============================================================
# DOMAIN NORMALIZATION
# ============================================================

def norm_target(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = (
        value.split("/", 1)[0]
        .split("?", 1)[0]
        .split("#", 1)[0]
    )
    return value.rstrip(".")


def norm_host(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def root_domain(host: str) -> str:
    """Dependency-free approximation; not a full Public Suffix List."""
    host = norm_host(host)
    labels = host.split(".")

    if len(labels) <= 2:
        return host

    suffix2 = ".".join(labels[-2:])

    if suffix2 in COMMON_2LEVEL_SUFFIXES:
        return ".".join(labels[-3:])

    return suffix2


def host_in_scope(host: str, target: str) -> bool:
    host = norm_host(host)
    target = norm_target(target)
    return bool(host) and (
        host == target
        or host.endswith("." + target)
    )


def looks_like_hostname(value: str) -> bool:
    value = norm_host(value)

    if not value or any(c in value for c in ":/@"):
        return False

    labels = value.split(".")

    if len(labels) < 2:
        return False

    if any(not x or len(x) > 63 for x in labels):
        return False

    if not re.fullmatch(
        r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",
        value,
        re.I,
    ):
        return False

    return len(labels[-1]) >= 2


def get_file_created_at(path: Path) -> Tuple[str, str]:
    try:
        st = path.stat()

        if hasattr(st, "st_birthtime"):
            ts = st.st_birthtime
            basis = "filesystem_birthtime"
        elif os.name == "nt":
            ts = st.st_ctime
            basis = "filesystem_creation_time"
        else:
            ts = st.st_ctime
            basis = "filesystem_metadata_change_time_fallback"

        return (
            dt.datetime.fromtimestamp(ts).isoformat(
                timespec="seconds"
            ),
            basis,
        )

    except (OSError, ValueError):
        return "", "unavailable"


def choose_encoding(path: Path) -> str:
    with path.open("rb") as f:
        sample = f.read(4096)

    if sample.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"

    if sample.startswith((
        codecs.BOM_UTF16_LE,
        codecs.BOM_UTF16_BE,
    )):
        return "utf-16"

    if len(sample) > 8:
        even = (
            sum(b == 0 for b in sample[0::2])
            / max(1, len(sample[0::2]))
        )
        odd = (
            sum(b == 0 for b in sample[1::2])
            / max(1, len(sample[1::2]))
        )

        if odd > 0.25 and even < 0.05:
            return "utf-16-le"

        if even > 0.25 and odd < 0.05:
            return "utf-16-be"

    return "utf-8"


def clean_line(value: str) -> str:
    # Preserve original content except NUL bytes and line terminators.
    return value.replace("\x00", "").rstrip("\r\n")


def safe_read_lines(
    path: Path,
) -> Iterator[Tuple[int, str]]:
    encoding = choose_encoding(path)

    with path.open(
        "r",
        encoding=encoding,
        errors="replace",
        newline=None,
    ) as f:
        for line_no, line in enumerate(f, 1):
            yield line_no, clean_line(line)


def remove_trailing_noise(value: str) -> str:
    value = TRAILING_NOISE_RE.sub("", value.strip()).strip()
    value = re.split(
        r"\s+[:|]\s*https?\s*:\s*//t\.me/",
        value,
        maxsplit=1,
        flags=re.I,
    )[0].strip()
    return value


# ============================================================
# SERVICE PARSING
# ============================================================

def parse_service(
    service: str,
) -> Tuple[str, str, Optional[int]]:
    """
    Extract hostname, path and port.

    Supports nested URI schemes such as:
        http://android://TOKEN@co.brainly/
    """
    candidate = (service or "").strip()

    if not candidate:
        return "", "", None

    nested = re.match(
        r"^[a-z][a-z0-9+.-]*://"
        r"(?P<inner>[a-z][a-z0-9+.-]*://.+)$",
        candidate,
        re.I,
    )

    if nested:
        candidate = nested.group("inner")

    normalized = (
        candidate
        if re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I)
        else "https://" + candidate
    )

    try:
        parsed = urlsplit(normalized)

        if parsed.hostname:
            try:
                port = parsed.port
            except ValueError:
                port = None

            return (
                norm_host(parsed.hostname),
                parsed.path or "",
                port,
            )

    except ValueError:
        pass

    # Conservative fallback for malformed/opaque services.
    bare = candidate

    if "://" in bare:
        bare = bare.rsplit("://", 1)[-1]
        if "@" in bare:
            bare = bare.rsplit("@", 1)[-1]

    if "/" in bare:
        host, tail = bare.split("/", 1)
        path = "/" + tail
    else:
        host, path = bare, ""

    port = None

    if ":" in host:
        maybe_host, maybe_port = host.rsplit(":", 1)
        if (
            maybe_port.isdigit()
            and 1 <= int(maybe_port) <= 65535
        ):
            host = maybe_host
            port = int(maybe_port)

    return norm_host(host), path, port


# ============================================================
# PARSER VALIDATION AND CREDENTIAL MATERIAL CLASSIFICATION
# ============================================================

def invalid_field(value: str) -> bool:
    value = value.strip().lower()

    return (
        not value
        or value in {
            "http", "https", "ftp", "ftps",
            "none", "null", "n/a", "na",
        }
        or value.startswith((
            "http://", "https://", "ftp://", "ftps://",
        ))
    )


def invalid_username(value: str) -> bool:
    value = value.strip()

    return (
        invalid_field(value)
        or any(c.isspace() for c in value)
        or "/" in value
        or "|" in value
    )


def invalid_service(value: str) -> bool:
    value = value.strip().lower()
    return not value or value in {"none", "null", "n/a", "na"}


def invalid_password(value: str) -> bool:
    return (
        not value
        or value.strip().lower() in {"none", "null", "n/a", "na"}
    )


def classify_credential_material(value: str) -> str:
    """
    Best-effort format classification. It does not prove validity.
    """
    value = str(value or "").strip()

    if not value:
        return "unknown"

    if re.fullmatch(r"\$P\$[./0-9A-Za-z]{31}", value):
        return "phpass_hash_candidate"

    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", value):
        return "bcrypt_hash_candidate"

    if re.match(r"^\$argon2(?:id|i|d)\$", value):
        return "argon2_hash_candidate"

    if re.match(r"^\$(?:1|5|6)\$", value):
        return "unix_crypt_hash_candidate"

    # Not a recognized hash format: still only a candidate password value.
    return "plaintext_candidate"


def is_hash_candidate_record(record: Dict[str, Any]) -> bool:
    return str(
        record.get("credential_material_type", "")
    ).endswith("_hash_candidate")


def is_plaintext_candidate_record(record: Dict[str, Any]) -> bool:
    return (
        record.get("credential_material_type")
        == "plaintext_candidate"
    )


# ============================================================
# EMAIL IDENTITY EXTRACTION AND RECORD PARSING
# ============================================================

def select_record_email(
    candidate: str,
    target: str = "",
) -> Optional[re.Match]:
    """
    Prefer corporate email matches and avoid email-like URI userinfo tokens.
    """
    matches = list(EMAIL_RE.finditer(candidate))

    if not matches:
        return None

    target_root = (
        root_domain(norm_target(target))
        if target
        else ""
    )

    ranked = []

    for match in matches:
        email = match.group(1).strip()
        domain = email.rsplit("@", 1)[-1].lower()
        prefix = candidate[:match.start()]
        scheme_at = prefix.rfind("://")
        in_authority = False

        if scheme_at >= 0:
            after_scheme = prefix[scheme_at + 3:]
            in_authority = "/" not in after_scheme

        is_target = bool(
            target_root and root_domain(domain) == target_root
        )

        ranked.append((
            0 if is_target else 1,
            1 if in_authority else 0,
            match.start(),
            match,
        ))

    valid = [item for item in ranked if item[1] == 0]

    if not valid:
        return None

    valid.sort(key=lambda item: item[:3])
    return valid[0][3]


def line_has_target_context(
    line: str,
    target: str,
    target_root: str,
) -> bool:
    """Conservative fallback for unparsed matches."""
    for match in EMAIL_RE.finditer(line or ""):
        email = match.group(1).lower()
        domain = email.rsplit("@", 1)[-1]

        if root_domain(domain) == target_root:
            return True

    target_host = re.escape(norm_target(target))
    host_pattern = re.compile(
        rf"(?i)(?:https?://)?(?:[a-z0-9-]+\.)*{target_host}"
        r"(?=[:/\s|]|$)"
    )

    for match in host_pattern.finditer(line or ""):
        start = match.start()
        prefix = (line or "")[max(0, start - 8):start].lower()

        if start == 0 or re.search(r"(?:https?://|[\s:|])$", prefix):
            return True

    return False


def parsed_record_is_target_related(
    parsed: Optional[Dict[str, Any]],
    line: str,
    target: str,
    target_root: str,
) -> bool:
    """
    True only if the parsed identity is corporate or service is explicitly
    in scope. Unparsed candidate lines require explicit target context.
    """
    if parsed:
        username = str(parsed.get("username", "")).strip().lower()

        if EMAIL_RE.fullmatch(username):
            domain = username.rsplit("@", 1)[-1]

            if root_domain(domain) == target_root:
                return True

        service_host, _, _ = parse_service(parsed.get("service", ""))

        if service_host and (
            host_in_scope(service_host, target)
            or root_domain(service_host) == target_root
        ):
            return True

        return False

    return line_has_target_context(line, target, target_root)


def parse_record(
    line: str,
    target: str = "",
) -> Optional[Dict[str, str]]:
    """
    Supported formats:
      EMAIL:VALUE
      SERVICE:EMAIL:VALUE
      SERVICE|EMAIL|VALUE
      VALUE:SERVICE:EMAIL
      URL:USERNAME:VALUE

    Secret contents may include punctuation and colons.
    """
    candidate = clean_line(line).strip()

    if not candidate:
        return None

    candidate = re.split(
        r"\s+[:|]\s*https?\s*:\s*//t\.me/",
        candidate,
        maxsplit=1,
        flags=re.I,
    )[0].strip()

    candidate = re.sub(
        r"^[A-Za-z]{2,4}\s+(?=https?://)",
        "",
        candidate,
        count=1,
        flags=re.I,
    ).strip()

    # First: EMAIL:VALUE. The service remains explicitly unknown.
    simple = re.match(
        r"^(?P<identity>[^:|]+?)\s*[:|]\s*(?P<secret>.+)$",
        candidate,
        flags=re.S,
    )

    if simple:
        possible_email = simple.group("identity").strip()
        secret = simple.group("secret")

        if (
            EMAIL_RE.fullmatch(possible_email)
            and not invalid_password(secret)
        ):
            return {
                "service": "",
                "username": possible_email.lower(),
                "password": secret,
                "source_format": "email_value",
                "credential_material_type": classify_credential_material(
                    secret
                ),
            }

    email_match = select_record_email(candidate, target)

    if email_match:
        email = email_match.group(1).strip().lower()
        left = candidate[:email_match.start()].rstrip(" :|")
        right = candidate[email_match.end():].lstrip(" :|")

        # SERVICE:EMAIL:VALUE
        if left and right:
            secret = remove_trailing_noise(right)

            if not invalid_password(secret):
                return {
                    "service": left,
                    "username": email,
                    "password": secret,
                    "source_format": "service_email_value",
                    "credential_material_type": classify_credential_material(
                        secret
                    ),
                }

        # VALUE:SERVICE:EMAIL
        parts = re.split(r"\s*[:|]\s*", left, maxsplit=1)

        if len(parts) == 2:
            secret, service = parts[0].strip(), parts[1].strip()
            secret = remove_trailing_noise(secret)

            if (
                secret
                and service
                and not invalid_password(secret)
                and not invalid_service(service)
            ):
                return {
                    "service": service,
                    "username": email,
                    "password": secret,
                    "source_format": "value_service_email",
                    "credential_material_type": classify_credential_material(
                        secret
                    ),
                }

        return None

    # URL/service:username:value. Try separator positions conservatively.
    separators = [
        i for i, char in enumerate(candidate)
        if char in ":|"
    ]

    for first in separators:
        service = candidate[:first].strip()

        if not service or service.lower() in {
            "http", "https", "ftp", "ftps",
        }:
            continue

        remainder = candidate[first + 1:]
        second_rel = next(
            (
                i for i, char in enumerate(remainder)
                if char in ":|"
            ),
            -1,
        )

        if second_rel < 0:
            continue

        username = remainder[:second_rel].strip()
        secret = remove_trailing_noise(
            remainder[second_rel + 1:].strip()
        )
        service_host, _, _ = parse_service(service)

        valid_service = bool(
            service_host and looks_like_hostname(service_host)
        )
        valid_username = (
            bool(username)
            and not any(ch.isspace() for ch in username)
            and "/" not in username
            and "|" not in username
            and not re.match(
                r"^[a-z][a-z0-9+.-]*://",
                username,
                re.I,
            )
        )

        if (
            valid_service
            and valid_username
            and not invalid_password(secret)
        ):
            return {
                "service": service,
                "username": username.lower(),
                "password": secret,
                "source_format": "service_username_value",
                "credential_material_type": classify_credential_material(
                    secret
                ),
            }

    return None


# ============================================================
# IDENTITY / PASSWORD FEATURES
# ============================================================

def account_features(username: str) -> Dict[str, Any]:
    local = username.strip().lower().split("@", 1)[0]
    tokens = set(re.findall(r"[a-z0-9]+", local))

    service_hint = (
        bool(tokens & SERVICE_TOKENS)
        or bool(
            re.search(
                r"(?:^|[._+-])(?:svc|sa|api)(?:[._+-]|$)",
                local,
            )
        )
    )

    temporary = bool(tokens & TEMP_TOKENS)
    generic = bool(tokens & GENERIC_TOKENS)
    privileged = bool(tokens & PRIVILEGED_TOKENS)

    if temporary:
        hint = "temporary"
    elif service_hint:
        hint = "service"
    elif generic:
        hint = "generic"
    elif "@" in username:
        hint = "individual"
    else:
        hint = "unknown"

    return {
        "username_pattern": hint,
        "is_generic": generic,
        "is_temporary": temporary,
        "is_service_account": service_hint,
        "is_privileged_like": privileged,
        "local_part_tokens": sorted(tokens),
        "former_markers": sorted(tokens & FORMER_TOKENS),
    }


def password_features(password: str) -> Dict[str, Any]:
    return {
        "password_present": bool(password),
        "password_length": len(password),
        "password_has_upper": bool(re.search(r"[A-Z]", password)),
        "password_has_lower": bool(re.search(r"[a-z]", password)),
        "password_has_digit": bool(re.search(r"\d", password)),
        "password_has_special": bool(
            re.search(r"[^A-Za-z0-9]", password)
        ),
    }


def hmac_fp(key: bytes, value: str) -> str:
    return hmac.new(
        key,
        value.encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def password_family(password: str) -> str:
    return re.sub(r"\d+", "#", password.casefold())


def path_type(path: str) -> str:
    p = (path or "").lower()

    if any(x in p for x in (
        "/login", "/signin", "/auth", "/oauth",
    )):
        return "authentication"

    if any(x in p for x in (
        "/api", "/graphql",
    )):
        return "api"

    if any(x in p for x in (
        "/account", "/profile", "/user",
    )):
        return "account"

    return "other" if path else "root"


# ============================================================
# PROGRESS / PATH HELPERS
# ============================================================

def progress(
    stage: str,
    current: int,
    total: int,
    detail: str = "",
) -> None:
    pct = 100.0 if total == 0 else current / total * 100
    width = 28
    filled = int(width * pct / 100)
    bar = "=" * filled + ">" + " " * max(0, width - filled - 1)

    sys.stdout.write(
        f"\r[{stage}] [{bar}] {pct:6.2f}% "
        f"({current}/{total}) {detail[-38:]:<38}"
    )
    sys.stdout.flush()

    if current >= total:
        sys.stdout.write("\n")


def path_is_within(
    path: Path,
    directory: Path,
) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except (ValueError, OSError):
        return False


def list_txt_files(
    input_dir: Path,
    output_dir: Path,
) -> List[Path]:
    result = []

    for p in input_dir.rglob("*.txt"):
        if not p.is_file():
            continue

        if not path_is_within(p, input_dir):
            continue

        if path_is_within(p, output_dir):
            continue

        if (
            "_results_" in p.name.lower()
            or p.name.lower().endswith("_unique.txt")
        ):
            continue

        result.append(p.resolve())

    return sorted(result, key=lambda p: str(p).casefold())


def find_tgrep(
    tgrep_path: Optional[str],
) -> Optional[str]:
    candidates = (
        [tgrep_path]
        if tgrep_path
        else [DEFAULT_TGREP_PATH, "tgrep"]
    )

    for candidate in candidates:
        if not candidate:
            continue

        p = Path(candidate)

        if p.is_file():
            return str(p.resolve())

        located = shutil.which(candidate)

        if located:
            return located

    return None


def stable_id(
    value: str,
    length: int = 24,
) -> str:
    return hashlib.sha256(
        value.encode("utf-8", errors="replace")
    ).hexdigest()[:length]


def normalize_path_key(value: str) -> str:
    if value.startswith("\\\\?\\"):
        value = value[4:]

    return os.path.normcase(
        os.path.abspath(value)
    ).casefold()


def decode_tgrep_payload(value: Any) -> str:
    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]

        if isinstance(value.get("bytes"), str):
            try:
                return base64.b64decode(
                    value["bytes"]
                ).decode(
                    "utf-8",
                    errors="replace",
                )
            except Exception:
                return ""

    return ""


def resolve_tgrep_path(
    value: str,
    input_dir: Path,
    known_files: Dict[str, Path],
) -> Optional[Path]:
    value = value.strip().strip('"')

    if value.startswith("\\\\?\\"):
        value = value[4:]

    candidate = Path(value)

    guesses = (
        [candidate]
        if candidate.is_absolute()
        else [
            input_dir / candidate,
            Path.cwd() / candidate,
        ]
    )

    for guess in guesses:
        try:
            found = known_files.get(
                normalize_path_key(str(guess))
            )
            if found:
                return found
        except (OSError, ValueError):
            continue

    return None


# ============================================================
# TGREP JSON SEARCH / FALLBACK
# ============================================================

def run_tgrep_json(
    binary: str,
    input_dir: Path,
    files: Sequence[Path],
    pattern: str,
    index_dir: Optional[Path],
    mode: str,
    fixed: bool,
) -> Dict[str, Any]:
    """Stream tgrep JSON events; indexed mode uses the external index."""
    if mode not in {"indexed", "text_scan"}:
        raise ValueError(f"Modo tgrep inválido: {mode}")

    cmd = [binary]

    if mode == "indexed":
        if not index_dir or not index_dir.is_dir():
            raise FileNotFoundError(
                f"No existe el índice externo: {index_dir}"
            )

        cmd.extend([
            "--index-path", str(index_dir),
            "--max-filesize", "64M",
        ])
    else:
        cmd.extend([
            "--no-index",
            "--no-max-filesize",
            "--text",
        ])

    cmd.extend([
        "--json",
        "--no-require-git",
        "-i",
    ])

    if fixed:
        cmd.append("-F")

    cmd.extend([
        "-g", "*.txt",
        "-g", "!*_results_*",
        "--",
        pattern,
        str(input_dir),
    ])

    known = {
        normalize_path_key(str(p)): p
        for p in files
    }

    matches: List[Dict[str, Any]] = []
    unmapped: Set[str] = set()
    stats: Dict[str, Any] = {}
    start = time.perf_counter()

    with tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        try:
            if process.stdout is None:
                raise RuntimeError(
                    "No se pudo abrir stdout de tgrep."
                )

            for json_line in process.stdout:
                if not json_line.strip():
                    continue

                try:
                    event = json.loads(json_line)
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        f"JSON inválido de tgrep: {exc}"
                    ) from exc

                event_type = event.get("type")
                data = event.get("data", {}) or {}

                if event_type == "match":
                    path_text = decode_tgrep_payload(
                        data.get("path", {})
                    )

                    path = resolve_tgrep_path(
                        path_text,
                        input_dir,
                        known,
                    )

                    if path is None:
                        unmapped.add(path_text)
                        continue

                    try:
                        line_number = int(
                            data.get("line_number", 0)
                        )
                    except (TypeError, ValueError):
                        line_number = 0

                    content = decode_tgrep_payload(
                        data.get("lines", {})
                    )

                    if line_number < 1 or not content:
                        continue

                    for offset, raw in enumerate(content.splitlines()):
                        line = clean_line(raw)

                        if line:
                            matches.append({
                                "path": path,
                                "line_number": line_number + offset,
                                "line": line,
                            })

                elif event_type == "summary":
                    stats = data.get("stats", {}) or {}

            return_code = process.wait()

        except Exception:
            process.kill()
            process.wait()
            raise

        elapsed = time.perf_counter() - start
        stderr_file.seek(0)
        stderr_text = stderr_file.read().decode(
            "utf-8",
            errors="replace",
        ).strip()

    if return_code not in (0, 1):
        raise RuntimeError(
            f"tgrep terminó con código {return_code}: "
            f"{stderr_text[-4000:]}"
        )

    return {
        "matches": matches,
        "elapsed_seconds": round(elapsed, 4),
        "stats": stats,
        "stderr": stderr_text,
        "unmapped_paths": sorted(unmapped),
        "command": subprocess.list2cmdline(cmd),
    }


def match_signature(
    matches: Sequence[Dict[str, Any]],
) -> Counter:
    return Counter(
        (
            normalize_path_key(str(match["path"])),
            int(match["line_number"]),
            match["line"],
        )
        for match in matches
    )


def python_search(
    files: Sequence[Path],
    matcher: Any,
    stage: str,
) -> Dict[str, Any]:
    start = time.perf_counter()
    matches = []
    errors = []

    for idx, path in enumerate(files, 1):
        try:
            for line_no, line in safe_read_lines(path):
                if line and matcher(line):
                    matches.append({
                        "path": path,
                        "line_number": line_no,
                        "line": line,
                    })

        except Exception as exc:
            errors.append({
                "source_file": str(path),
                "error": str(exc),
            })

        progress(stage, idx, len(files), path.name)

    return {
        "matches": matches,
        "elapsed_seconds": round(time.perf_counter() - start, 4),
        "errors": errors,
    }


def search_with_fallback(
    binary: Optional[str],
    input_dir: Path,
    all_files: Sequence[Path],
    pattern: str,
    matcher: Any,
    index_dir: Optional[Path],
    search_engine: str,
    fixed: bool,
    verify_index: bool,
    stage: str,
) -> Dict[str, Any]:
    """Try indexed tgrep, verify when requested, then controlled fallback."""
    result = {
        "matches": [],
        "engine": "python",
        "indexed_seconds": 0.0,
        "text_scan_seconds": 0.0,
        "python_seconds": 0.0,
        "command": "",
        "warning": "",
        "stats": {},
        "errors": [],
        "index_verified": False,
        "verification_performed": False,
    }

    if search_engine == "python" or not binary:
        if search_engine != "python" and not binary:
            result["warning"] = (
                "tgrep no disponible; se utilizó Python."
            )

        py = python_search(all_files, matcher, stage)
        result.update(
            matches=py["matches"],
            python_seconds=py["elapsed_seconds"],
        )
        result["errors"].extend(py["errors"])
        return result

    eligible = []
    oversized = []

    for path in all_files:
        try:
            (
                eligible
                if path.stat().st_size <= INDEX_MAX_FILESIZE
                else oversized
            ).append(path)
        except OSError as exc:
            result["errors"].append({
                "source_file": str(path),
                "error": str(exc),
            })
            oversized.append(path)

    indexed = None

    if index_dir and index_dir.is_dir() and eligible:
        try:
            indexed = run_tgrep_json(
                binary, input_dir, eligible, pattern,
                index_dir, "indexed", fixed,
            )
            result["indexed_seconds"] = indexed["elapsed_seconds"]
            result["stats"] = indexed["stats"]
            result["command"] = indexed["command"]

            if indexed["unmapped_paths"]:
                result["warning"] = (
                    f"Rutas indexadas no mapeadas: "
                    f"{len(indexed['unmapped_paths'])}; se hará fallback."
                )
                indexed = None

            elif (
                "out of memory" in indexed["stderr"].lower()
                or "cannot read indexed file" in indexed["stderr"].lower()
            ):
                result["warning"] = (
                    "tgrep reportó errores de lectura/memoria en el índice; "
                    "se hará fallback."
                )
                indexed = None

        except Exception as exc:
            result["warning"] = (
                f"Búsqueda indexada no disponible: {exc}"
            )
            indexed = None

    else:
        result["warning"] = (
            "No se encontró índice utilizable; se intentará Full Text."
        )

    if indexed is not None:
        indexed_matches = [
            match for match in indexed["matches"]
            if matcher(match["line"])
        ]

        if oversized:
            large = python_search(
                oversized,
                matcher,
                stage + "_OVERSIZED",
            )
            indexed_matches.extend(large["matches"])
            result["python_seconds"] += large["elapsed_seconds"]
            result["errors"].extend(large["errors"])

        if verify_index:
            result["verification_performed"] = True

            full = run_tgrep_json(
                binary,
                input_dir,
                all_files,
                pattern,
                None,
                "text_scan",
                fixed,
            )
            result["text_scan_seconds"] = full["elapsed_seconds"]

            if full["unmapped_paths"]:
                result["warning"] += (
                    " Full Text devolvió rutas no mapeadas; "
                    "fallback Python."
                )
                py = python_search(
                    all_files,
                    matcher,
                    stage + "_VERIFY_FALLBACK",
                )
                result["matches"] = py["matches"]
                result["python_seconds"] += py["elapsed_seconds"]
                result["errors"].extend(py["errors"])
                result["engine"] = "python_unmapped_fallback"
                return result

            full_matches = [
                match for match in full["matches"]
                if matcher(match["line"])
            ]

            equal = (
                match_signature(indexed_matches)
                == match_signature(full_matches)
            )
            result["index_verified"] = equal

            if equal:
                result["matches"] = indexed_matches
                result["engine"] = "tgrep_indexed_verified"
            else:
                result["matches"] = full_matches
                result["engine"] = "tgrep_textscan_verified_fallback"
                result["warning"] += (
                    " Índice y Full Text difieren; se usan resultados completos."
                )

        elif indexed_matches:
            result["matches"] = indexed_matches
            result["engine"] = "tgrep_indexed_unverified"
            result["warning"] = (
                (result["warning"] + " ") if result["warning"] else ""
            ) + "Cobertura indexada no contrastada contra Full Text."

        else:
            full = run_tgrep_json(
                binary,
                input_dir,
                all_files,
                pattern,
                None,
                "text_scan",
                fixed,
            )
            result["text_scan_seconds"] = full["elapsed_seconds"]

            if full["unmapped_paths"]:
                py = python_search(
                    all_files,
                    matcher,
                    stage + "_ZERO_FALLBACK",
                )
                result["matches"] = py["matches"]
                result["python_seconds"] += py["elapsed_seconds"]
                result["errors"].extend(py["errors"])
                result["engine"] = "python_unmapped_fallback"
            else:
                result["matches"] = [
                    match for match in full["matches"]
                    if matcher(match["line"])
                ]
                result["engine"] = "tgrep_textscan_zero_check"

            result["warning"] = (
                (result["warning"] + " ") if result["warning"] else ""
            ) + "Índice sin coincidencias; se verificó con Full Text."

        return result

    try:
        full = run_tgrep_json(
            binary,
            input_dir,
            all_files,
            pattern,
            None,
            "text_scan",
            fixed,
        )
        result["text_scan_seconds"] = full["elapsed_seconds"]

        if full["unmapped_paths"]:
            raise RuntimeError(
                f"No se pudieron mapear {len(full['unmapped_paths'])} rutas de tgrep."
            )

        result["matches"] = [
            match for match in full["matches"]
            if matcher(match["line"])
        ]
        result["engine"] = "tgrep_textscan_fallback"

    except Exception as exc:
        result["warning"] = (
            (result["warning"] + " ") if result["warning"] else ""
        ) + f"Full Text falló ({exc}); fallback Python."

        py = python_search(
            all_files,
            matcher,
            stage + "_PYTHON_FALLBACK",
        )
        result["matches"] = py["matches"]
        result["python_seconds"] += py["elapsed_seconds"]
        result["errors"].extend(py["errors"])
        result["engine"] = "python_fallback"

    return result


# ============================================================
# SYNTHETIC DEMO CORPUS
# ============================================================

def make_demo_corpus(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)

    synthetic = {
        "demo_01_corporate.txt": [
            "https://portal.acme.example/login:ana.perez@acme.example:DemoWinter2025!",
            "https://portal.acme.example/login:qa-team@acme.example:DemoQA2026!",
            "https://portal.acme.example/login:former.jorge@acme.example:DemoFormer2024!",
            "https://portal.acme.example/login:lucia.mora@acme.example:DemoPortal2026!",
            "https://portal.acme.example/login:diego.salas@acme.example:DemoOne2026!",
            "https://portal.acme.example/login:carla.rios@acme.example:DemoOnly2026!",
            "https://support.acme.example/login:svc_reports@acme.example:DemoSvc2026!",
        ],
        "demo_02_external.txt": [
            "https://crm.vendor.example/login:ana.perez@acme.example:DemoWinter2026!",
            "https://training.vendor.example/login:qa-team@acme.example:DemoQA2026!",
            "https://crm.vendor.example/login:former.jorge@acme.example:DemoFormerCRM2024!",
            "https://docs.vendor.example/login:lucia.mora@acme.example:DemoDocs2026!",
            "https://github.com/login:diego.salas@acme.example:DemoTwo2026!",
        ],
        "demo_03_aliases.txt": [
            "https://legacy-crm.vendor.example/login:former.jorge:DemoAlias2024!",
            "https://support.vendor.example/login:lucia.mora:DemoSupport2026!",
            "https://gitlab.com/users/sign_in:ana.perez:DemoWinter2027!",
            "https://jira.vendor.example/login:diego.salas:DemoThree2026!",
        ],
        "demo_04_more_observations.txt": [
            "https://portal.acme.example/login:diego.salas@acme.example:DemoOne2026!",
            "https://portal.acme.example/login:ana.perez@acme.example:DemoWinter2025!",
        ],
        "demo_05_opaque_service.txt": [
            "GadielDemo2026.:siebelprd:former.jorge@acme.example",
        ],
    }

    for name, lines in synthetic.items():
        (directory / name).write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )


# ============================================================
# NORMALIZED RECORDS
# ============================================================

def build_normalized_record(
    parsed: Dict[str, str],
    evidence: Dict[str, Any],
    target: str,
    target_root: str,
    key: bytes,
    linked_candidates: Optional[List[str]] = None,
) -> Dict[str, Any]:
    username = parsed["username"].strip().lower()
    secret = parsed["password"]
    raw_service = str(parsed.get("service", "") or "").strip()
    material_type = (
        parsed.get("credential_material_type")
        or classify_credential_material(secret)
    )

    if raw_service:
        service_host, service_path, service_port = parse_service(
            raw_service
        )
        is_host = bool(
            service_host and looks_like_hostname(service_host)
        )
        is_target_service = bool(
            is_host
            and (
                host_in_scope(service_host, target)
                or root_domain(service_host) == target_root
            )
        )

        if is_target_service:
            service_scope = "corporate"
        elif is_host:
            service_scope = "third_party"
        else:
            service_scope = "opaque_identifier"

        service_key = (
            service_host
            if is_host
            else f"opaque:{service_host or raw_service.lower()}"
        )

    else:
        service_host, service_path, service_port = (
            "unknown-service", "", None
        )
        is_host = False
        is_target_service = False
        service_scope = "unknown"
        service_key = "unknown-service"

    is_email = bool(EMAIL_RE.fullmatch(username))
    identity_domain = (
        username.rsplit("@", 1)[1].lower()
        if is_email else ""
    )
    is_corporate_email = bool(
        identity_domain
        and root_domain(identity_domain) == target_root
    )

    if is_corporate_email:
        identity_type = "corporate_email"
    elif is_email and is_target_service:
        identity_type = "external_email_on_corporate_service"
    elif is_email:
        identity_type = "external_email"
    elif is_target_service:
        identity_type = "corporate_identifier"
    else:
        identity_type = "username_only"

    acct = account_features(username)
    pw = password_features(secret)
    pw_fp = hmac_fp(key, secret)

    family_value = (
        password_family(secret)
        if material_type == "plaintext_candidate"
        else f"{material_type}:{pw_fp}"
    )
    family_fp = hmac_fp(key, family_value)

    rid = stable_id(
        evidence["evidence_id"]
        + "\x1f" + username
        + "\x1f" + service_key
        + "\x1f" + pw_fp
        + "\x1f" + material_type
    )

    return {
        "record_id": rid,
        "evidence_id": evidence["evidence_id"],
        "source_file": evidence["source_file"],
        "source_line": evidence["source_line"],
        "source_type": evidence.get("source_type", "unknown"),
        "file_created_at": evidence.get("file_created_at", ""),
        "source_timestamp_basis": evidence.get(
            "source_timestamp_basis", "unavailable"
        ),

        "identity": username,
        "identity_domain": identity_domain,
        "identity_type": identity_type,
        "is_corporate_identity": is_corporate_email,

        "service_observed": raw_service,
        "service_domain": service_host,
        "service_port": service_port,
        "service_path": service_path,
        "service_key": service_key,
        "service_scope": service_scope,
        "service_origin_known": bool(raw_service and is_host),

        "is_target_service": is_target_service,
        "is_third_party": service_scope == "third_party",
        "is_probable_hostname": is_host,
        "path_type": path_type(service_path),

        "source_format": parsed.get("source_format", "unknown"),
        "credential_material_type": material_type,
        "password_features_applicable": (
            material_type == "plaintext_candidate"
        ),

        "search_match_reasons": sorted(
            evidence.get("match_reasons", [])
        ),
        "identity_match_type": (
            "exact_observed_identity"
            if is_email else "username_only"
        ),
        "linked_identity_candidates": sorted(
            set(linked_candidates or [])
        ),

        **acct,
        **pw,

        "password_fingerprint": pw_fp,
        "password_pattern_fingerprint": family_fp,
    }


def record_evidence_ids(
    record: Dict[str, Any],
) -> List[str]:
    values = record.get("evidence_ids")

    if values:
        return sorted(set(values))

    value = record.get("evidence_id")
    return [value] if value else []


# ============================================================
# FINDINGS
# ============================================================

def add_finding(
    findings: List[Dict[str, Any]],
    rule_id: str,
    triage_pattern: str,
    title: str,
    subject: str,
    evidence_ids: Iterable[str],
    confidence: str,
    evidence_status: str,
    hypothesis: str,
    limitations: str,
    validation: str,
    details: Dict[str, Any],
) -> None:
    evidence = sorted(set(evidence_ids))
    finding_id = stable_id(
        rule_id + "\x1f" + subject + "\x1f" + "|".join(evidence),
        24,
    )

    findings.append({
        "finding_id": finding_id,
        "rule_id": rule_id,
        "triage_pattern": triage_pattern,
        "title": title,
        "subject_identity": subject,
        "evidence_ids": evidence,
        "evidence_status": evidence_status,
        "confidence": confidence,
        "hypothesis": hypothesis,
        "limitations": limitations,
        "recommended_validation": validation,
        "details": details,
    })


def derive_findings(
    records: List[Dict[str, Any]],
    corporate_identities: Set[str],
    alias_records_by_identity: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Generate findings only for target identities and their explicit aliases."""
    by_identity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for record in records:
        by_identity[record["identity"]].append(record)

    findings: List[Dict[str, Any]] = []

    # PWD-001 / PWD-002 only use candidate plaintext material, explicit hosts
    # and corporate identities. Hash candidates are excluded from reuse logic.
    for identity in sorted(corporate_identities):
        rows = [
            record
            for record in by_identity.get(identity, [])
            if (
                record.get("is_corporate_identity")
                and is_plaintext_candidate_record(record)
                and record.get("service_scope") in {"corporate", "third_party"}
                and record.get("service_domain")
            )
        ]

        by_password: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for record in rows:
            by_password[record["password_fingerprint"]].append(record)

        for fingerprint, group in by_password.items():
            services = {record["service_key"] for record in group}

            if len(services) < 2:
                continue

            evidence = [
                eid
                for record in group
                for eid in record_evidence_ids(record)
            ]

            add_finding(
                findings,
                "PWD-001",
                "password_pattern",
                "Exact credential-material fingerprint observed across services",
                identity,
                evidence,
                "high",
                "observed",
                (
                    "The same HMAC fingerprint of candidate password material "
                    "was observed for this corporate identifier on multiple "
                    "explicitly identified services."
                ),
                (
                    "This does not prove current validity, successful "
                    "authentication or a shared authentication backend."
                ),
                (
                    "Review with authorized identity/service owners; "
                    "validate live authentication only when explicitly "
                    "in scope."
                ),
                {
                    "pattern_type": "exact_reuse",
                    "distinct_services": sorted(services),
                    "service_count": len(services),
                    "password_fingerprint": fingerprint,
                    "credential_material_type": "plaintext_candidate",
                },
            )

        by_family: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for record in rows:
            by_family[
                record["password_pattern_fingerprint"]
            ].append(record)

        for family, group in by_family.items():
            services = {record["service_key"] for record in group}
            fingerprints = {
                record["password_fingerprint"] for record in group
            }

            if len(services) < 2 or len(fingerprints) < 2:
                continue

            evidence = [
                eid
                for record in group
                for eid in record_evidence_ids(record)
            ]

            add_finding(
                findings,
                "PWD-002",
                "password_pattern",
                "Candidate password variations share a numeric-run pattern across services",
                identity,
                evidence,
                "medium",
                "observed",
                (
                    "Distinct candidate password-material fingerprints share "
                    "a deterministic shape after numeric runs are replaced "
                    "with a marker across explicitly identified services."
                ),
                (
                    "This heuristic may group unrelated values and cannot "
                    "prove validity. Hash candidates are excluded."
                ),
                (
                    "Review provenance and use only an approved offline "
                    "audit or scoped validation process."
                ),
                {
                    "pattern_type": "digit_run_variation",
                    "distinct_services": sorted(services),
                    "service_count": len(services),
                    "distinct_password_fingerprints": len(fingerprints),
                    "pattern_fingerprint": family,
                },
            )

    # ID-002: naming heuristics only for corporate identities.
    for identity in sorted(corporate_identities):
        rows = [
            record
            for record in by_identity.get(identity, [])
            if record.get("is_corporate_identity")
        ]

        flagged = []
        labels = set()

        for record in rows:
            current = []

            if record.get("is_temporary"):
                current.append("temporary")
            if record.get("is_generic"):
                current.append("generic")
            if record.get("is_service_account"):
                current.append("service_account")
            if record.get("is_privileged_like"):
                current.append("privileged_like")

            if current:
                flagged.append(record)
                labels.update(current)

        if flagged:
            add_finding(
                findings,
                "ID-002",
                "temporary_generic_account",
                "Corporate account naming indicators detected",
                identity,
                [
                    eid
                    for record in flagged
                    for eid in record_evidence_ids(record)
                ],
                "medium",
                "observed",
                (
                    "The corporate identifier contains deterministic tokens "
                    "associated with temporary, generic, service-account "
                    "or privileged-like naming."
                ),
                (
                    "Naming indicators do not prove account purpose, "
                    "privilege, ownership or current activity."
                ),
                (
                    "Confirm account ownership, purpose, lifecycle, "
                    "privileges and business justification."
                ),
                {
                    "account_labels": sorted(labels),
                    "observed_services": sorted({
                        record["service_key"] for record in flagged
                    }),
                    "unique_observations": len(flagged),
                },
            )

    # LIFE-001: historical identity markers remain hypotheses.
    for identity in sorted(corporate_identities):
        corporate_rows = [
            record
            for record in by_identity.get(identity, [])
            if record.get("is_corporate_identity")
        ]

        tokens = set(
            re.findall(r"[a-z0-9]+", identity.split("@", 1)[0])
        )
        former_markers = tokens & FORMER_TOKENS
        alias_rows = alias_records_by_identity.get(identity, [])
        external_rows = [
            record
            for record in corporate_rows + alias_rows
            if record.get("service_scope") == "third_party"
        ]

        if not former_markers or not external_rows:
            continue

        evidence = [
            eid
            for record in external_rows
            for eid in record_evidence_ids(record)
        ]

        add_finding(
            findings,
            "LIFE-001",
            "former_employee",
            "Historical identity marker with external-service traces",
            identity,
            evidence,
            "low",
            "hypothesis",
            (
                "The corporate identifier contains a historical-status "
                "naming marker and related evidence appears on an external "
                "service."
            ),
            (
                "ULP records cannot establish employment status, ownership, "
                "account validity or persistent access. Alias links remain "
                "candidates."
            ),
            (
                "Corroborate employment/account lifecycle using authorized "
                "HR/IAM sources and the external service owner."
            ),
            {
                "former_markers": sorted(former_markers),
                "external_services": sorted({
                    record["service_key"] for record in external_rows
                }),
                "alias_match_count": len(alias_rows),
            },
        )

    # EXT-001 and EXT-002: direct corporate email versus candidate alias.
    for identity in sorted(corporate_identities):
        direct = [
            record
            for record in by_identity.get(identity, [])
            if (
                record.get("is_corporate_identity")
                and record.get("service_scope") == "third_party"
                and record.get("service_domain")
            )
        ]

        aliases = [
            record
            for record in alias_records_by_identity.get(identity, [])
            if (
                record.get("service_scope") == "third_party"
                and record.get("service_domain")
                and identity in record.get("linked_identity_candidates", [])
                and record.get("identity", "").casefold()
                == identity.split("@", 1)[0].casefold()
            )
        ]

        if direct:
            add_finding(
                findings,
                "EXT-001",
                "third_party_dependency",
                "Potential exposure of a corporate identity on a third-party application",
                identity,
                [
                    eid
                    for record in direct
                    for eid in record_evidence_ids(record)
                ],
                "medium",
                "observed",
                (
                    "A record explicitly associates the exact corporate email "
                    "identity with an externally hosted service. If the "
                    "credential material remains valid, authentication on "
                    "that service may be possible."
                ),
                (
                    "An external hostname does not prove an approved business "
                    "dependency, active account, valid credential or successful "
                    "authentication."
                ),
                (
                    "Identify the service owner/vendor, confirm business "
                    "purpose and account status, and review MFA/SSO and "
                    "offboarding controls."
                ),
                {
                    "external_services": sorted({
                        record["service_key"] for record in direct
                    }),
                    "external_observations": len(direct),
                    "relationship_type": "direct_corporate_email",
                },
            )

        if aliases:
            add_finding(
                findings,
                "EXT-002",
                "third_party_dependency",
                "Possible third-party account linked by exact local-part match",
                identity,
                [
                    eid
                    for record in aliases
                    for eid in record_evidence_ids(record)
                ],
                "low",
                "candidate",
                (
                    "An external-service record uses a username exactly "
                    "matching the local part of the corporate email, without "
                    "containing the full corporate email."
                ),
                (
                    "Local-part equality alone does not establish account "
                    "ownership; collisions are possible."
                ),
                (
                    "Verify ownership through a service owner or authoritative "
                    "identity inventory before using this relationship as "
                    "an attack-path hypothesis."
                ),
                {
                    "candidate_services": sorted({
                        record["service_key"] for record in aliases
                    }),
                    "alias_observations": len(aliases),
                    "match_type": "exact_local_part_candidate",
                },
            )

    # CORR-001: recurrence only for target corporate identities.
    for identity in sorted(corporate_identities):
        rows = [
            record
            for record in by_identity.get(identity, [])
            if record.get("is_corporate_identity")
        ]

        services = {
            record["service_key"]
            for record in rows
            if record.get("service_domain")
        }
        sources = {
            source
            for record in rows
            for source in record.get("source_files", [])
        }
        distinct_lines = {
            line_id
            for record in rows
            for line_id in record.get("unique_line_ids", [])
        }

        if (
            len(distinct_lines) < 2
            or (len(services) < 2 and len(sources) < 2)
        ):
            continue

        add_finding(
            findings,
            "CORR-001",
            "identity_correlation",
            "Recurring corporate identifier across distinct observations",
            identity,
            [
                eid
                for record in rows
                for eid in record_evidence_ids(record)
            ],
            "medium",
            "observed",
            (
                "The same corporate account identifier occurs in distinct "
                "observations and/or normalized services within the analyzed "
                "corpus."
            ),
            (
                "Recurrence confirms presence in the corpus, not a unique "
                "human identity, current validity or a working access path."
            ),
            (
                "Review source provenance and corroborate account mapping "
                "using an authorized identity source."
            ),
            {
                "unique_normalized_observations": len(rows),
                "distinct_services": sorted(services),
                "service_count": len(services),
                "source_files": sorted(sources),
                "source_file_count": len(sources),
                "unique_raw_lines": len(distinct_lines),
                "raw_occurrence_count": sum(
                    record.get("occurrence_count", 1) for record in rows
                ),
            },
        )

    # CORR-002: alias relation; identities are not merged.
    for identity in sorted(corporate_identities):
        alias_rows = [
            record
            for record in alias_records_by_identity.get(identity, [])
            if (
                record.get("service_scope") == "third_party"
                and record.get("service_domain")
                and identity in record.get("linked_identity_candidates", [])
            )
        ]

        if not alias_rows:
            continue

        base_rows = [
            record
            for record in by_identity.get(identity, [])
            if record.get("is_corporate_identity")
        ]

        add_finding(
            findings,
            "CORR-002",
            "identity_correlation",
            "Candidate relation from exact local-part match",
            identity,
            [
                eid
                for record in base_rows + alias_rows
                for eid in record_evidence_ids(record)
            ],
            "low",
            "candidate",
            (
                "An observed username exactly matches the local part of a "
                "corporate email identifier on an external service."
            ),
            (
                "The account identities remain separate; local-part equality "
                "may be coincidental."
            ),
            (
                "Verify ownership using an authoritative identity inventory "
                "before merging entities or using the relation in an "
                "attack-path hypothesis."
            ),
            {
                "candidate_usernames": sorted({
                    record["identity"] for record in alias_rows
                }),
                "candidate_services": sorted({
                    record["service_key"] for record in alias_rows
                }),
                "match_type": "exact_local_part_candidate",
            },
        )

    # CRED-001 / HASH-001: corporate EMAIL:VALUE with unknown source service.
    for identity in sorted(corporate_identities):
        rows = [
            record
            for record in by_identity.get(identity, [])
            if (
                record.get("is_corporate_identity")
                and record.get("service_scope") == "unknown"
            )
        ]

        plaintext_rows = [
            record
            for record in rows
            if is_plaintext_candidate_record(record)
        ]
        hash_rows = [
            record
            for record in rows
            if is_hash_candidate_record(record)
        ]

        if plaintext_rows:
            add_finding(
                findings,
                "CRED-001",
                "corporate_credential_pair_unknown_service",
                "Corporate credential pair observed; source service not identified",
                identity,
                [
                    eid
                    for record in plaintext_rows
                    for eid in record_evidence_ids(record)
                ],
                "medium",
                "observed",
                (
                    "Candidate password material was observed with a "
                    "corporate identity, but the record does not identify "
                    "the application of origin. It can inform the authorized "
                    "Red Team application-validation plan."
                ),
                (
                    "The material may not be current. No application, "
                    "successful authentication or credential reuse has "
                    "been established."
                ),
                (
                    "Correlate the identity with the authorized application "
                    "inventory. Do not infer a service from the email local-part."
                ),
                {
                    "credential_material_type": "plaintext_candidate",
                    "service_scope": "unknown",
                    "observation_count": len(plaintext_rows),
                },
            )

        if hash_rows:
            add_finding(
                findings,
                "HASH-001",
                "credential_hash_candidate_unknown_service",
                "Possible credential hash associated with a corporate identity",
                identity,
                [
                    eid
                    for record in hash_rows
                    for eid in record_evidence_ids(record)
                ],
                "low",
                "candidate",
                (
                    "A value matches a known hash-format heuristic and is "
                    "associated with a corporate identity, but the service "
                    "of origin is unknown."
                ),
                (
                    "The algorithm, integrity, recoverability and any "
                    "corresponding password have not been confirmed."
                ),
                (
                    "Identify the format locally and, only when authorized, "
                    "evaluate recoverability through a controlled offline audit."
                ),
                {
                    "credential_material_types": sorted({
                        record.get(
                            "credential_material_type", "unknown"
                        )
                        for record in hash_rows
                    }),
                    "service_scope": "unknown",
                    "hash_candidate_count": len(hash_rows),
                },
            )

    # AUTH-001: credential record associated with an AD FS endpoint.
    for identity in sorted(corporate_identities):
        adfs_rows = []

        for record in by_identity.get(identity, []):
            if (
                not record.get("is_corporate_identity")
                or not is_plaintext_candidate_record(record)
                or record.get("service_scope") != "corporate"
            ):
                continue

            host = str(record.get("service_domain", "")).lower()
            path = str(record.get("service_path", "")).lower()

            if (
                re.search(r"(?:^|[.-])adfs(?:[.-]|$)", host)
                or re.search(r"/adfs(?:/|$)", path)
            ):
                adfs_rows.append(record)

        if adfs_rows:
            add_finding(
                findings,
                "AUTH-001",
                "corporate_authentication_entry",
                "Potential corporate credential associated with an AD FS endpoint",
                identity,
                [
                    eid
                    for record in adfs_rows
                    for eid in record_evidence_ids(record)
                ],
                "medium",
                "observed",
                (
                    "A credential record is associated with a corporate "
                    "identity and an endpoint related to AD FS. If the "
                    "association is accurate and the pair remains current, "
                    "it may represent a potential initial-authentication "
                    "opportunity within the approved Red Team scope."
                ),
                (
                    "The endpoint reference does not prove valid credentials, "
                    "successful authentication, domain access or lateral "
                    "movement."
                ),
                (
                    "Corroborate the endpoint and account with the identity "
                    "owner; validate only under explicit authorization."
                ),
                {
                    "endpoints": sorted({
                        record.get("service_observed", "")
                        for record in adfs_rows
                    }),
                    "authentication_success_confirmed": False,
                },
            )

    # BASE-000 is limited to corporate identities and excluded if an actionable
    # rule already exists for the same subject.
    actionable_subjects = {
        finding["subject_identity"]
        for finding in findings
        if finding["rule_id"] != "BASE-000"
    }

    for identity in sorted(corporate_identities):
        rows = [
            record
            for record in by_identity.get(identity, [])
            if record.get("is_corporate_identity")
        ]

        if not rows or identity in actionable_subjects:
            continue

        add_finding(
            findings,
            "BASE-000",
            "no_actionable_pattern",
            "No configured actionable rule matched this corporate identity",
            identity,
            [
                eid
                for record in rows
                for eid in record_evidence_ids(record)
            ],
            "informational",
            "observed",
            (
                "The configured deterministic rules did not identify an "
                "actionable pattern for this corporate identity."
            ),
            (
                "Absence of a rule match is not evidence of absence of risk; "
                "the rule catalogue is finite."
            ),
            (
                "Retain the observation for future rule expansion or manual "
                "review if context becomes available."
            ),
            {
                "unique_normalized_observations": len(rows),
                "raw_occurrence_count": sum(
                    record.get("occurrence_count", 1) for record in rows
                ),
                "baseline_only": True,
            },
        )

    # Final invariant: BASE-000 cannot coexist with another rule for a subject.
    actionable_subjects = {
        finding["subject_identity"]
        for finding in findings
        if finding["rule_id"] != "BASE-000"
    }
    findings = [
        finding
        for finding in findings
        if (
            finding["rule_id"] != "BASE-000"
            or finding["subject_identity"] not in actionable_subjects
        )
    ]

    return sorted(
        findings,
        key=lambda finding: (
            finding["triage_pattern"],
            finding["subject_identity"],
            finding["rule_id"],
            finding["finding_id"],
        ),
    )


# ============================================================
# RAW DEDUPLICATION / NORMALIZED AGGREGATION / TRIAGE
# ============================================================

def group_unique_observations(
    observations: Dict[str, Dict[str, Any]],
    key: bytes,
) -> List[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}

    ordered = sorted(
        observations.values(),
        key=lambda o: (
            o["source_file"].casefold(),
            o["source_line"],
            o["evidence_id"],
        ),
    )

    for obs in ordered:
        unique_id = hmac_fp(key, obs["raw_line"].strip())[:32]
        group = groups.setdefault(
            unique_id,
            {
                "unique_line_id": unique_id,
                "raw_line": obs["raw_line"],
                "evidence_ids": [],
                "occurrences": [],
                "match_reasons": set(),
            },
        )

        group["evidence_ids"].append(obs["evidence_id"])
        group["occurrences"].append({
            "evidence_id": obs["evidence_id"],
            "source_file": obs["source_file"],
            "source_line": obs["source_line"],
            "source_type": obs["source_type"],
            "file_created_at": obs["file_created_at"],
            "source_timestamp_basis": obs["source_timestamp_basis"],
            "match_reasons": sorted(obs["match_reasons"]),
        })
        group["match_reasons"].update(obs["match_reasons"])

    result = []

    for group in groups.values():
        group["evidence_ids"] = sorted(set(group["evidence_ids"]))
        group["occurrences"].sort(
            key=lambda o: (
                o["source_file"].casefold(),
                o["source_line"],
            )
        )
        group["match_reasons"] = sorted(group["match_reasons"])
        group["occurrence_count"] = len(group["occurrences"])
        group["source_files"] = sorted({
            o["source_file"] for o in group["occurrences"]
        })
        result.append(group)

    return sorted(
        result,
        key=lambda g: (
            g["occurrences"][0]["source_file"].casefold(),
            g["occurrences"][0]["source_line"],
        ),
    )


def aggregate_normalized_records(
    line_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Consolidate semantically equivalent observations.

    Identity + service + port + path + credential fingerprint + match type.
    Keep every source occurrence and evidence ID.
    """
    groups: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    for record in line_records:
        semantic_key = (
            record["identity"],
            record["service_key"],
            record.get("service_port"),
            record.get("service_path", ""),
            record["password_fingerprint"],
            record.get("identity_match_type", ""),
            record.get("credential_material_type", "unknown"),
        )

        current = groups.get(semantic_key)

        if current is None:
            current = dict(record)
            current.update({
                "evidence_ids": [],
                "unique_line_ids": [],
                "source_occurrences": [],
                "search_match_reasons": [],
            })
            groups[semantic_key] = current

        current["evidence_ids"].extend(record.get("evidence_ids", []))
        current["unique_line_ids"].append(record["unique_line_id"])
        current["source_occurrences"].extend(
            record.get("source_occurrences", [])
        )
        current["search_match_reasons"].extend(
            record.get("search_match_reasons", [])
        )

    result = []

    for semantic_key, record in groups.items():
        record["evidence_ids"] = sorted(set(record["evidence_ids"]))
        record["unique_line_ids"] = sorted(set(record["unique_line_ids"]))

        occurrence_map = {
            occurrence["evidence_id"]: occurrence
            for occurrence in record["source_occurrences"]
        }

        record["source_occurrences"] = sorted(
            occurrence_map.values(),
            key=lambda o: (
                o["source_file"].casefold(),
                o["source_line"],
            ),
        )
        record["source_files"] = sorted({
            occurrence["source_file"]
            for occurrence in record["source_occurrences"]
        })
        record["source_line_refs"] = [
            {
                "source_file": occurrence["source_file"],
                "source_line": occurrence["source_line"],
                "evidence_id": occurrence["evidence_id"],
            }
            for occurrence in record["source_occurrences"]
        ]
        record["occurrence_count"] = len(record["source_occurrences"])
        record["unique_line_count"] = len(record["unique_line_ids"])
        record["search_match_reasons"] = sorted(set(
            record["search_match_reasons"]
        ))
        record["evidence_id"] = (
            record["evidence_ids"][0]
            if record["evidence_ids"] else ""
        )
        record["record_id"] = stable_id(
            "\x1f".join(map(str, semantic_key))
        )
        result.append(record)

    return sorted(
        result,
        key=lambda r: (
            r["identity"],
            r["service_key"],
            r["record_id"],
        ),
    )


def build_triage_decisions(
    unique_groups: List[Dict[str, Any]],
    line_records: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    records_by_uid = {
        record["unique_line_id"]: record
        for record in line_records
    }
    findings_by_evidence: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for finding in findings:
        for evidence_id in finding["evidence_ids"]:
            findings_by_evidence[evidence_id].append(finding)

    decisions_unique = []
    decisions_all = []

    for group in unique_groups:
        record = records_by_uid.get(group["unique_line_id"])
        related = {}

        for evidence_id in group["evidence_ids"]:
            for finding in findings_by_evidence.get(evidence_id, []):
                related[finding["finding_id"]] = finding

        related_findings = sorted(
            related.values(),
            key=lambda f: (f["rule_id"], f["finding_id"]),
        )
        actionable = [
            finding
            for finding in related_findings
            if finding["rule_id"] != "BASE-000"
        ]

        if actionable:
            related_findings = actionable

        if record is None:
            decision = "unparsed"
            explanation = (
                "La línea coincidió con la búsqueda, pero no se "
                "reconoció un formato válido."
            )
        elif actionable:
            decision = "finding"
            explanation = (
                "Una o más reglas deterministas generaron hallazgos "
                "asociados a esta evidencia."
            )
        else:
            decision = "no_actionable_pattern"
            explanation = (
                "La observación fue normalizada, pero no activó ninguna "
                "regla accionable. BASE-000 es informativa."
            )

        base = {
            "unique_line_id": group["unique_line_id"],
            "evidence_ids": group["evidence_ids"],
            "occurrence_count": group["occurrence_count"],
            "decision": decision,
            "decision_explanation": explanation,
            "identity": record["identity"] if record else "",
            "identity_type": record["identity_type"] if record else "unparsed",
            "service": record["service_key"] if record else "",
            "service_scope": record["service_scope"] if record else "",
            "matched_rule_ids": sorted({
                finding["rule_id"] for finding in related_findings
            }),
            "finding_ids": [
                finding["finding_id"] for finding in related_findings
            ],
            "source_files": group["source_files"],
        }

        decisions_unique.append(base)

        for occurrence in group["occurrences"]:
            decisions_all.append({
                **base,
                "decision_id": stable_id(
                    occurrence["evidence_id"] + "\x1f" + decision
                ),
                "evidence_id": occurrence["evidence_id"],
                "source_file": occurrence["source_file"],
                "source_line": occurrence["source_line"],
            })

    decisions_all.sort(
        key=lambda d: (
            d["source_file"].casefold(),
            d["source_line"],
        )
    )
    decisions_unique.sort(key=lambda d: d["unique_line_id"])

    return decisions_all, decisions_unique


def build_relationships(
    records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rels: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for record in records:
        evidence_ids = set(record_evidence_ids(record))
        key = (
            record["identity"],
            "observed_on_service",
            record["service_key"],
        )

        item = rels.setdefault(
            key,
            {
                "relationship_id": stable_id("|".join(key)),
                "source_identity": record["identity"],
                "relationship_type": "observed_on_service",
                "destination_service": record["service_key"],
                "service_scope": record["service_scope"],
                "evidence_ids": set(),
                "evidence_status": "observed",
                "confidence": "high",
            },
        )

        item["evidence_ids"].update(evidence_ids)

        for linked in record.get("linked_identity_candidates", []):
            alias_key = (
                linked,
                "possible_localpart_alias_of",
                record["identity"] + "|" + record["service_key"],
            )

            edge = rels.setdefault(
                alias_key,
                {
                    "relationship_id": stable_id("|".join(alias_key)),
                    "source_identity": linked,
                    "relationship_type": "possible_localpart_alias_of",
                    "destination_identity": record["identity"],
                    "destination_service": record["service_key"],
                    "service_scope": record["service_scope"],
                    "evidence_ids": set(),
                    "evidence_status": "candidate",
                    "confidence": "low",
                    "match_method": "exact_local_part_candidate",
                },
            )
            edge["evidence_ids"].update(evidence_ids)

    result = []

    for relation in rels.values():
        relation["evidence_ids"] = sorted(relation["evidence_ids"])
        result.append(relation)

    return sorted(
        result,
        key=lambda r: (
            r["source_identity"],
            r["relationship_type"],
            r.get("destination_service", ""),
        ),
    )


# ============================================================
# ATTACK-PATH WORDING AND HYPOTHESES
# ============================================================

def render_path_wording(
    path_type: str,
    identity: str,
    external_service: str = "",
    endpoint: str = "",
) -> Dict[str, str]:
    templates = {
        "observed_corporate_identity_to_external_service": {
            "title": (
                "Potencial exposición de credencial corporativa "
                "en una aplicación de terceros"
            ),
            "narrative": (
                "Se observó un registro que asocia la identidad corporativa "
                "{identity} con el servicio externo {external_service}. "
                "Si el par continúa vigente, podría permitir autenticación "
                "en ese servicio; si se demuestra reutilización, podría "
                "ampliar el riesgo a otras aplicaciones."
            ),
            "limitations": (
                "No se ha confirmado vigencia, autenticación exitosa, "
                "reutilización ni acceso corporativo."
            ),
            "recommended_validation": (
                "Identificar al responsable del servicio y corroborar el "
                "contexto de la cuenta. Cualquier validación de autenticación "
                "debe estar expresamente dentro del alcance autorizado."
            ),
        },
        "candidate_localpart_alias_to_external_service": {
            "title": (
                "Posible vinculación de una cuenta externa "
                "con una identidad corporativa"
            ),
            "narrative": (
                "El usuario observado en {external_service} coincide "
                "exactamente con la parte local de la identidad corporativa "
                "{identity}. La coincidencia permite priorizar una revisión, "
                "pero no establece por sí misma que ambas cuentas pertenezcan "
                "a la misma persona o compartan credenciales."
            ),
            "limitations": (
                "La coincidencia de alias no prueba misma persona, "
                "contraseña compartida ni acceso al entorno corporativo."
            ),
            "recommended_validation": (
                "Corroborar la relación con un inventario autorizado o el "
                "responsable de la aplicación antes de considerar esta "
                "relación como una ruta de acceso."
            ),
        },
        "potential_corporate_credential_on_adfs": {
            "title": (
                "Potencial credencial corporativa expuesta en un endpoint "
                "de autenticación federada"
            ),
            "narrative": (
                "Se observó un registro de credenciales asociado a {identity} "
                "y al endpoint {endpoint}, relacionado con AD FS. Si la "
                "asociación es correcta y el par continúa vigente, podría "
                "representar una oportunidad de autenticación inicial dentro "
                "del alcance aprobado del Red Team."
            ),
            "limitations": (
                "La URL no confirma credenciales válidas, autenticación "
                "exitosa, acceso al dominio ni movimiento lateral."
            ),
            "recommended_validation": (
                "Corroborar la relación entre la identidad y el endpoint con "
                "el responsable de identidad. Realizar cualquier validación "
                "solo con autorización explícita."
            ),
        },
    }

    spec = templates.get(path_type)

    if not spec:
        return {
            "title": "Hipótesis de acceso no tipificada",
            "narrative": (
                "No existe una plantilla de presentación configurada para "
                "esta relación; requiere revisión manual."
            ),
            "limitations": (
                "No debe inferirse acceso operativo de una relación "
                "no tipificada."
            ),
            "recommended_validation": (
                "Revisar la evidencia y definir una regla explícita antes "
                "de publicar una conclusión."
            ),
        }

    return {
        "title": spec["title"],
        "narrative": spec["narrative"].format(
            identity=identity or "identidad no determinada",
            external_service=external_service or "servicio no determinado",
            endpoint=endpoint or "endpoint no determinado",
        ),
        "limitations": spec["limitations"],
        "recommended_validation": spec["recommended_validation"],
    }


def build_attack_paths(
    corporate_identities: Set[str],
    by_identity: Dict[str, List[Dict[str, Any]]],
    alias_records: Dict[str, List[Dict[str, Any]]],
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Generate scoped, aggregated path hypotheses."""
    paths: List[Dict[str, Any]] = []

    for identity in sorted(corporate_identities):
        own = [
            record
            for record in by_identity.get(identity, [])
            if record.get("is_corporate_identity")
        ]

        direct = [
            record
            for record in own
            if (
                record.get("service_scope") == "third_party"
                and record.get("service_domain")
                and is_plaintext_candidate_record(record)
            )
        ]

        aliases = [
            record
            for record in alias_records.get(identity, [])
            if (
                record.get("service_scope") == "third_party"
                and record.get("service_domain")
                and identity in record.get("linked_identity_candidates", [])
                and record.get("identity", "").casefold()
                == identity.split("@", 1)[0].casefold()
                and is_plaintext_candidate_record(record)
            )
        ]

        adfs_rows = []

        for record in own:
            if record.get("service_scope") != "corporate":
                continue

            if not is_plaintext_candidate_record(record):
                continue

            host = str(record.get("service_domain", "")).lower()
            path = str(record.get("service_path", "")).lower()

            if (
                re.search(r"(?:^|[.-])adfs(?:[.-]|$)", host)
                or re.search(r"/adfs(?:/|$)", path)
            ):
                adfs_rows.append(record)

        # One aggregate per corporate identity and path type, not one per
        # occurrence or password. Multiple service hosts are grouped together.
        if direct:
            services = sorted({
                record["service_key"] for record in direct
            })
            evidence = sorted({
                evidence_id
                for record in direct
                for evidence_id in record_evidence_ids(record)
            })
            path_type = "observed_corporate_identity_to_external_service"
            wording = render_path_wording(
                path_type,
                identity,
                ", ".join(services),
            )

            paths.append({
                "path_id": stable_id(
                    identity + "|" + path_type + "|" + "|".join(services)
                ),
                "identity": identity,
                "path_type": path_type,
                "steps": [
                    {
                        "step": 1,
                        "type": "observed_identity",
                        "value": identity,
                        "evidence_status": "observed",
                    },
                    {
                        "step": 2,
                        "type": "external_service",
                        "value": services,
                        "evidence_status": "observed",
                    },
                ],
                "services": services,
                "evidence_ids": evidence,
                "evidence_ref_count": len(evidence),
                "evidence_status": "hypothesis_not_validated",
                "not_validated": True,
                "confidence": "medium",
                **wording,
            })

        if aliases:
            services = sorted({
                record["service_key"] for record in aliases
            })
            usernames = sorted({
                record["identity"] for record in aliases
            })
            evidence = sorted({
                evidence_id
                for record in aliases
                for evidence_id in record_evidence_ids(record)
            })
            path_type = "candidate_localpart_alias_to_external_service"
            wording = render_path_wording(
                path_type,
                identity,
                ", ".join(services),
            )

            paths.append({
                "path_id": stable_id(
                    identity + "|candidate_alias|" + "|".join(services)
                ),
                "identity": identity,
                "path_type": path_type,
                "steps": [
                    {
                        "step": 1,
                        "type": "observed_corporate_identity",
                        "value": identity,
                        "evidence_status": "observed",
                    },
                    {
                        "step": 2,
                        "type": "candidate_username_alias",
                        "value": usernames,
                        "evidence_status": "candidate",
                    },
                    {
                        "step": 3,
                        "type": "external_service",
                        "value": services,
                        "evidence_status": "observed",
                    },
                ],
                "services": services,
                "candidate_usernames": usernames,
                "evidence_ids": evidence,
                "evidence_ref_count": len(evidence),
                "evidence_status": "candidate_not_validated",
                "not_validated": True,
                "confidence": "low",
                **wording,
            })

        if adfs_rows:
            endpoints = sorted({
                record.get("service_observed")
                or record.get("service_domain", "")
                + record.get("service_path", "")
                for record in adfs_rows
            })
            evidence = sorted({
                evidence_id
                for record in adfs_rows
                for evidence_id in record_evidence_ids(record)
            })
            path_type = "potential_corporate_credential_on_adfs"
            wording = render_path_wording(
                path_type,
                identity,
                endpoint=", ".join(endpoints),
            )

            paths.append({
                "path_id": stable_id(
                    identity + "|adfs|" + "|".join(endpoints)
                ),
                "identity": identity,
                "path_type": path_type,
                "steps": [
                    {
                        "step": 1,
                        "type": "observed_corporate_identity",
                        "value": identity,
                        "evidence_status": "observed",
                    },
                    {
                        "step": 2,
                        "type": "corporate_authentication_endpoint",
                        "value": endpoints,
                        "evidence_status": "observed",
                    },
                ],
                "services": endpoints,
                "evidence_ids": evidence,
                "evidence_ref_count": len(evidence),
                "evidence_status": "hypothesis_not_validated",
                "not_validated": True,
                "confidence": "medium",
                **wording,
            })

    return sorted(
        paths,
        key=lambda path: (
            path["identity"],
            path["path_type"],
            path.get("services", []),
        ),
    )


# ============================================================
# HTML DASHBOARD — PRESERVE ORIGINAL DARK THEME
# ============================================================

def write_dashboard(
    path: Path,
    summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    attack_paths: List[Dict[str, Any]],
) -> None:
    """Delegate report rendering to the bilingual dashboard module."""
    dashboard.write_dashboard(
        path=path,
        summary=summary,
        findings=findings,
        attack_paths=attack_paths,
        language=summary.get(
            "report_language",
            REPORT_LANGUAGE,
        ),
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline(
    input_dir: Path,
    target: str,
    output_dir: Path,
    source_type: str,
    search_engine: str,
    tgrep_path: Optional[str],
    index_dir: Optional[Path],
    verify_index: bool,
    allow_demo: bool = False,
) -> int:
    started = time.perf_counter()
    timings: Dict[str, float] = {}
    target = norm_target(target)

    if not target:
        raise ValueError("Target de dominio inválido.")

    input_dir = input_dir.resolve()
    output_dir = output_dir.resolve()

    if not input_dir.is_dir():
        raise ValueError(
            f"El directorio de entrada no existe: {input_dir}"
        )

    if path_is_within(output_dir, input_dir):
        raise ValueError(
            "El directorio de salida no puede estar dentro del corpus."
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    for sub in (
        "search", "normalized", "identities",
        "findings", "triage", "attack_paths",
    ):
        (output_dir / sub).mkdir(parents=True, exist_ok=True)

    key_path = output_dir / "password_hmac_key.bin"

    if key_path.exists():
        key = key_path.read_bytes()

        if len(key) < 32:
            raise ValueError(f"Clave HMAC inválida: {key_path}")
    else:
        key = secrets.token_bytes(32)
        key_path.write_bytes(key)

        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

    inventory_start = time.perf_counter()
    all_files = list_txt_files(input_dir, output_dir)

    if not all_files:
        raise ValueError(f"No se encontraron archivos TXT en {input_dir}")

    total_bytes = 0
    oversized = 0
    unreadable_files = []

    for path in all_files:
        try:
            size = path.stat().st_size
            total_bytes += size

            if size > INDEX_MAX_FILESIZE:
                oversized += 1

        except OSError as exc:
            unreadable_files.append(path)
            print(
                f"[!] No se pudo consultar tamaño de {path.name}: {exc}"
            )

    timings["inventory"] = round(
        time.perf_counter() - inventory_start, 4
    )

    print("\n" + "=" * 68)
    print(f" Leak2Path v{VERSION} — deterministic intelligence")
    print("=" * 68)
    print(f"[+] Target             : {target}")
    print(f"[+] Target root        : {root_domain(target)}")
    print(f"[+] Input              : {input_dir}")
    print(f"[+] TXT files          : {len(all_files)}")
    print(f"[+] Corpus size        : {total_bytes:,} bytes")
    print(f"[+] Files over 64 MiB  : {oversized}")
    print(f"[+] Index              : {index_dir}")
    print("[!] RAW evidence may retain plaintext passwords.")

    errors: List[Dict[str, Any]] = []

    for path in unreadable_files:
        errors.append({
            "source_file": str(path),
            "stage": "inventory",
            "error": "Unable to stat file.",
        })

    observations: Dict[str, Dict[str, Any]] = {}
    target_root = root_domain(target)
    target_cf = target.casefold()

    def rel_path(path: Path) -> str:
        try:
            return path.resolve().relative_to(input_dir).as_posix()
        except ValueError:
            return str(path.resolve())

    def add_observation(
        path: Path,
        line_no: int,
        line: str,
        reason: str,
    ) -> Dict[str, Any]:
        relative = rel_path(path)
        evidence_id = stable_id(
            relative + "\x1f" + str(line_no) + "\x1f" + line,
            24,
        )

        if evidence_id not in observations:
            created, basis = get_file_created_at(path)

            observations[evidence_id] = {
                "evidence_id": evidence_id,
                "source_file": relative,
                "source_line": line_no,
                "source_type": source_type,
                "file_created_at": created,
                "source_timestamp_basis": basis,
                "match_reasons": set(),
                "raw_line": line,
            }

        observations[evidence_id]["match_reasons"].add(reason)
        return observations[evidence_id]

    # --------------------------------------------------------
    # 1. Direct target search, then strict relevance filtering.
    # --------------------------------------------------------
    print("\n[1/6] Target search")
    t0 = time.perf_counter()
    binary = find_tgrep(tgrep_path)

    target_result = search_with_fallback(
        binary,
        input_dir,
        all_files,
        target,
        lambda line: target_cf in line.casefold(),
        index_dir,
        search_engine,
        fixed=True,
        verify_index=verify_index,
        stage="TARGET",
    )

    timings["target_search_total"] = round(
        time.perf_counter() - t0, 4
    )
    raw_target_match_count = len(target_result["matches"])
    scoped_target_matches = []
    target_root_for_filter = root_domain(target)

    for match in target_result["matches"]:
        parsed_target_line = parse_record(match["line"], target)

        if parsed_record_is_target_related(
            parsed_target_line,
            match["line"],
            target,
            target_root_for_filter,
        ):
            scoped_target_matches.append(match)

    target_result["raw_candidate_matches"] = raw_target_match_count
    target_result["scope_excluded_matches"] = (
        raw_target_match_count - len(scoped_target_matches)
    )
    target_result["matches"] = scoped_target_matches
    target_files = {match["path"] for match in scoped_target_matches}

    for match in scoped_target_matches:
        add_observation(
            match["path"],
            match["line_number"],
            match["line"],
            "target_match",
        )

    errors.extend(
        {**error, "stage": "target_search"}
        for error in target_result["errors"]
    )

    print(f"[+] Target engine      : {target_result['engine']}")
    print(f"[+] Target matches     : {len(scoped_target_matches)}")
    print(f"[+] Target files       : {len(target_files)}")

    if target_result["warning"]:
        print(f"[!] Target note        : {target_result['warning']}")

    # --------------------------------------------------------
    # Corporate identity anchors from in-scope records only.
    # --------------------------------------------------------
    corporate_identities: Set[str] = set()

    for obs in list(observations.values()):
        parsed = parse_record(obs["raw_line"], target)

        if not parsed:
            continue

        record = build_normalized_record(
            parsed, obs, target, target_root, key
        )

        if record["is_corporate_identity"] and record["identity_domain"]:
            corporate_identities.add(record["identity"])

    alias_map: Dict[str, Set[str]] = defaultdict(set)

    for identity in corporate_identities:
        local = identity.split("@", 1)[0]
        tokens = set(re.findall(r"[a-z0-9]+", local))
        normalized_local = local.casefold()

        if (
            len(local) >= 5
            and normalized_local not in LOCALPART_ALIAS_STOPWORDS
            and not tokens & LOCALPART_ALIAS_STOPWORDS
            and not tokens & (GENERIC_TOKENS | TEMP_TOKENS | SERVICE_TOKENS)
        ):
            alias_map[local].add(identity)

    # Alias must have exactly one corporate anchor. Do not merge identities.
    alias_map = {
        local: identities
        for local, identities in alias_map.items()
        if len(identities) == 1
    }

    print(f"[+] Corporate anchors : {len(corporate_identities)}")
    print(f"[+] Alias candidates   : {len(alias_map)}")

    # --------------------------------------------------------
    # 2. Expand only exact parsed corporate identities and aliases.
    # --------------------------------------------------------
    print("\n[2/6] Identity expansion")
    t0 = time.perf_counter()

    expansion_terms = sorted(
        set(corporate_identities) | set(alias_map),
        key=lambda value: (-len(value), value),
    )
    expansion_matches: Dict[
        Tuple[str, int, str], Dict[str, Any]
    ] = {}

    expansion_result_meta = {
        "engine": "not_executed",
        "indexed_seconds": 0.0,
        "text_scan_seconds": 0.0,
        "python_seconds": 0.0,
        "warning": "",
        "index_verified": False,
        "verification_performed": False,
        "stats": {},
        "errors": [],
    }

    if expansion_terms:
        if len(expansion_terms) > 8000:
            expansion_terms = sorted(
                corporate_identities,
                key=lambda value: (-len(value), value),
            )
            print(
                "[!] Más de 8,000 términos; "
                "se omite expansión por local-part."
            )

        expansion_regex = re.compile(
            r"(?i)(?<![a-z0-9._%+\-])(?:"
            + "|".join(re.escape(term) for term in expansion_terms)
            + r")(?![a-z0-9._%+\-])"
        )

        tgrep_pattern = (
            "(?:"
            + "|".join(re.escape(term) for term in expansion_terms)
            + ")"
        )

        expansion_mode = (
            search_engine
            if len(tgrep_pattern) <= MAX_REGEX_CHARS
            else "python"
        )

        if expansion_mode == "python":
            expansion_result = python_search(
                all_files,
                lambda line: bool(expansion_regex.search(line)),
                "EXPANSION",
            )
            expansion_result_meta.update({
                "engine": "python_expansion",
                "python_seconds": expansion_result["elapsed_seconds"],
                "errors": expansion_result["errors"],
            })

        else:
            expansion_result = search_with_fallback(
                binary,
                input_dir,
                all_files,
                tgrep_pattern,
                lambda line: bool(expansion_regex.search(line)),
                index_dir,
                expansion_mode,
                fixed=False,
                verify_index=verify_index,
                stage="EXPANSION",
            )
            expansion_result_meta.update({
                key: expansion_result.get(key)
                for key in expansion_result_meta
                if key in expansion_result
            })

        errors.extend(
            {**error, "stage": "identity_expansion"}
            for error in expansion_result.get("errors", [])
        )

        for match in expansion_result["matches"]:
            parsed = parse_record(match["line"], target)

            if not parsed:
                # Keep only unparsed lines with an exact corporate email
                # already established as an anchor. Generic substring hits
                # are not enough to add an observation.
                corporate_email_present = any(
                    email_match.group(1).strip().lower()
                    in corporate_identities
                    for email_match in EMAIL_RE.finditer(match["line"])
                )

                if corporate_email_present:
                    match_key = (
                        normalize_path_key(str(match["path"])),
                        int(match["line_number"]),
                        match["line"],
                    )
                    expansion_matches[match_key] = match
                    add_observation(
                        match["path"],
                        match["line_number"],
                        match["line"],
                        "identity_expansion_unparsed",
                    )
                continue

            username = parsed["username"].strip().lower()

            if username in corporate_identities:
                reason = "identity_expansion_exact"

            elif username in alias_map:
                service_host, _, _ = parse_service(
                    parsed.get("service", "")
                )

                if not service_host or not looks_like_hostname(service_host):
                    continue

                reason = "identity_expansion_localpart_candidate"

            else:
                # Do not admit a line just because an anchor string occurs
                # in its URL, password or another unrelated field.
                continue

            match_key = (
                normalize_path_key(str(match["path"])),
                int(match["line_number"]),
                match["line"],
            )
            expansion_matches[match_key] = match

            add_observation(
                match["path"],
                match["line_number"],
                match["line"],
                reason,
            )

    timings["identity_expansion_total"] = round(
        time.perf_counter() - t0, 4
    )
    expansion_files = {
        match["path"] for match in expansion_matches.values()
    }

    print(
        f"[+] Expansion engine  : {expansion_result_meta['engine']}"
    )
    print(f"[+] Expansion matches : {len(expansion_matches)}")
    print(f"[+] Expansion files   : {len(expansion_files)}")

    if expansion_result_meta.get("warning"):
        print(
            f"[!] Expansion note    : {expansion_result_meta['warning']}"
        )

    # --------------------------------------------------------
    # 3. RAW evidence and exact deduplication.
    # --------------------------------------------------------
    print("\n[3/6] RAW evidence and exact deduplication")
    t0 = time.perf_counter()

    unique_groups = group_unique_observations(observations, key)
    ordered_obs = sorted(
        observations.values(),
        key=lambda o: (
            o["source_file"].casefold(),
            o["source_line"],
            o["evidence_id"],
        ),
    )

    unique_id_by_evidence = {
        evidence_id: group["unique_line_id"]
        for group in unique_groups
        for evidence_id in group["evidence_ids"]
    }

    date_tag = dt.datetime.now().strftime("%Y%m%d")
    raw_path = output_dir / f"{target}_raw_results_{date_tag}.txt"
    raw_unique_path = (
        output_dir / f"{target}_raw_results_unique_{date_tag}.txt"
    )
    raw_index_path = output_dir / "raw_evidence_index.jsonl"

    with raw_path.open("w", encoding="utf-8", newline="\n") as f:
        for obs in ordered_obs:
            f.write(obs["raw_line"] + "\n")

    with raw_unique_path.open("w", encoding="utf-8", newline="\n") as f:
        for group in unique_groups:
            f.write(group["raw_line"] + "\n")

    evidence_index = []

    for out_line, obs in enumerate(ordered_obs, 1):
        evidence_index.append({
            "raw_output_line": out_line,
            "evidence_id": obs["evidence_id"],
            "unique_line_id": unique_id_by_evidence[obs["evidence_id"]],
            "source_file": obs["source_file"],
            "source_line": obs["source_line"],
            "match_reasons": sorted(obs["match_reasons"]),
            "source_type": obs["source_type"],
            "file_created_at": obs["file_created_at"],
            "source_timestamp_basis": obs["source_timestamp_basis"],
            "contains_plaintext_if_present": True,
        })

    jsonl_write(raw_index_path, evidence_index)

    jsonl_write(
        output_dir / "raw_unique_occurrences.jsonl",
        [
            {
                key: group[key]
                for key in (
                    "unique_line_id",
                    "evidence_ids",
                    "occurrence_count",
                    "source_files",
                    "occurrences",
                    "match_reasons",
                )
            }
            for group in unique_groups
        ],
    )

    timings["raw_dedup_and_write"] = round(
        time.perf_counter() - t0, 4
    )

    print(f"[+] RAW occurrences   : {len(observations)}")
    print(f"[+] Unique RAW lines   : {len(unique_groups)}")

    # --------------------------------------------------------
    # 4. Normalize and deduplicate semantic records.
    # --------------------------------------------------------
    print("\n[4/6] Normalization and semantic deduplication")
    t0 = time.perf_counter()
    line_records: List[Dict[str, Any]] = []
    unparsed_lines: List[str] = []

    for group in unique_groups:
        parsed = parse_record(group["raw_line"], target)

        if not parsed:
            unparsed_lines.append(group["unique_line_id"])
            continue

        first = group["occurrences"][0]
        evidence = {
            "evidence_id": group["evidence_ids"][0],
            "source_file": first["source_file"],
            "source_line": first["source_line"],
            "source_type": first["source_type"],
            "file_created_at": first["file_created_at"],
            "source_timestamp_basis": first["source_timestamp_basis"],
            "match_reasons": set(group["match_reasons"]),
        }

        username = parsed["username"].strip().lower()
        linked = sorted(alias_map.get(username, set()))

        record = build_normalized_record(
            parsed,
            evidence,
            target,
            target_root,
            key,
            linked,
        )

        if username in corporate_identities or record["is_corporate_identity"]:
            record["identity_match_type"] = "exact_observed_identity"
        elif linked:
            record["identity_match_type"] = "exact_local_part_candidate"
        else:
            record["identity_match_type"] = "username_only"

        record["unique_line_id"] = group["unique_line_id"]
        record["evidence_ids"] = group["evidence_ids"]
        record["source_occurrences"] = group["occurrences"]
        record["source_files"] = group["source_files"]
        record["occurrence_count"] = group["occurrence_count"]
        line_records.append(record)

    records = aggregate_normalized_records(line_records)

    credential_occurrences = Counter()

    for record in records:
        credential_key = (
            record["identity"],
            record["service_key"],
            record["password_fingerprint"],
        )
        credential_occurrences[credential_key] += record["occurrence_count"]

    for record in records:
        credential_key = (
            record["identity"],
            record["service_key"],
            record["password_fingerprint"],
        )
        record["same_credential_observation_count"] = (
            credential_occurrences[credential_key]
        )

    alias_records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for record in records:
        for linked in record.get("linked_identity_candidates", []):
            alias_records[linked].append(record)

    by_identity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for record in records:
        by_identity[record["identity"]].append(record)

    profiles = []

    for identity, rows in sorted(by_identity.items()):
        sample = rows[0]
        linked_to = sorted({
            candidate
            for record in rows
            for candidate in record.get("linked_identity_candidates", [])
        })

        profiles.append({
            "profile_id": stable_id(identity, 20),
            "identity": identity,
            "identity_type": sample["identity_type"],
            "is_corporate_identity": sample["is_corporate_identity"],
            "username_pattern": sample["username_pattern"],
            "unique_normalized_observations": len(rows),
            "raw_occurrence_count": sum(
                record["occurrence_count"] for record in rows
            ),
            "services": sorted({
                record["service_key"] for record in rows
            }),
            "service_count": len({
                record["service_key"] for record in rows
            }),
            "source_files": sorted({
                source
                for record in rows
                for source in record["source_files"]
            }),
            "evidence_ids": sorted({
                evidence_id
                for record in rows
                for evidence_id in record_evidence_ids(record)
            }),
            "candidate_linked_corporate_identities": linked_to,
            "notes": (
                "A profile represents an observed account identifier, "
                "not necessarily a unique human being."
            ),
        })

    relationships = build_relationships(records)

    timings["normalization_and_profiles"] = round(
        time.perf_counter() - t0, 4
    )

    print(f"[+] Parsed unique lines: {len(line_records)}")
    print(f"[+] Normalized records : {len(records)}")
    print(f"[+] Identity profiles  : {len(profiles)}")
    print(f"[+] Unparsed lines     : {len(unparsed_lines)}")

    # --------------------------------------------------------
    # 5. Deterministic findings, triage and attack paths.
    # --------------------------------------------------------
    print("\n[5/6] Deterministic rules and triage")
    t0 = time.perf_counter()

    findings = derive_findings(
        records,
        corporate_identities,
        alias_records,
    )

    triage_all, triage_unique = build_triage_decisions(
        unique_groups,
        line_records,
        findings,
    )

    attack_paths = build_attack_paths(
        corporate_identities,
        by_identity,
        alias_records,
        findings,
    )

    timings["triage_and_attack_paths"] = round(
        time.perf_counter() - t0, 4
    )

    print(f"[+] Findings           : {len(findings)}")
    print(f"[+] Triage occurrences : {len(triage_all)}")
    print(f"[+] Triage unique lines: {len(triage_unique)}")
    print(f"[+] Attack paths       : {len(attack_paths)}")

    # --------------------------------------------------------
    # 6. Write outputs.
    # --------------------------------------------------------
    print("\n[6/6] Writing outputs")
    t0 = time.perf_counter()

    jsonl_write(
        output_dir / "normalized" / "normalized_records.jsonl",
        records,
    )
    jsonl_write(
        output_dir / "normalized" / "normalized_records_by_unique_line.jsonl",
        line_records,
    )
    jsonl_write(
        output_dir / "identities" / "identity_profiles.jsonl",
        profiles,
    )
    jsonl_write(
        output_dir / "identities" / "identity_relationships.jsonl",
        relationships,
    )
    jsonl_write(
        output_dir / "findings" / "case_findings.jsonl",
        findings,
    )
    jsonl_write(
        output_dir / "triage" / "deterministic_triage.jsonl",
        triage_all,
    )
    jsonl_write(
        output_dir / "triage" / "deterministic_triage_unique.jsonl",
        triage_unique,
    )
    jsonl_write(
        output_dir / "attack_paths" / "attack_path_hypotheses.jsonl",
        attack_paths,
    )

    def write_path_list(name: str, paths: Set[Path]) -> None:
        rows = sorted(
            {
                p.resolve().relative_to(input_dir).as_posix()
                for p in paths
            },
            key=str.casefold,
        )
        (output_dir / "search" / name).write_text(
            "".join(x + "\n" for x in rows),
            encoding="utf-8",
        )

    write_path_list("target_candidate_files.txt", target_files)
    write_path_list("expansion_candidate_files.txt", expansion_files)
    write_path_list("candidate_files.txt", target_files | expansion_files)

    jsonl_write(
        output_dir / "search" / "scan_errors.jsonl",
        errors,
    )

    target_search_manifest = {
        key: target_result.get(key)
        for key in (
            "engine",
            "indexed_seconds",
            "text_scan_seconds",
            "python_seconds",
            "warning",
            "index_verified",
            "verification_performed",
            "stats",
            "command",
        )
    }

    expansion_search_manifest = {
        key: expansion_result_meta.get(key)
        for key in (
            "engine",
            "indexed_seconds",
            "text_scan_seconds",
            "python_seconds",
            "warning",
            "index_verified",
            "verification_performed",
            "stats",
        )
    }

    engines = sorted({
        engine
        for engine in (
            target_result["engine"],
            expansion_result_meta["engine"],
        )
        if engine != "not_executed"
    })
    combined_engine = "+".join(engines) if engines else "not_executed"

    search_manifest = {
        "version": VERSION,
        "target": target,
        "input_directory": str(input_dir),
        "index_directory": str(index_dir) if index_dir else "",
        "search_engine": combined_engine,
        "target_search": target_search_manifest,
        "identity_expansion": expansion_search_manifest,
        "txt_files_discovered": len(all_files),
        "corpus_bytes": total_bytes,
        "files_over_64_mib": oversized,
        "target_matches": len(target_result["matches"]),
        "target_raw_candidate_matches": target_result.get(
            "raw_candidate_matches",
            len(target_result["matches"]),
        ),
        "target_scope_excluded_matches": target_result.get(
            "scope_excluded_matches",
            0,
        ),
        "expansion_matches": len(expansion_matches),
        "target_candidate_files": len(target_files),
        "expansion_candidate_files": len(expansion_files),
        "corporate_identity_anchors": len(corporate_identities),
        "localpart_alias_candidates": len(alias_map),
        "scan_errors": len(errors),
        "verify_index_requested": verify_index,
        "coverage_note": (
            "Indexed search eligibility follows tgrep --max-filesize 64M. "
            "Oversized TXT files are searched separately with Python. "
            "Index completeness is not established unless verify_index is true."
        ),
    }

    json_write(
        output_dir / "search" / "search_manifest.json",
        search_manifest,
    )

    rule_catalogue = {
        "PWD-001": {
            "family": "R01_password_patterns",
            "name": "Exact password reuse",
            "condition": (
                "Same corporate identity + same password HMAC fingerprint "
                "+ at least two distinct explicitly identified service hosts."
            ),
            "limitation": (
                "Does not prove the password is valid or currently active."
            ),
        },
        "PWD-002": {
            "family": "R01_password_patterns",
            "name": "Numeric-run password variation",
            "condition": (
                "Same corporate identity + password shape HMAC after numeric "
                "runs become # + at least two services + two exact fingerprints."
            ),
            "limitation": "Heuristic; similar shapes can be coincidental.",
        },
        "ID-002": {
            "family": "R02_account_naming",
            "name": "Generic/temporary/service/privileged-like naming",
            "condition": (
                "Corporate identity local-part has one or more exact tokens "
                "in the configured token dictionaries."
            ),
            "limitation": (
                "Naming alone does not establish account function, privilege or ownership."
            ),
        },
        "LIFE-001": {
            "family": "R03_historical_identity",
            "name": "Historical marker with external-service trace",
            "condition": (
                "Corporate identity local-part has a configured former marker "
                "and direct or alias-linked third-party evidence exists."
            ),
            "limitation": (
                "Does not establish an employment termination or persistent access."
            ),
        },
        "EXT-001": {
            "family": "R04_third_party_dependency",
            "name": "Direct corporate identity on external service",
            "condition": (
                "Exact corporate email identity appears on a syntactically "
                "valid external hostname."
            ),
            "limitation": (
                "Does not prove approved business dependency or active account."
            ),
        },
        "EXT-002": {
            "family": "R04_third_party_dependency",
            "name": "Candidate external account by local-part",
            "condition": (
                "Non-email username exactly matches a unique corporate email "
                "local-part and service host is external."
            ),
            "limitation": (
                "Candidate link only; local-part collisions are possible."
            ),
        },
        "CORR-001": {
            "family": "R05_identity_correlation",
            "name": "Recurring exact corporate identifier",
            "condition": (
                "At least two distinct raw unique lines and either multiple "
                "service hosts or multiple source files for a corporate identifier."
            ),
            "limitation": (
                "Recurrence does not prove a unique human or current account."
            ),
        },
        "CORR-002": {
            "family": "R05_identity_correlation",
            "name": "Candidate identity relation",
            "condition": (
                "Observed non-email username exactly matches the local-part "
                "of a unique corporate email anchor."
            ),
            "limitation": "Does not merge identities or prove ownership.",
        },
        "CRED-001": {
            "family": "R06_unscoped_credential_material",
            "name": "Corporate credential pair with unknown source service",
            "condition": (
                "Corporate email identity + candidate plaintext material "
                "+ no service explicitly present in the source record."
            ),
            "limitation": (
                "Does not establish the application, current validity or successful authentication."
            ),
        },
        "HASH-001": {
            "family": "R06_unscoped_credential_material",
            "name": "Possible password hash with unknown source service",
            "condition": (
                "Corporate identity + value matching a specific hash-format "
                "heuristic + unknown source service."
            ),
            "limitation": (
                "Does not establish algorithm, recoverability or current password validity."
            ),
        },
        "AUTH-001": {
            "family": "R07_corporate_authentication_endpoint",
            "name": "Corporate credential record associated with AD FS",
            "condition": (
                "Corporate identity + candidate plaintext material + explicit "
                "in-scope host/path matching an AD FS indicator."
            ),
            "limitation": (
                "Does not prove successful authentication, domain access or lateral movement."
            ),
        },
        "BASE-000": {
            "family": "informational_baseline",
            "name": "No actionable configured rule",
            "condition": "Corporate identity has no other rule finding.",
            "limitation": "Informational only; not an actionable finding.",
        },
    }

    json_write(
        output_dir / "findings" / "rule_catalogue.json",
        rule_catalogue,
    )

    finding_counts_pattern = dict(Counter(
        finding["triage_pattern"] for finding in findings
    ))
    finding_counts_rule = dict(Counter(
        finding["rule_id"] for finding in findings
    ))
    decision_counts = dict(Counter(
        decision["decision"] for decision in triage_all
    ))
    unique_decision_counts = dict(Counter(
        decision["decision"] for decision in triage_unique
    ))

    end_time = dt.datetime.now().isoformat(timespec="seconds")
    timings["output_writing"] = round(time.perf_counter() - t0, 4)
    timings["total_execution"] = round(time.perf_counter() - started, 4)

    summary = {
        "version": VERSION,
		"report_language": REPORT_LANGUAGE,
        "generated_at": end_time,
        "target": target,
        "source_type": source_type,
        "files_discovered": len(all_files),
        "raw_evidence_occurrences": len(observations),
        "raw_evidence_observations": len(observations),
        "raw_unique_lines": len(unique_groups),
        "normalized_unique_lines": len(line_records),
        "parsed_normalized_observations": len(line_records),
        "unique_normalized_records": len(records),
        "unparsed_unique_lines": len(unparsed_lines),
        "corporate_identity_anchors": len(corporate_identities),
        "unique_observed_account_identifiers": len(by_identity),
        "relationship_edges": len(relationships),
        "case_findings": len(findings),
        "finding_counts_by_pattern": finding_counts_pattern,
        "finding_counts_by_rule": finding_counts_rule,
        "triage_decisions_all_occurrences": len(triage_all),
        "triage_decisions_unique_lines": len(triage_unique),
        "triage_decision_counts": decision_counts,
        "triage_unique_decision_counts": unique_decision_counts,
        "attack_path_hypotheses": len(attack_paths),
        "scan_errors": len(errors),
        "processing_times_seconds": timings,
        "processing_time_seconds": timings["total_execution"],
        "search_engine": combined_engine,
        "index_verification_requested": verify_index,
        "passwords_in_structured_outputs": False,
        "plaintext_passwords_retained_in_raw_files": True,
        "raw_file": raw_path.name,
        "raw_unique_file": raw_unique_path.name,
        "raw_file_warning": (
            "RAW files contain original lines and may contain plaintext "
            "credentials; encrypt and restrict access."
        ),
        "source_timestamp_warning": (
            "Filesystem creation time is not proof of the actual credential exposure date."
        ),
        "identity_warning": (
            "An observed email is an account identifier, not proof of a unique person. "
            "Local-part matches remain candidates."
        ),
        "attack_path_warning": (
            "All attack paths are hypotheses and are not validated operational access."
        ),
        "laya_used": False,
        "classification_method": "deterministic Python rules",
    }

    json_write(output_dir / "summary.json", summary)
    write_dashboard(
        output_dir / "report.html",
        summary,
        findings,
        attack_paths,
    )

    manifest = {
        "project": "Leak2Path",
        "version": VERSION,
        "target": target,
        "generated_at": end_time,
        "outputs": {
            "raw_all": raw_path.name,
            "raw_unique": raw_unique_path.name,
            "raw_evidence_index": raw_index_path.name,
            "raw_unique_occurrences": "raw_unique_occurrences.jsonl",
            "normalized_records": "normalized/normalized_records.jsonl",
            "normalized_records_by_unique_line": (
                "normalized/normalized_records_by_unique_line.jsonl"
            ),
            "identity_profiles": "identities/identity_profiles.jsonl",
            "identity_relationships": "identities/identity_relationships.jsonl",
            "case_findings": "findings/case_findings.jsonl",
            "rule_catalogue": "findings/rule_catalogue.json",
            "triage_all": "triage/deterministic_triage.jsonl",
            "triage_unique": "triage/deterministic_triage_unique.jsonl",
            "attack_paths": "attack_paths/attack_path_hypotheses.jsonl",
            "search_manifest": "search/search_manifest.json",
            "summary": "summary.json",
            "dashboard": "report.html",
            "hmac_key_local_only": "password_hmac_key.bin",
        },
        "security": {
            "plaintext_retained_only_in_raw_files": True,
            "structured_outputs_exclude_password_plaintext": True,
            "hmac_key_sensitive": True,
            "hmac_key_must_not_be_shared": True,
        },
    }
    json_write(output_dir / "manifest.json", manifest)

    print("\n" + "=" * 68)
    print(f"[+] Leak2Path v{VERSION} completed")
    print("=" * 68)
    print(f"[+] Search engine             : {combined_engine}")
    print(f"[+] Files discovered          : {len(all_files)}")
    print(f"[+] RAW occurrences           : {len(observations)}")
    print(f"[+] Unique RAW lines          : {len(unique_groups)}")
    print(f"[+] Parsed unique lines       : {len(line_records)}")
    print(f"[+] Unique normalized records : {len(records)}")
    print(f"[+] Corporate identities      : {len(corporate_identities)}")
    print(f"[+] Findings                  : {len(findings)}")
    print(f"[+] Triage all occurrences    : {len(triage_all)}")
    print(f"[+] Triage unique lines       : {len(triage_unique)}")
    print(f"[+] Attack-path hypotheses    : {len(attack_paths)}")
    print(f"[+] File errors               : {len(errors)}")
    print(
        f"[+] Target search             : "
        f"{timings['target_search_total']:.2f}s"
    )
    print(
        f"[+] Identity expansion        : "
        f"{timings['identity_expansion_total']:.2f}s"
    )
    print(
        f"[+] Normalization/profiles    : "
        f"{timings['normalization_and_profiles']:.2f}s"
    )
    print(
        f"[+] Triage/attack paths       : "
        f"{timings['triage_and_attack_paths']:.2f}s"
    )
    print(
        f"[+] Total                     : "
        f"{timings['total_execution']:.2f}s"
    )
    print(f"[+] Output                    : {output_dir}")
    print(f"[+] RAW all                   : {raw_path}")
    print(f"[+] RAW unique                : {raw_unique_path}")
    print(f"[+] Dashboard                 : {output_dir / 'report.html'}")
    print(
        "[!] Results do not prove password validity, account activity "
        "or operational attack paths."
    )
    print("=" * 68)

    return 2 if errors else 0


# ============================================================
# LEAK2PATH 5.4.0 - INTEGRATION LAYER
# ============================================================

import datetime as _dt
import os as _os
import tempfile as _tempfile

_FORCE_REBUILD = False
_SEARCH_CONTEXT = None

_BASE_SEARCH = search_with_fallback
_BASE_DERIVE_FINDINGS = derive_findings
_BASE_BUILD_TRIAGE = build_triage_decisions
_BASE_BUILD_ATTACK_PATHS = build_attack_paths
_BASE_RUN_PIPELINE = run_pipeline


def _integration_key(path, input_dir):
    return (
        path.resolve()
        .relative_to(input_dir.resolve())
        .as_posix()
        .casefold()
    )


def _integration_snapshot(input_dir, output_dir):
    files = list_txt_files(input_dir, output_dir)
    snapshot = {}
    errors = []

    for path in files:
        try:
            stat = path.stat()
            snapshot[_integration_key(path, input_dir)] = {
                "size_bytes": int(stat.st_size),
                "mtime_ns": int(stat.st_mtime_ns),
                "ctime_ns": int(stat.st_ctime_ns),
            }
        except OSError as exc:
            errors.append({
                "path": str(path),
                "error": str(exc),
            })

    return files, snapshot, errors


def _integration_load_state(path):
    if not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8") as source:
            state = json.load(source)

        if isinstance(state, dict) and isinstance(
            state.get("files"), dict
        ):
            return state
    except (OSError, json.JSONDecodeError):
        pass

    return None


def _integration_atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = _tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:
        with _os.fdopen(
            fd, "w", encoding="utf-8", newline="\n"
        ) as target:
            json.dump(
                data,
                target,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            target.write("\n")

        _os.replace(temporary_name, path)

    except Exception:
        try:
            _os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _integration_search(
    binary,
    input_dir,
    all_files,
    pattern,
    matcher,
    index_dir,
    search_engine,
    fixed,
    verify_index,
    stage,
):
    context = _SEARCH_CONTEXT

    # Explicit native Text Scan: no index and no Python pass over
    # oversized files. tgrep scans the current filesystem directly.
    if search_engine == "tgrep-text":
        if not binary:
            result = _BASE_SEARCH(
                binary, input_dir, all_files, pattern, matcher,
                index_dir, "python", fixed, verify_index, stage,
            )
            result["warning"] = (
                "tgrep no disponible; se recurrió a Python."
            )
            return result

        try:
            native = run_tgrep_json(
                binary,
                input_dir,
                all_files,
                pattern,
                None,
                "text_scan",
                fixed,
            )

            if native.get("unmapped_paths"):
                raise RuntimeError(
                    "tgrep devolvió rutas no mapeadas."
                )

            if native.get("errors"):
                raise RuntimeError(
                    "tgrep devolvió errores durante el Text Scan."
                )

            return {
                "matches": [
                    match
                    for match in native["matches"]
                    if matcher(match["line"])
                ],
                "engine": "tgrep_textscan_direct",
                "indexed_seconds": 0.0,
                "text_scan_seconds": native["elapsed_seconds"],
                "python_seconds": 0.0,
                "command": native.get("command", ""),
                "warning": "",
                "stats": native.get("stats", {}),
                "errors": [],
                "index_verified": False,
                "verification_performed": False,
            }

        except Exception as exc:
            print(
                f"[!] Text Scan nativo falló en {stage}: {exc}; "
                "se recurrirá a Python."
            )
            fallback = python_search(
                all_files,
                matcher,
                stage + "_TEXT_FALLBACK",
            )

            return {
                "matches": fallback["matches"],
                "engine": "python_textscan_fallback",
                "indexed_seconds": 0.0,
                "text_scan_seconds": 0.0,
                "python_seconds": fallback["elapsed_seconds"],
                "command": "",
                "warning": str(exc),
                "stats": {},
                "errors": fallback["errors"],
                "index_verified": False,
                "verification_performed": False,
            }

    result = _BASE_SEARCH(
        binary,
        input_dir,
        all_files,
        pattern,
        matcher,
        index_dir,
        search_engine,
        fixed,
        verify_index,
        stage,
    )

    if not context:
        return result

    # The indexed snapshot is not authoritative if results have not
    # been compared against Text Scan. Replace changed-file matches
    # with current filesystem results for those files.
    if result.get("engine") != "tgrep_indexed_unverified":
        return result

    changed_keys = context.get("changed_keys", set())
    if not changed_keys:
        return result

    changed_files = [
        path for path in all_files
        if _integration_key(
            path, context["input_dir"]
        ) in changed_keys
    ]

    if not changed_files:
        return result

    changed_paths = {
        normalize_path_key(str(path))
        for path in changed_files
    }

    unchanged_index_matches = [
        match for match in result.get("matches", [])
        if normalize_path_key(str(match["path"])) not in changed_paths
    ]

    delta = python_search(
        changed_files,
        matcher,
        stage + "_INCREMENTAL_DELTA",
    )

    merged = {}

    for match in unchanged_index_matches + delta["matches"]:
        key = (
            normalize_path_key(str(match["path"])),
            int(match["line_number"]),
            match["line"],
        )
        merged[key] = match

    result["matches"] = list(merged.values())
    result["python_seconds"] = round(
        float(result.get("python_seconds", 0.0))
        + float(delta["elapsed_seconds"]),
        4,
    )
    result.setdefault("errors", []).extend(delta["errors"])
    result["engine"] = "tgrep_indexed_unverified+python_delta"
    result["warning"] = (
        (result.get("warning", "") + " ")
        + f"{len(changed_files)} archivo(s) nuevo(s)/modificado(s) "
        "buscados directamente con Python."
    ).strip()

    return result


def derive_findings(
    records,
    corporate_identities,
    alias_records_by_identity,
):
    findings = _BASE_DERIVE_FINDINGS(
        records,
        corporate_identities,
        alias_records_by_identity,
    )

    return rules.apply_additional_findings(
        records=records,
        existing_findings=findings,
        corporate_identities=corporate_identities,
        alias_records_by_identity=alias_records_by_identity,
        add_finding=add_finding,
        record_evidence_ids=record_evidence_ids,
    )


def build_triage_decisions(
    unique_groups,
    line_records,
    findings,
):
    triage_all, triage_unique = _BASE_BUILD_TRIAGE(
        unique_groups,
        line_records,
        findings,
    )

    return (
        rules.fix_triage_explanations(triage_all),
        rules.fix_triage_explanations(triage_unique),
    )


def build_attack_paths(
    corporate_identities,
    by_identity,
    alias_records,
    findings,
):
    base_paths = _BASE_BUILD_ATTACK_PATHS(
        corporate_identities,
        by_identity,
        alias_records,
        findings,
    )

    return rules.extend_attack_paths(
        existing_paths=base_paths,
        findings=findings,
        stable_id=stable_id,
    )


def search_with_fallback(
    binary,
    input_dir,
    all_files,
    pattern,
    matcher,
    index_dir,
    search_engine,
    fixed,
    verify_index,
    stage,
):
    return _integration_search(
        binary,
        input_dir,
        all_files,
        pattern,
        matcher,
        index_dir,
        search_engine,
        fixed,
        verify_index,
        stage,
    )


def run_pipeline(
    input_dir,
    target,
    output_dir,
    source_type,
    search_engine,
    tgrep_path,
    index_dir,
    verify_index,
    allow_demo=False,
):
    global _SEARCH_CONTEXT

    input_dir = Path(input_dir).resolve()
    output_dir = Path(output_dir).resolve()
    rules.set_target_domain(target)

    files, snapshot, stat_errors = _integration_snapshot(
        input_dir,
        output_dir,
    )

    state_path = output_dir / "incremental_state.json"
    previous = _integration_load_state(state_path)

    same_context = bool(
        previous
        and previous.get("target") == norm_target(target)
        and str(previous.get("input_directory", "")).casefold()
        == str(input_dir).casefold()
    )

    old_files = previous.get("files", {}) if same_context else {}

    added = set(snapshot) - set(old_files)
    deleted = set(old_files) - set(snapshot)
    modified = {
        key for key in set(snapshot) & set(old_files)
        if snapshot[key] != old_files[key]
    }

    if _FORCE_REBUILD or not same_context:
        changed_keys = set(snapshot)
    else:
        changed_keys = added | modified

    _SEARCH_CONTEXT = {
        "input_dir": input_dir,
        "changed_keys": changed_keys,
    }

    print("\n[+] Leak2Path v5.4.0 - inventory")
    print(f"[+] TXT files : {len(files)}")
    print(f"[+] Added     : {len(added)}")
    print(f"[+] Modified  : {len(modified)}")
    print(f"[+] Deleted   : {len(deleted)}")
    print(f"[+] Unchanged : {len(snapshot) - len(changed_keys)}")

    try:
        status = _BASE_RUN_PIPELINE(
            input_dir,
            target,
            output_dir,
            source_type,
            search_engine,
            tgrep_path,
            index_dir,
            verify_index,
            allow_demo=allow_demo,
        )
    finally:
        _SEARCH_CONTEXT = None

    if status == 0:
        # Merge new rules into the original catalogue.
        rules.merge_rule_catalogue(output_dir)

        # Append the graph to the freshly generated dark dashboard.
        dashboard.inject_relationship_graph(
            output_dir / "report.html",
            target,
            output_dir / "normalized" / "normalized_records.jsonl",
        )

        if not stat_errors:
            state = {
                "version": VERSION,
                "target": norm_target(target),
                "input_directory": str(input_dir),
                "generated_at": _dt.datetime.now().isoformat(
                    timespec="seconds"
                ),
                "files": snapshot,
                "signature_fields": [
                    "size_bytes", "mtime_ns", "ctime_ns"
                ],
            }
            _integration_atomic_json(state_path, state)

    else:
        print(
            "[!] El análisis terminó con errores; no se actualizará "
            "el inventario incremental."
        )

    return status

def simple_search(
    input_dir: Path,
    term: str,
    output_path: Path,
    case_sensitive: bool = False,
    search_engine: str = "python",
    tgrep_path: Optional[str] = None,
) -> int:
    """Single-term search; no normalization, findings or Attack Paths."""
    input_dir = Path(input_dir).resolve()
    output_path = Path(output_path).resolve()

    if not input_dir.is_dir():
        raise ValueError(f"No existe el directorio: {input_dir}")

    # Enumerate before creating the output so it cannot match itself.
    files = sorted(
        path for path in input_dir.rglob("*.txt")
        if path.is_file()
        and "_results_" not in path.name.casefold()
        and not path.name.casefold().endswith("_unique.txt")
        and not path.name.casefold().startswith(
            "leak2path_simple_search_"
        )
        and path.resolve() != output_path
    )

    start = time.perf_counter()
    matches = []
    errors = []

    if search_engine == "tgrep-text":
        binary = find_tgrep(tgrep_path)

        if binary:
            try:
                native = run_tgrep_json(
                    binary,
                    input_dir,
                    files,
                    term,
                    None,
                    "text_scan",
                    True,
                )

                if not native.get("unmapped_paths") and not native.get("errors"):
                    matches = native["matches"]
                else:
                    raise RuntimeError(
                        "tgrep devolvió rutas sin mapear o errores."
                    )

            except Exception as exc:
                print(
                    f"[!] tgrep simple falló: {exc}; "
                    "se utilizará Python."
                )
                search_engine = "python"
        else:
            print("[!] tgrep no está disponible; se utilizará Python.")
            search_engine = "python"

    if search_engine == "python":
        needle = term if case_sensitive else term.casefold()

        for index, path in enumerate(files, 1):
            try:
                with path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace",
                    newline="",
                ) as source:
                    for line_number, line in enumerate(source, 1):
                        comparable = line if case_sensitive else line.casefold()

                        if needle in comparable:
                            matches.append({
                                "path": path,
                                "line_number": line_number,
                                "line": line.rstrip("\r\n"),
                            })

            except OSError as exc:
                errors.append({
                    "source_file": str(path),
                    "error": str(exc),
                })

            progress("SIMPLE_SEARCH", index, len(files), path.name)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        encoding="utf-8",
        errors="replace",
        newline="\n",
    ) as destination:
        for match in matches:
            destination.write(
                f"{match['path']}:{match['line_number']}:"
                f"{match['line']}\n"
            )

    elapsed = time.perf_counter() - start

    print(f"\n[+] Leak2Path simple search")
    print(f"[+] Term          : {term}")
    print(f"[+] Search engine : {search_engine}")
    print(f"[+] TXT files     : {len(files)}")
    print(f"[+] Matches       : {len(matches)}")
    print(f"[+] Errors        : {len(errors)}")
    print(f"[+] Elapsed       : {elapsed:.2f}s")
    print(f"[+] Output        : {output_path}")
    print(
        "[!] El resultado simple puede conservar líneas RAW con "
        "credenciales. Protege el archivo resultante."
    )

    return 2 if errors else 0


def main() -> int:
    global _FORCE_REBUILD, REPORT_LANGUAGE

    parser = argparse.ArgumentParser(
        description=(
            "Leak2Path v5.4.0 - deterministic ULP intelligence."
        )
    )

    parser.add_argument(
        "--language",
        choices=("es", "en"),
        default="es",
        help="Idioma del reporte HTML: es (español) o en (inglés).",
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default=str(DEFAULT_INPUT_DIR),
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Dominio objetivo, compatible con CLI anterior.",
    )

    parser.add_argument(
        "--input-dir",
        dest="input_dir",
        default=None,
        help="Directorio que contiene los archivos TXT.",
    )

    parser.add_argument(
        "--leak2path",
        dest="leak2path_target",
        metavar="DOMAIN",
        help="Ejecuta el pipeline completo de inteligencia.",
    )

    parser.add_argument(
        "--simple-search",
        metavar="TERM",
        default=None,
        help="Busca un término literal en todos los archivos TXT.",
    )

    parser.add_argument(
        "--simple-engine",
        choices=("python", "tgrep-text"),
        default="python",
    )

    parser.add_argument(
        "--simple-output",
        default=None,
    )

    parser.add_argument(
        "--case-sensitive",
        action="store_true",
    )

    parser.add_argument("--output-dir", default=None)

    parser.add_argument(
        "--source-type",
        default="ulp",
        choices=("unknown", "stealer", "ulp", "breach", "combolist"),
    )

    parser.add_argument(
        "--search-engine",
        default="tgrep-text",
        choices=("auto", "python", "tgrep", "tgrep-text"),
        help=(
            "tgrep-text fuerza búsqueda nativa sin índice. "
            "auto/tgrep conserva la estrategia indexada con fallback."
        ),
    )

    parser.add_argument("--tgrep-path", default=DEFAULT_TGREP_PATH)
    parser.add_argument("--index-path", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--verify-index", action="store_true")
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Ignora el inventario previo y reconstruye el análisis.",
    )

    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--demo-input-dir", default=None)

    args = parser.parse_args()
    REPORT_LANGUAGE = args.language

    input_dir = Path(
        args.input_dir or args.directory
    ).expanduser().resolve()

    if args.simple_search is not None:
        if args.target or args.leak2path_target:
            parser.error(
                "--simple-search y --leak2path son modos excluyentes."
            )

        output_path = (
            Path(args.simple_output).expanduser().resolve()
            if args.simple_output
            else (
                Path.cwd()
                / (
                    "leak2path_simple_search_"
                    + _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                    + ".txt"
                )
            )
        )

        return simple_search(
            input_dir=input_dir,
            term=args.simple_search,
            output_path=output_path,
            case_sensitive=args.case_sensitive,
            search_engine=args.simple_engine,
            tgrep_path=args.tgrep_path,
        )

    target = args.leak2path_target or args.target

    if args.target and args.leak2path_target:
        parser.error(
            "Usa el objetivo posicional o --leak2path, no ambos."
        )

    if args.demo:
        demo_dir = (
            Path(args.demo_input_dir).expanduser().resolve()
            if args.demo_input_dir
            else Path(_tempfile.mkdtemp(prefix="leak2path_demo_"))
        )

        make_demo_corpus(demo_dir)
        input_dir = demo_dir
        target = "acme.example"
        source_type = "unknown"
        search_engine = "python"
        tgrep_path = None
        index_dir = None
        verify_index = False

    else:
        if not target:
            parser.error(
                "Usa --simple-search TERM o --leak2path DOMAIN."
            )

        source_type = args.source_type
        search_engine = args.search_engine
        tgrep_path = args.tgrep_path
        index_dir = Path(args.index_path).expanduser().resolve()
        verify_index = args.verify_index

    _FORCE_REBUILD = bool(args.force_rebuild)

    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else (
            Path.cwd()
            / (
                f"{norm_target(target)}-v{VERSION}-"
                + _dt.datetime.now().strftime("%Y%m%d")
            )
        ).resolve()
    )

    try:
        return run_pipeline(
            input_dir=input_dir,
            target=target,
            output_dir=output_dir,
            source_type=source_type,
            search_engine=search_engine,
            tgrep_path=tgrep_path,
            index_dir=index_dir,
            verify_index=verify_index,
            allow_demo=args.demo,
        )

    except Exception as exc:
        print(f"[!] Fatal error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
