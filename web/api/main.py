# ------------------------------------------------------------------
# Recursive-IR source file
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
#
from fastapi import FastAPI, Request, Response, Depends, HTTPException, APIRouter, File, Form, UploadFile
from typing import List, Optional, Literal, Dict, Any, Tuple
from pydantic import BaseModel, Field, RootModel, root_validator, ConfigDict
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
import ctypes.util
import aiosqlite
import subprocess
import requests
import hashlib
import secrets
import ctypes
import string
import yaml
import time
import json
import uuid
import os
import re

app = FastAPI()
api_v1 = APIRouter(prefix="/v1")

# OpenSearch Dashboards base URL (source of truth: OSD_HOST)
# In the loopback+nginx model, this can be either:
#   - the Dashboards origin (e.g. http://127.0.0.1:5601)
#   - the nginx front door (e.g. http://127.0.0.1)
# API uses it only to call /api/v1/auth/authinfo with the user's cookie.
OSD_HOST = (
    os.getenv("OSD_HOST")
    or os.getenv("OSD_URL_LAN")
    or os.getenv("OSD_URL")
    or "http://127.0.0.1:5601"
)


# Persisted on host via docker volume mount:
#   /var/lib/recursive-ir/web  ->  /data
WEB_DATA_ROOT = os.getenv("WEB_DATA_ROOT", "/data")
JOBS_ROOT = os.getenv("JOBS_ROOT", os.path.join(WEB_DATA_ROOT, "jobs"))
UPLOADS_ROOT = os.getenv("UPLOADS_ROOT", os.path.join(WEB_DATA_ROOT, "uploads"))
DB_PATH = os.getenv("JOBS_DB", os.path.join(JOBS_ROOT, "jobs.db"))

# OpenSearch for server-side truth (case_id derivation)
# Expect these to be provided to the container environment.
OS_HOST = os.getenv("OS_HOST") 
OS_USER = os.getenv("OS_USER")
OS_PASS = os.getenv("OS_PASS")
OS_CACERT = os.getenv("OS_CACERT")
OS_INSECURE = (os.getenv("OS_INSECURE") or "").strip().lower() in ("1", "true", "yes", "y")

def _os_verify_param():
    if OS_INSECURE:
        return False
    if OS_CACERT and os.path.isfile(OS_CACERT):
        return OS_CACERT
    return True

# Validation locks
RE_DOC_ID = re.compile(r"^[a-f0-9]{64}$")
RE_CASE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
RE_INDEX = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

MAX_TAG_LEN = 128
MAX_BULK_DOCS = 10_000
MAX_COMMENT_LEN = 500
MAX_IOC_LEN = 512

# Tag YAML sources (served to UI)
TAGS_DIR = os.getenv("TAGS_DIR", "/etc/recursive-ir/conf/tags")

RE_TAG_SOURCE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_TAGS_YAML_BYTES = 1_000_000  # 1MB safety cap


PARSERS_YML = os.getenv("PARSERS_YML", "/etc/recursive-ir/conf/parsers.yml")
FIELD_MAPPINGS_YML = os.getenv("FIELD_MAPPINGS_YML", "/etc/recursive-ir/conf/field-mappings.yml")


PATHS_ENV = os.getenv("PATHS_ENV", "/etc/recursive-ir/env/paths.env")


class HostBulkNewRequest(BaseModel):
    case_id: str
    cidr: str
    hostname: str | None = None
    os: str | None = None
    description: str | None = None

    @root_validator(pre=True)
    def _validate_bulk_new(cls, values):
        case_id = (values.get("case_id") or "").strip()
        cidr = (values.get("cidr") or "").strip()
        hostname = values.get("hostname")
        os_value = values.get("os")
        description = values.get("description")

        if not case_id:
            raise ValueError("case_id is required")
        if not cidr:
            raise ValueError("cidr is required")

        values["case_id"] = case_id
        values["cidr"] = cidr

        if hostname is not None:
            hostname = str(hostname).strip()
            values["hostname"] = hostname or None

        if os_value is not None:
            os_value = str(os_value).strip()
            values["os"] = os_value or None

        if description is not None:
            description = str(description).strip()
            values["description"] = description or None

        return values

class HostListRequest(BaseModel):
    case_id: str

    @root_validator(pre=True)
    def _validate_case_id(cls, values):
        case_id = (values.get("case_id") or "").strip()
        values["case_id"] = case_id

        if not case_id:
            raise ValueError("case_id is required")

        return values

class HostArtefactsListRequest(BaseModel):
    case_id: str
    host_ip: str

    @root_validator(pre=True)
    def _validate_fields(cls, values):
        case_id = (values.get("case_id") or "").strip()
        host_ip = (values.get("host_ip") or "").strip()

        values["case_id"] = case_id
        values["host_ip"] = host_ip

        if not case_id:
            raise ValueError("case_id is required")
        if not host_ip:
            raise ValueError("host_ip is required")

        return values

class HostNewRequest(BaseModel):
    case_id: str
    ip: str
    hostname: str | None = None
    os: str | None = None
    description: str | None = None

    @root_validator(pre=True)
    def _validate_new(cls, values):
        case_id = (values.get("case_id") or "").strip()
        ip = (values.get("ip") or "").strip()
        hostname = values.get("hostname")
        os_value = values.get("os")
        description = values.get("description")

        if not case_id:
            raise ValueError("case_id is required")
        if not ip:
            raise ValueError("ip is required")

        values["case_id"] = case_id
        values["ip"] = ip

        if hostname is not None:
            values["hostname"] = str(hostname).strip()
        if os_value is not None:
            values["os"] = str(os_value).strip()
        if description is not None:
            values["description"] = str(description).strip()

        return values

class HostUpdateRequest(BaseModel):
    case_id: str
    ip: str
    hostname: str | None = None
    os: str | None = None
    description: str | None = None

    @root_validator(pre=True)
    def _validate_update(cls, values):
        case_id = (values.get("case_id") or "").strip()
        ip = (values.get("ip") or "").strip()
        hostname = values.get("hostname")
        os_name = values.get("os")
        description = values.get("description")

        values["case_id"] = case_id
        values["ip"] = ip

        if hostname is not None:
            hostname = hostname.strip()
            values["hostname"] = hostname or None

        if os_name is not None:
            os_name = os_name.strip()
            values["os"] = os_name or None

        if description is not None:
            description = description.strip()
            values["description"] = description or None

        if not case_id:
            raise ValueError("case_id is required")

        if not ip:
            raise ValueError("ip is required")

        if values.get("hostname") is None and values.get("os") is None and values.get("description") is None:
            raise ValueError("nothing to update")

        return values

class ParserCreateSubmit(BaseModel):
    type: str = Field(..., min_length=1, max_length=128)
    patterns: List[str] = Field(..., min_items=1)
    bin: str = Field(..., min_length=1, max_length=512)
    args: List[str] = Field(default_factory=list)
    route_mode: str = Field(..., min_length=1, max_length=64)
    expand_archives: Optional[str] = Field(None, max_length=64)
    timezone: Optional[str] = Field(None, max_length=64)
    inherit_type: Optional[bool] = False
    fingerprint_fields: Optional[List[str]] = None
    force: Optional[bool] = False

class ParserUpdateSubmit(BaseModel):
    patterns: Optional[List[str]] = None
    bin: Optional[str] = None
    args: Optional[List[str]] = None
    route_mode: Optional[str] = None
    expand_archives: Optional[str] = None
    timezone: Optional[str] = None
    inherit_type: Optional[bool] = None
    fingerprint_fields: Optional[List[str]] = None

def _parser_scalar_list_to_csv(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return str(v)


async def _find_active_parser_job(db: aiosqlite.Connection, parser_type: str):
    cur = await db.execute(
        """
        SELECT id, action
          FROM jobs
         WHERE status IN ('queued','running')
           AND action IN ('parser_enable','parser_disable','parser_update','parser_delete','parser_new')
           AND json_extract(payload_json, '$.type') = ?
         ORDER BY id DESC
         LIMIT 1
        """,
        (parser_type,),
    )
    return await cur.fetchone()


def _load_parsers_from_yaml() -> Dict[str, Any]:
    path = PARSERS_YML

    if not os.path.isfile(path):
        return {"parsers": []}

    try:
        st = os.stat(path)
        if st.st_size > 2_000_000:
            raise HTTPException(status_code=500, detail="parsers.yml too large")
    except FileNotFoundError:
        return {"parsers": []}

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to read parsers.yml: {e}")

    types = doc.get("types") or {}
    if not isinstance(types, dict):
        raise HTTPException(status_code=500, detail="invalid parsers.yml: expected top-level 'types' mapping")

    out = []
    for ptype, cfg in types.items():
        if not isinstance(ptype, str):
            continue
        if not isinstance(cfg, dict):
            continue

        enabled = bool(cfg.get("enabled", True))
        bin_name = str(cfg.get("bin") or "")

        pid = cfg.get("id")
        if isinstance(pid, str) and pid.isdigit():
            pid = int(pid)

        patterns = cfg.get("patterns")
        if patterns is None:
            patterns = []
        elif not isinstance(patterns, list):
            patterns = [str(patterns)]
        else:
            patterns = [str(x) for x in patterns]

        args = cfg.get("args")
        if args is None:
            args = []
        elif not isinstance(args, list):
            args = [str(args)]
        else:
            args = [str(x) for x in args]

        fingerprint_fields = cfg.get("fingerprint_fields")
        if fingerprint_fields is None:
            fingerprint_fields = None
        elif not isinstance(fingerprint_fields, list):
            fingerprint_fields = [str(fingerprint_fields)]
        else:
            fingerprint_fields = [str(x) for x in fingerprint_fields]

        out.append({
            "type": ptype,
            "enabled": enabled,
            "id": pid if isinstance(pid, int) else None,
            "patterns": patterns,
            "bin": bin_name,
            "route_mode": str(cfg.get("route_mode") or "walk"),
            "expand_archives": str(cfg.get("expand_archives") or "top"),
            "timezone": str(cfg.get("timezone") or "UTC"),
            "inherit_type": bool(cfg.get("inherit_type", False)),
            "args": args,
            "fingerprint_fields": fingerprint_fields,
        })
    out.sort(key=lambda x: ((x.get("type") or "").lower()))
    return {"parsers": out}


def _field_mappings_default_config() -> Dict[str, Any]:
    return {
        "rename": {},
        "copy": {},
        "set_if_present": {},
        "drop": [],
        "derive": {
            "basename": [],
            "parentdirs": [],
        },
        "stringify": [],
        "store_only": {
            "max_bytes": 8192,
            "preview_bytes": 8192,
            "add_sha256": True,
            "fields": ["event.original"],
        },
    }


def _normalize_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            s = str(item).strip()
            if s:
                out.append(s)
        return out

    s = str(value).strip()
    return [s] if s else []


def _normalize_string_map(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}

    out: Dict[str, str] = {}
    for k, v in value.items():
        key = str(k).strip()
        val = str(v).strip()
        if not key or not val:
            continue
        out[key] = val
    return out


def _normalize_string_list_map(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, dict):
        return {}

    out: Dict[str, List[str]] = {}
    for k, v in value.items():
        key = str(k).strip()
        if not key:
            continue

        vals = _normalize_string_list(v)
        if vals:
            out[key] = vals

    return out


def _normalize_set_if_present(value: Any) -> Dict[str, Dict[str, List[str]]]:
    if not isinstance(value, dict):
        return {}

    out: Dict[str, Dict[str, List[str]]] = {}

    for cond_key, assigns in value.items():
        condition = str(cond_key).strip()
        if not condition or not isinstance(assigns, dict):
            continue

        normalized_assigns: Dict[str, List[str]] = {}

        for tmpl_key, destinations in assigns.items():
            template = str(tmpl_key).strip()
            if not template:
                continue

            dests = _normalize_string_list(destinations)
            if dests:
                normalized_assigns[template] = dests

        if normalized_assigns:
            out[condition] = normalized_assigns

    return out


def _normalize_store_only(value: Any) -> Dict[str, Any]:
    default = _field_mappings_default_config()["store_only"]

    if not isinstance(value, dict):
        return dict(default)

    max_bytes = value.get("max_bytes", default["max_bytes"])
    preview_bytes = value.get("preview_bytes", default["preview_bytes"])
    add_sha256 = value.get("add_sha256", default["add_sha256"])
    fields = _normalize_string_list(value.get("fields"))

    if "event.original" not in fields:
        fields = ["event.original", *fields]

    try:
        max_bytes = int(max_bytes)
    except Exception:
        max_bytes = default["max_bytes"]

    try:
        preview_bytes = int(preview_bytes)
    except Exception:
        preview_bytes = default["preview_bytes"]

    return {
        "max_bytes": max(0, max_bytes),
        "preview_bytes": max(0, preview_bytes),
        "add_sha256": bool(add_sha256),
        "fields": fields,
    }


def _normalize_field_mappings_config(value: Any) -> Dict[str, Any]:
    default = _field_mappings_default_config()

    if not isinstance(value, dict):
        return default

    derive = value.get("derive")
    if not isinstance(derive, dict):
        derive = {}

    return {
        "rename": _normalize_string_map(value.get("rename")),
        "copy": _normalize_string_list_map(value.get("copy")),
        "set_if_present": _normalize_set_if_present(value.get("set_if_present")),
        "drop": _normalize_string_list(value.get("drop")),
        "derive": {
            "basename": _normalize_string_list(derive.get("basename")),
            "parentdirs": _normalize_string_list(derive.get("parentdirs")),
        },
        "stringify": _normalize_string_list(value.get("stringify")),
        "store_only": _normalize_store_only(value.get("store_only")),
    }


class FieldMappingsStoreOnlyPayload(BaseModel):
    max_bytes: int = 8192
    preview_bytes: int = 8192
    add_sha256: bool = True
    fields: List[str] = ["event.original"]


class FieldMappingsDerivePayload(BaseModel):
    basename: List[str] = []
    parentdirs: List[str] = []


class FieldMappingsConfigPayload(BaseModel):
    rename: Dict[str, str] = {}
    copy: Dict[str, List[str]] = {}
    set_if_present: Dict[str, Dict[str, List[str]]] = {}
    drop: List[str] = []
    derive: FieldMappingsDerivePayload = FieldMappingsDerivePayload()
    stringify: List[str] = []
    store_only: FieldMappingsStoreOnlyPayload = FieldMappingsStoreOnlyPayload()


class FieldMappingsSourceTypePayload(BaseModel):
    sourceType: str
    config: FieldMappingsConfigPayload


class FieldMappingsSavePayload(BaseModel):
    source_types: List[FieldMappingsSourceTypePayload]


class OSDColumnsSectionPayload(BaseModel):
    default_columns: List[str]


class OSDSetColumnsPayload(BaseModel):
    global_: OSDColumnsSectionPayload = Field(alias="global")
    types: Dict[str, OSDColumnsSectionPayload] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

class TimestampCandidatePayload(BaseModel):
    field_name: str = Field(..., min_length=1)
    description: str = ""

class TimestampSetPayload(BaseModel):
    candidates: List[TimestampCandidatePayload] = Field(default_factory=list)

class TimestampCoveragePayload(BaseModel):
    candidates: List[str] = Field(default_factory=list)

class TimestampCandidatesForViewPayload(BaseModel):
    source_type: str = Field(..., min_length=1, max_length=128)

class TimestampFallbackSamplesPayload(BaseModel):
    source_type: str = Field(..., min_length=1, max_length=128)
    limit: int = Field(1, ge=1, le=25)
    search_after: Optional[List[Any]] = None

class OSDPreviewEventSummaryPayload(BaseModel):
    section: str
    fields: List[str] = Field(default_factory=list)

class OSDFieldInspectorPayload(BaseModel):
    section: str
    field: str
    sections: List[str] = Field(default_factory=list)

def _load_field_mappings_from_yaml() -> Dict[str, Any]:
    path = FIELD_MAPPINGS_YML

    if not os.path.isfile(path):
        return {"source_types": []}

    try:
        st = os.stat(path)
        if st.st_size > 2_000_000:
            raise HTTPException(status_code=500, detail="field-mappings.yml too large")
    except FileNotFoundError:
        return {"source_types": []}

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to read field-mappings.yml: {e}")

    if not isinstance(doc, dict):
        raise HTTPException(status_code=500, detail="invalid field-mappings.yml: expected top-level mapping")

    out = []
    for source_type, cfg in doc.items():
        if not isinstance(source_type, str):
            continue

        out.append({
            "sourceType": source_type,
            "config": _normalize_field_mappings_config(cfg),
        })

    out.sort(key=lambda x: (x.get("sourceType") or "").lower())
    return {"source_types": out}

# -------------------------
# Job dedupe (API-side suppression of identical queued/running jobs)
# -------------------------
DEDUP_ACTIVE_STATUSES = ("queued", "running")

def _job_dedupe_key(action: str, case_id: str, seed_index: str, seed_id: str, tag: str | None, hits: list | None) -> str:
    """Stable key for identical job requests.
    - For tag_add: key covers action + case/index/id + tag
    - For tag_add_bulk: key covers action + case + tag + exact hit set (order-insensitive)
    """
    h = hashlib.sha256()
    h.update(action.encode("utf-8"))
    h.update(b"\0")
    h.update((case_id or "").encode("utf-8"))
    h.update(b"\0")
    h.update((seed_index or "").encode("utf-8"))
    h.update(b"\0")
    h.update((seed_id or "").encode("utf-8"))
    h.update(b"\0")
    h.update((tag or "").encode("utf-8"))

    if hits:
        # order-insensitive: sort by (index,id) so same set => same hash
        items = [(getattr(x, "index", None) or x.get("index"), getattr(x, "id", None) or x.get("id")) for x in hits]
        items.sort()
        h.update(b"\0")
        for ix, did in items:
            h.update((ix or "").encode("utf-8"))
            h.update(b"\t")
            h.update((did or "").encode("utf-8"))
            h.update(b"\n")

    return h.hexdigest()

# -------------------------
# libzstd compression (ctypes)
# -------------------------

def _load_zstd() -> ctypes.CDLL:
    path = ctypes.util.find_library("zstd")
    if not path:
        # common fallback
        for p in ("/usr/lib/x86_64-linux-gnu/libzstd.so.1", "/usr/lib/libzstd.so.1", "libzstd.so.1"):
            try:
                return ctypes.CDLL(p)
            except Exception:
                pass
        raise RuntimeError("libzstd not found (install libzstd1 / libzstd-dev)")
    return ctypes.CDLL(path)

_ZSTD = _load_zstd()

_ZSTD.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
_ZSTD.ZSTD_compressBound.restype = ctypes.c_size_t

_ZSTD.ZSTD_compress.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_int,
]
_ZSTD.ZSTD_compress.restype = ctypes.c_size_t

_ZSTD.ZSTD_isError.argtypes = [ctypes.c_size_t]
_ZSTD.ZSTD_isError.restype = ctypes.c_uint

_ZSTD.ZSTD_getErrorName.argtypes = [ctypes.c_size_t]
_ZSTD.ZSTD_getErrorName.restype = ctypes.c_char_p

def zstd_compress(data: bytes, level: int = 3) -> bytes:
    if not data:
        return b""
    bound = _ZSTD.ZSTD_compressBound(len(data))
    dst = (ctypes.c_ubyte * bound)()
    src = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    rc = _ZSTD.ZSTD_compress(
        ctypes.cast(dst, ctypes.c_void_p), bound,
        ctypes.cast(src, ctypes.c_void_p), len(data),
        level
    )
    if _ZSTD.ZSTD_isError(rc):
        name = _ZSTD.ZSTD_getErrorName(rc)
        raise RuntimeError(f"zstd compress failed: {name.decode('utf-8', 'ignore')}")
    return bytes(dst[:rc])

# -------------------------
# OSD authinfo helpers
# -------------------------

def _fetch_authinfo(cookie: str):
    """
    Return dict:
      {"ok": True, "url": <used>, "json": {...}}
    or
      {"ok": False, "error": "...", "last": {...}}
    """
    candidates = [
        f"{OSD_HOST}/api/v1/auth/authinfo",
        f"{OSD_HOST}/_dashboards/api/v1/auth/authinfo",
    ]

    last = None
    for url in candidates:
        try:
            r = requests.get(url, headers={"Cookie": cookie}, timeout=5)
            last = {"url": url, "status": r.status_code, "text_preview": r.text[:200]}
            if r.status_code == 200:
                try:
                    return {"ok": True, "url": url, "json": r.json()}
                except Exception:
                    return {"ok": True, "url": url, "text": r.text}
        except Exception as e:
            last = {"url": url, "error": str(e)}

    return {"ok": False, "error": "authinfo not reachable/authorized", "last": last}

def _require_cookie(req: Request):
    cookie = req.headers.get("cookie")
    if not cookie:
        return None, {"ok": False, "error": "no cookie forwarded to API"}
    return cookie, None

def _require_auth(req: Request) -> Tuple[Optional[str], Optional[str], Optional[JSONResponse]]:
    cookie, err = _require_cookie(req)
    if err:
        return None, None, JSONResponse(status_code=401, content=err)

    auth = _fetch_authinfo(cookie)
    if not auth.get("ok"):
        return None, None, JSONResponse(status_code=401, content=auth)

    user_name = (auth.get("json") or {}).get("user_name") or "unknown"
    return cookie, user_name, None

def _auth_backend_roles(auth_json: Dict[str, Any]) -> List[str]:
    roles = auth_json.get("backend_roles")

    if not isinstance(roles, list):
        roles = auth_json.get("backendRoles")

    if not isinstance(roles, list):
        return []

    return [str(role) for role in roles if role is not None]

def _is_recursive_ir_admin(user_name: str, backend_roles: List[str]) -> bool:
    return user_name == "admin" or "recursive_ir_admin" in backend_roles


def _require_admin_auth(req: Request) -> Tuple[Optional[str], Optional[str], Optional[JSONResponse]]:
    cookie, user, resp = _require_auth(req)
    if resp:
        return None, None, resp

    auth = _fetch_authinfo(cookie)
    auth_json = auth.get("json") or {}
    backend_roles = _auth_backend_roles(auth_json)

    if not _is_recursive_ir_admin(user or "", backend_roles):
        return None, None, JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "admin role required",
            },
        )

    return cookie, user, None

@api_v1.get("/auth/session")
async def auth_session(req: Request):
    cookie, user, resp = _require_auth(req)
    if resp:
        return resp

    auth = _fetch_authinfo(cookie)
    auth_json = auth.get("json") or {}
    backend_roles = _auth_backend_roles(auth_json)

    return {
        "ok": True,
        "user": user,
        "backend_roles": backend_roles,
        "is_recursive_ir_user": "recursive_ir_user" in backend_roles,
        "is_recursive_ir_case_admin": "recursive_ir_case_admin" in backend_roles,
        "is_recursive_ir_admin": _is_recursive_ir_admin(user, backend_roles),
    }
# -------------------------
# OpenSearch truth helpers
# -------------------------

def _os_ready() -> Optional[str]:
    if not OS_HOST:
        return "OS_HOST is not set in API environment"
    if not OS_USER or not OS_PASS:
        return "OS_USER/OS_PASS are not set in API environment"
    return None

def os_get_case_id(index: str, doc_id: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (case_id, error).
    """
    if not RE_INDEX.match(index):
        return None, "invalid index"
    if not RE_DOC_ID.match(doc_id):
        return None, "invalid id"

    missing = _os_ready()
    if missing:
        return None, missing

    url = f"{OS_HOST.rstrip('/')}/{index}/_doc/{doc_id}"
    try:
       r = requests.get(
           url,
           auth=(OS_USER, OS_PASS),
           timeout=10,
           verify=_os_verify_param(),
       )
    except Exception as e:
        return None, f"opensearch request failed: {e}"

    if r.status_code == 404:
        return None, "document not found"
    if r.status_code != 200:
        return None, f"opensearch error {r.status_code}: {r.text[:200]}"

    try:
        j = r.json()
    except Exception:
        return None, "opensearch returned non-json"

    src = (j or {}).get("_source") or {}
    case_id = src.get("case_id")
    if not case_id or not isinstance(case_id, str):
        return None, "document missing case_id"
    if not RE_CASE_ID.match(case_id):
        return None, "document case_id failed validation"
    return case_id, None

# -------------------------
# DB schema helpers
# -------------------------

async def _table_has_column(db: aiosqlite.Connection, table: str, col: str) -> bool:
    q = f"PRAGMA table_info({table});"
    async with db.execute(q) as cur:
        async for row in cur:
            # row[1] == name
            if row and len(row) > 1 and row[1] == col:
                return True
    return False

async def _ensure_column(db: aiosqlite.Connection, table: str, col: str, col_def: str):
    if await _table_has_column(db, table, col):
        return
    await db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def};")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _upload_session_dir(upload_id: str) -> str:
    return os.path.join(UPLOADS_ROOT, upload_id)


def _upload_session_meta_path(upload_id: str) -> str:
    return os.path.join(_upload_session_dir(upload_id), "meta.json")


def _upload_session_assembled_dir(upload_id: str) -> str:
    return os.path.join(_upload_session_dir(upload_id), "assembled")

def _upload_session_chunks_root(upload_id: str) -> str:
    return os.path.join(_upload_session_dir(upload_id), "chunks")


def _upload_item_chunk_dir(upload_id: str, item_id: str) -> str:
    return os.path.join(_upload_session_chunks_root(upload_id), item_id)


def _upload_item_chunk_meta_path(upload_id: str, item_id: str) -> str:
    return os.path.join(_upload_item_chunk_dir(upload_id, item_id), "item_meta.json")


def _write_json_atomic(path: str, payload: dict) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp_path, path)


def _create_upload_session_meta(
    *,
    case_id: str,
    host_ip: str,
    created_by: str,
    selection_mode: str,
    preserve_folder_structure: bool,
    verify_sha256: bool,
    chunk_large_files: bool,
) -> dict:
    upload_id = f"upl_{int(time.time())}_{uuid.uuid4().hex[:12]}"
    created_at = _utc_now_iso()
    session_dir = _upload_session_dir(upload_id)
    assembled_dir = _upload_session_assembled_dir(upload_id)
    chunks_root = _upload_session_chunks_root(upload_id)
    final_inbox_path = f"/var/log/recursive-ir/cases/{case_id}/hosts/{host_ip}/inbox"

    os.makedirs(session_dir, exist_ok=False)
    os.makedirs(assembled_dir, exist_ok=False)
    os.makedirs(chunks_root, exist_ok=False)

    meta = {
        "upload_id": upload_id,
        "case_id": case_id,
        "host_ip": host_ip,
        "created_by": created_by,
        "created_at": created_at,
        "updated_at": created_at,
        "status": "pending",
        "selection_mode": selection_mode,
        "item_count": 0,
        "total_bytes": 0,
        "preserve_folder_structure": preserve_folder_structure,
        "verify_sha256": verify_sha256,
        "chunk_large_files": chunk_large_files,
        "staging_root": assembled_dir,
        "final_inbox_path": final_inbox_path,
        "error": "",
        "warnings": [],
        "items": [],
    }

    _write_json_atomic(_upload_session_meta_path(upload_id), meta)
    return meta


def _load_upload_session_meta(upload_id: str) -> dict:
    meta_path = _upload_session_meta_path(upload_id)

    if not os.path.isfile(meta_path):
        raise FileNotFoundError(f"Upload session metadata not found for {upload_id}")

    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_upload_session_meta(upload_id: str, meta: dict) -> None:
    meta["updated_at"] = _utc_now_iso()
    _write_json_atomic(_upload_session_meta_path(upload_id), meta)


def infer_artefact_type(file_name: str) -> str:
    lower = file_name.lower()

    if lower.endswith(".zip") or lower.endswith(".7z") or lower.endswith(".tar") or lower.endswith(".gz"):
        return "Archive"
    if lower.endswith(".evtx"):
        return "EVTX"
    if lower.endswith(".json") or lower.endswith(".jsonl"):
        return "JSON"
    if lower.endswith(".csv"):
        return "CSV"
    if lower.endswith(".txt") or lower.endswith(".log"):
        return "Text"
    if lower.endswith(".pcap") or lower.endswith(".pcapng"):
        return "PCAP"

    return "File"

def _append_upload_session_item(
    meta: dict,
    *,
    relative_path: str,
    size_bytes: int,
    source: str,
    sha256: str,
) -> dict:
    item = {
        "id": f"item_{uuid.uuid4().hex[:12]}",
        "name": relative_path,
        "relative_path": relative_path,
        "kind": "file",
        "type": infer_artefact_type(relative_path),
        "size_bytes": size_bytes,
        "status": "staged",
        "sha256": sha256 or "",
        "source": source,
    }

    meta.setdefault("items", []).append(item)
    meta["item_count"] = len(meta["items"])
    meta["total_bytes"] = sum(int(x.get("size_bytes", 0)) for x in meta["items"])
    meta["status"] = "uploading"

    return item


def _init_chunked_upload_item(
    upload_id: str,
    *,
    relative_path: str,
    source: str,
    total_chunks: int,
    total_size_bytes: int,
) -> dict:
    safe_relative_path = (relative_path or "").replace("\\", "/").lstrip("/").strip()
    if not safe_relative_path:
        raise ValueError("relative_path is required")

    normalized = os.path.normpath(safe_relative_path).replace("\\", "/")
    if normalized == "." or normalized.startswith("../") or "/../" in normalized:
        raise ValueError("relative_path is invalid")

    if total_chunks <= 0:
        raise ValueError("total_chunks must be greater than 0")

    if total_size_bytes < 0:
        raise ValueError("total_size_bytes must be zero or greater")

    item_id = f"item_{uuid.uuid4().hex[:12]}"
    item_dir = _upload_item_chunk_dir(upload_id, item_id)
    os.makedirs(item_dir, exist_ok=False)

    item_meta = {
        "item_id": item_id,
        "relative_path": normalized,
        "source": source,
        "total_chunks": int(total_chunks),
        "total_size_bytes": int(total_size_bytes),
        "received_chunks": [],
        "status": "pending",
        "created_at": _utc_now_iso(),
        "updated_at": _utc_now_iso(),
    }

    _write_json_atomic(_upload_item_chunk_meta_path(upload_id, item_id), item_meta)
    return item_meta

async def _stage_upload_chunk(
    upload_id: str,
    item_id: str,
    upload_file: UploadFile,
    *,
    chunk_index: int,
) -> dict:
    if chunk_index < 0:
        raise ValueError("chunk_index must be zero or greater")

    item_meta_path = _upload_item_chunk_meta_path(upload_id, item_id)
    if not os.path.isfile(item_meta_path):
        raise FileNotFoundError("Chunked upload item not found")

    with open(item_meta_path, "r", encoding="utf-8") as f:
        item_meta = json.load(f)

    total_chunks = int(item_meta.get("total_chunks", 0))
    if chunk_index >= total_chunks:
        raise ValueError("chunk_index is out of range")

    item_dir = _upload_item_chunk_dir(upload_id, item_id)
    chunk_path = os.path.join(item_dir, f"chunk_{chunk_index:06d}")

    size_bytes = 0
    try:
        with open(chunk_path, "wb") as out:
            while True:
                chunk = await upload_file.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                size_bytes += len(chunk)
    finally:
        await upload_file.close()

    received = set(int(x) for x in item_meta.get("received_chunks", []))
    received.add(int(chunk_index))
    item_meta["received_chunks"] = sorted(received)
    item_meta["status"] = "uploading"
    item_meta["updated_at"] = _utc_now_iso()

    _write_json_atomic(item_meta_path, item_meta)

    return {
        "item_id": item_id,
        "chunk_index": chunk_index,
        "chunk_size_bytes": size_bytes,
        "received_chunks": item_meta["received_chunks"],
        "total_chunks": total_chunks,
    }

def _complete_chunked_upload_item(upload_id: str, item_id: str, meta: dict) -> dict:
    item_meta_path = _upload_item_chunk_meta_path(upload_id, item_id)
    if not os.path.isfile(item_meta_path):
        raise FileNotFoundError("Chunked upload item not found")

    with open(item_meta_path, "r", encoding="utf-8") as f:
        item_meta = json.load(f)

    relative_path = item_meta.get("relative_path") or ""
    source = item_meta.get("source") or "file-picker"
    total_chunks = int(item_meta.get("total_chunks", 0))
    received_chunks = [int(x) for x in item_meta.get("received_chunks", [])]

    missing = [i for i in range(total_chunks) if i not in set(received_chunks)]
    if missing:
        raise ValueError(f"Missing chunks: {missing[:10]}{'...' if len(missing) > 10 else ''}")

    assembled_root = _upload_session_assembled_dir(upload_id)
    dest_path = os.path.join(assembled_root, relative_path)
    dest_dir = os.path.dirname(dest_path)
    os.makedirs(dest_dir, exist_ok=True)

    size_bytes = 0
    sha256 = hashlib.sha256()
    item_dir = _upload_item_chunk_dir(upload_id, item_id)

    with open(dest_path, "wb") as out:
        for i in range(total_chunks):
            chunk_path = os.path.join(item_dir, f"chunk_{i:06d}")
            with open(chunk_path, "rb") as chunk_file:
                while True:
                    buf = chunk_file.read(1024 * 1024)
                    if not buf:
                        break
                    out.write(buf)
                    sha256.update(buf)
                    size_bytes += len(buf)

    final_sha256 = sha256.hexdigest()

    _append_upload_session_item(
        meta,
        relative_path=relative_path,
        size_bytes=size_bytes,
        source=source,
        sha256=final_sha256,
    )
    _save_upload_session_meta(upload_id, meta)

    item_meta["status"] = "completed"
    item_meta["assembled_size_bytes"] = size_bytes
    item_meta["assembled_sha256"] = final_sha256
    item_meta["updated_at"] = _utc_now_iso()
    _write_json_atomic(item_meta_path, item_meta)

    return {
        "item_id": item_id,
        "relative_path": relative_path,
        "size_bytes": size_bytes,
        "source": source,
        "sha256": final_sha256,
    }


async def _stage_upload_file(
    upload_id: str,
    upload_file: UploadFile,
    *,
    relative_path: str,
    source: str,
) -> dict:
    safe_relative_path = (relative_path or "").replace("\\", "/").lstrip("/").strip()
    if not safe_relative_path:
        raise ValueError("relative_path is required")

    normalized = os.path.normpath(safe_relative_path).replace("\\", "/")
    if normalized == "." or normalized.startswith("../") or "/../" in normalized:
        raise ValueError("relative_path is invalid")

    assembled_root = _upload_session_assembled_dir(upload_id)
    dest_path = os.path.join(assembled_root, normalized)
    dest_dir = os.path.dirname(dest_path)

    os.makedirs(dest_dir, exist_ok=True)

    size_bytes = 0
    sha256 = hashlib.sha256()

    try:
        with open(dest_path, "wb") as out:
            while True:
                chunk = await upload_file.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                sha256.update(chunk)
                size_bytes += len(chunk)
    finally:
        await upload_file.close()

    return {
        "relative_path": normalized,
        "size_bytes": size_bytes,
        "source": source,
        "sha256": sha256.hexdigest(),
    }

@app.on_event("startup")
async def _init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA synchronous=NORMAL;")

        # Base jobs table (original)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at INTEGER NOT NULL,
          created_by TEXT NOT NULL,
          status TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          started_at INTEGER,
          finished_at INTEGER,
          last_error TEXT,
          last_output TEXT,
          full_output TEXT
        );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);")

        # Additive S2 columns (worker will also ensure these)
        await _ensure_column(db, "jobs", "action", "TEXT")
        await _ensure_column(db, "jobs", "role_at_create", "TEXT")
        await _ensure_column(db, "jobs", "claim_token", "TEXT")
        await _ensure_column(db, "jobs", "claimed_by", "TEXT")
        await _ensure_column(db, "jobs", "claimed_at", "INTEGER")
        await _ensure_column(db, "jobs", "full_output", "TEXT")

        # Job dedupe key (API will set; DB enforces dedupe for active jobs)
        await _ensure_column(db, "jobs", "dedupe_key", "TEXT")
        await _ensure_column(db, "jobs", "parser_type_lock", "TEXT")

        await db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created_by_created_at ON jobs(created_by, created_at);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created_by_status ON jobs(created_by, status);")

        # Dedupe indexes:
        # - Unique only while active (queued/running), so a completed job doesn't block re-submission.
        # - Partial unique index is race-safe dedupe enforcement.
        await db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uniq_jobs_dedupe_active "
            "ON jobs(action, dedupe_key) "
            "WHERE dedupe_key IS NOT NULL AND status IN ('queued','running')"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_dedupe_key "
            "ON jobs(dedupe_key)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_parser_type_lock "
            "ON jobs(action, parser_type_lock, status)"
        )

        # bulk_batches table (for bulk + undo)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS bulk_batches (
          batch_id TEXT PRIMARY KEY,
          job_id INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          created_by TEXT NOT NULL,
          case_id TEXT NOT NULL,
          index_name TEXT NOT NULL,
          kind TEXT NOT NULL,
          op TEXT NOT NULL,
          value TEXT NOT NULL,
          doc_count INTEGER NOT NULL,
          doc_ids_blob BLOB NOT NULL,
          comment_ids_blob BLOB
        );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_bulk_batches_job_id ON bulk_batches(job_id);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_bulk_batches_created_by ON bulk_batches(created_by);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_bulk_batches_case_id ON bulk_batches(case_id);")

        await db.commit()
# -------------------------
# Debug endpoints (kept)
# -------------------------

@api_v1.get("/debug/headers")
async def debug_headers(req: Request):
    c = req.headers.get("cookie", "")
    return {
        "ok": True,
        "has_cookie": bool(c),
        "cookie_preview": (c[:160] + "...") if c else "",
        "host": req.headers.get("host"),
        "x_real_ip": req.headers.get("x-real-ip"),
        "x_forwarded_for": req.headers.get("x-forwarded-for"),
        "user_agent": req.headers.get("user-agent"),
    }

@api_v1.get("/debug/authinfo")
async def debug_authinfo(req: Request):
    cookie, user, resp = _require_auth(req)
    if resp:
        return resp
    return {"ok": True, "user": user, "authinfo": _fetch_authinfo(cookie)}

@api_v1.get("/enrich")
def api_v1_enrich(
    case_id: str,
    index: str,
    id: str,
    auth=Depends(_require_auth),
):
    # auth is: (cookie, user, resp)
    cookie, user, resp = auth
    if resp:
        return resp  # JSONResponse from _require_auth (401/redirect/etc.)

    doc, err = os_get_doc(index=index, doc_id=id)

    if err:
        raise HTTPException(status_code=502, detail=f"opensearch: {err}")

    if not doc:
        raise HTTPException(status_code=404, detail="Not Found")

    src = (doc or {}).get("_source") or {}
    doc_case = src.get("case_id")
    if doc_case and doc_case != case_id:
        raise HTTPException(status_code=404, detail="Not Found")

    return {
        "ok": True,
        "user": user,
        "case_id": case_id,
        "index": index,
        "id": id,
        "doc": doc,
    }

# -------------------------
# Enrichment entry validation (server-derives case_id)
# -------------------------

@api_v1.get("/enrich/resolve")
async def enrich_resolve(req: Request, case_id: str, index: str, id: str):
    """
    Called by UI when user lands from Add_Enrichment link.
    Validates that querystring case_id matches the document's actual case_id in OS.

    Returns { ok, derived_case_id, index, id, user }
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    if not RE_CASE_ID.match(case_id):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid case_id"})
    if not RE_INDEX.match(index):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid index"})
    if not RE_DOC_ID.match(id):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid id"})

    derived, err = os_get_case_id(index, id)
    if err:
        return JSONResponse(status_code=400, content={"ok": False, "error": err})

    if derived != case_id:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "case_id mismatch",
                "provided_case_id": case_id,
                "derived_case_id": derived
            }
        )

    return {"ok": True, "user": user, "derived_case_id": derived, "index": index, "id": id}


# -------------------------
# Tags YAML sources (served to UI)
# -------------------------

def _tags_source_path(name: str) -> str:
    """
    Resolve a tag source name (without extension) to an on-disk YAML path
    under TAGS_DIR. Rejects traversal and invalid names.
    """
    if not RE_TAG_SOURCE.match(name):
        raise HTTPException(status_code=400, detail="invalid tag source name")

    base = os.path.abspath(TAGS_DIR)
    # prefer .yml, then .yaml
    cands = [
        os.path.abspath(os.path.join(base, f"{name}.yml")),
        os.path.abspath(os.path.join(base, f"{name}.yaml")),
    ]

    # Ensure resolved paths remain under TAGS_DIR
    for p in cands:
        if not p.startswith(base + os.sep):
            continue
        if os.path.isfile(p):
            return p

    raise HTTPException(status_code=404, detail="tag source not found")

@api_v1.get("/tags/sources")
async def tags_sources(req: Request):
    """
    List YAML tag sources in TAGS_DIR.

    Returns:
      { ok: true, sources: [ { name, filename } ] }
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    base = os.path.abspath(TAGS_DIR)
    if not os.path.isdir(base):
        return {"ok": True, "user": user, "sources": []}

    sources = []
    try:
        for fn in sorted(os.listdir(base)):
            # only .yml/.yaml
            if not (fn.endswith(".yml") or fn.endswith(".yaml")):
                continue
            name = fn.rsplit(".", 1)[0]
            if not RE_TAG_SOURCE.match(name):
                continue
            sources.append({"name": name, "filename": fn})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to list tags: {e}")

    return {"ok": True, "user": user, "sources": sources}

@api_v1.get("/tags/source")
async def tags_source(req: Request, name: str):
    """
    Fetch a YAML tag source file content by name (without extension).

    Returns:
      { ok: true, name, filename, yaml }
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    path = _tags_source_path(name)
    fn = os.path.basename(path)

    try:
        with open(path, "rb") as f:
            data = f.read(MAX_TAGS_YAML_BYTES + 1)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to read tag source: {e}")

    if len(data) > MAX_TAGS_YAML_BYTES:
        raise HTTPException(status_code=413, detail="tag source too large")

    # Best-effort UTF-8 decode; UI expects text
    yaml_text = data.decode("utf-8", "replace")

    return {"ok": True, "user": user, "name": name, "filename": fn, "yaml": yaml_text}

async def _find_active_parser_job(db: aiosqlite.Connection, parser_type: str):
    cur = await db.execute(
        """
        SELECT id, action
          FROM jobs
         WHERE status IN ('queued','running')
           AND action IN ('parser_enable','parser_disable','parser_update','parser_delete','parser_new')
           AND json_extract(payload_json, '$.type') = ?
         ORDER BY id DESC
         LIMIT 1
        """,
        (parser_type,),
    )
    return await cur.fetchone()

@api_v1.get("/parsers")
async def parsers_list(req: Request):
    """
    List parser definitions from parsers.yml.

    Read-only endpoint:
      - direct file read, same pattern as tags
      - no job queue needed
      - no dfir subprocess call
    """
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    data = _load_parsers_from_yaml()
    data["ok"] = True
    data["user"] = user
    return data

@api_v1.post("/parsers")
async def parser_create(req: Request, body: ParserCreateSubmit):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    type = (body.type or "").strip()
    if not type:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type is required"})
    if len(type) > 128:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 128)"})
    if re.search(r"\s", type):
        return JSONResponse(status_code=400, content={"ok": False, "error": "type cannot contain spaces"})

    patterns = [str(x).strip() for x in (body.patterns or []) if str(x).strip()]
    if not patterns:
        return JSONResponse(status_code=400, content={"ok": False, "error": "patterns is required"})

    bin = (body.bin or "").strip()
    if not bin:
        return JSONResponse(status_code=400, content={"ok": False, "error": "bin is required"})

    args = [str(x).strip() for x in (body.args or []) if str(x).strip()]
    route_mode = (body.route_mode or "").strip()
    if not route_mode:
        return JSONResponse(status_code=400, content={"ok": False, "error": "route_mode is required"})

    expand_archives = (body.expand_archives or "").strip()
    timezone = (body.timezone or "").strip()
    fingerprint_fields = None
    if body.fingerprint_fields is not None:
        fingerprint_fields = [str(x).strip() for x in body.fingerprint_fields if str(x).strip()]

    now = int(time.time())
    action = "parser_new"
    payload = {
        "type": type,
        "patterns_csv": ",".join(patterns),
        "bin": bin,
        "args": args,
        "route_mode": route_mode,
        "expand_archives": expand_archives,
        "timezone": timezone,
        "inherit_type": "true" if body.inherit_type else "false",
        "force": "true" if body.force else "false",
    }
    if fingerprint_fields is not None:
        payload["fingerprint_fields"] = fingerprint_fields
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    dedupe_material = f"v1|parser_new|{type}|{payload_json}"
    dedupe_key = hashlib.sha256(dedupe_material.encode("utf-8")).hexdigest()

    async with aiosqlite.connect(DB_PATH) as db:
        row = await _find_active_parser_job(db, type)
        if row:
            existing_id, existing_action = row
            print(f"[job dedupe] existing_id={existing_id} action={existing_action} user={user} payload={payload} parser_type_lock={type}")
            return {
                "ok": True,
                "status": "already_queued",
                "job_id": existing_id,
                "action": existing_action,
                **payload,
            }

        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, user, "queued", action, dedupe_key, payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
            return {"ok": True, "status": "queued", "job_id": job_id, "action": action, **payload}

        except aiosqlite.Error as e:
            msg = str(e).lower()
            if "unique" in msg or "constraint" in msg:
                cur = await db.execute(
                    """
                    SELECT id
                      FROM jobs
                     WHERE action = ?
                       AND dedupe_key = ?
                       AND status IN ('queued','running')
                     ORDER BY id DESC
                     LIMIT 1
                    """,
                    (action, dedupe_key),
                )
                row = await cur.fetchone()
                existing_id = row[0] if row else None
                if existing_id:
                    print(f"[job dedupe] existing_id={existing_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
                    return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": action, **payload}

            return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})

@api_v1.patch("/parsers/{type}")
async def parser_update(type: str, req: Request, body: ParserUpdateSubmit):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    type = (type or "").strip()
    if not type:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type is required"})
    if len(type) > 128:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 128)"})
    if re.search(r"\s", type):
        return JSONResponse(status_code=400, content={"ok": False, "error": "type cannot contain spaces"})

    try:
        raw_body = await req.json()
        if not isinstance(raw_body, dict):
            raw_body = {}
    except Exception:
        raw_body = {}

    payload = {"type": type}
    changed = 0

    if body.patterns is not None:
        patterns = [str(x).strip() for x in body.patterns if str(x).strip()]
        payload["patterns_csv"] = ",".join(patterns)
        changed += 1

    if body.bin is not None:
        payload["bin"] = (body.bin or "").strip()
        changed += 1

    if body.args is not None:
        args = [str(x).strip() for x in body.args if str(x).strip()]
        payload["args"] = args
        changed += 1

    if body.route_mode is not None:
        payload["route_mode"] = (body.route_mode or "").strip()
        changed += 1

    if body.expand_archives is not None:
        payload["expand_archives"] = (body.expand_archives or "").strip()
        changed += 1

    if body.timezone is not None:
        payload["timezone"] = (body.timezone or "").strip()
        changed += 1

    if body.inherit_type is not None:
        payload["inherit_type"] = "true" if body.inherit_type else "false"
        changed += 1

    if "fingerprint_fields" in raw_body:
        if raw_body["fingerprint_fields"] is None:
            payload["clear_fingerprint_fields"] = "true"
        else:
            fingerprint_fields = [
                str(x).strip()
                for x in (body.fingerprint_fields or [])
                if str(x).strip()
            ]
            payload["fingerprint_fields"] = fingerprint_fields
        changed += 1

    if changed == 0:
        return JSONResponse(status_code=400, content={"ok": False, "error": "nothing to update"})

    now = int(time.time())
    action = "parser_update"
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    dedupe_material = f"v1|parser_update|{type}|{payload_json}"
    dedupe_key = hashlib.sha256(dedupe_material.encode("utf-8")).hexdigest()

    async with aiosqlite.connect(DB_PATH) as db:
        row = await _find_active_parser_job(db, type)
        if row:
            existing_id, existing_action = row
            print(f"[job dedupe] existing_id={existing_id} action={existing_action} user={user} payload={payload} parser_type_lock={type}")
            return {
                "ok": True,
                "status": "already_queued",
                "job_id": existing_id,
                "action": existing_action,
                **payload,
            }

        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json, parser_type_lock) VALUES (?, ?, 'queued', ?, ?, ?, ?)",
                (now, user, action, dedupe_key, payload_json, type),
            )
            await db.commit()
            job_id = cur.lastrowid
        except aiosqlite.IntegrityError:
            row = await _find_active_parser_job(db, type)
            if row:
                existing_id, existing_action = row
                print(f"[job dedupe] race-hit existing_id={existing_id} action={existing_action} user={user} payload={payload} parser_type_lock={type}")
                return {
                    "ok": True,
                    "status": "already_queued",
                    "job_id": existing_id,
                    "action": existing_action,
                    **payload,
                }
            raise

    return {"ok": True, "job_id": job_id, "action": action, **payload}

@api_v1.delete("/parsers/{type}")
async def parser_delete(type: str, req: Request):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    type = (type or "").strip()
    if not type:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type is required"})
    if len(type) > 128:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 128)"})
    if re.search(r"\s", type):
        return JSONResponse(status_code=400, content={"ok": False, "error": "type cannot contain spaces"})

    now = int(time.time())
    action = "parser_delete"
    payload = {"type": type}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    dedupe_material = f"v1|parser_delete|{type}"
    dedupe_key = hashlib.sha256(dedupe_material.encode("utf-8")).hexdigest()

    async with aiosqlite.connect(DB_PATH) as db:
        row = await _find_active_parser_job(db, type)
        if row:
            existing_id, existing_action = row
            print(f"[job dedupe] existing_id={existing_id} action={existing_action} user={user} payload={payload} parser_type_lock={type}")
            return {
                "ok": True,
                "status": "already_queued",
                "job_id": existing_id,
                "action": existing_action,
                **payload,
            }

        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, user, "queued", action, dedupe_key, payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
            return {"ok": True, "status": "queued", "job_id": job_id, "action": action, **payload}

        except aiosqlite.Error as e:
            msg = str(e).lower()
            if "unique" in msg or "constraint" in msg:
                cur = await db.execute(
                    """
                    SELECT id
                      FROM jobs
                     WHERE action = ?
                       AND dedupe_key = ?
                       AND status IN ('queued','running')
                     ORDER BY id DESC
                     LIMIT 1
                    """,
                    (action, dedupe_key),
                )
                row = await cur.fetchone()
                existing_id = row[0] if row else None
                if existing_id:
                    print(f"[job dedupe] existing_id={existing_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
                    return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": action, **payload}

            return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})

@api_v1.post("/parsers/{type}/enable")
async def parser_enable(type: str, req: Request):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    type = (type or "").strip()
    if not type:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type is required"})
    if len(type) > 128:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 128)"})
    if re.search(r"\s", type):
        return JSONResponse(status_code=400, content={"ok": False, "error": "type cannot contain spaces"})

    now = int(time.time())
    action = "parser_enable"
    payload = {"type": type}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    dedupe_material = f"v1|parser_enable|{type}"
    dedupe_key = hashlib.sha256(dedupe_material.encode("utf-8")).hexdigest()

    async with aiosqlite.connect(DB_PATH) as db:
        row = await _find_active_parser_job(db, type)
        if row:
            existing_id, existing_action = row
            print(f"[job dedupe] existing_id={existing_id} action={existing_action} user={user} payload={payload} parser_type_lock={type}")
            return {
                "ok": True,
                "status": "already_queued",
                "job_id": existing_id,
                "action": existing_action,
                **payload,
            }

        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, user, "queued", action, dedupe_key, payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
            return {"ok": True, "status": "queued", "job_id": job_id, "action": action, **payload}

        except aiosqlite.Error as e:
            msg = str(e).lower()
            if "unique" in msg or "constraint" in msg:
                cur = await db.execute(
                    """
                    SELECT id
                      FROM jobs
                     WHERE action = ?
                       AND dedupe_key = ?
                       AND status IN ('queued','running')
                     ORDER BY id DESC
                     LIMIT 1
                    """,
                    (action, dedupe_key),
                )
                row = await cur.fetchone()
                existing_id = row[0] if row else None
                if existing_id:
                    print(f"[job dedupe] existing_id={existing_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
                    return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": action, **payload}

            return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})

@api_v1.post("/parsers/{type}/disable")
async def parser_disable(type: str, req: Request):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    type = (type or "").strip()
    if not type:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type is required"})
    if len(type) > 128:
        return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 128)"})
    if re.search(r"\s", type):
        return JSONResponse(status_code=400, content={"ok": False, "error": "type cannot contain spaces"})

    now = int(time.time())
    action = "parser_disable"
    payload = {"type": type}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    dedupe_material = f"v1|parser_disable|{type}"
    dedupe_key = hashlib.sha256(dedupe_material.encode("utf-8")).hexdigest()

    async with aiosqlite.connect(DB_PATH) as db:
        row = await _find_active_parser_job(db, type)
        if row:
            existing_id, existing_action = row
            print(f"[job dedupe] existing_id={existing_id} action={existing_action} user={user} payload={payload} parser_type_lock={type}")
            return {
                "ok": True,
                "status": "already_queued",
                "job_id": existing_id,
                "action": existing_action,
                **payload,
            }

        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, user, "queued", action, dedupe_key, payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
            return {"ok": True, "status": "queued", "job_id": job_id, "action": action, **payload}

        except aiosqlite.Error as e:
            msg = str(e).lower()
            if "unique" in msg or "constraint" in msg:
                cur = await db.execute(
                    """
                    SELECT id
                      FROM jobs
                     WHERE action = ?
                       AND dedupe_key = ?
                       AND status IN ('queued','running')
                     ORDER BY id DESC
                     LIMIT 1
                    """,
                    (action, dedupe_key),
                )
                row = await cur.fetchone()
                existing_id = row[0] if row else None
                if existing_id:
                    print(f"[job dedupe] existing_id={existing_id} action={action} user={user} payload={payload} dedupe={dedupe_key}")
                    return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": action, **payload}

            return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})


# -------------------------
# Event fetch (server-side proxy to OpenSearch)
# -------------------------

def os_get_doc(index: str, doc_id: str, source: bool = True) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (doc, error). doc contains: _index, _id, _version, _source.
    """
    if not RE_INDEX.match(index):
        return None, "invalid index"
    if not RE_DOC_ID.match(doc_id):
        return None, "invalid id"

    missing = _os_ready()
    if missing:
        return None, missing

    # Allow callers to fetch metadata-only without _source if they want
    url = f"{OS_HOST.rstrip('/')}/{index}/_doc/{doc_id}"
    if not source:
        url += "?_source=false"

    try:
        r = requests.get(
            url,
            auth=(OS_USER, OS_PASS),
            timeout=10,
            verify=_os_verify_param(),
        )
    except Exception as e:
        return None, f"opensearch request failed: {e}"

    if r.status_code == 404:
        return None, "document not found"
    if r.status_code != 200:
        return None, f"opensearch error {r.status_code}: {r.text[:200]}"

    try:
        j = r.json()
    except Exception:
        return None, "opensearch returned non-json"

    doc = {
        "_index": j.get("_index") or index,
        "_id": j.get("_id") or doc_id,
        "_version": j.get("_version"),
        "_source": (j.get("_source") or {}) if source else {},
    }
    return doc, None

@api_v1.get("/event")
async def event_get(req: Request, case_id: str, index: str, id: str, truncate_event_original: int = 0):
    """
    Fetch an OpenSearch document for UI display.

    Security model:
      - Requires OSD cookie auth (same as /jobs)
      - Validates provided case_id matches the doc's true case_id in OpenSearch

    Query params:
      - case_id, index, id (required)
      - truncate_event_original: if >0, truncate event.original to this many chars (UI safety)
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    if not RE_CASE_ID.match(case_id):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid case_id"})
    if not RE_INDEX.match(index):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid index"})
    if not RE_DOC_ID.match(id):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid id"})

    derived, err = os_get_case_id(index, id)
    if err:
        return JSONResponse(status_code=400, content={"ok": False, "error": err})
    if derived != case_id:
        return JSONResponse(
            status_code=403,
            content={"ok": False, "error": "case_id mismatch", "provided_case_id": case_id, "derived_case_id": derived},
        )

    doc, err = os_get_doc(index, id)
    if err:
        return JSONResponse(status_code=400, content={"ok": False, "error": err})

    # Optional truncation for massive payloads (keeps UI snappy / avoids huge responses).
    if truncate_event_original and isinstance(truncate_event_original, int) and truncate_event_original > 0:
        src = doc.get("_source") or {}
        ev = src.get("event")
        if isinstance(ev, dict):
            orig = ev.get("original")
            if isinstance(orig, str) and len(orig) > truncate_event_original:
                ev["original"] = orig[:truncate_event_original] + f"... (truncated, len={len(orig)})"

    return {
        "ok": True,
        "user": user,
        "case_id": case_id,
        "index": index,
        "id": id,
        "doc": doc,
    }

# -------------------------
# Jobs API (generic)
# -------------------------



class BulkHit(BaseModel):
    index: str = Field(..., min_length=1, max_length=128)
    id: str = Field(..., min_length=64, max_length=64)
    # case_id is intentionally NOT accepted from the client per lock.

class JobSubmit(BaseModel):
    action: Literal[
        "tag_add", "tag_add_bulk",
        "comment_add",
        "ioc_add", "ioc_add_bulk", "ioc_del", "ioc_del_bulk",
        "timeline_add", "timeline_del",
        "collection_add", "collection_del",
        "collection_add_bulk", "collection_del_bulk",
    ]
    # seed context (from Add_Enrichment)
    seed_index: str = Field(..., min_length=1, max_length=128)
    seed_id: str = Field(..., min_length=64, max_length=64)
    seed_case_id: str = Field(..., min_length=1, max_length=64)  # provided in link; we verify against derived

    # tag/comment params
    tag: Optional[str] = Field(None, max_length=MAX_TAG_LEN)
    text: Optional[str] = Field(None, max_length=MAX_COMMENT_LEN)

    # IOC params
    type: Optional[str] = Field(None, max_length=32)
    value: Optional[str] = Field(None, max_length=512)
    field: Optional[str] = Field(None, max_length=128)

    # collections params
    name: Optional[str] = Field(None, max_length=256)

    # bulk only (tag_add_bulk / ioc_add_bulk / collection_*_bulk)
    hits: Optional[List[BulkHit]] = None

    @root_validator(pre=True)
    def _enforce_action_requirements(cls, values):
        action = values.get("action")

        tag = (values.get("tag") or "").strip()
        text = (values.get("text") or "").strip()

        type = (values.get("type") or "").strip()
        value = (values.get("value") or "").strip()
        field = (values.get("field") or "").strip()

        name = (values.get("name") or "").strip()
        hits = values.get("hits")

        # Write normalized/trimmed values back so downstream code sees stable payloads.
        # (Also makes dedupe keys stable.)
        if "tag" in values:
            values["tag"] = tag or None
        if "text" in values:
            values["text"] = text or None
        if "type" in values:
            values["type"] = type or None
        if "value" in values:
            values["value"] = value or None
        if "field" in values:
            values["field"] = field or None
        if "name" in values:
            values["name"] = name or None

        # --- tag actions ---
        if action in ("tag_add", "tag_add_bulk"):
            if not tag:
                raise ValueError("tag is required for tag_add/tag_add_bulk")
            # tag actions must not accept IOC fields
            if type or value or field:
                raise ValueError("ioc_* fields are not allowed for tag_add/tag_add_bulk")
            # tag actions must not accept text
            if text:
                raise ValueError("text is not allowed for tag_add/tag_add_bulk")
            # tag actions must not accept collections name
            if name:
                raise ValueError("name is not allowed for tag_add/tag_add_bulk")

            if action == "tag_add":
                if hits not in (None, [], ()):
                    raise ValueError("hits is not allowed for tag_add")
            else:  # tag_add_bulk
                if not hits:
                    raise ValueError("hits is required for tag_add_bulk")

        # --- comment action ---
        elif action == "comment_add":
            if not text:
                raise ValueError("text is required for comment_add")
            if hits not in (None, [], ()):
                raise ValueError("hits is not allowed for comment_add")
            if tag:
                raise ValueError("tag is not allowed for comment_add")
            if type or value or field:
                raise ValueError("ioc_* fields are not allowed for comment_add")
            if name:
                raise ValueError("name is not allowed for comment_add")

        # --- IOC actions ---
        elif action in ("ioc_add", "ioc_add_bulk", "ioc_del", "ioc_del_bulk"):
            if not type:
                raise ValueError("type is required for ioc_add/ioc_add_bulk/ioc_del/ioc_del_bulk")
            if not value:
                raise ValueError("value is required for ioc_add/ioc_add_bulk/ioc_del/ioc_del_bulk")
            if tag:
                raise ValueError("tag is not allowed for ioc_add/ioc_add_bulk/ioc_del/ioc_del_bulk")
            if text:
                raise ValueError("text is not allowed for ioc_add/ioc_add_bulk/ioc_del/ioc_del_bulk")
            if name:
                raise ValueError("name is not allowed for ioc_add/ioc_add_bulk/ioc_del/ioc_del_bulk")

            if action in ("ioc_add", "ioc_del"):
                if hits not in (None, [], ()):
                    raise ValueError("hits is not allowed for ioc_add/ioc_del")
            else:
                if not hits:
                    raise ValueError("hits is required for ioc_add_bulk/ioc_del_bulk")

        # --- timeline actions ---
        elif action in ("timeline_add", "timeline_del"):
            # timeline actions only operate on the seed doc (for now)
            if hits not in (None, [], ()):
                raise ValueError("hits is not allowed for timeline_add/timeline_del")
            if tag:
                raise ValueError("tag is not allowed for timeline_add/timeline_del")
            if text:
                raise ValueError("text is not allowed for timeline_add/timeline_del")
            if type or value or field:
                raise ValueError("ioc_* fields are not allowed for timeline_add/timeline_del")
            if name:
                raise ValueError("name is not allowed for timeline_add/timeline_del")

        # --- collection actions ---
        elif action in ("collection_add", "collection_del", "collection_add_bulk", "collection_del_bulk"):
            if not name:
                raise ValueError("name is required for collection_*")
            if tag:
                raise ValueError("tag is not allowed for collection_*")
            if text:
                raise ValueError("text is not allowed for collection_*")
            if type or value or field:
                raise ValueError("ioc_* fields are not allowed for collection_*")

            if action in ("collection_add", "collection_del"):
                if hits not in (None, [], ()):
                    raise ValueError("hits is not allowed for collection_add/collection_del")
            else:  # *_bulk
                if not hits:
                    raise ValueError("hits is required for collection_add_bulk/collection_del_bulk")

        else:
            # Defensive: should never happen due to Literal, but keeps errors clear if model changes.
            raise ValueError(f"unsupported action: {action}")

        return values

class JobSearchSubmit(BaseModel):
    action: Literal[
        "tag_add_bulk",
        "ioc_add_bulk",
        "ioc_del_bulk",
        "collection_add_bulk",
        "collection_del_bulk",
    ]
    # seed context (same verification model as existing endpoints)
    seed_index: str = Field(..., min_length=1, max_length=128)
    seed_id: str = Field(..., min_length=64, max_length=64)
    seed_case_id: str = Field(..., min_length=1, max_length=64)

    # search semantics (same as search/ioc)
    type: str = Field(..., min_length=1, max_length=32)
    value: str = Field(..., min_length=1, max_length=MAX_IOC_LEN)
    mode: str = Field("wildcard", min_length=1, max_length=32)
    smart: str = Field("auto", min_length=1, max_length=32)
    include_terms: Optional[Dict[str, List[str]]] = None
    exclude_terms: Optional[Dict[str, List[str]]] = None

    # confirmation / safety
    expected_total: Optional[int] = None

    # tag / IOC / collection params
    tag: Optional[str] = Field(None, max_length=MAX_TAG_LEN)
    type_ioc: Optional[str] = Field(None, max_length=32, alias="ioc_type")
    value_ioc: Optional[str] = Field(None, max_length=512, alias="ioc_value")
    field: Optional[str] = Field(None, max_length=128)
    name: Optional[str] = Field(None, max_length=256)

    class Config:
        allow_population_by_field_name = True

    @root_validator(pre=True)
    def _norm(cls, values):
        values["type"] = (values.get("type") or "").strip()
        values["value"] = (values.get("value") or "").strip()

        m = (values.get("mode") or "wildcard").strip().lower()
        s = (values.get("smart") or "auto").strip().lower()
        if m not in ("wildcard", "smart"):
            m = "wildcard"
        if s not in ("auto", "match", "match_phrase"):
            s = "auto"
        values["mode"] = m
        values["smart"] = s

        if "tag" in values:
            values["tag"] = ((values.get("tag") or "").strip() or None)
        if "ioc_type" in values:
            values["ioc_type"] = ((values.get("ioc_type") or "").strip() or None)
        if "ioc_value" in values:
            values["ioc_value"] = ((values.get("ioc_value") or "").strip() or None)
        if "field" in values:
            values["field"] = ((values.get("field") or "").strip() or None)
        if "name" in values:
            values["name"] = ((values.get("name") or "").strip() or None)

        return values

def _validate_seed(seed_case_id: str, seed_index: str, seed_id: str) -> Tuple[Optional[str], Optional[JSONResponse]]:
    if not RE_CASE_ID.match(seed_case_id):
        return None, JSONResponse(status_code=400, content={"ok": False, "error": "invalid seed_case_id"})
    if not RE_INDEX.match(seed_index):
        return None, JSONResponse(status_code=400, content={"ok": False, "error": "invalid seed_index"})
    if not RE_DOC_ID.match(seed_id):
        return None, JSONResponse(status_code=400, content={"ok": False, "error": "invalid seed_id"})

    derived, err = os_get_case_id(seed_index, seed_id)
    if err:
        return None, JSONResponse(status_code=400, content={"ok": False, "error": f"seed lookup failed: {err}"})

    if derived != seed_case_id:
        return None, JSONResponse(
            status_code=403,
            content={"ok": False, "error": "seed case_id mismatch", "provided": seed_case_id, "derived": derived}
        )
    return derived, None

# -------------------------
# IOC search (server-side OpenSearch query)
# -------------------------

class IocSearchSubmit(BaseModel):
    # seed context (from Add_Enrichment)
    seed_index: str = Field(..., min_length=1, max_length=128)
    seed_id: str = Field(..., min_length=64, max_length=64)
    seed_case_id: str = Field(..., min_length=1, max_length=64)

    # IOC params
    type: str = Field(..., min_length=1, max_length=32)
    value: str = Field(..., min_length=1, max_length=MAX_IOC_LEN)

    # behavior
    include_hits: bool = False
    limit: int = 5000  # only used when include_hits=true (max 10k)
    page_size: Optional[int] = None
    search_after: Optional[List[Any]] = None

    # - wildcard: substring search on .wc field (best for pivot-from-highlight)
    # - smart: analyzed text search on text field (match/match_phrase)
    mode: str = Field("wildcard", min_length=1, max_length=32)   # "wildcard" | "smart"
    smart: str = Field("auto", min_length=1, max_length=32)      # "auto" | "match" | "match_phrase"
    include_terms: Optional[Dict[str, List[str]]] = None
    exclude_terms: Optional[Dict[str, List[str]]] = None


    @root_validator(pre=True)
    def _norm(cls, values):
        t = (values.get("type") or "").strip()
        v = (values.get("value") or "").strip()
        values["type"] = t
        values["value"] = v

        # normalize new fields
        m = (values.get("mode") or "wildcard").strip().lower()
        s = (values.get("smart") or "auto").strip().lower()

        # clamp to allowed values (don’t 422 clients who send junk; just default)
        if m not in ("wildcard", "smart"):
            m = "wildcard"
        if s not in ("auto", "match", "match_phrase"):
            s = "auto"

        values["mode"] = m
        values["smart"] = s
        return values

def os_search_ioc(
    case_id: str,
    value: str,
    size: int = 200,
    *,
    mode: str = "wildcard",
    smart: str = "auto",
    include_terms: Optional[Dict[str, List[str]]] = None,
    exclude_terms: Optional[Dict[str, List[str]]] = None,
    search_after: Optional[List[Any]] = None,
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Returns (json, error). Searches within alias all-json, filtered by case_id.
    - Always uses track_total_hits so caller gets accurate total.
    - size controls number of returned hits (0 => count only).

    Modes:
      - mode="wildcard": substring search using wildcard field(s) (.wc)
      - mode="smart": token/phrase search on text base field
          smart="auto": match_phrase if whitespace else match(AND)
          smart="match": match only (AND)
          smart="match_phrase": match_phrase only

    Paging:
      - search_after: optional cursor from the previous page's last hit sort values
    """

    missing = _os_ready()
    if missing:
        return None, missing

    value = (value or "").strip()
    if not value:
        return None, "value is empty"
    # clamp
    if size < 0:
        size = 0
    if size > 10_000:
        size = 10_000

    mode = (mode or "wildcard").strip().lower()
    smart = (smart or "auto").strip().lower()
    if mode not in ("wildcard", "smart"):
        mode = "wildcard"
    if smart not in ("auto", "match", "match_phrase"):
        smart = "auto"

    target = "all-json"
    url = f"{OS_HOST.rstrip('/')}/{target}/_search"

    # ---- helpers ----
    def escape_wildcard_literal(s: str) -> str:
        """
        Escape user input so it is treated literally inside a wildcard pattern.
        Only escape: backslash, * and ?
        """
        return (s or "").replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")

    def build_wildcard_pattern(raw: str) -> str:
        """
        Always do a contains-substring search: *value*
        """
        return f"*{escape_wildcard_literal(raw)}*"

    wildcard_pattern = build_wildcard_pattern(value)

    # ---- query per mode ----
    if mode == "wildcard":
        # OR across a small set of common blob_preview wc fields.
        # (You can't wildcard the field name in a term-level wildcard query.)
        should = [
            {
                "wildcard": {
                    "event.blob_preview.event_original.wc": {
                        "value": wildcard_pattern,
                        "case_insensitive": True,
                    }
                }
            },
            {
                "wildcard": {
                    "event.blob_preview.message.wc": {
                        "value": wildcard_pattern,
                        "case_insensitive": True,
                    }
                }
            },
        ]

        must_query = {
            "bool": {
                "should": should,
                "minimum_should_match": 1,
            }
        }

    else:
        # smart mode: intentionally target the base text field ONLY,
        # to align with "Search in OSD" phrase semantics.
        field = "event.blob_preview.event_original"

        if smart == "match":
            must_query = {
                "match": {
                    field: {
                        "query": value, 
                        "operator": "AND",
                    }
                }
            }

        elif smart == "match_phrase":
            must_query = {
                "match_phrase": {
                    field: {
                        "query": value
                    }
                }
            }

        else:  # auto
            if any(ch.isspace() for ch in value):
                must_query = {
                    "match_phrase": {
                        field: {
                            "query": value
                        }
                    }
                }
            else:
                must_query = {
                    "match": {
                        field: {
                            "query": value,
                            "operator": "AND",
                        }
                    }
                }

    # Build additional include/exclude term filters (facets)
    extra_filters = []
    must_not = []
    
    def _clean_terms_map(m):
        out = {}
        if not isinstance(m, dict):
            return out
        for k, v in m.items():
            kk = str(k or "").strip()
            if not kk:
                continue
            vals = []
            if isinstance(v, list):
                for x in v:
                    sx = str(x).strip()
                    if sx:
                        vals.append(sx)
            if vals:
                out[kk] = vals
        return out
    
    inc = _clean_terms_map(include_terms)
    exc = _clean_terms_map(exclude_terms)
    
    for f, vals in inc.items():
        extra_filters.append({"terms": {f: vals}})
    
    for f, vals in exc.items():
        must_not.append({"terms": {f: vals}})
    
    bool_q = {
        "filter": [{"term": {"case_id": case_id}}] + extra_filters,
        "must": [must_query],
    }
    
    if must_not:
        bool_q["must_not"] = must_not

    body = {
        "track_total_hits": True,
        "size": size,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"_index": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
        "_source": {
            "includes": [
                "@timestamp",
                "source_type",
                "event_summary",
                "event_in_timeline",
                "event_in_artefacts",
                "event_collections",
                "tags",
                "event.iocs",
                "event.comments.count"
            ]
        },
        "query": {
            "bool": bool_q
        },
    }

    if search_after:
        body["search_after"] = search_after

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            timeout=20,
            verify=_os_verify_param(),
            headers={"content-type": "application/json"},
            data=json.dumps(body),
        )
    except Exception as e:
        return None, f"opensearch request failed: {e}"

    if r.status_code != 200:
        return None, f"opensearch error {r.status_code}: {r.text[:200]}"

    try:
        return r.json(), None
    except Exception:
        return None, "opensearch returned non-json"

def os_collect_search_hits(
    case_id: str,
    value: str,
    *,
    mode: str = "wildcard",
    smart: str = "auto",
    include_terms: Optional[Dict[str, List[str]]] = None,
    exclude_terms: Optional[Dict[str, List[str]]] = None,
    page_size: int = 500,
    max_docs: int = 200000,
) -> Tuple[Optional[List[Dict[str, str]]], Optional[int], Optional[str]]:
    """
    Collect all matching hits for a search scope using search_after paging.

    Returns: (targets, total, error)
      - targets: [{"index": "...", "id": "..."}, ...]
      - total: full OpenSearch total
      - error: error string or None
    """
    if page_size <= 0:
        page_size = 500
    if page_size > 5000:
        page_size = 5000
    if max_docs <= 0:
        max_docs = 200000

    collected: List[Dict[str, str]] = []
    search_after: Optional[List[Any]] = None
    total: Optional[int] = None

    while True:
        j, err = os_search_ioc(
            case_id,
            value,
            size=page_size,
            mode=mode,
            smart=smart,
            include_terms=include_terms,
            exclude_terms=exclude_terms,
            search_after=search_after,
        )
        if err:
            return None, None, err
        if not j:
            return None, None, "search returned no response"

        if total is None:
            total = int(((j.get("hits") or {}).get("total") or {}).get("value") or 0)

        hits_block = j.get("hits") or {}
        hits = hits_block.get("hits") or []
        if not hits:
            break

        for h in hits:
            ix = h.get("_index")
            did = h.get("_id")
            if ix and did:
                collected.append({"index": str(ix), "id": str(did)})
                if len(collected) > max_docs:
                    return None, total, f"too many matching documents (>{max_docs})"

        last_sort = hits[-1].get("sort")
        if not isinstance(last_sort, list) or not last_sort:
            break
        search_after = last_sort

        if len(hits) < page_size:
            break

    return collected, (total or 0), None

def os_list_collections(
    case_id: str,
    *,
    q: Optional[str] = None,
    size: int = 500,
) -> Tuple[Optional[list], Optional[str]]:
    """
    Returns (items, error). Uses a terms aggregation over event_collections.keyword.
    Filters by case_id. Optionally filters bucket keys by prefix via q.
    """
    missing = _os_ready()
    if missing:
        return None, missing

    case_id = (case_id or "").strip()
    if not case_id:
        return None, "case_id is empty"

    if size < 1:
        size = 1
    if size > 5000:
        size = 5000

    target = "all-json"
    url = f"{OS_HOST.rstrip('/')}/{target}/_search"

    # Optional prefix filter for buckets
    include = None
    if q is not None:
        qq = (q or "").strip()
        if qq:
            # case-insensitive "starts with"
            include = f"(?i){re.escape(qq)}.*"

    body = {
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"case_id": case_id}},
                    {"exists": {"field": "event_collections"}},
                ]
            }
        },
        "aggs": {
            "collections": {
                "terms": {
                    "field": "event_collections.keyword",
                    "size": size,
                    "order": {"_key": "asc"},
                    **({"include": include} if include else {}),
                }
            }
        },
    }

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            json=body,
            verify=OS_CACERT if OS_CACERT else True,
            timeout=30,
        )
        if r.status_code >= 300:
            return None, f"OpenSearch error {r.status_code}: {r.text[:300]}"
        data = r.json() if r.text else {}
        buckets = (((data.get("aggregations") or {}).get("collections") or {}).get("buckets") or [])
        items = [b.get("key") for b in buckets if isinstance(b, dict) and b.get("key")]
        return items, None
    except Exception as e:
        return None, str(e)


@api_v1.get("/collections")
def api_collections_list(case_id: str, q: Optional[str] = None, size: int = 500):
    items, err = os_list_collections(case_id, q=q, size=size)
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "items": items}

@api_v1.post("/search/ioc")
async def search_ioc(req: Request, body: IocSearchSubmit):
    """
    Search matching events for an IOC within the seed's derived case_id.

    Returns:
      { ok, case_id, type, value, mode, smart, total, returned, hits:[{index,id}...]? }
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    derived_case_id, bad = _validate_seed(body.seed_case_id, body.seed_index, body.seed_id)
    if bad:
        return bad

    ioc_value = (body.value or "").strip()
    if not ioc_value:
        return JSONResponse(status_code=400, content={"ok": False, "error": "value is empty after trim"})
    if len(ioc_value) > MAX_IOC_LEN:
        return JSONResponse(status_code=400, content={"ok": False, "error": f"value too long (max {MAX_IOC_LEN})"})

    include_hits = bool(body.include_hits)
    limit = int(body.limit or 0)
    if limit <= 0:
        limit = 5000
    if limit > MAX_BULK_DOCS:
        limit = MAX_BULK_DOCS

    page_size = int(body.page_size or 0)
    if page_size <= 0:
        page_size = limit
    if page_size > MAX_BULK_DOCS:
        page_size = MAX_BULK_DOCS

    size = page_size if include_hits else 0

    mode = (getattr(body, "mode", None) or "wildcard").strip().lower()
    smart = (getattr(body, "smart", None) or "auto").strip().lower()
    if mode not in ("wildcard", "smart"):
        mode = "wildcard"
    if smart not in ("auto", "match", "match_phrase"):
        smart = "auto"

    # ✅ pass mode to OpenSearch query builder
    j, err = os_search_ioc(
        derived_case_id,
        ioc_value,
        size,
        mode=mode,
        smart=smart,
        include_terms=body.include_terms,
        exclude_terms=body.exclude_terms,
        search_after=body.search_after,
    )
    if err:
        return JSONResponse(status_code=500, content={"ok": False, "error": err})

    hits_block = (j or {}).get("hits") or {}
    total_obj = hits_block.get("total") or {}
    total = total_obj.get("value") if isinstance(total_obj, dict) else None
    if total is None:
        # fallback (older formats)
        try:
            total = int(hits_block.get("total", 0))
        except Exception:
            total = 0

    out_hits = []
    if include_hits:
        for h in (hits_block.get("hits") or []):
            ix = h.get("_index")
            did = h.get("_id")
            if ix and did:
                src = h.get("_source") or {}
                out_hits.append({
                    "index": ix,
                    "id": did,
                    "source": src,
                    "sort": h.get("sort"),
                })

    next_search_after = None
    if include_hits and out_hits:
        last_sort = out_hits[-1].get("sort")
        if isinstance(last_sort, list) and last_sort:
            next_search_after = last_sort

    return {
        "ok": True,
        "user": user,
        "case_id": derived_case_id,
        "type": body.type,
        "value": ioc_value,
        "mode": mode,
        "smart": smart,
        "total": total,
        "returned": len(out_hits),
        "page_size": page_size if include_hits else 0,
        "next_search_after": next_search_after,
        "hits": out_hits if include_hits else None,
    }

DEDUP_TTL_SECONDS = 300  # 5 minutes

def _canonical_json(obj) -> str:
    # stable representation so equality checks work
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

async def _find_duplicate_job(db, action: str, payload_json: str, now: int):
    cutoff = now - DEDUP_TTL_SECONDS
    cur = await db.execute(
        """
        SELECT id
        FROM jobs
        WHERE action = ?
          AND payload_json = ?
          AND status IN ('queued','running')
          AND created_at >= ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (action, payload_json, cutoff),
    )
    row = await cur.fetchone()
    return row[0] if row else None


@api_v1.get("/jobs/{job_id}")
async def job_status(job_id: int, req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            SELECT id,
                   created_at,
                   created_by,
                   status,
                   action,
                   payload_json,
                   started_at,
                   finished_at,
                   last_error,
                   last_output,
                   full_output,
                   claimed_by,
                   claimed_at,
                   dedupe_key
              FROM jobs
             WHERE id = ?
             LIMIT 1
            """,
            (job_id,),
        )
        row = await cur.fetchone()

    if not row:
        return JSONResponse(status_code=404, content={"ok": False, "error": "job not found"})

    if row[2] != user:
        return JSONResponse(status_code=403, content={"ok": False, "error": "forbidden"})

    payload = {}
    try:
        payload = json.loads(row[5] or "{}")
    except Exception:
        payload = {}

    return {
        "ok": True,
        "job": {
            "id": row[0],
            "created_at": row[1],
            "created_by": row[2],
            "status": row[3],
            "action": row[4],
            "payload": payload,
            "started_at": row[6],
            "finished_at": row[7],
            "last_error": row[8],
            "last_output": row[9],
            "full_output": row[10],
            "claimed_by": row[11],
            "claimed_at": row[12],
            "dedupe_key": row[13],
        },
    }

@api_v1.post("/jobs")
async def jobs_submit(req: Request, body: JobSubmit):
    """
    Enqueue jobs. Server derives the authoritative case_id from the seed doc.

    Supported:
      - tag_add: single tag against seed doc
      - tag_add_bulk: tag against provided hits list (max 10k), enforced to same case as seed
      - comment_add: single comment against seed doc
      - ioc_add: single IOC against seed doc
      - ioc_add_bulk: IOC against provided hits list (max 10k), enforced to same case as seed
      - timeline_add: mark seed doc in timeline
      - timeline_del: unmark seed doc in timeline
      - collection_add: add seed doc to named collection
      - collection_del: remove seed doc from named collection
      - collection_add_bulk: add hits list to named collection
      - collection_del_bulk: remove hits list from named collection
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    derived_case_id, bad = _validate_seed(body.seed_case_id, body.seed_index, body.seed_id)
    if bad:
        return bad

    now = int(time.time())

    # ------------------------------------------------------------
    # Helpers: stable dedupe key hashing
    # ------------------------------------------------------------
    import hashlib

    def _sha256_hex(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    async def _return_existing_active_job(db, action: str, dedupe_key: str):
        cur = await db.execute(
            """
            SELECT id
              FROM jobs
             WHERE action = ?
               AND dedupe_key = ?
               AND status IN ('queued','running')
             ORDER BY id DESC
             LIMIT 1
            """,
            (action, dedupe_key),
        )
        row = await cur.fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------
    # comment_add (single)
    # ------------------------------------------------------------
    if body.action == "comment_add":
        text = (body.text or "").strip()
        if not text:
            return JSONResponse(status_code=400, content={"ok": False, "error": "text is empty after trim"})
        if len(text) > MAX_COMMENT_LEN:
            return JSONResponse(status_code=400, content={"ok": False, "error": f"text too long (max {MAX_COMMENT_LEN})"})

        payload = {
            "case_id": derived_case_id,
            "index": body.seed_index,
            "id": body.seed_id,
            "text": text,
        }

        dedupe_material = f"v1|comment_add|{derived_case_id}|{body.seed_index}|{body.seed_id}|{user}|{text}"
        dedupe_key = _sha256_hex(dedupe_material)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cur = await db.execute(
                    "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (now, user, "queued", "comment_add", dedupe_key, payload_json),
                )
                await db.commit()
                job_id = cur.lastrowid
                print(f"[job queued] id={job_id} action=comment_add user={user} payload={payload} dedupe={dedupe_key}")
                return {"ok": True, "status": "queued", "job_id": job_id, "action": "comment_add", **payload}

            except aiosqlite.Error as e:
                msg = str(e).lower()
                if "unique" in msg or "constraint" in msg:
                    existing_id = await _return_existing_active_job(db, "comment_add", dedupe_key)
                    if existing_id:
                        print(f"[job dedupe] existing_id={existing_id} action=comment_add user={user} payload={payload} dedupe={dedupe_key}")
                        return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": "comment_add", **payload}
                return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})

    # ------------------------------------------------------------
    # tag_add (single)
    # ------------------------------------------------------------
    if body.action == "tag_add":
        tag = (body.tag or "").strip()
        if not tag:
            return JSONResponse(status_code=400, content={"ok": False, "error": "tag is empty after trim"})
        if len(tag) > MAX_TAG_LEN:
            return JSONResponse(status_code=400, content={"ok": False, "error": f"tag too long (max {MAX_TAG_LEN})"})

        payload = {
            "case_id": derived_case_id,
            "index": body.seed_index,
            "id": body.seed_id,
            "tag": tag,
        }

        dedupe_material = f"v1|tag_add|{derived_case_id}|{body.seed_index}|{body.seed_id}|{tag}"
        dedupe_key = _sha256_hex(dedupe_material)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cur = await db.execute(
                    "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (now, user, "queued", "tag_add", dedupe_key, payload_json),
                )
                await db.commit()
                job_id = cur.lastrowid
                print(f"[job queued] id={job_id} action=tag_add user={user} payload={payload} dedupe={dedupe_key}")
                return {"ok": True, "status": "queued", "job_id": job_id, "action": "tag_add", **payload}

            except aiosqlite.Error as e:
                msg = str(e).lower()
                if "unique" in msg or "constraint" in msg:
                    existing_id = await _return_existing_active_job(db, "tag_add", dedupe_key)
                    if existing_id:
                        print(f"[job dedupe] existing_id={existing_id} action=tag_add user={user} payload={payload} dedupe={dedupe_key}")
                        return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": "tag_add", **payload}
                return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})

    # ------------------------------------------------------------
    # ioc_add / ioc_del (single)
    # ------------------------------------------------------------
    if body.action in ("ioc_add", "ioc_del"):
        type = (body.type or "").strip()
        value = (body.value or "").strip()
        field = (body.field or "").strip() or None

        if not type:
            return JSONResponse(status_code=400, content={"ok": False, "error": "type is empty after trim"})
        if not value:
            return JSONResponse(status_code=400, content={"ok": False, "error": "value is empty after trim"})
        if len(type) > 32:
            return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 32)"})
        if len(value) > 512:
            return JSONResponse(status_code=400, content={"ok": False, "error": "value too long (max 512)"})
        if field and len(field) > 128:
            return JSONResponse(status_code=400, content={"ok": False, "error": "field too long (max 128)"})

        payload = {
            "case_id": derived_case_id,
            "index": body.seed_index,
            "id": body.seed_id,
            "type": type,
            "value": value,
            "field": field,
        }

        dedupe_material = f"v1|{body.action}|{derived_case_id}|{body.seed_index}|{body.seed_id}|{user}|{type}|{value}|{field or ''}"
        dedupe_key = _sha256_hex(dedupe_material)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cur = await db.execute(
                    "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (now, user, "queued", body.action, dedupe_key, payload_json),                    
                )
                await db.commit()
                job_id = cur.lastrowid
                print(f"[job queued] id={job_id} action={body.action} user={user} payload={payload} dedupe={dedupe_key}")                
                return {"ok": True, "status": "queued", "job_id": job_id, "action": body.action, **payload}                

            except aiosqlite.Error as e:
                msg = str(e).lower()
                if "unique" in msg or "constraint" in msg:
                    existing_id = await _return_existing_active_job(db, body.action, dedupe_key)
                    if existing_id:
                        print(f"[job dedupe] existing_id={existing_id} action={body.action} user={user} payload={payload} dedupe={dedupe_key}")                        
                        return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": body.action, **payload}                        
                return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})

    # ------------------------------------------------------------
    # timeline_add / timeline_del (single)
    # ------------------------------------------------------------
    if body.action in ("timeline_add", "timeline_del"):
        payload = {
            "case_id": derived_case_id,
            "index": body.seed_index,
            "id": body.seed_id,
        }

        dedupe_material = f"v1|{body.action}|{derived_case_id}|{body.seed_index}|{body.seed_id}|{user}"
        dedupe_key = _sha256_hex(dedupe_material)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cur = await db.execute(
                    "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (now, user, "queued", body.action, dedupe_key, payload_json),
                )
                await db.commit()
                job_id = cur.lastrowid
                print(f"[job queued] id={job_id} action={body.action} user={user} payload={payload} dedupe={dedupe_key}")
                return {"ok": True, "status": "queued", "job_id": job_id, "action": body.action, **payload}

            except aiosqlite.Error as e:
                msg = str(e).lower()
                if "unique" in msg or "constraint" in msg:
                    existing_id = await _return_existing_active_job(db, body.action, dedupe_key)
                    if existing_id:
                        print(f"[job dedupe] existing_id={existing_id} action={body.action} user={user} payload={payload} dedupe={dedupe_key}")
                        return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": body.action, **payload}
                return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})


    # ------------------------------------------------------------
    # collection_add / collection_del (single)
    # ------------------------------------------------------------
    if body.action in ("collection_add", "collection_del"):
        name = (body.name or "").strip()
        if not name:
            return JSONResponse(status_code=400, content={"ok": False, "error": "name is empty after trim"})
        if len(name) > 256:
            return JSONResponse(status_code=400, content={"ok": False, "error": "name too long (max 256)"})

        payload = {
            "case_id": derived_case_id,
            "index": body.seed_index,
            "id": body.seed_id,
            "name": name,
        }

        # Dedupe: treat collections like tags (per doc+name), not per-user.
        dedupe_material = f"v1|{body.action}|{derived_case_id}|{body.seed_index}|{body.seed_id}|{name}"
        dedupe_key = _sha256_hex(dedupe_material)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cur = await db.execute(
                    "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (now, user, "queued", body.action, dedupe_key, payload_json),
                )
                await db.commit()
                job_id = cur.lastrowid
                print(f"[job queued] id={job_id} action={body.action} user={user} payload={payload} dedupe={dedupe_key}")
                return {"ok": True, "status": "queued", "job_id": job_id, "action": body.action, **payload}

            except aiosqlite.Error as e:
                msg = str(e).lower()
                if "unique" in msg or "constraint" in msg:
                    existing_id = await _return_existing_active_job(db, body.action, dedupe_key)
                    if existing_id:
                        print(f"[job dedupe] existing_id={existing_id} action={body.action} user={user} payload={payload} dedupe={dedupe_key}")
                        return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": body.action, **payload}
                return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})


    # ------------------------------------------------------------
    # Bulk: tag_add_bulk / ioc_add_bulk / collection_add_bulk / collection_del_bulk
    # ------------------------------------------------------------
    if body.action not in ("tag_add_bulk", "ioc_add_bulk", "ioc_del_bulk", "collection_add_bulk", "collection_del_bulk"):
        return JSONResponse(status_code=400, content={"ok": False, "error": f"unsupported action: {body.action}"})    
        return JSONResponse(status_code=400, content={"ok": False, "error": f"unsupported action: {body.action}"})

    hits = body.hits or []
    if len(hits) == 0:
        return JSONResponse(status_code=400, content={"ok": False, "error": f"hits is required for {body.action}"})
    if len(hits) > MAX_BULK_DOCS:
        return JSONResponse(status_code=400, content={"ok": False, "error": f"too many hits (max {MAX_BULK_DOCS})"})

    # Bulk action-specific parameter validation (and mapping to bulk_batches.kind/op/value)
    if body.action == "tag_add_bulk":
        tag = (body.tag or "").strip()
        if not tag:
            return JSONResponse(status_code=400, content={"ok": False, "error": "tag is empty after trim"})
        if len(tag) > MAX_TAG_LEN:
            return JSONResponse(status_code=400, content={"ok": False, "error": f"tag too long (max {MAX_TAG_LEN})"})
        kind = "tag"
        op = "add"
        bulk_value = tag

    elif body.action in ("ioc_add_bulk", "ioc_del_bulk"):
        ioc_type = (body.type or "").strip()
        ioc_value_raw = (body.value or "").strip()
        if not ioc_type:
            return JSONResponse(status_code=400, content={"ok": False, "error": "type is empty after trim"})
        if not ioc_value_raw:
            return JSONResponse(status_code=400, content={"ok": False, "error": "value is empty after trim"})
        if len(ioc_type) > 32:
            return JSONResponse(status_code=400, content={"ok": False, "error": "type too long (max 32)"})
        if len(ioc_value_raw) > 512:
            return JSONResponse(status_code=400, content={"ok": False, "error": "value too long (max 512)"})

        kind = "ioc"
        op = "add" if body.action == "ioc_add_bulk" else "del"
        bulk_value = f"{ioc_type}:{ioc_value_raw}"  # worker expects type:value

    elif body.action in ("collection_add_bulk", "collection_del_bulk"):
        name = (body.name or "").strip()
        if not name:
            return JSONResponse(status_code=400, content={"ok": False, "error": "name is empty after trim"})
        if len(name) > 256:
            return JSONResponse(status_code=400, content={"ok": False, "error": "name too long (max 256)"})
        kind = "collection"
        op = "add" if body.action == "collection_add_bulk" else "del"
        bulk_value = name

    else:
        # Defensive; unreachable due to the initial bulk action guard.
        return JSONResponse(status_code=400, content={"ok": False, "error": f"unsupported bulk action: {body.action}"})

    # Validate hits and build raw id list
    lines = []
    for h in hits:
        if not RE_INDEX.match(h.index):
            return JSONResponse(status_code=400, content={"ok": False, "error": f"invalid hit index: {h.index}"})
        if not RE_DOC_ID.match(h.id):
            return JSONResponse(status_code=400, content={"ok": False, "error": f"invalid hit id: {h.id}"})
        lines.append(f"{derived_case_id}\t{h.index}\t{h.id}\n")

    raw = "".join(lines).encode("utf-8")
    try:
        blob = zstd_compress(raw, level=3)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": f"zstd compress failed: {e}"})

    batch_id = secrets.token_hex(16)
    doc_count = len(hits)

    docs_hash = hashlib.sha256(raw).hexdigest()
    bulk_dedupe_material = f"v1|{body.action}|{derived_case_id}|{bulk_value}|{doc_count}|{docs_hash}"
    bulk_dedupe_key = _sha256_hex(bulk_dedupe_material)

    async with aiosqlite.connect(DB_PATH) as db:
        payload = {"batch_id": batch_id, "doc_count": doc_count}
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, user, "queued", body.action, bulk_dedupe_key, payload_json),
            )
            job_id = cur.lastrowid

            await db.execute(
                "INSERT INTO bulk_batches "
                "(batch_id, job_id, created_at, created_by, case_id, index_name, kind, op, value, doc_count, doc_ids_blob) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (batch_id, job_id, now, user, derived_case_id, "multi", kind, op, bulk_value, doc_count, blob),
            )

            await db.commit()

            print(
                f"[job queued] id={job_id} action={body.action} user={user} batch_id={batch_id} "
                f"case={derived_case_id} doc_count={doc_count} dedupe={bulk_dedupe_key}"
            )
            return {
                "ok": True,
                "status": "queued",
                "job_id": job_id,
                "action": body.action,
                "batch_id": batch_id,
                "case_id": derived_case_id,
                "doc_count": doc_count,
            }

        except aiosqlite.Error as e:
            msg = str(e).lower()
            if "unique" in msg or "constraint" in msg:
                existing_id = await _return_existing_active_job(db, body.action, bulk_dedupe_key)
                if existing_id:
                    print(
                        f"[job dedupe] existing_id={existing_id} action={body.action} user={user} "
                        f"case={derived_case_id} doc_count={doc_count} dedupe={bulk_dedupe_key}"
                    )
                    return {
                        "ok": True,
                        "status": "already_queued",
                        "job_id": existing_id,
                        "action": body.action,
                        "case_id": derived_case_id,
                        "doc_count": doc_count,
                    }

            return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})



@api_v1.post("/jobs/search")
async def jobs_search_submit(req: Request, body: JobSearchSubmit):
    """
    Enqueue bulk jobs based on full server-side search scope, not client preview hits.

    This preserves the existing /jobs endpoint for explicit selected hits.
    The expensive search replay will be executed by the worker, not inside this API request.
    """
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    derived_case_id, bad = _validate_seed(body.seed_case_id, body.seed_index, body.seed_id)
    if bad:
        return bad

    if body.action not in ("tag_add_bulk", "ioc_add_bulk", "ioc_del_bulk", "collection_add_bulk", "collection_del_bulk"):
        return JSONResponse(status_code=400, content={"ok": False, "error": f"unsupported action: {body.action}"})

    now = int(time.time())

    import hashlib

    def _sha256_hex(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    async def _return_existing_active_job(db, action: str, dedupe_key: str):
        cur = await db.execute(
            """
            SELECT id
              FROM jobs
             WHERE action = ?
               AND dedupe_key = ?
               AND status IN ('queued','running')
             ORDER BY id DESC
             LIMIT 1
            """,
            (action, dedupe_key),
        )
        row = await cur.fetchone()
        return row[0] if row else None

    # Validate action-specific params
    tag = None
    ioc_type = None
    ioc_value = None
    field = None
    name = None

    if body.action == "tag_add_bulk":
        tag = (body.tag or "").strip()
        if not tag:
            return JSONResponse(status_code=400, content={"ok": False, "error": "tag is empty after trim"})
        if len(tag) > MAX_TAG_LEN:
            return JSONResponse(status_code=400, content={"ok": False, "error": f"tag too long (max {MAX_TAG_LEN})"})

    elif body.action in ("ioc_add_bulk", "ioc_del_bulk"): 
        ioc_type = (body.type_ioc or "").strip()
        ioc_value = (body.value_ioc or "").strip()
        field = (body.field or "").strip() or None

        if not ioc_type:
            return JSONResponse(status_code=400, content={"ok": False, "error": "ioc_type is empty after trim"})
        if not ioc_value:
            return JSONResponse(status_code=400, content={"ok": False, "error": "ioc_value is empty after trim"})
        if len(ioc_type) > 32:
            return JSONResponse(status_code=400, content={"ok": False, "error": "ioc_type too long (max 32)"})
        if len(ioc_value) > 512:
            return JSONResponse(status_code=400, content={"ok": False, "error": "ioc_value too long (max 512)"})
        if field and len(field) > 128:
            return JSONResponse(status_code=400, content={"ok": False, "error": "field too long (max 128)"})

    elif body.action in ("collection_add_bulk", "collection_del_bulk"):
        name = (body.name or "").strip()
        if not name:
            return JSONResponse(status_code=400, content={"ok": False, "error": "name is empty after trim"})
        if len(name) > 256:
            return JSONResponse(status_code=400, content={"ok": False, "error": "name too long (max 256)"})

    # Fast count/sanity check only (no full replay here)
    j, err = os_search_ioc(
        derived_case_id,
        body.value,
        size=0,
        mode=body.mode,
        smart=body.smart,
        include_terms=body.include_terms or {},
        exclude_terms=body.exclude_terms or {},
    )
    if err:
        return JSONResponse(status_code=400, content={"ok": False, "error": err})
    if not j:
        return JSONResponse(status_code=500, content={"ok": False, "error": "search returned no response"})

    total = int(((j.get("hits") or {}).get("total") or {}).get("value") or 0)

    if body.expected_total is not None and int(body.expected_total) != total:
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "error": "search result count changed",
                "expected_total": int(body.expected_total),
                "actual_total": total,
            },
        )

    action_map = {
        "tag_add_bulk": "tag_add_bulk_search",
        "ioc_add_bulk": "ioc_add_bulk_search",
        "ioc_del_bulk": "ioc_del_bulk_search",
        "collection_add_bulk": "collection_add_bulk_search",
        "collection_del_bulk": "collection_del_bulk_search",
    }
    queued_action = action_map[body.action]

    payload = {
        "case_id": derived_case_id,
        "seed_index": body.seed_index,
        "seed_id": body.seed_id,
        "seed_case_id": body.seed_case_id,
        "search": {
            "type": body.type,
            "value": body.value,
            "mode": body.mode,
            "smart": body.smart,
            "include_terms": body.include_terms or {},
            "exclude_terms": body.exclude_terms or {},
            "expected_total": body.expected_total,
            "matched_total": total,
        },
    }

    if queued_action == "tag_add_bulk_search":
        payload["tag"] = tag
    elif queued_action in ("ioc_add_bulk_search", "ioc_del_bulk_search"):
        payload["ioc_type"] = ioc_type
        payload["ioc_value"] = ioc_value
        payload["field"] = field
    elif queued_action in ("collection_add_bulk_search", "collection_del_bulk_search"):
        payload["name"] = name

    dedupe_material = json.dumps(
        {
            "action": queued_action,
            "case_id": derived_case_id,
            "seed_index": body.seed_index,
            "seed_id": body.seed_id,
            "search": payload["search"],
            "tag": payload.get("tag"),
            "ioc_type": payload.get("ioc_type"),
            "ioc_value": payload.get("ioc_value"),
            "field": payload.get("field"),
            "name": payload.get("name"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    dedupe_key = _sha256_hex(f"v1|jobs_search|{dedupe_material}")
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        try:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, user, "queued", queued_action, dedupe_key, payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action={queued_action} user={user} matched_total={total} dedupe={dedupe_key}")
            return {
                "ok": True,
                "status": "queued",
                "job_id": job_id,
                "action": queued_action,
                "case_id": derived_case_id,
                "matched_total": total,
                "search": payload["search"],
            }

        except aiosqlite.Error as e:
            msg = str(e).lower()
            if "unique" in msg or "constraint" in msg:
                existing_id = await _return_existing_active_job(db, queued_action, dedupe_key)
                if existing_id:
                    print(f"[job dedupe] existing_id={existing_id} action={queued_action} user={user} matched_total={total} dedupe={dedupe_key}")
                    return {
                        "ok": True,
                        "status": "already_queued",
                        "job_id": existing_id,
                        "action": queued_action,
                        "case_id": derived_case_id,
                        "matched_total": total,
                        "search": payload["search"],
                    }
            return JSONResponse(status_code=500, content={"ok": False, "error": f"db insert failed: {e}"})
# -------------------------
# Search Stats Model
# -------------------------
class SearchStatsSubmit(BaseModel):
    seed_case_id: str
    seed_index: Optional[str] = None
    seed_id: Optional[str] = None

    type: str = "term"
    value: str

    # Match UI search semantics
    mode: str = "wildcard"        # "wildcard" | "smart"
    smart: str = "auto"           # "auto" | "match" | "match_phrase"

    # Fields the user wants stats for (UI-controlled)
    fields: List[str] = Field(default_factory=list)

    # Top buckets per field
    top_n: int = 10


class CaseNewRequest(BaseModel):
    org_name: str
    title: str
    description: str
    timezones: list[str] = Field(default_factory=list)

class CaseUpdateRequest(BaseModel):
    case_id: str
    org_name: str | None = None
    title: str | None = None
    description: str | None = None
    status: str | None = None
    timezones: list[str] | None = None

class CaseReloadRequest(BaseModel):
    case_id: str
    reparse_artefacts: bool = False

class ResetCaseRequest(BaseModel):
    case_id: str

class MaintenanceInitRequest(BaseModel):
    overwrite: bool = False
    bootstrapEnv: bool = False
    enable: bool = False
    createUser: bool = False

class MaintenanceResetRequest(BaseModel):
    all: bool = False
    os: bool = False
    osd: bool = False
    cases: bool = False
    caseIds: list[str] = []

class UserListRequest(BaseModel):
    pass

class UserCreateRequest(BaseModel):
    user_name: str
    send_invite: bool = False
    print_password: bool = False

    @root_validator(pre=True)
    def _validate_user_create(cls, values):
        user_name = (values.get("user_name") or "").strip()
        values["user_name"] = user_name

        if not user_name:
            raise ValueError("user_name is required")

        return values

class UserNameRequest(BaseModel):
    user_name: str

    @root_validator(pre=True)
    def _validate_user_name(cls, values):
        user_name = (values.get("user_name") or "").strip()
        values["user_name"] = user_name

        if not user_name:
            raise ValueError("user_name is required")

        return values

class UserAssignRequest(BaseModel):
    user_name: str
    case_id: str
    role: Literal["user", "case_admin"]

    @root_validator(pre=True)
    def _validate_user_assign(cls, values):
        user_name = (values.get("user_name") or "").strip()
        case_id = (values.get("case_id") or "").strip()
        role = (values.get("role") or "").strip()

        values["user_name"] = user_name
        values["case_id"] = case_id
        values["role"] = role

        if not user_name:
            raise ValueError("user_name is required")
        if not case_id:
            raise ValueError("case_id is required")
        if role not in ("user", "case_admin"):
            raise ValueError("role must be user or case_admin")

        return values

class UserUnassignRequest(BaseModel):
    user_name: str
    case_id: str

    @root_validator(pre=True)
    def _validate_user_unassign(cls, values):
        user_name = (values.get("user_name") or "").strip()
        case_id = (values.get("case_id") or "").strip()

        values["user_name"] = user_name
        values["case_id"] = case_id

        if not user_name:
            raise ValueError("user_name is required")
        if not case_id:
            raise ValueError("case_id is required")

        return values


USER_SECRET_DIR = "/data/job-secrets"

USER_PASSWORD_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789"
    "!@#%^_-+="
)

def _generate_user_password(length: int = 24) -> str:
    return "".join(secrets.choice(USER_PASSWORD_ALPHABET) for _ in range(length))

def _write_user_password_secret(password: str) -> str:
    os.makedirs(USER_SECRET_DIR, mode=0o700, exist_ok=True)
    os.chmod(USER_SECRET_DIR, 0o700)

    secret_id = uuid.uuid4().hex
    path = os.path.join(USER_SECRET_DIR, secret_id)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(password)
            f.write("\n")
    except Exception:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise

    return secret_id

class UploadSessionStartRequest(BaseModel):
    case_id: str
    host_ip: str
    selection_mode: str = "files"
    preserve_folder_structure: bool = True
    verify_sha256: bool = True
    chunk_large_files: bool = True


class UploadSessionStartResponse(BaseModel):
    ok: bool
    upload_id: str
    status: str
    meta: dict

def _build_search_must_query(ioc_value: str, *, mode: str, smart: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Returns (must_query, error).
    Mirrors os_search_ioc() behavior so stats are consistent with the search UI.
    """
    ioc_value = (ioc_value or "").strip()
    if not ioc_value:
        return None, "value is empty"

    mode = (mode or "wildcard").strip().lower()
    smart = (smart or "auto").strip().lower()
    if mode not in ("wildcard", "smart"):
        mode = "wildcard"
    if smart not in ("auto", "match", "match_phrase"):
        smart = "auto"

    def escape_wildcard_literal(s: str) -> str:
        return (s or "").replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")

    def build_wildcard_pattern(raw: str) -> str:
        return f"*{escape_wildcard_literal(raw)}*"

    if mode == "wildcard":
        wildcard_pattern = build_wildcard_pattern(ioc_value)
        should = [
            {
                "wildcard": {
                    "event.blob_preview.event_original.wc": {
                        "value": wildcard_pattern,
                        "case_insensitive": True,
                    }
                }
            },
            {
                "wildcard": {
                    "event.blob_preview.message.wc": {
                        "value": wildcard_pattern,
                        "case_insensitive": True,
                    }
                }
            },
        ]
        must_query = {"bool": {"should": should, "minimum_should_match": 1}}
        return must_query, None

    # smart mode: same as os_search_ioc()
    field = "event.blob_preview.event_original"

    if smart == "match":
        return {"match": {field: {"query": ioc_value, "operator": "AND"}}}, None

    if smart == "match_phrase":
        return {"match_phrase": {field: {"query": ioc_value}}}, None

    # auto
    if any(ch.isspace() for ch in ioc_value):
        return {"match_phrase": {field: {"query": ioc_value}}}, None
    return {"match": {field: {"query": ioc_value, "operator": "AND"}}}, None


def os_search_stats(
    case_id: str,
    value: str,
    fields: List[str],
    *,
    mode: str = "wildcard",
    smart: str = "auto",
    top_n: int = 10,
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Returns (json, error).

    For each requested field:
      - try terms agg on "<field>.keyword" and "<field>" (both directions)
      - accept the first candidate that produces buckets (or accept empty buckets only if total==0)

    Returns:
      {
        "total": <track_total_hits>,
        "stats": {
          "<field>": {
            "agg_field": "<actual field used>",
            "buckets": [{"key": ..., "doc_count": ...}, ...]
          },
          ...
        }
      }
    """
    missing = _os_ready()
    if missing:
        return None, missing

    if top_n < 1:
        top_n = 1
    if top_n > 100:
        top_n = 100

    # sanitize fields
    clean_fields = []
    for f in (fields or []):
        ff = str(f or "").strip()
        if ff:
            clean_fields.append(ff)

    if not clean_fields:
        return None, "fields is empty"

    must_query, err = _build_search_must_query(value, mode=mode, smart=smart)
    if err:
        return None, err

    target = "all-json"
    base_url = f"{OS_HOST.rstrip('/')}/{target}/_search"

    base_query = {
        "bool": {
            "filter": [{"term": {"case_id": case_id}}],
            "must": [must_query],
        }
    }

    # 1) get total hits once
    total_body = {
        "track_total_hits": True,
        "size": 0,
        "query": base_query,
    }

    try:
        r0 = requests.post(
            base_url,
            auth=(OS_USER, OS_PASS),
            timeout=20,
            verify=_os_verify_param(),
            headers={"content-type": "application/json"},
            data=json.dumps(total_body),
        )
    except Exception as e:
        return None, f"opensearch request failed: {e}"

    if r0.status_code != 200:
        return None, f"opensearch error {r0.status_code}: {r0.text[:200]}"

    try:
        j0 = r0.json()
    except Exception:
        return None, "opensearch returned non-json"

    total = int((((j0 or {}).get("hits") or {}).get("total") or {}).get("value") or 0)

    # 2) run aggs per field (small N, safer fallback)
    out_stats: Dict[str, Any] = {}

    for f in clean_fields:
        # Always try both directions:
        # - If user passed ".keyword", also try base field (for keyword-mapped fields)
        # - Otherwise try ".keyword" then base (classic text->keyword multi-field)
        if f.endswith(".keyword"):
            base = f[: -len(".keyword")]
            candidates = [f, base]
        else:
            candidates = [f"{f}.keyword", f]

        field_ok = None
        buckets: List[Any] = []
        last_err = None

        for agg_field in candidates:
            body = {
                "track_total_hits": False,
                "size": 0,
                "query": base_query,
                "aggs": {
                    "top": {
                        "terms": {
                            "field": agg_field,
                            "size": top_n,
                            "order": {"_count": "desc"},
                        }
                    }
                },
            }

            try:
                rr = requests.post(
                    base_url,
                    auth=(OS_USER, OS_PASS),
                    timeout=20,
                    verify=_os_verify_param(),
                    headers={"content-type": "application/json"},
                    data=json.dumps(body),
                )
            except Exception as e:
                last_err = f"opensearch request failed: {e}"
                continue

            if rr.status_code != 200:
                last_err = f"opensearch error {rr.status_code}: {rr.text[:200]}"
                continue

            try:
                jj = rr.json()
            except Exception:
                last_err = "opensearch returned non-json"
                continue

            agg = ((jj.get("aggregations") or {}).get("top") or {})
            b = agg.get("buckets") or []

            # Only accept this candidate if:
            #   - it produced buckets, OR
            #   - total==0 (no docs matched; empty buckets are meaningful)
            if b or total == 0:
                field_ok = agg_field
                buckets = b
                last_err = None
                break

            # buckets empty but total>0 → likely wrong field (e.g. ".keyword" on keyword field)
            last_err = None
            continue

        if field_ok is None:
            out_stats[f] = {"error": last_err or "aggregation failed"}
        else:
            out_stats[f] = {"agg_field": field_ok, "buckets": buckets}

    return {"total": total, "stats": out_stats}, None


@api_v1.post("/cases/list")
async def cases_list_submit(req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "case_list"
    payload_json = json.dumps({}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/cases/new")
async def cases_new_submit(req: Request, body: CaseNewRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp
    
    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "case_new"
    payload_json = json.dumps(
        {
            "org_name": body.org_name,
            "title": body.title,
            "description": body.description,
            "timezones": body.timezones,
        },
        separators=(",", ":"),
    )

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/cases/update")
async def cases_update_submit(req: Request, body: CaseUpdateRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {"case_id": body.case_id}
    if body.org_name is not None:
        payload["org_name"] = body.org_name
    if body.title is not None:
        payload["title"] = body.title
    if body.description is not None:
        payload["description"] = body.description
    if body.timezones is not None:
        payload["timezones"] = body.timezones

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "case_update"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/cases/reload")
async def cases_reload_submit(req: Request, body: CaseReloadRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {"case_id": body.case_id}
    if body.reparse_artefacts:
        payload["reparse_artefacts"] = True

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "case_reload"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/cases/reset")
async def cases_reset_submit(req: Request, body: ResetCaseRequest):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "reset_case"
    payload_json = json.dumps({"case_id": body.case_id}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/maintenance/sync/templates-push")
async def maintenance_sync_templates_push_submit(req: Request):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "maintenance_sync_templates_push"
    payload_json = json.dumps({}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/maintenance/sync/patterns-push")
async def maintenance_sync_patterns_push_submit(req: Request):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "maintenance_sync_patterns_push"
    payload_json = json.dumps({}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/maintenance/sync/fields-refresh-all")
async def maintenance_sync_fields_refresh_all_submit(req: Request):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "maintenance_sync_fields_refresh_all"
    payload_json = json.dumps({}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/maintenance/sync/settings-sync-private")
async def maintenance_sync_settings_sync_private_submit(req: Request):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "maintenance_sync_settings_sync_private"
    payload_json = json.dumps({}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/maintenance/init")
async def maintenance_init_submit(req: Request, body: MaintenanceInitRequest):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    payload = {
        "overwrite": body.overwrite,
        "bootstrapEnv": body.bootstrapEnv,
        "enable": body.enable,
        "createUser": body.createUser,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "maintenance_init"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/maintenance/reset")
async def maintenance_reset_submit(req: Request, body: MaintenanceResetRequest):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    payload = {
        "all": body.all,
        "os": body.os,
        "osd": body.osd,
        "cases": body.cases,
        "caseIds": body.caseIds,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "maintenance_reset"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/users/list")
async def users_list_submit(req: Request, body: UserListRequest = UserListRequest()):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_list"
    payload_json = json.dumps({}, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/users/create")
async def users_create_submit(req: Request, body: UserCreateRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    generated_password = _generate_user_password()
    password_secret_id = _write_user_password_secret(generated_password)

    payload = {
        "user_name": body.user_name,
        "send_invite": body.send_invite,
        "print_password": False,
        "password_secret_id": password_secret_id,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_create"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {
        "ok": True,
        "job_id": job_id,
        "generated_password": generated_password,
    }

@api_v1.post("/users/password")
async def users_password_submit(req: Request, body: UserNameRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    generated_password = _generate_user_password()
    password_secret_id = _write_user_password_secret(generated_password)

    payload = {
        "user_name": body.user_name,
        "password_secret_id": password_secret_id,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_password"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {
        "ok": True,
        "job_id": job_id,
        "generated_password": generated_password,
    }


@api_v1.post("/users/enable")
async def users_enable_submit(req: Request, body: UserNameRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {"user_name": body.user_name}

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_enable"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/users/disable")
async def users_disable_submit(req: Request, body: UserNameRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {"user_name": body.user_name}

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_disable"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/users/assign")
async def users_assign_submit(req: Request, body: UserAssignRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {
        "user_name": body.user_name,
        "case_id": body.case_id,
        "role": body.role,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_assign"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/users/unassign")
async def users_unassign_submit(req: Request, body: UserUnassignRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {
        "user_name": body.user_name,
        "case_id": body.case_id,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "user_unassign"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/hosts/new-bulk")
async def hosts_new_bulk_submit(req: Request, body: HostBulkNewRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {
        "case_id": body.case_id,
        "cidr": body.cidr,
    }
    if body.hostname is not None:
        payload["hostname"] = body.hostname
    if body.os is not None:
        payload["os"] = body.os
    if body.description is not None:
        payload["description"] = body.description

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "host_new_bulk"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/hosts/list")
async def hosts_list_submit(req: Request, body: HostListRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "host_list"
    payload_json = json.dumps(
        {"case_id": body.case_id},
        separators=(",", ":"),
    )

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/hosts/list-artefacts")
async def hosts_list_artefacts_submit(req: Request, body: HostArtefactsListRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "host_list_artefacts"
    payload_json = json.dumps(
        {
            "case_id": body.case_id,
            "host_ip": body.host_ip,
        },
        separators=(",", ":"),
    )

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/osd/list-columns")
async def osd_list_columns_submit(req: Request):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "osd_list_columns"
    payload_json = json.dumps(
        {},
        separators=(",", ":"),
    )

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/osd/set-columns")
async def osd_set_columns_submit(req: Request):
    _, user, resp = _require_admin_auth(req) 
    if resp:
        return resp

    try:
        raw = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)

    try:
        payload = OSDSetColumnsPayload.model_validate(raw)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid columns payload: {e}"}, status_code=400)

    try:
        payload_json = payload.model_dump_json(by_alias=True)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"failed to serialize payload: {e}"}, status_code=500)

    now = int(time.time())

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, payload_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (now, user, "queued", "osd_set_columns", payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action=osd_set_columns user={user}")
    except aiosqlite.Error as e:
        return JSONResponse({"ok": False, "error": f"failed to enqueue job: {e}"}, status_code=500)

    return {
        "ok": True,
        "job_id": job_id,
    }

@api_v1.post("/timestamp/list")
async def timestamp_list_submit(req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "timestamp_list"
    payload_json = json.dumps(
        {},
        separators=(",", ":"),
    )

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}


@api_v1.post("/timestamp/set")
async def timestamp_set_submit(req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        raw = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)

    try:
        payload = TimestampSetPayload.model_validate(raw)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid timestamp payload: {e}"}, status_code=400)

    try:
        payload_json = payload.model_dump_json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"failed to serialize payload: {e}"}, status_code=500)

    now = int(time.time())

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, payload_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (now, user, "queued", "timestamp_set", payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action=timestamp_set user={user}")
    except aiosqlite.Error as e:
        return JSONResponse({"ok": False, "error": f"failed to enqueue job: {e}"}, status_code=500)

    return {
        "ok": True,
        "job_id": job_id,
    }

@api_v1.post("/timestamp/coverage")
async def timestamp_coverage(req: Request, body: TimestampCoveragePayload):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    candidates: List[str] = []
    seen = set()

    for raw in body.candidates or []:
        field = str(raw or "").strip()
        if not field or field in seen:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_@#.-]+", field):
            return JSONResponse({"ok": False, "error": f"invalid timestamp field: {field}"}, status_code=400)

        seen.add(field)
        candidates.append(field)

    if not candidates:
        return {
            "ok": True,
            "rows": [],
        }

    missing = _os_ready()
    if missing:
        return JSONResponse({"ok": False, "error": missing}, status_code=500)

    aggs: Dict[str, Any] = {}
    agg_to_field: Dict[str, str] = {}

    for idx, field in enumerate(candidates):
        agg_name = f"field_{idx}"
        agg_to_field[agg_name] = field
        aggs[agg_name] = {
            "filter": {
                "exists": {
                    "field": field
                }
            }
        }

    body_json = {
        "size": 0,
        "track_total_hits": False,
        "aggs": {
            "by_source_type": {
                "terms": {
                    "field": "source_type",
                    "size": 200,
                },
                "aggs": aggs,
            }
        }
    }

    url = f"{OS_HOST.rstrip('/')}/all-json/_search"

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(body_json, separators=(",", ":")),
            timeout=30,
            verify=_os_verify_param(),
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"opensearch request failed: {e}"}, status_code=500)

    if r.status_code != 200:
        return JSONResponse(
            {"ok": False, "error": f"opensearch error {r.status_code}: {r.text[:200]}"},
            status_code=500,
        )

    try:
        j = r.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid opensearch JSON: {e}"}, status_code=500)

    buckets = ((((j.get("aggregations") or {}).get("by_source_type") or {}).get("buckets")) or [])
    rows: List[Dict[str, Any]] = []

    for bucket in buckets:
        source_type = str(bucket.get("key") or "").strip()
        if not source_type:
            continue

        fields: List[Dict[str, Any]] = []
        preferred_field: Optional[str] = None

        for idx, field in enumerate(candidates):
            agg_name = f"field_{idx}"
            count = int(((bucket.get(agg_name) or {}).get("doc_count")) or 0)

            if count <= 0:
                continue

            if preferred_field is None:
                preferred_field = field

            fields.append({
                "field": field,
                "count": count,
                "isPreferred": field == preferred_field,
            })

        if not fields:
            continue

        for item in fields:
            rows.append({
                "viewName": f"{source_type}-*",
                "sourceType": source_type,
                "field": item["field"],
                "count": item["count"],
                "isPreferred": item["isPreferred"],
                "candidateCount": len(fields),
                "preferredField": preferred_field,
            })

    return {
        "ok": True,
        "rows": rows,
    }

@api_v1.post("/timestamp/candidates-for-view")
async def timestamp_candidates_for_view(req: Request, body: TimestampCandidatesForViewPayload):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    source_type = str(body.source_type or "").strip()

    if not re.fullmatch(r"[A-Za-z0-9_-]+", source_type):
        return JSONResponse({"ok": False, "error": f"invalid source_type: {source_type}"}, status_code=400)

    missing = _os_ready()
    if missing:
        return JSONResponse({"ok": False, "error": missing}, status_code=500)

    body_json = {
        "size": 1,
        "_source": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "source_type": source_type
                        }
                    },
                    {
                        "exists": {
                            "field": "timestamp_candidates"
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            }
        ]
    }

    url = f"{OS_HOST.rstrip('/')}/all-json/_search"

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(body_json, separators=(",", ":")),
            timeout=30,
            verify=_os_verify_param(),
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"opensearch request failed: {e}"}, status_code=500)

    if r.status_code != 200:
        return JSONResponse(
            {"ok": False, "error": f"opensearch error {r.status_code}: {r.text[:200]}"},
            status_code=500,
        )

    try:
        j = r.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid opensearch JSON: {e}"}, status_code=500)

    hits = (((j.get("hits") or {}).get("hits")) or [])

    if not hits:
        return {
            "ok": True,
            "sourceType": source_type,
            "viewName": f"{source_type}-*",
            "candidates": [],
            "sample": None,
        }

    hit = hits[0]
    src = hit.get("_source") or {}
    raw_candidates = src.get("timestamp_candidates") or []
    candidates: List[str] = []
    seen = set()

    if isinstance(raw_candidates, list):
        for item in raw_candidates:
            field = str(item or "").strip()
            if not field or field in seen:
                continue

            seen.add(field)
            candidates.append(field)

    return {
        "ok": True,
        "sourceType": source_type,
        "viewName": f"{source_type}-*",
        "candidates": candidates,
        "sample": {
            "index": hit.get("_index"),
            "id": hit.get("_id"),
            "timestamp": src.get("@timestamp"),
            "timestamp_desc": src.get("timestamp_desc"),
            "event_summary": src.get("event_summary"),
            "source": src,
        },
    }

@api_v1.post("/timestamp/fallback-views")
async def timestamp_fallback_views(req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    missing = _os_ready()
    if missing:
        return JSONResponse({"ok": False, "error": missing}, status_code=500)

    body_json = {
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "should": [
                    {
                        "term": {
                            "timestamp_desc.keyword": "ingestion time"
                        }
                    },
                    {
                        "match_phrase": {
                            "timestamp_desc": "ingestion time"
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        },
        "aggs": {
            "by_source_type": {
                "terms": {
                    "field": "source_type",
                    "size": 200,
                }
            }
        }
    }

    url = f"{OS_HOST.rstrip('/')}/all-json/_search"

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(body_json, separators=(",", ":")),
            timeout=30,
            verify=_os_verify_param(),
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"opensearch request failed: {e}"}, status_code=500)

    if r.status_code != 200:
        return JSONResponse(
            {"ok": False, "error": f"opensearch error {r.status_code}: {r.text[:200]}"},
            status_code=500,
        )

    try:
        j = r.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid opensearch JSON: {e}"}, status_code=500)

    buckets = ((((j.get("aggregations") or {}).get("by_source_type") or {}).get("buckets")) or [])
    views: List[Dict[str, Any]] = []

    for bucket in buckets:
        source_type = str(bucket.get("key") or "").strip()
        if not source_type:
            continue

        views.append({
            "viewName": f"{source_type}-*",
            "sourceType": source_type,
            "fallbackCount": int(bucket.get("doc_count") or 0),
        })

    return {
        "ok": True,
        "views": views,
    }


@api_v1.post("/timestamp/fallback-samples")
async def timestamp_fallback_samples(req: Request, body: TimestampFallbackSamplesPayload):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    source_type = str(body.source_type or "").strip()

    if not re.fullmatch(r"[A-Za-z0-9_-]+", source_type):
        return JSONResponse({"ok": False, "error": f"invalid source_type: {source_type}"}, status_code=400)

    missing = _os_ready()
    if missing:
        return JSONResponse({"ok": False, "error": missing}, status_code=500)

    body_json: Dict[str, Any] = {
        "size": body.limit,
        "_source": True,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "source_type": source_type
                        }
                    },
                    {
                        "bool": {
                            "should": [
                                {
                                    "term": {
                                        "timestamp_desc.keyword": "ingestion time"
                                    }
                                },
                                {
                                    "match_phrase": {
                                        "timestamp_desc": "ingestion time"
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                    
                ]
            }
        },
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            },
            {
                "_id": {
                    "order": "asc"
                }
            }
        ]
    }

    if body.search_after:
        body_json["search_after"] = body.search_after

    url = f"{OS_HOST.rstrip('/')}/all-json/_search"

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(body_json, separators=(",", ":")),
            timeout=30,
            verify=_os_verify_param(),
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"opensearch request failed: {e}"}, status_code=500)

    if r.status_code != 200:
        return JSONResponse(
            {"ok": False, "error": f"opensearch error {r.status_code}: {r.text[:200]}"},
            status_code=500,
        )

    try:
        j = r.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid opensearch JSON: {e}"}, status_code=500)

    hits_obj = j.get("hits") or {}
    hits = hits_obj.get("hits") or []
    total_obj = hits_obj.get("total") or {}
    total = int(total_obj.get("value") or 0) if isinstance(total_obj, dict) else int(total_obj or 0)

    samples: List[Dict[str, Any]] = []

    for hit in hits:
        src = hit.get("_source") or {}

        samples.append({
            "index": hit.get("_index"),
            "id": hit.get("_id"),
            "sort": hit.get("sort"),
            "timestamp": src.get("@timestamp"),
            "timestamp_desc": src.get("timestamp_desc"),
            "event_summary": src.get("event_summary"),
            "source": src,
        })

    next_search_after = samples[-1].get("sort") if samples else None

    return {
        "ok": True,
        "sourceType": source_type,
        "viewName": f"{source_type}-*",
        "total": total,
        "samples": samples,
        "next_search_after": next_search_after,
    }


@api_v1.post("/osd/preview-event-summary")
async def osd_preview_event_summary(req: Request, body: OSDPreviewEventSummaryPayload):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    section = (body.section or "").strip()

    if not section:
        return JSONResponse({"ok": False, "error": "missing section"}, status_code=400)

    if section == "global":
        return {
            "ok": True,
            "event_summary": None,
            "message": None,
        }

    if not re.fullmatch(r"[a-zA-Z0-9._-]+", section):
        return JSONResponse({"ok": False, "error": "invalid section"}, status_code=400)

    missing = _os_ready()
    if missing:
        return JSONResponse({"ok": False, "error": missing}, status_code=500)

    raw_fields = body.fields or []
    if not isinstance(raw_fields, list):
        raw_fields = []

    skip = {
        "tags",
        "event.comments.last",
        "event.comments.count",
        "event.comments.history",
        "Add_Enrichment",
        "document_id",
        "case_id",
        "source_type",
        "@timestamp",
        "event_summary",
    }

    should_clauses = []
    seen = set()

    for field in raw_fields[:50]:
        f = str(field or "").strip()
        if not f:
            continue
        if f in skip:
            continue
        if f in seen:
            continue
        seen.add(f)
        should_clauses.append({
            "exists": {
                "field": f
            }
        })

    target = f"{section}-*"
    url = f"{OS_HOST.rstrip('/')}/{target}/_search"

    bool_query: Dict[str, Any] = {
        "must": [
            {
                "exists": {
                    "field": "event_summary"
                }
            }
        ]
    }

    if should_clauses:
        bool_query["should"] = should_clauses
        bool_query["minimum_should_match"] = 1

    query = {
        "size": 1,
        "_source": ["event_summary"],
        "track_total_hits": False,
        "query": {
            "bool": bool_query
        },
        "sort": [
            {"_score": {"order": "desc"}}
        ]
    }

    try:
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query, separators=(",", ":")),
            timeout=10,
            verify=_os_verify_param(),
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"opensearch request failed: {e}"}, status_code=500)

    if r.status_code != 200:
        return JSONResponse(
            {"ok": False, "error": f"opensearch error {r.status_code}: {r.text[:200]}"},
            status_code=500,
        )

    try:
        j = r.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid opensearch JSON: {e}"}, status_code=500)

    hits = ((j.get("hits") or {}).get("hits") or [])
    if not hits:
        return {
            "ok": True,
            "event_summary": None,
            "message": "No sample event found for this source type. Try reloading the case artefacts.",
        }

    src = (hits[0].get("_source") or {})
    summary = src.get("event_summary")

    if summary is None or str(summary).strip() == "":
        return {
            "ok": True,
            "event_summary": None,
            "message": "No sample event found for this source type. Try reloading the case artefacts.",
        }

    return {
        "ok": True,
        "event_summary": str(summary),
        "message": None,
    }

@api_v1.post("/osd/inspect-field")
async def osd_inspect_field(req: Request, body: OSDFieldInspectorPayload):
    _, user, resp = _require_admin_auth(req)
    if resp:
        return resp

    section = (body.section or "").strip()
    field = (body.field or "").strip()
    sections = body.sections or []
    if not isinstance(sections, list):
        sections = []

    if not section:
        return JSONResponse({"ok": False, "error": "missing section"}, status_code=400)

    if not field:
        return JSONResponse({"ok": False, "error": "missing field"}, status_code=400)

    if section == "global":
        target_pattern = "*"
    else:
        target_pattern = f"{section}-*"

    if not re.fullmatch(r"[a-zA-Z0-9._-]+", section):
        return JSONResponse({"ok": False, "error": "invalid section"}, status_code=400)

    missing = _os_ready()
    if missing:
        return JSONResponse({"ok": False, "error": missing}, status_code=500)

    def _format_pct(part: int, total: int) -> str:
        if total <= 0:
            return "0%"
        pct = (float(part) / float(total)) * 100.0
        s = f"{pct:.1f}".rstrip("0").rstrip(".")
        return f"{s}%"

    def _post_search(target: str, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        url = f"{OS_HOST.rstrip('/')}/{target}/_search"
        try:
            r = requests.post(
                url,
                auth=(OS_USER, OS_PASS),
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload, separators=(",", ":")),
                timeout=15,
                verify=_os_verify_param(),
            )
        except Exception as e:
            return None, f"opensearch request failed: {e}"

        if r.status_code != 200:
            return None, f"opensearch error {r.status_code}: {r.text[:200]}"

        try:
            return r.json(), None
        except Exception as e:
            return None, f"invalid opensearch JSON: {e}"

    top_values: List[Dict[str, Any]] = []

    candidates = [f"{field}.keyword", field] if not field.endswith(".keyword") else [field, field[:-8]]

    for agg_field in candidates:
        if not agg_field:
            continue

        body_json = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "exists": {
                    "field": field
                }
            },
            "aggs": {
                "top": {
                    "terms": {
                        "field": agg_field,
                        "size": 10,
                        "order": {"_count": "desc"},
                    }
                }
            }
        }

        j, err = _post_search(target_pattern, body_json)

        if err:
            continue

        buckets = (((j or {}).get("aggregations") or {}).get("top") or {}).get("buckets") or []
        if not isinstance(buckets, list):
            buckets = []

        top_values = [
            {
                "value": str(b.get("key_as_string", b.get("key", ""))),
                "count": int(b.get("doc_count", 0)),
            }
            for b in buckets
            if str(b.get("key_as_string", b.get("key", ""))).strip() != ""
        ]

        if top_values:
            break

    data_views: List[Dict[str, str]] = []

    if section == "global":
        targets = [("all", "all"), ("all-json", "all-json")]
        for s in sections:
            if s and s != "global":
                targets.append((f"{s}-*", f"{s}-*"))
    else:
        targets = [
            (f"{section}-*", f"{section}-*"),
            ("all", "all"),
            ("all-json", "all-json"),
        ]

    for view_name, target in targets:
        body_json = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "match_all": {}
            },
            "aggs": {
                "with_field": {
                    "filter": {
                        "exists": {
                            "field": field
                        }
                    }
                }
            }
        }

        j, err = _post_search(target, body_json)
        if err:
            continue

        total = int((((j or {}).get("hits") or {}).get("total") or {}).get("value") or 0)
        with_field = int(((((j or {}).get("aggregations") or {}).get("with_field") or {}).get("doc_count")) or 0)

        if total <= 0 or with_field <= 0:
            continue

        data_views.append({
            "name": view_name,
            "coverage": _format_pct(with_field, total),
        })

    return {
        "ok": True,
        "top_values": top_values,
        "data_views": data_views,
    }

@api_v1.post("/hosts/new")
async def hosts_new_submit(req: Request, body: HostNewRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {
        "case_id": body.case_id,
        "ip": body.ip,
    }
    if body.hostname is not None:
        payload["hostname"] = body.hostname
    if body.os is not None:
        payload["os"] = body.os
    if body.description is not None:
        payload["description"] = body.description

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "host_new"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/hosts/update")
async def hosts_update_submit(req: Request, body: HostUpdateRequest):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    payload = {
        "case_id": body.case_id,
        "ip": body.ip,
    }
    if body.hostname is not None:
        payload["hostname"] = body.hostname
    if body.os is not None:
        payload["os"] = body.os
    if body.description is not None:
        payload["description"] = body.description

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "host_update"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {"ok": True, "job_id": job_id}

@api_v1.post("/search/stats")
def api_search_stats(body: SearchStatsSubmit):
    case_id = (body.seed_case_id or "").strip()
    value = (body.value or "").strip()

    r, err = os_search_stats(
        case_id,
        value,
        body.fields,
        mode=body.mode,
        smart=body.smart,
        top_n=body.top_n,
    )

    if err:
        return {"ok": False, "error": err}

    return {"ok": True, **(r or {})}


@api_v1.post("/uploads/start", response_model=UploadSessionStartResponse)
async def api_upload_session_start(
    payload: UploadSessionStartRequest,
    req: Request,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    case_id = (payload.case_id or "").strip()
    host_ip = (payload.host_ip or "").strip()
    selection_mode = (payload.selection_mode or "files").strip().lower()

    if not case_id:
        raise HTTPException(status_code=400, detail="case_id is required")

    if not host_ip:
        raise HTTPException(status_code=400, detail="host_ip is required")

    if selection_mode not in {"files", "folder", "mixed"}:
        raise HTTPException(status_code=400, detail="selection_mode must be one of: files, folder, mixed")

    try:
        meta = _create_upload_session_meta(
            case_id=case_id,
            host_ip=host_ip,
            created_by=user,
            selection_mode=selection_mode,
            preserve_folder_structure=payload.preserve_folder_structure,
            verify_sha256=payload.verify_sha256,
            chunk_large_files=payload.chunk_large_files,
        )
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Upload session already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create upload session: {e}")

    return UploadSessionStartResponse(
        ok=True,
        upload_id=meta["upload_id"],
        status=meta["status"],
        meta=meta,
    )

@api_v1.post("/uploads/{upload_id}/items")
async def api_upload_session_add_item(
    upload_id: str,
    req: Request,
    file: UploadFile = File(...),
    relative_path: str = Form(...),
    source: str = Form("file-picker"),
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        meta = _load_upload_session_meta(upload_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Upload session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load upload session: {e}")

    if meta.get("created_by") != user:
        raise HTTPException(status_code=403, detail="Upload session does not belong to the current user")

    status = (meta.get("status") or "").strip().lower()
    if status not in {"pending", "uploading", "staged"}:
        raise HTTPException(status_code=409, detail=f"Upload session is not writable in status '{status}'")

    try:
        staged = await _stage_upload_file(
            upload_id,
            file,
            relative_path=relative_path,
            source=source,
        )

        _append_upload_session_item(
            meta,
            relative_path=staged["relative_path"],
            size_bytes=staged["size_bytes"],
            source=staged["source"],
            sha256=staged["sha256"],
        )

        _save_upload_session_meta(upload_id, meta)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        meta["status"] = "failed"
        meta["error"] = str(e)
        try:
            _save_upload_session_meta(upload_id, meta)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to stage upload item: {e}")

    return {
        "ok": True,
        "upload_id": upload_id,
        "status": meta["status"],
        "item_count": meta["item_count"],
        "total_bytes": meta["total_bytes"],
        "last_item": meta["items"][-1] if meta.get("items") else None,
    }



@api_v1.post("/uploads/{upload_id}/finalize")
async def api_upload_session_finalize(
    upload_id: str,
    req: Request,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        meta = _load_upload_session_meta(upload_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Upload session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load upload session: {e}")

    if meta.get("created_by") != user:
        raise HTTPException(status_code=403, detail="Upload session does not belong to the current user")

    status = (meta.get("status") or "").strip().lower()
    if status not in {"uploading", "staged"}:
        raise HTTPException(status_code=409, detail=f"Upload session is not finalizable in status '{status}'")

    items = meta.get("items") or []
    if not items:
        raise HTTPException(status_code=400, detail="Upload session has no staged items")

    created_at = int(time.time())
    created_by = user
    job_status = "queued"
    action = "upload_finalize"
    payload_json = json.dumps(
        {
            "upload_id": upload_id,
        },
        separators=(",", ":"),
    )

    try:
        meta["status"] = "staged"
        meta["error"] = ""
        _save_upload_session_meta(upload_id, meta)

        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                """
                INSERT INTO jobs (created_at, created_by, status, action, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (created_at, created_by, job_status, action, payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to enqueue upload finalize job: {e}")

    return {
        "ok": True,
        "job_id": job_id,
    }

@api_v1.post("/uploads/{upload_id}/items/init")
async def api_upload_session_init_chunked_item(
    upload_id: str,
    req: Request,
    payload: dict,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        meta = _load_upload_session_meta(upload_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Upload session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load upload session: {e}")

    if meta.get("created_by") != user:
        raise HTTPException(status_code=403, detail="Upload session does not belong to the current user")

    status = (meta.get("status") or "").strip().lower()
    if status not in {"pending", "uploading", "staged"}:
        raise HTTPException(status_code=409, detail=f"Upload session is not writable in status '{status}'")

    try:
        item_meta = _init_chunked_upload_item(
            upload_id,
            relative_path=str(payload.get("relative_path") or ""),
            source=str(payload.get("source") or "file-picker"),
            total_chunks=int(payload.get("total_chunks") or 0),
            total_size_bytes=int(payload.get("total_size_bytes") or 0),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Chunked upload item already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initialize chunked upload item: {e}")

    return {
        "ok": True,
        "upload_id": upload_id,
        "item_id": item_meta["item_id"],
        "relative_path": item_meta["relative_path"],
        "total_chunks": item_meta["total_chunks"],
        "status": item_meta["status"],
    }


@api_v1.post("/uploads/list-incomplete-items")
async def api_upload_list_incomplete_items(
    req: Request,
    payload: dict,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    case_id = str(payload.get("case_id") or "").strip()
    host_ip = str(payload.get("host_ip") or "").strip()

    if not case_id:
        raise HTTPException(status_code=400, detail="case_id is required")
    if not host_ip:
        raise HTTPException(status_code=400, detail="host_ip is required")

    uploads_root = UPLOADS_ROOT
    if not os.path.isdir(uploads_root):
        return {
            "ok": True,
            "items": [],
        }

    def _normalize_relative_path(value):
        return str(value or "").replace("\\", "/").lstrip("/").strip()

    def _candidate_sort_key(entry):
        return (
            int(entry.get("received_count") or 0),
            str(entry.get("updated_at") or "").strip(),
            str(entry.get("upload_id") or "").strip(),
        )

    best_items_by_key = {}

    try:
        for upload_id in sorted(os.listdir(uploads_root), reverse=True):
            session_dir = _upload_session_dir(upload_id)
            meta_path = _upload_session_meta_path(upload_id)

            if not os.path.isdir(session_dir) or not os.path.isfile(meta_path):
                continue

            try:
                meta = _load_upload_session_meta(upload_id)
            except Exception:
                continue

            if meta.get("created_by") != user:
                continue
            if str(meta.get("case_id") or "").strip() != case_id:
                continue
            if str(meta.get("host_ip") or "").strip() != host_ip:
                continue

            chunks_root = _upload_session_chunks_root(upload_id)
            if not os.path.isdir(chunks_root):
                continue

            for item_id in os.listdir(chunks_root):
                item_meta_path = _upload_item_chunk_meta_path(upload_id, item_id)
                if not os.path.isfile(item_meta_path):
                    continue

                try:
                    with open(item_meta_path, "r", encoding="utf-8") as f:
                        item_meta = json.load(f)
                except Exception:
                    continue

                item_status = str(item_meta.get("status") or "").strip().lower()
                if item_status not in {"pending", "uploading", "assembling"}:
                    continue

                relative_path = _normalize_relative_path(item_meta.get("relative_path"))
                total_chunks = int(item_meta.get("total_chunks") or 0)
                total_size_bytes = int(item_meta.get("total_size_bytes") or 0)
                received_chunks = sorted(
                    {
                        int(x)
                        for x in (item_meta.get("received_chunks") or [])
                        if str(x).isdigit()
                    }
                )
                received_chunks_set = set(received_chunks)

                candidate = {
                    "upload_id": upload_id,
                    "item_id": item_id,
                    "relative_path": relative_path,
                    "source": item_meta.get("source") or "file-picker",
                    "status": item_meta.get("status") or "pending",
                    "total_chunks": total_chunks,
                    "total_size_bytes": total_size_bytes,
                    "received_chunks": received_chunks,
                    "received_count": len(received_chunks),
                    "missing_chunks": [i for i in range(total_chunks) if i not in received_chunks_set],
                    "assembled_size_bytes": int(item_meta.get("assembled_size_bytes") or 0),
                    "created_at": item_meta.get("created_at"),
                    "updated_at": item_meta.get("updated_at"),
                }

                dedupe_key = (relative_path, total_size_bytes)
                existing = best_items_by_key.get(dedupe_key)

                if existing is None or _candidate_sort_key(candidate) > _candidate_sort_key(existing):
                    best_items_by_key[dedupe_key] = candidate

        items = sorted(
            best_items_by_key.values(),
            key=lambda x: (
                str(x.get("updated_at") or "").strip(),
                str(x.get("upload_id") or "").strip(),
                str(x.get("relative_path") or "").strip(),
            ),
            reverse=True,
        )

        return {
            "ok": True,
            "items": items,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list incomplete upload items: {e}")



@api_v1.post("/uploads/find-resumable-item")
async def api_upload_find_resumable_item(
    req: Request,
    payload: dict,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    case_id = str(payload.get("case_id") or "").strip()
    host_ip = str(payload.get("host_ip") or "").strip()
    relative_path = str(payload.get("relative_path") or "").replace("\\", "/").lstrip("/").strip()
    total_size_bytes = int(payload.get("total_size_bytes") or 0)

    if not case_id:
        raise HTTPException(status_code=400, detail="case_id is required")
    if not host_ip:
        raise HTTPException(status_code=400, detail="host_ip is required")
    if not relative_path:
        raise HTTPException(status_code=400, detail="relative_path is required")
    if total_size_bytes < 0:
        raise HTTPException(status_code=400, detail="total_size_bytes must be zero or greater")

    uploads_root = UPLOADS_ROOT
    if not os.path.isdir(uploads_root):
        return {
            "ok": True,
            "found": False,
        }

    def _normalize_relative_path(value):
        return str(value or "").replace("\\", "/").lstrip("/").strip()

    def _candidate_sort_key(entry):
        return (
            int(entry.get("received_count") or 0),
            str(entry.get("updated_at") or "").strip(),
            str(entry.get("upload_id") or "").strip(),
        )

    best_match = None

    try:
        for upload_id in sorted(os.listdir(uploads_root), reverse=True):
            session_dir = _upload_session_dir(upload_id)
            meta_path = _upload_session_meta_path(upload_id)

            if not os.path.isdir(session_dir) or not os.path.isfile(meta_path):
                continue

            try:
                meta = _load_upload_session_meta(upload_id)
            except Exception:
                continue

            if meta.get("created_by") != user:
                continue
            if str(meta.get("case_id") or "").strip() != case_id:
                continue
            if str(meta.get("host_ip") or "").strip() != host_ip:
                continue

            chunks_root = _upload_session_chunks_root(upload_id)
            if not os.path.isdir(chunks_root):
                continue

            for item_id in os.listdir(chunks_root):
                item_meta_path = _upload_item_chunk_meta_path(upload_id, item_id)
                if not os.path.isfile(item_meta_path):
                    continue

                try:
                    with open(item_meta_path, "r", encoding="utf-8") as f:
                        item_meta = json.load(f)
                except Exception:
                    continue

                item_relative_path = _normalize_relative_path(item_meta.get("relative_path"))
                item_total_size_bytes = int(item_meta.get("total_size_bytes") or 0)
                item_status = str(item_meta.get("status") or "").strip().lower()

                if item_relative_path != relative_path:
                    continue
                if item_total_size_bytes != total_size_bytes:
                    continue
                if item_status not in {"pending", "uploading", "assembling"}:
                    continue

                received_chunks = sorted(
                    {
                        int(x)
                        for x in (item_meta.get("received_chunks") or [])
                        if str(x).isdigit()
                    }
                )

                candidate = {
                    "ok": True,
                    "found": True,
                    "upload_id": upload_id,
                    "item_id": item_id,
                    "status": item_meta.get("status") or "pending",
                    "relative_path": item_relative_path,
                    "total_size_bytes": item_total_size_bytes,
                    "total_chunks": int(item_meta.get("total_chunks") or 0),
                    "received_chunks": received_chunks,
                    "received_count": len(received_chunks),
                    "assembled_size_bytes": int(item_meta.get("assembled_size_bytes") or 0),
                    "created_at": item_meta.get("created_at"),
                    "updated_at": item_meta.get("updated_at"),
                }

                if best_match is None or _candidate_sort_key(candidate) > _candidate_sort_key(best_match):
                    best_match = candidate

        if best_match is not None:
            best_match.pop("received_count", None)
            return best_match

        return {
            "ok": True,
            "found": False,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search for resumable upload item: {e}")


@api_v1.post("/uploads/{upload_id}/items/{item_id}/chunks")
async def api_upload_session_add_chunk(
    upload_id: str,
    item_id: str,
    req: Request,
    file: UploadFile = File(...),
    chunk_index: int = Form(...),
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        meta = _load_upload_session_meta(upload_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Upload session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load upload session: {e}")

    if meta.get("created_by") != user:
        raise HTTPException(status_code=403, detail="Upload session does not belong to the current user")

    try:
        staged = await _stage_upload_chunk(
            upload_id,
            item_id,
            file,
            chunk_index=int(chunk_index),
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Chunked upload item not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stage upload chunk: {e}")

    return {
        "ok": True,
        "upload_id": upload_id,
        "item_id": item_id,
        **staged,
    }


@api_v1.get("/uploads/{upload_id}/items/{item_id}/status")
async def api_upload_session_chunked_item_status(
    upload_id: str,
    item_id: str,
    req: Request,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        meta = _load_upload_session_meta(upload_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Upload session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load upload session: {e}")

    if meta.get("created_by") != user:
        raise HTTPException(status_code=403, detail="Upload session does not belong to the current user")

    item_meta_path = _upload_item_chunk_meta_path(upload_id, item_id)
    if not os.path.isfile(item_meta_path):
        raise HTTPException(status_code=404, detail="Chunked upload item not found")

    try:
        with open(item_meta_path, "r", encoding="utf-8") as f:
            item_meta = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read chunked upload item metadata: {e}")

    total_chunks = int(item_meta.get("total_chunks") or 0)
    received_chunks = sorted(
        {
            int(x)
            for x in (item_meta.get("received_chunks") or [])
            if str(x).isdigit()
        }
    )
    missing_chunks = [i for i in range(total_chunks) if i not in set(received_chunks)]

    return {
        "ok": True,
        "upload_id": upload_id,
        "item_id": item_id,
        "relative_path": item_meta.get("relative_path") or "",
        "source": item_meta.get("source") or "file-picker",
        "status": item_meta.get("status") or "pending",
        "total_chunks": total_chunks,
        "total_size_bytes": int(item_meta.get("total_size_bytes") or 0),
        "received_chunks": received_chunks,
        "received_count": len(received_chunks),
        "missing_chunks": missing_chunks,
        "next_missing_chunk": missing_chunks[0] if missing_chunks else None,
        "assembled_size_bytes": int(item_meta.get("assembled_size_bytes") or 0),
        "created_at": item_meta.get("created_at"),
        "updated_at": item_meta.get("updated_at"),
    }

@api_v1.post("/uploads/{upload_id}/items/{item_id}/complete")
async def api_upload_session_complete_chunked_item(
    upload_id: str,
    item_id: str,
    req: Request,
):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        meta = _load_upload_session_meta(upload_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Upload session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load upload session: {e}")

    if meta.get("created_by") != user:
        raise HTTPException(status_code=403, detail="Upload session does not belong to the current user")

    status = (meta.get("status") or "").strip().lower()
    if status not in {"pending", "uploading", "staged"}:
        raise HTTPException(status_code=409, detail=f"Upload session is not writable in status '{status}'")

    item_meta_path = _upload_item_chunk_meta_path(upload_id, item_id)
    if not os.path.isfile(item_meta_path):
        raise HTTPException(status_code=404, detail="Chunked upload item not found")

    try:
        with open(item_meta_path, "r", encoding="utf-8") as f:
            item_meta = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read chunked upload item metadata: {e}")

    item_meta["status"] = "assembling"
    item_meta["updated_at"] = _utc_now_iso()
    _write_json_atomic(item_meta_path, item_meta)

    payload = {
        "upload_id": upload_id,
        "item_id": item_id,
    }

    created_at = int(time.time())
    created_by = user
    status = "queued"
    action = "upload_chunked_item_complete"
    payload_json = json.dumps(payload, separators=(",", ":"))

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO jobs (created_at, created_by, status, action, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, created_by, status, action, payload_json),
        )
        await db.commit()
        job_id = cur.lastrowid

    return {
        "ok": True,
        "upload_id": upload_id,
        "item_id": item_id,
        "status": "assembling",
        "job_id": job_id,
    }


@api_v1.get("/field-mappings")
async def field_mappings_list(req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    data = _load_field_mappings_from_yaml()
    return {
        "ok": True,
        "source_types": data["source_types"],
    }

@api_v1.post("/field-mappings/save")
async def field_mappings_save(req: Request):
    _, user, resp = _require_auth(req)
    if resp:
        return resp

    try:
        raw = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)

    try:
        payload = FieldMappingsSavePayload(**raw)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid field mappings payload: {e}"}, status_code=400)

    try:
        payload_json = payload.model_dump_json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"failed to serialize payload: {e}"}, status_code=500)

    now = int(time.time())

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO jobs (created_at, created_by, status, action, payload_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (now, user, "queued", "field_mappings_save", payload_json),
            )
            await db.commit()
            job_id = cur.lastrowid
            print(f"[job queued] id={job_id} action=field_mappings_save user={user}")
    except aiosqlite.Error as e:
        return JSONResponse({"ok": False, "error": f"failed to enqueue job: {e}"}, status_code=500)

    return {
        "ok": True,
        "job_id": job_id,
    }

# -------------------------
# API route
# -------------------------

app.include_router(api_v1)

