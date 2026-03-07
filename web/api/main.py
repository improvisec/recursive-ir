# ------------------------------------------------------------------
# Recursive-IR source file
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
#
from fastapi import FastAPI, Request, Response, Depends, HTTPException, APIRouter
from typing import List, Optional, Literal, Dict, Any, Tuple
from pydantic import BaseModel, Field, root_validator
from fastapi.responses import JSONResponse
import ctypes.util
import aiosqlite
import requests
import hashlib
import secrets
import ctypes
import time
import json
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
DB_PATH = os.getenv("JOBS_DB", "/data/jobs.db")

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
          last_output TEXT
        );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);")

        # Additive S2 columns (worker will also ensure these)
        await _ensure_column(db, "jobs", "action", "TEXT")
        await _ensure_column(db, "jobs", "role_at_create", "TEXT")
        await _ensure_column(db, "jobs", "claim_token", "TEXT")
        await _ensure_column(db, "jobs", "claimed_by", "TEXT")
        await _ensure_column(db, "jobs", "claimed_at", "INTEGER")

        # Job dedupe key (API will set; DB enforces dedupe for active jobs)
        await _ensure_column(db, "jobs", "dedupe_key", "TEXT")

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
        "ioc_add", "ioc_add_bulk",
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
        elif action in ("ioc_add", "ioc_add_bulk"):
            if not type:
                raise ValueError("type is required for ioc_add/ioc_add_bulk")
            if not value:
                raise ValueError("value is required for ioc_add/ioc_add_bulk")

            # Optional: cheap sanity check to keep payloads consistent
            if field and any(ch.isspace() for ch in field):
                raise ValueError("field must not contain whitespace")

            # IOC actions must not accept tag/text
            if tag:
                raise ValueError("tag is not allowed for ioc_add/ioc_add_bulk")
            if text:
                raise ValueError("text is not allowed for ioc_add/ioc_add_bulk")
            if name:
                raise ValueError("name is not allowed for ioc_add/ioc_add_bulk")

            if action == "ioc_add":
                if hits not in (None, [], ()):
                    raise ValueError("hits is not allowed for ioc_add")
            else:  # ioc_add_bulk
                if not hits:
                    raise ValueError("hits is required for ioc_add_bulk")

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

    size = limit if include_hits else 0

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
                })                

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
    # ioc_add (single)
    # ------------------------------------------------------------
    if body.action == "ioc_add":
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

        dedupe_material = f"v1|ioc_add|{derived_case_id}|{body.seed_index}|{body.seed_id}|{user}|{type}|{value}|{field or ''}"
        dedupe_key = _sha256_hex(dedupe_material)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cur = await db.execute(
                    "INSERT INTO jobs (created_at, created_by, status, action, dedupe_key, payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (now, user, "queued", "ioc_add", dedupe_key, payload_json),
                )
                await db.commit()
                job_id = cur.lastrowid
                print(f"[job queued] id={job_id} action=ioc_add user={user} payload={payload} dedupe={dedupe_key}")
                return {"ok": True, "status": "queued", "job_id": job_id, "action": "ioc_add", **payload}

            except aiosqlite.Error as e:
                msg = str(e).lower()
                if "unique" in msg or "constraint" in msg:
                    existing_id = await _return_existing_active_job(db, "ioc_add", dedupe_key)
                    if existing_id:
                        print(f"[job dedupe] existing_id={existing_id} action=ioc_add user={user} payload={payload} dedupe={dedupe_key}")
                        return {"ok": True, "status": "already_queued", "job_id": existing_id, "action": "ioc_add", **payload}
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
    if body.action not in ("tag_add_bulk", "ioc_add_bulk", "collection_add_bulk", "collection_del_bulk"):
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

    elif body.action == "ioc_add_bulk":
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
        op = "add"
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

# -------------------------
# API route
# -------------------------
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


app.include_router(api_v1)

