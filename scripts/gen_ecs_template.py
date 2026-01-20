# ------------------------------------------------------------------
# Recursive-IR helper script
# Copyright (c) 2026 Mark Jayson Alvarez
# Licensed under the Recursive-IR License
# ------------------------------------------------------------------
#!/usr/bin/env python3
"""
gen_ecs_template.py — ECS template builder 

Outputs:
  opensearch/templates/ecs-component.json
"""

import sys, csv, json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


# ---------- Paths ----------
ROOT = (
    Path(__file__).resolve().parents[1]
    if (Path(__file__).resolve().parents[1] / "conf").exists()
    else Path(__file__).resolve().parents[0]
)
ECS_CSV = ROOT / "conf" / "ecs-fields.csv"
OUT_ECS_TEMPLATE = ROOT / "opensearch" / "templates" / "ecs-component.json"


# ---------- Template config ----------
TEMPLATE_NAME = "ecs-component"
TEMPLATE_PRIORITY = 450
SCALED_FLOAT_DEFAULT = 1000
MAX_FIELDS_LIMIT = 10000


# ---------- ECS type mapping to OpenSearch ----------
ECS_TYPE_MAP = {
    # pass-through
    "keyword": "keyword", "text": "text", "long": "long", "integer": "integer",
    "short": "short", "byte": "byte", "double": "double", "float": "float",
    "half_float": "half_float", "date": "date", "boolean": "boolean",
    "ip": "ip", "geo_point": "geo_point", "geo_shape": "geo_shape",
    "nested": "nested", "object": "object", "version": "version",
    # compatibility
    "constant_keyword": "keyword",
    "flattened": "object",
    "scaled_float": "scaled_float",
    "aggregate_metric_double": "object",
    "histogram": "object",
    "rank_feature": "float",
    "rank_features": "object",
    "unsigned_long": "unsigned_long",
    "date_nanos": "date_nanos",
    "wildcard": "wildcard",
}

STRUCTURAL_TYPES = {"object", "nested", "flattened"}

def is_structural(t: Optional[str]) -> bool:
    return t in STRUCTURAL_TYPES

def is_scalar(t: Optional[str]) -> bool:
    return bool(t) and t not in STRUCTURAL_TYPES


EVTX_OBJECT_HINTS = []


# ---------- CSV loaders ----------
def load_ecs_fields_with_types(csv_path: Path):
    rows = []
    if not csv_path.exists():
        print(f"[ERROR] ECS CSV not found: {csv_path}", file=sys.stderr)
        return rows

    def parse_bool(s: str) -> Optional[bool]:
        if s is None:
            return None
        v = str(s).strip().lower()
        if v in ("true", "1", "yes", "y", "t"):
            return True
        if v in ("false", "0", "no", "n", "f"):
            return False
        return None

    with open(csv_path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        fn = [c or "" for c in (r.fieldnames or [])]

        field_col = next((c for c in fn if (c or "").strip().lower() == "field"), None)
        type_col  = next((c for c in fn if (c or "").strip().lower() == "type"), None)
        if not field_col or not type_col:
            print(
                f"[ERROR] 'Field' and/or 'Type' column not found in {csv_path}\n"
                f"Found columns: {fn}",
                file=sys.stderr,
            )
            return rows

        indexed_col = next(
            (c for c in fn if (c or "").strip().lower() in ("indexed", "index")),
            None,
        )

        sf_col = next(
            (c for c in fn if (c or "").strip().lower().replace(" ", "_") in ("scaling_factor", "scale", "scale_factor")),
            None,
        )

        for row in r:
            field = (row.get(field_col) or "").strip()
            typ   = (row.get(type_col)  or "").strip().lower()
            if not field or not typ:
                continue

            sf = None
            if sf_col:
                raw_sf = (row.get(sf_col) or "").strip()
                if raw_sf:
                    try:
                        sf = int(raw_sf)
                    except ValueError:
                        pass

            indexed = None
            if indexed_col:
                indexed = parse_bool(row.get(indexed_col))

            rows.append({
                "field": field,
                "type": typ,
                "scaling_factor": sf,
                "indexed": indexed,   # None => unknown/unset
            })

    return rows

# ---------- ECS template builder ----------
def insert_mapping_path(tree: dict, path_parts: list, leaf_mapping: dict, dropped: list, src_label: str):
    """
    Inserts/merges a mapping at the given dotted path, respecting structural types:
      - object/nested may have 'properties'
      - flattened MUST NOT have 'properties' and cannot nest subfields
    """
    def _is_structural(t):
        return t in ("object", "nested", "flattened")

    def _is_scalar(t):
        return t is not None and t not in ("object", "nested", "flattened")

    node = tree
    for i, part in enumerate(path_parts):
        is_leaf = (i == len(path_parts) - 1)
        props = node.setdefault("properties", {})
        child = props.get(part)
        if child is None:
            child = {}
            props[part] = child

        if not is_leaf:
            existing_type = child.get("type")

            # If an ancestor is already 'flattened', we cannot create children
            if existing_type == "flattened":
                dropped.append({
                    "field": ".".join(path_parts),
                    "reason": f"parent '{'.'.join(path_parts[:i+1])}' is flattened; cannot add nested field for source '{src_label}'"
                })
                return False

            # If there is a non-structural existing type on a non-leaf, conflict
            if existing_type and existing_type not in ("object", "nested", "flattened"):
                dropped.append({
                    "field": ".".join(path_parts),
                    "reason": f"parent '{'.'.join(path_parts[:i+1])}' is non-object ({existing_type}) for source '{src_label}'"
                })
                return False

            # Default non-leaf to object, preserving an existing structural type
            if not existing_type:
                child["type"] = "object"

        else:
            existing_type = child.get("type")
            new_type = leaf_mapping.get("type")

            # Structural/scalar conflicts
            if _is_structural(existing_type) and _is_scalar(new_type):
                dropped.append({
                    "field": ".".join(path_parts),
                    "reason": f"existing structural parent conflicts with scalar leaf for source '{src_label}'"
                })
                return False
            if _is_scalar(existing_type) and _is_structural(new_type):
                dropped.append({
                    "field": ".".join(path_parts),
                    "reason": f"existing scalar leaf conflicts with structural type ({new_type}) for source '{src_label}'"
                })
                return False

            if new_type in ("object", "nested", "flattened"):
                # Set structural type exactly as requested
                child["type"] = new_type or child.get("type", "object")

                if new_type in ("object", "nested"):
                    # Only object/nested may have properties
                    child.setdefault("properties", {})
                    in_props = leaf_mapping.get("properties")
                    if isinstance(in_props, dict) and in_props:
                        child["properties"].update(in_props)
                else:
                    # flattened: ensure no properties are attached
                    child.pop("properties", None)

                # Copy any additional attributes except properties (handled above)
                for k, v in leaf_mapping.items():
                    if k not in ("type", "properties"):
                        child[k] = v
            else:
                # Scalar or other non-structural leaf: just merge
                child.update(leaf_mapping)

        node = child

    return True


def coerce_type(t: str) -> str:
    return ECS_TYPE_MAP.get(t, t)


def get_mapping_node(mapping: dict, parts: list[str]):
    """
    Navigate mapping['properties'] by dotted parts and return the node dict, or None.
    """
    node = mapping
    for p in parts:
        props = node.get("properties")
        if not isinstance(props, dict):
            return None
        node = props.get(p)
        if not isinstance(node, dict):
            return None
    return node


def attach_multifield(mapping: dict, base_parts: list[str], subfield_name: str,
                      subfield_mapping: dict, dropped: list, src_label: str):
    """
    Attach a multi-field (e.g., .text) under an existing scalar field.
    """
    base = get_mapping_node(mapping, base_parts)
    if base is None:
        dropped.append({
            "field": ".".join(base_parts) + f".{subfield_name}",
            "reason": f"base field does not exist for multi-field source '{src_label}'"
        })
        return False

    base_type = base.get("type")
    if not is_scalar(base_type):
        dropped.append({
            "field": ".".join(base_parts) + f".{subfield_name}",
            "reason": f"base field is not scalar (type={base_type}) for multi-field source '{src_label}'"
        })
        return False

    fields = base.setdefault("fields", {})
    existing = fields.get(subfield_name)
    if isinstance(existing, dict) and existing.get("type") and existing.get("type") != subfield_mapping.get("type"):
        dropped.append({
            "field": ".".join(base_parts) + f".{subfield_name}",
            "reason": f"multi-field conflict: existing type={existing.get('type')} new type={subfield_mapping.get('type')} for source '{src_label}'"
        })
        return False

    fields[subfield_name] = subfield_mapping
    return True


def build_ecs_mapping_from_csv(csv_path: Path):
    mapping = {"date_detection": False, "dynamic": True, "properties": {}}
    dropped_ecs = []
    rows = load_ecs_fields_with_types(csv_path)

    # Collect ambiguous ".text" declarations; decide in second pass whether they are
    # true multi-fields OR real ECS fields like process.io.text
    # Tuple shape: (base_field, subfield, raw_type, scaling_factor, indexed, src_label)
    pending_text_suffix = []

    for item in rows:
        field = item["field"]
        raw_type = item["type"]
        sf_from_csv = item.get("scaling_factor")
        indexed = item.get("indexed")  # True/False/None

        # Wildcard parent (e.g., foo.*) → ensure parent is an object and skip concrete leaf
        if "*" in field:
            prefix = field.split("*", 1)[0].rstrip(".")
            if prefix:
                insert_mapping_path(mapping, prefix.split("."), {"type": "object"}, dropped_ecs, field)
            continue

        # Ambiguous suffix: could be a multi-field OR a real ECS field name
        if field.endswith(".text"):
            base_field = field[:-len(".text")]
            pending_text_suffix.append((base_field, "text", raw_type, sf_from_csv, indexed, field))
            continue

        parts = field.split(".")
        t = coerce_type(raw_type)

        if t == "scaled_float":
            leaf = {"type": "scaled_float", "scaling_factor": int(sf_from_csv or SCALED_FLOAT_DEFAULT)}
            if indexed is False:
                leaf["index"] = False
        elif t in ("object", "nested", "flattened"):
            leaf = {"type": t}
            if t in ("object", "nested"):
                leaf["properties"] = {}
            # structural types: ignore indexed flag
        else:
            leaf = {"type": t}
            if indexed is False:
                leaf["index"] = False

        insert_mapping_path(mapping, parts, leaf, dropped_ecs, field)

    # Second pass: resolve each *.text row:
    #   - if base exists & is scalar => attach as multi-field under base.fields.text
    #   - else => insert as a real field path (e.g., process.io.text)
    for base_field, subfield, raw_type, sf_from_csv, indexed, src_label in pending_text_suffix:
        base_parts = base_field.split(".")
        base_node = get_mapping_node(mapping, base_parts)
        base_type = base_node.get("type") if isinstance(base_node, dict) else None

        t = coerce_type(raw_type)

        # Case 1: true multi-field (keyword + fields.text)
        if base_node is not None and is_scalar(base_type):
            if t == "scaled_float":
                sub_leaf = {"type": "scaled_float", "scaling_factor": int(sf_from_csv or SCALED_FLOAT_DEFAULT)}
                if indexed is False:
                    sub_leaf["index"] = False
            elif t in ("object", "nested", "flattened"):
                dropped_ecs.append({
                    "field": f"{base_field}.{subfield}",
                    "reason": f"multi-field cannot be structural type ({t}) for source '{src_label}'"
                })
                continue
            else:
                sub_leaf = {"type": t}
                if indexed is False:
                    sub_leaf["index"] = False

            attach_multifield(mapping, base_parts, subfield, sub_leaf, dropped_ecs, src_label)
            continue

        # Case 2: real ECS field (structural parent or missing base) -> insert normally
        full_field = f"{base_field}.{subfield}"
        parts = full_field.split(".")

        if t == "scaled_float":
            leaf = {"type": "scaled_float", "scaling_factor": int(sf_from_csv or SCALED_FLOAT_DEFAULT)}
            if indexed is False:
                leaf["index"] = False
        elif t in ("object", "nested", "flattened"):
            leaf = {"type": t}
            if t in ("object", "nested"):
                leaf["properties"] = {}
            # structural types: ignore indexed flag
        else:
            leaf = {"type": t}
            if indexed is False:
                leaf["index"] = False

        insert_mapping_path(mapping, parts, leaf, dropped_ecs, full_field)

    return mapping, dropped_ecs


def add_object_hints(mapping: dict, hints: list, dropped: list):
    for dotted in hints:
        parts = dotted.split(".")
        insert_mapping_path(mapping, parts, {"type": "object", "dynamic": True}, dropped, dotted)


def main():
    now_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ecs_mapping, dropped_ecs = build_ecs_mapping_from_csv(ECS_CSV)

    # Optional object hints (safe no-op if EVTX_OBJECT_HINTS is empty)
    add_object_hints(ecs_mapping, EVTX_OBJECT_HINTS, dropped_ecs)

    ecs_component = {
        "template": {
            "settings": {
                "index.number_of_shards": "1",
                "index.number_of_replicas": "0",
                "index.codec": "best_compression",
                "index.mapping.total_fields.limit": int(MAX_FIELDS_LIMIT),
            },
            "mappings": ecs_mapping,
            "aliases": {}
        },
        "_meta": {
            "project": "Recursive-IR",
            "copyright": "Copyright (c) 2026 Mark Jayson Alvarez",
            "license": "Recursive-IR License",
            "description": f"ECS mapping template generated from {ECS_CSV.name}",
            "generator": Path(__file__).name,
            "generated_at": now_utc,
            "template_name": TEMPLATE_NAME,
            "dropped_ecs": dropped_ecs,
        },
        "version": 1
    }

    OUT_ECS_TEMPLATE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_ECS_TEMPLATE, "w", encoding="utf-8") as f:
        json.dump(ecs_component, f, ensure_ascii=False, indent=2)
    print(f"[OK] wrote {OUT_ECS_TEMPLATE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
