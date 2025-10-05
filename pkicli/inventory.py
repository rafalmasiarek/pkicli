# inventory.py
from typing import List, Dict, Any
from .aws_s3 import S3Client
from .utils import safe_get, now_utc_str
from .serde.io import read_inventory, write_inventory, read_cert

def extract_cas(inv):
    cas = inv.get("cas")
    return cas if isinstance(cas, list) else []

def extract_certs(inv):
    certs = inv.get("certs")
    return certs if isinstance(certs, list) else []


def rebuild_inventory(s3: S3Client, target_version: str = "v1") -> Dict[str, Any]:
    """
    Rebuild 'certs' in the inventory keeping only active certificates.
    Active means:
      - rotation.status != 'revoked'
      - status != 'revoked'
      - 'deleted' tag not present
    We re-read each cert by name via read_cert() to refresh data.
    """
    inv = read_inventory(s3)
    cas = extract_cas(inv)
    current = extract_certs(inv)

    rebuilt: List[Dict[str, Any]] = []
    for entry in current:
        name = entry.get("name")
        if not name:
            continue
        try:
            doc = read_cert(s3, name)
        except Exception:
            # Skip unreadable/missing certs
            continue

        status_rotation = (safe_get(doc, "rotation.status", "") or "").lower()
        status_explicit = (doc.get("status") or "").lower()
        tags = [str(t).lower() for t in (doc.get("tags") or [])]

        if status_rotation == "revoked" or status_explicit == "revoked" or "deleted" in tags:
            continue

        rebuilt.append(doc)

    inv["certs"] = rebuilt
    inv.setdefault("cas", cas)
    inv["updated_at"] = now_utc_str()
    write_inventory(s3, inv, schema_version=target_version)
    return inv