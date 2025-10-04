# cert_ops.py
# Certificate list/show operations (read paths). Mutating ops can be added later.
import json
from .aws_s3 import S3Client
from .render import fmt_table
from .utils import safe_get, days_until

def cert_list(s3: S3Client, expiring_in: int, out: str):
    """List certificates from cert-inventory.json, optionally filter by expiring_in days."""
    inv = s3.get_json(s3.key("cert-inventory.json"))
    certs = inv.get("certs") or []
    # Basic filter by expiry
    rows_data = []
    for c in certs:
        na = safe_get(c, "metadata.not_after", "")
        if expiring_in is not None:
            if not na:
                continue
            if days_until(na) > expiring_in:
                continue
        rows_data.append({
            "name": c.get("name",""),
            "type": c.get("type",""),
            "not_after": na,
            "ca": safe_get(c, "ca.name", ""),
            "cert_arn": c.get("cert_secret_arn","") or "",
            "key_arn": c.get("key_secret_arn","") or "",
            "state_s3": "",  # per-cert state is usually <prefix>/<name>.json, but inventory can be enough
        })

    if out == "table":
        if not rows_data:
            print("No certificates found.")
            return
        rows = [["NAME","TYPE","NOT_AFTER","CA","CERT_ARN","KEY_ARN"]]
        for r in rows_data:
            rows.append([
                r["name"], r["type"], r["not_after"], r["ca"], r["cert_arn"], r["key_arn"]
            ])
        print(fmt_table(rows))
    else:
        print(json.dumps(rows_data, indent=2))

def cert_show(s3: S3Client, name: str, out: str):
    """Show a single certificate JSON by name (reads <name>.json from S3)."""
    doc = s3.get_json(s3.key(f"{name}.json"))
    if out == "table":
        rows = [["FIELD","VALUE"]]
        rows += [
            ["name", doc.get("name","")],
            ["type", doc.get("type","")],
            ["CN", safe_get(doc,"subject.CN","")],
            ["O",  safe_get(doc,"subject.O","")],
            ["not_before", safe_get(doc,"metadata.not_before","")],
            ["not_after",  safe_get(doc,"metadata.not_after","")],
            ["sha256",     safe_get(doc,"metadata.sha256","")],
            ["sig_alg",    safe_get(doc,"metadata.sig_alg","")],
            ["pubkey",     f"{safe_get(doc,'metadata.pubkey_algo','')}/{safe_get(doc,'metadata.pubkey_bits','')}"],
            ["ca.name",    safe_get(doc,"ca.name","")],
            ["ca.version", str(safe_get(doc,"ca.version",""))],
            ["cert_arn",   doc.get("cert_secret_arn","") or ""],
            ["key_arn",    doc.get("key_secret_arn","") or ""],
            ["updated_at", doc.get("updated_at","")],
            ["tags",       ", ".join(doc.get("tags",[]) or [])],
            ["description", doc.get("description","") or ""],
        ]
        print(fmt_table(rows))
    else:
        print(json.dumps(doc, indent=2))