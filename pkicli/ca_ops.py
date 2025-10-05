import subprocess, tempfile, json, os
import boto3
from .aws_s3 import S3Client
from .render import fmt_table
from .inventory import extract_cas
from .utils import safe_get, days_until, now_utc_str, ts_compact_utc
from .serde.io import read_inventory, write_inventory, read_ca, write_ca
from .ir import CAIR, X509Meta

def ca_list(s3: S3Client, expiring_in: int, out: str):
    inv = read_inventory(s3)
    cas_meta = extract_cas(inv)
    enriched = []
    for c in cas_meta:
        name = c.get("name", "")
        not_after = ""
        tags = []
        try:
            ca_ir = read_ca(s3, name)
            not_after = safe_get(ca_ir, "metadata.not_after", "") or ""
            tags = ca_ir.get("tags", []) or []
        except Exception:
            not_after = ""
            tags = []

        if isinstance(tags, list) and any(str(t).lower() == "deleted" for t in tags):
            continue

        item = {
            "name": name,
            "version": c.get("version", ""),
            "not_after": not_after,
            "crt_arn": c.get("crt_arn", "") or "",
            "key_arn": c.get("key_arn", "") or "",
            "state_s3": c.get("state_s3", "") or "",
            "tags": tags,
        }
        
        if expiring_in is not None:
            if not not_after:
                continue
            if days_until(not_after) > expiring_in:
                continue
        enriched.append(item)

    if out == "table":
        if not enriched:
            print("No CAs found.")
            return
        rows = [["NAME","VERSION","NOT_AFTER","DAYS_LEFT","CRT_ARN","KEY_ARN","STATE_S3","TAGS"]]
        for e in enriched:
            dl = str(days_until(e["not_after"])) if e["not_after"] else ""
            rows.append([
                str(e["name"]), str(e["version"]), e["not_after"], dl,
                e["crt_arn"], e["key_arn"], e["state_s3"],
                ",".join(e["tags"]) if isinstance(e["tags"], list) else str(e["tags"] or "")
            ])
        print(fmt_table(rows))
    else:
        print(json.dumps(enriched, indent=2))

def ca_show(s3: S3Client, name: str, out: str):
    ca_ir = read_ca(s3, name)
    if out == "table":
        rows = [["FIELD","VALUE"]]
        rows += [
            ["name", ca_ir.get("name","")],
            ["version", str(ca_ir.get("version",""))],
            ["not_before", safe_get(ca_ir,"metadata.not_before","")],
            ["not_after",  safe_get(ca_ir,"metadata.not_after","")],
            ["sha256",     safe_get(ca_ir,"metadata.sha256","")],
            ["crt_arn", safe_get(ca_ir,"secrets.crt_arn","") or ""],
            ["key_arn", safe_get(ca_ir,"secrets.key_arn","") or ""],
            ["updated_at", ca_ir.get("updated_at","")],
        ]
        print(fmt_table(rows))
    else:
        print(json.dumps(ca_ir, indent=2))

def ca_history(s3: S3Client, name: str, out: str):
    ca_ir = read_ca(s3, name)
    hist = ca_ir.get("history", []) or []
    if out == "table":
        if not hist:
            print("No CA history entries.")
            return
        rows = [["VERSION","ACTIVATED_AT","DEACTIVATED_AT","SERIAL","SHA256","STATE_S3"]]
        for h in hist:
            rows.append([
                str(h.get("version","")),
                h.get("activated_at",""),
                h.get("deactivated_at",""),
                h.get("serial",""),
                h.get("sha256",""),
                h.get("state_s3","") or "",
            ])
        print(fmt_table(rows))
    else:
        print(json.dumps(hist, indent=2))

def _openssl(*args: str):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def _x509_meta(crt_path: str):
    def cmd(*a):
        r = subprocess.run(["openssl", *a], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return r.stdout.strip()
    start = cmd("x509","-in",crt_path,"-noout","-startdate").split("=",1)[1]
    end   = cmd("x509","-in",crt_path,"-noout","-enddate").split("=",1)[1]
    import dateutil.parser as dp, datetime as dt, re
    nbf = dp.parse(start).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    naf = dp.parse(end).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = cmd("x509","-in",crt_path,"-noout","-serial").split("=",1)[1]
    sha = cmd("x509","-in",crt_path,"-noout","-fingerprint","-sha256").split("=",1)[1].replace(":","")
    text = cmd("x509","-in",crt_path,"-noout","-text")

    sig_alg = ""
    pub_algo = ""
    pub_bits = 0
    for line in text.splitlines():
        if "Signature Algorithm:" in line and not sig_alg:
            sig_alg = line.split("Signature Algorithm:")[-1].strip()
        if "Public Key Algorithm:" in line and not pub_algo:
            pub_algo = line.split("Public Key Algorithm:")[-1].strip()
        m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", line)
        if m:
            pub_bits = int(m.group(1))
    skid = ""
    akid = ""
    lines = iter(text.splitlines())
    for ln in lines:
        if "Subject Key Identifier" in ln:
            skid = next(lines,"").strip()
        if "Authority Key Identifier" in ln:
            v = next(lines,"").strip()
            akid = v.split("keyid:",1)[-1].replace(" ","")
    if not akid:
        akid = skid
    return {
        "not_before": nbf,
        "not_after": naf,
        "serial": serial,
        "sha256": sha,
        "sig_alg": sig_alg,
        "pubkey_algo": pub_algo,
        "pubkey_bits": pub_bits,
        "skid": skid,
        "akid": akid,
        "issuer_cn": "",
        "subject_cn": ""
    }

def ca_init(
    s3: S3Client,
    name: str,
    subject_cn: str,
    subject_o: str,
    days: int,
    key_size: int,
    tags,
    description,
    sm_prefix: str,
    region: str,
    target_version: str,
    out: str
):
    from .ir import CAIR, X509Meta  # use IR types

    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "ca.key")
        crt_path = os.path.join(td, "ca.crt")
        cnf = f"""[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[ dn ]
CN = {subject_cn}
{"O  = " + subject_o if subject_o else ""}
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical, cRLSign, keyCertSign
"""
        cnf_path = os.path.join(td, "ca.cnf")
        with open(cnf_path, "w") as f:
            f.write(cnf)
        _openssl(
            "req", "-x509", "-new", "-nodes", "-newkey", f"rsa:{key_size}",
            "-keyout", key_path, "-out", crt_path, "-days", str(days), "-config", cnf_path
        )

        meta = _x509_meta(crt_path)

        sm = boto3.client("secretsmanager", region_name=region)
        def _sm_put_plain(n: str, v: str) -> str:
            try:
                r = sm.create_secret(Name=n, Description="pkicli CA asset", SecretString=v)
                return r["ARN"]
            except sm.exceptions.ResourceExistsException:
                sm.put_secret_value(SecretId=n, SecretString=v)
                return sm.describe_secret(SecretId=n)["ARN"]
            except sm.exceptions.InvalidRequestException as e:
                msg = str(e)
                if "scheduled for deletion" in msg.lower():
                    sm.restore_secret(SecretId=n)
                    sm.put_secret_value(SecretId=n, SecretString=v)
                    return sm.describe_secret(SecretId=n)["ARN"]
                raise

        base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""
        crt_arn = _sm_put_plain(f"{base}pki/{name}.crt", open(crt_path).read())
        key_arn = _sm_put_plain(f"{base}pki/{name}.key", open(key_path).read())

        now = now_utc_str()
        cair = CAIR(
            version="ir/1",
            name=name,
            ca_version=1,
            metadata=X509Meta(
                not_before=meta.get("not_before", ""),
                not_after=meta.get("not_after", ""),
                serial=meta.get("serial", ""),
                sha256=meta.get("sha256", ""),
                sig_alg=meta.get("sig_alg", ""),
                pubkey_algo=meta.get("pubkey_algo", ""),
                pubkey_bits=int(meta.get("pubkey_bits", 0) or 0),
                skid=meta.get("skid"),
                akid=meta.get("akid"),
                issuer_cn=meta.get("issuer_cn"),
                subject_cn=meta.get("subject_cn"),
                san=meta.get("san"),
            ),
            rotation={"status": "active", "last_update": now, "reason": "bootstrap"},
            history=[],
            secrets_manager={"crt_arn": crt_arn, "key_arn": key_arn},
            secrets_manager_meta={},
            tags=tags or [],
            description=description or f"CA {name}",
            updated_at=now,
            s3_meta=None,
        )
        write_ca(s3, cair, schema_version=target_version)

        # Inventory (dict-style) – keep schema version at top
        inv = read_inventory(s3)
        inv["version"] = target_version
        inv["cas"] = [c for c in inv.get("cas", []) if c.get("name") != name]
        inv["cas"].append({
            "name": name,
            "version": 1,
            "crt_arn": crt_arn,
            "key_arn": key_arn,
            "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}"
        })
        inv.setdefault("certs", inv.get("certs", []))
        inv["updated_at"] = now
        write_inventory(s3, inv, schema_version=target_version)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"], ["created", "CA and inventory updated"]]))
    else:
        print(json.dumps({"result": "created", "name": name}, indent=2))

def ca_renew(s3: S3Client, args, region: str, sm_prefix: str, target_version: str, out: str):
    from .ir import CAIR, X509Meta  # use IR types

    name = args.name
    doc = read_ca(s3, name)

    # Read CA rotation counter from IR field
    current_ver = int(safe_get(doc, "ca_version", 0) or 0)

    subject_cn = args.subject_cn or safe_get(doc, "metadata.subject_cn", "") or name
    subject_o  = args.subject_o  or ""

    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "ca.key")
        crt_path = os.path.join(td, "ca.crt")

        dn_lines = [f"CN = {subject_cn}"]
        if subject_o:
            dn_lines.append(f"O  = {subject_o}")

        cnf = f"""[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[ dn ]
{chr(10).join(dn_lines)}
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical, cRLSign, keyCertSign
"""
        cnf_path = os.path.join(td, "ca.cnf")
        with open(cnf_path, "w") as f:
            f.write(cnf)

        _openssl("req","-x509","-new","-nodes","-newkey",f"rsa:{args.key_size}",
                 "-keyout", key_path, "-out", crt_path, "-days", str(args.days), "-config", cnf_path)

        meta = _x509_meta(crt_path)

        sm = boto3.client("secretsmanager", region_name=region)
        def _sm_put_plain(n: str, v: str) -> str:
            try:
                r = sm.create_secret(Name=n, Description="pkicli CA asset", SecretString=v)
                return r["ARN"]
            except sm.exceptions.ResourceExistsException:
                sm.put_secret_value(SecretId=n, SecretString=v)
                return sm.describe_secret(SecretId=n)["ARN"]
            except sm.exceptions.InvalidRequestException as e:
                msg = str(e)
                if "scheduled for deletion" in msg.lower():
                    sm.restore_secret(SecretId=n)
                    sm.put_secret_value(SecretId=n, SecretString=v)
                    return sm.describe_secret(SecretId=n)["ARN"]
                raise

        base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""
        crt_arn = _sm_put_plain(f"{base}pki/{name}.crt", open(crt_path).read())
        key_arn = _sm_put_plain(f"{base}pki/{name}.key", open(key_path).read())

        prev_hist = doc.get("history", []) or []
        ts = ts_compact_utc()
        snap_key = f"{name}@{ts}.json"
        snap_doc = dict(doc)
        snap_doc["snapshot_of"] = name
        s3.put_json_with_meta(s3.key(snap_key), snap_doc)

        hist_entry = {
            "version": current_ver,
            "activated_at": safe_get(doc, "rotation.last_update", doc.get("updated_at")),
            "deactivated_at": now_utc_str(),
            "reason": args.reason or "rotation",
            "serial": safe_get(doc, "metadata.serial", ""),
            "sha256": safe_get(doc, "metadata.sha256", ""),
            "not_before": safe_get(doc, "metadata.not_before", ""),
            "not_after": safe_get(doc, "metadata.not_after", ""),
            "state_s3": f"s3://{s3.bucket}/{s3.key(snap_key)}"
        }

        now = now_utc_str()
        cair = CAIR(
            version="ir/1",
            name=name,
            ca_version=current_ver + 1,
            metadata=X509Meta(
                not_before=meta.get("not_before", ""),
                not_after=meta.get("not_after", ""),
                serial=meta.get("serial", ""),
                sha256=meta.get("sha256", ""),
                sig_alg=meta.get("sig_alg", ""),
                pubkey_algo=meta.get("pubkey_algo", ""),
                pubkey_bits=int(meta.get("pubkey_bits", 0) or 0),
                skid=meta.get("skid"),
                akid=meta.get("akid"),
                issuer_cn=meta.get("issuer_cn"),
                subject_cn=meta.get("subject_cn"),
                san=meta.get("san"),
            ),
            rotation={"status": "active", "last_update": now, "reason": args.reason or "rotation"},
            history=prev_hist + [hist_entry],
            secrets_manager={"crt_arn": crt_arn, "key_arn": key_arn},
            secrets_manager_meta=doc.get("secrets_manager_meta", {}) or {},
            tags=doc.get("tags", []),
            description=(doc.get("description") if args.description is None else args.description),
            updated_at=now,
            s3_meta=None,
        )
        write_ca(s3, cair, schema_version=target_version)

        # Inventory (dict-style)
        try:
            inv = read_inventory(s3)
        except Exception:
            inv = {"version": target_version, "cas": [], "certs": [], "updated_at": now}
        inv["version"] = target_version
        inv["cas"] = [c for c in inv.get("cas", []) if c.get("name") != name]
        inv["cas"].append({
            "name": name,
            "version": current_ver + 1,
            "crt_arn": crt_arn,
            "key_arn": key_arn,
            "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}"
        })
        inv.setdefault("certs", inv.get("certs", []))
        inv["updated_at"] = now
        write_inventory(s3, inv, schema_version=target_version)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["renewed", f"CA {name} rotated to version {current_ver+1}"]]))
    else:
        print(json.dumps({"result":"renewed","name":name,"version":current_ver+1}, indent=2))

def ca_export(s3: S3Client, name: str, out_file: str, with_secrets: bool, region: str):
    bundle = read_ca(s3, name)
    if with_secrets:
        sm = boto3.client("secretsmanager", region_name=region)
        crt_arn = safe_get(bundle,"secrets.crt_arn","")
        key_arn = safe_get(bundle,"secrets.key_arn","")
        if crt_arn:
            bundle["crt_pem"] = sm.get_secret_value(SecretId=crt_arn)["SecretString"]
        if key_arn:
            bundle["key_pem"] = sm.get_secret_value(SecretId=key_arn)["SecretString"]
    data = json.dumps(bundle, indent=2)
    if out_file == "-" or out_file == "/dev/stdout":
        print(data)
    else:
        with open(out_file, "w") as f:
            f.write(data)

def ca_import(s3: S3Client, in_file: str, region: str, sm_prefix: str, target_version: str, out: str):
    import sys as _sys, json as _json
    if in_file in ("-", "/dev/stdin"):
        bundle = _json.load(_sys.stdin)
    else:
        with open(in_file) as f:
            bundle = _json.load(f)

    name = safe_get(bundle, "name") or safe_get(bundle, "ca.name")
    if not name:
        raise SystemExit("Bundle missing CA name")

    sm = boto3.client("secretsmanager", region_name=region)
    base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""

    crt_arn = safe_get(bundle,"secrets.crt_arn","") or safe_get(bundle,"secrets_manager.crt_arn","")
    key_arn = safe_get(bundle,"secrets.key_arn","") or safe_get(bundle,"secrets_manager.key_arn","")

    if "crt_pem" in bundle:
        try:
            r = sm.create_secret(Name=f"{base}pki/{name}.crt", Description="pkicli CA asset", SecretString=bundle["crt_pem"])
            crt_arn = r["ARN"]
        except sm.exceptions.ResourceExistsException:
            sm.put_secret_value(SecretId=f"{base}pki/{name}.crt", SecretString=bundle["crt_pem"])
            crt_arn = sm.describe_secret(SecretId=f"{base}pki/{name}.crt")["ARN"]
    if "key_pem" in bundle:
        try:
            r = sm.create_secret(Name=f"{base}pki/{name}.key", Description="pkicli CA asset", SecretString=bundle["key_pem"])
            key_arn = r["ARN"]
        except sm.exceptions.ResourceExistsException:
            sm.put_secret_value(SecretId=f"{base}pki/{name}.key", SecretString=bundle["key_pem"])
            key_arn = sm.describe_secret(SecretId=f"{base}pki/{name}.key")["ARN"]

    now = now_utc_str()
    ca_ir = {
        "name": name,
        "version": int(safe_get(bundle,"version", safe_get(bundle,"ca.version",1)) or 1),
        "updated_at": now,
        "metadata": bundle.get("metadata", {}),
        "rotation": bundle.get("rotation", {"status":"active","last_update":now}),
        "secrets": {"crt_arn": crt_arn, "key_arn": key_arn or ""},
        "history": bundle.get("history", []) or safe_get(bundle, "ca.history", []) or [],
        "tags": bundle.get("tags", []),
        "description": bundle.get("description", f"CA {name}"),
    }
    write_ca(s3, ca_ir, schema_version=target_version)

    inv = read_inventory(s3)
    inv["cas"] = [c for c in inv.get("cas", []) if c.get("name") != name]
    inv["cas"].append({
        "name": name,
        "version": ca_ir["version"],
        "crt_arn": crt_arn,
        "key_arn": key_arn or "",
        "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}"
    })
    inv.setdefault("certs", inv.get("certs", []))
    inv["updated_at"] = now
    write_inventory(s3, inv, schema_version=target_version)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["imported", f"CA {name}"]]))
    else:
        print(json.dumps({"result":"imported","name":name}, indent=2))

def ca_delete(s3: S3Client, name: str, region: str, sm_prefix: str, target_version: str, hard: bool, retention_days: int, out: str):
    """
    Soft-delete (default) or hard-delete a CA.
    - Soft: schedule Secrets Manager deletion (default 30d), mark IR as revoked + tag 'deleted'
    - Hard: force-delete secrets immediately
    Always write back via IR -> adapter (no dict 'ir/1' fed to write_ca).
    """

    doc = read_ca(s3, name)
    now = now_utc_str()

    crt_arn = safe_get(doc, "secrets_manager.crt_arn", "") or safe_get(doc, "secrets.crt_arn", "")
    key_arn = safe_get(doc, "secrets_manager.key_arn", "") or safe_get(doc, "secrets.key_arn", "")

    sm = boto3.client("secretsmanager", region_name=region)
    base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""

    def _sm_delete(arn: str):
        if not arn:
            return
        try:
            if hard:
                sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
            else:
                wnd = int(retention_days or 30)
                sm.delete_secret(SecretId=arn, RecoveryWindowInDays=wnd)
        except sm.exceptions.ResourceNotFoundException:
            pass 
        except Exception:
            pass

    _sm_delete(crt_arn)
    _sm_delete(key_arn)

    rotation = dict(doc.get("rotation", {}) or {})
    rotation["status"] = "revoked"
    rotation["last_update"] = now
    rotation.setdefault("reason", "revoked")

    history = list(doc.get("history", []) or [])
    try:
        prev_ver = int(doc.get("ca_version", 1) or 1)
    except Exception:
        prev_ver = 1
    history.append({
        "version": prev_ver,
        "activated_at": safe_get(doc, "rotation.last_update", doc.get("updated_at")),
        "deactivated_at": now,
        "reason": "revoked",
        "serial": safe_get(doc, "metadata.serial", ""),
        "sha256": safe_get(doc, "metadata.sha256", ""),
        "not_before": safe_get(doc, "metadata.not_before", ""),
        "not_after": safe_get(doc, "metadata.not_after", ""),
        "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}",
    })

    m = doc.get("metadata", {}) or {}
    xmeta = X509Meta(
        not_before=m.get("not_before", ""),
        not_after=m.get("not_after", ""),
        serial=m.get("serial", ""),
        sha256=m.get("sha256", ""),
        sig_alg=m.get("sig_alg", ""),
        pubkey_algo=m.get("pubkey_algo", ""),
        pubkey_bits=int(m.get("pubkey_bits", 0) or 0),
        skid=m.get("skid"),
        akid=m.get("akid"),
        issuer_cn=m.get("issuer_cn"),
        subject_cn=m.get("subject_cn"),
        san=m.get("san"),
    )

    tags = list(doc.get("tags", []) or [])
    if not hard and "deleted" not in [str(t).lower() for t in tags]:
        tags.append("deleted")

    cair = CAIR(
        version="ir/1",
        name=doc.get("name", name),
        ca_version=prev_ver,
        metadata=xmeta,
        rotation=rotation,
        history=history,
        secrets_manager={"crt_arn": crt_arn or None, "key_arn": key_arn or None},
        secrets_manager_meta=doc.get("secrets_manager_meta", {}) or {},
        tags=tags,
        description=doc.get("description", "") or "",
        updated_at=now,
        s3_meta=None,
    )
    write_ca(s3, cair, schema_version=target_version)

    inv = read_inventory(s3)
    dependents = [c for c in inv.get("certs", []) if (c.get("ca") or {}).get("name") == name and (c.get("status") or "active") != "revoked"]
    if dependents:
        raise SystemExit(
            f"CA '{name}' has {len(dependents)} active certificates. Revoke them first."
        )
    inv["updated_at"] = now
    write_inventory(s3, inv, schema_version=target_version)

    if out == "table":
        print(fmt_table([["RESULT", "DETAIL"], ["revoked" if not hard else "deleted", f"CA {name}"]]))
    else:
        print(json.dumps({
            "result": "deleted" if hard else "revoked",
            "name": name,
            "hard": hard,
            "secrets": {"crt_arn": bool(crt_arn), "key_arn": bool(key_arn)}
        }, indent=2))