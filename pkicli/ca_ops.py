# ca_ops.py
# CA operations: list/show/history/init + renew/export/import.
import subprocess, tempfile, json, os, datetime, sys
import boto3
from .aws_s3 import S3Client
from .render import fmt_table
from .inventory import extract_cas
from .utils import safe_get, days_until, now_utc_str, ts_compact_utc

def ca_list(s3: S3Client, expiring_in: int, out: str):
    inv = s3.get_json(s3.key("cert-inventory.json"))
    cas = extract_cas(inv)

    enriched = []
    for c in cas:
        name = c.get("name", "")
        state_s3 = c.get("state_s3", "")
        not_after = ""
        tags = []
        try:
            doc = s3.get_json(s3.key(f"{name}.json"))
            not_after = safe_get(doc, "metadata.not_after", "") or ""
            tags = doc.get("tags", []) or []
        except Exception:
            not_after = ""
            tags = []
        item = {
            "name": name,
            "version": c.get("version", ""),
            "not_after": not_after,
            "crt_arn": c.get("crt_arn", "") or "",
            "key_arn": c.get("key_arn", "") or "",
            "state_s3": state_s3 or "",
            "tags": tags,
        }
        if expiring_in is not None:
            if not not_after: continue
            if days_until(not_after) > expiring_in: continue
        enriched.append(item)

    if out == "table":
        if not enriched:
            print("No CAs found.")
            return
        rows = [["NAME","VERSION","NOT_AFTER","DAYS_LEFT","CRT_ARN","KEY_ARN","STATE_S3","TAGS"]]
        for e in enriched:
            dl = str(days_until(e["not_after"])) if e["not_after"] else ""
            rows.append([str(e["name"]), str(e["version"]), e["not_after"], dl,
                         e["crt_arn"], e["key_arn"], e["state_s3"],
                         ",".join(e["tags"]) if isinstance(e["tags"], list) else str(e["tags"] or "")])
        print(fmt_table(rows))
    else:
        print(json.dumps(enriched, indent=2))

def ca_show(s3: S3Client, name: str, out: str):
    doc = s3.get_json(s3.key(f"{name}.json"))
    if out == "table":
        rows = [["FIELD","VALUE"]]
        rows += [
            ["name", safe_get(doc,"ca.name","")],
            ["version", str(safe_get(doc,"ca.version",""))],
            ["not_before", safe_get(doc,"metadata.not_before","")],
            ["not_after", safe_get(doc,"metadata.not_after","")],
            ["sha256", safe_get(doc,"metadata.sha256","")],
            ["crt_arn", safe_get(doc,"secrets_manager.crt_arn","") or ""],
            ["key_arn", safe_get(doc,"secrets_manager.key_arn","") or ""],
            ["updated_at", doc.get("updated_at","")],
        ]
        print(fmt_table(rows))
    else:
        print(json.dumps(doc, indent=2))

def ca_history(s3: S3Client, name: str, out: str):
    doc = s3.get_json(s3.key(f"{name}.json"))
    hist = doc.get("ca",{}).get("history",[]) or []
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

def ca_init(s3: S3Client, name: str, subject_cn: str, subject_o: str, days: int, key_size: int,
            tags, description, sm_prefix: str, region: str, yes: bool, out: str):
    if not yes:
        raise SystemExit("Refusing to mutate without --yes.")

    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "ca.key")
        crt_path = os.path.join(td, "ca.crt")
        cnf = f"""[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[ dn ]
CN = {subject_cn}
O  = {subject_o}
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical, cRLSign, keyCertSign
"""
        cnf_path = os.path.join(td, "ca.cnf")
        with open(cnf_path,"w") as f: f.write(cnf)
        _openssl("req","-x509","-new","-nodes","-newkey",f"rsa:{key_size}",
                 "-keyout", key_path, "-out", crt_path, "-days", str(days), "-config", cnf_path)

        meta = _x509_meta(crt_path)

        sm = boto3.client("secretsmanager", region_name=region)
        def _sm_put_plain(name: str, value: str) -> str:
            try:
                r = sm.create_secret(Name=name, Description="pkicli CA asset", SecretString=value)
                return r["ARN"]
            except sm.exceptions.ResourceExistsException:
                sm.put_secret_value(SecretId=name, SecretString=value)
                d = sm.describe_secret(SecretId=name)
                return d["ARN"]

        base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""
        crt_pem = open(crt_path).read()
        key_pem = open(key_path).read()
        crt_arn = _sm_put_plain(f"{base}pki/{name}.crt", crt_pem)
        key_arn = _sm_put_plain(f"{base}pki/{name}.key", key_pem)

        now = now_utc_str()
        ca_doc = {
            "version": "v1",
            "updated_at": now,
            "metadata": meta,
            "rotation": {"status":"active","last_update":now, "reason":"bootstrap"},
            "ca": {"name": name, "version": 1, "history": []},
            "secrets_manager": {"crt_arn": crt_arn, "key_arn": key_arn},
            "secrets_manager_meta": {
                "crt": {"arn": crt_arn, "version_id": None, "stages": []},
                "key": {"arn": key_arn, "version_id": None, "stages": []},
            },
            "tags": tags or [],
            "description": description or f"CA {name}"
        }

        s3.put_json_with_meta(s3.key(f"{name}.json"), ca_doc)

        # Update inventory.cas[]
        try:
            inv = s3.get_json(s3.key("cert-inventory.json"))
        except Exception:
            inv = {}
        cas = inv.get("cas", [])
        cas = [c for c in cas if c.get("name") != name]
        cas.append({
            "name": name,
            "version": 1,
            "crt_arn": ca_doc["secrets_manager"].get("crt_arn"),
            "key_arn": ca_doc["secrets_manager"].get("key_arn"),
            "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}"
        })
        inv["cas"] = cas
        inv.setdefault("certs", [])
        inv["updated_at"] = now
        s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["created","CA and inventory updated"]]))
    else:
        print(json.dumps({"result":"created","name":name}, indent=2))

# ---------------- RENEW / EXPORT / IMPORT ----------------

def ca_renew(s3: S3Client, args, region: str, sm_prefix: str, out: str):
    """
    Rotate CA: generate new key+crt, snapshot previous version to history (and @timestamp JSON),
    update inventory.cas[]. Subject can be overridden; else tries to keep old subject if present.
    """
    name = args.name
    doc = s3.get_json(s3.key(f"{name}.json"))

    current_ver = int(safe_get(doc, "ca.version", 0) or 0)
    subject_cn = args.subject_cn or safe_get(doc, "metadata.subject_cn", "") or name
    subject_o  = args.subject_o  or safe_get(doc, "metadata.issuer_cn", "") or ""

    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "ca.key")
        crt_path = os.path.join(td, "ca.crt")
        cnf = f"""[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[ dn ]
CN = {subject_cn}
O  = {subject_o}
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical, cRLSign, keyCertSign
"""
        cnf_path = os.path.join(td, "ca.cnf")
        with open(cnf_path,"w") as f: f.write(cnf)
        _openssl("req","-x509","-new","-nodes","-newkey",f"rsa:{args.key_size}",
                 "-keyout", key_path, "-out", crt_path, "-days", str(args.days), "-config", cnf_path)

        meta = _x509_meta(crt_path)

        sm = boto3.client("secretsmanager", region_name=region)
        def _sm_put_plain(name: str, value: str) -> str:
            try:
                r = sm.create_secret(Name=name, Description="pkicli CA asset", SecretString=value)
                return r["ARN"]
            except sm.exceptions.ResourceExistsException:
                sm.put_secret_value(SecretId=name, SecretString=value)
                d = sm.describe_secret(SecretId=name)
                return d["ARN"]

        base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""
        crt_arn = _sm_put_plain(f"{base}pki/{name}.crt", open(crt_path).read())
        key_arn = _sm_put_plain(f"{base}pki/{name}.key", open(key_path).read())

        # Build history entry for previous version
        prev_hist = doc.get("ca", {}).get("history", []) or []
        ts = ts_compact_utc()
        snap_key = f"{name}@{ts}.json"
        s3.put_json_with_meta(s3.key(snap_key), doc)

        hist_entry = {
            "version": current_ver,
            "activated_at": safe_get(doc,"rotation.last_update", doc.get("updated_at")),
            "deactivated_at": now_utc_str(),
            "reason": args.reason or "rotation",
            "serial": safe_get(doc, "metadata.serial", ""),
            "sha256": safe_get(doc, "metadata.sha256", ""),
            "not_before": safe_get(doc, "metadata.not_before", ""),
            "not_after": safe_get(doc, "metadata.not_after", ""),
            "state_s3": f"s3://{s3.bucket}/{s3.key(snap_key)}"
        }

        new_doc = {
            "version": "v1",
            "updated_at": now_utc_str(),
            "metadata": meta,
            "rotation": {"status": "active", "last_update": now_utc_str(), "reason": args.reason or "rotation"},
            "ca": {"name": name, "version": current_ver + 1, "history": prev_hist + [hist_entry]},
            "secrets_manager": {"crt_arn": crt_arn, "key_arn": key_arn},
            "secrets_manager_meta": {
                "crt": {"arn": crt_arn, "version_id": None, "stages": []},
                "key": {"arn": key_arn, "version_id": None, "stages": []}
            },
            "tags": args.tags or doc.get("tags", []),
            "description": (doc.get("description") if args.description is None else args.description)
        }

        s3.put_json_with_meta(s3.key(f"{name}.json"), new_doc)

        # Update inventory
        try:
            inv = s3.get_json(s3.key("cert-inventory.json"))
        except Exception:
            inv = {}
        cas = inv.get("cas", [])
        cas = [c for c in cas if c.get("name") != name]
        cas.append({
            "name": name,
            "version": current_ver + 1,
            "crt_arn": new_doc["secrets_manager"]["crt_arn"],
            "key_arn": new_doc["secrets_manager"]["key_arn"],
            "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}"
        })
        inv["cas"] = cas
        inv.setdefault("certs", inv.get("certs", []))
        inv["updated_at"] = now_utc_str()
        s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["renewed", f"CA {name} rotated to version {current_ver+1}"]]))
    else:
        print(json.dumps({"result":"renewed","name":name,"version":current_ver+1}, indent=2))

def ca_export(s3: S3Client, name: str, out_file: str, with_secrets: bool, region: str):
    bundle = s3.get_json(s3.key(f"{name}.json"))
    if with_secrets:
        sm = boto3.client("secretsmanager", region_name=region)
        crt_arn = safe_get(bundle,"secrets_manager.crt_arn","")
        key_arn = safe_get(bundle,"secrets_manager.key_arn","")
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

def ca_import(s3: S3Client, in_file: str, yes: bool, region: str, sm_prefix: str, out: str):
    if not yes:
        raise SystemExit("Refusing to mutate without --yes.")
    if in_file == "-" or in_file == "/dev/stdin":
        bundle = json.load(sys.stdin)
    else:
        with open(in_file) as f:
            bundle = json.load(f)

    name = safe_get(bundle, "ca.name") or bundle.get("name")
    if not name:
        raise SystemExit("Bundle missing ca.name")

    sm = boto3.client("secretsmanager", region_name=region)
    base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""

    crt_arn = safe_get(bundle,"secrets_manager.crt_arn","")
    key_arn = safe_get(bundle,"secrets_manager.key_arn","")

    # If PEMs present, (re)store them and override ARNs
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

    bundle.setdefault("version", "v1")
    bundle.setdefault("updated_at", now_utc_str())
    bundle.setdefault("rotation", {"status":"active","last_update":now_utc_str()})
    bundle.setdefault("secrets_manager", {})
    bundle["secrets_manager"]["crt_arn"] = crt_arn
    if key_arn: bundle["secrets_manager"]["key_arn"] = key_arn

    s3.put_json_with_meta(s3.key(f"{name}.json"), bundle)

    # Update inventory.cas[]
    try:
        inv = s3.get_json(s3.key("cert-inventory.json"))
    except Exception:
        inv = {}
    cas = inv.get("cas", [])
    cas = [c for c in cas if c.get("name") != name]
    cas.append({
        "name": name,
        "version": int(safe_get(bundle,"ca.version",1) or 1),
        "crt_arn": crt_arn,
        "key_arn": key_arn or "",
        "state_s3": f"s3://{s3.bucket}/{s3.key(f'{name}.json')}"
    })
    inv["cas"] = cas
    inv.setdefault("certs", inv.get("certs", []))
    inv["updated_at"] = now_utc_str()
    s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["imported", f"CA {name}"]]))
    else:
        print(json.dumps({"result":"imported","name":name}, indent=2))