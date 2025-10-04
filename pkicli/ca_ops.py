# ca_ops.py
# CA operations: list/show/history/init + helpers.
import subprocess, tempfile, json, os, datetime
from .aws_s3 import S3Client
from .render import fmt_table
from .inventory import extract_cas
from .utils import safe_get, days_until

def ca_list(s3: S3Client, expiring_in: int, out: str):
    """
    List CAs from inventory.cas[]. If expiring_in is provided, filter CAs whose
    metadata.not_after is within <= N days. We enrich each CA with not_after and tags
    by fetching the per-CA JSON pointed by state_s3.
    """
    inv = s3.get_json(s3.key("cert-inventory.json"))
    cas = extract_cas(inv)

    enriched = []
    for c in cas:
        name = c.get("name", "")
        state_s3 = c.get("state_s3", "")
        not_after = ""
        tags = []
        try:
            # Load per-CA JSON by name (we store them at <prefix>/<name>.json)
            doc = s3.get_json(s3.key(f"{name}.json"))
            not_after = safe_get(doc, "metadata.not_after", "") or ""
            tags = doc.get("tags", []) or []
        except Exception:
            # If CA file is missing or unreadable, leave fields blank
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
        # Apply expiring filter if requested and not_after is present
        if expiring_in is not None:
            if not not_after:
                continue  # cannot evaluate, skip
            if days_until(not_after) > expiring_in:
                continue
        enriched.append(item)

    if out == "table":
        if not enriched:
            print("No CAs found.")
            return
        rows = [["NAME","VERSION","NOT_AFTER","DAYS_LEFT","CRT_ARN","KEY_ARN","STATE_S3","TAGS"]]
        for e in enriched:
            days_left = ""
            if e["not_after"]:
                try:
                    days_left = str(days_until(e["not_after"]))
                except Exception:
                    days_left = ""
            rows.append([
                str(e["name"]),
                str(e["version"]),
                e["not_after"],
                days_left,
                e["crt_arn"],
                e["key_arn"],
                e["state_s3"],
                ",".join(e["tags"]) if isinstance(e["tags"], list) else str(e["tags"] or ""),
            ])
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
    import dateutil.parser as dp, datetime as dt
    nbf = dp.parse(start).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    naf = dp.parse(end).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = cmd("x509","-in",crt_path,"-noout","-serial").split("=",1)[1]
    sha = cmd("x509","-in",crt_path,"-noout","-fingerprint","-sha256").split("=",1)[1].replace(":","")
    text = cmd("x509","-in",crt_path,"-noout","-text")
    import re
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
            tags, description, sm_store_crt: bool, sm_store_key: bool,
            sm_prefix: str, region: str, yes: bool, out: str):
    if not yes:
        raise SystemExit("Refusing to mutate without --yes.")

    import tempfile
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
        with open(cnf_path,"w") as f:
            f.write(cnf)
        _openssl("req","-x509","-new","-nodes","-newkey",f"rsa:{key_size}",
                 "-keyout", key_path, "-out", crt_path, "-days", str(days), "-config", cnf_path)

        meta = _x509_meta(crt_path)

        import boto3
        sm = boto3.client("secretsmanager", region_name=region)
        crt_arn = None
        key_arn = None

        def _sm_put_plain(name: str, value: str) -> str:
            try:
                r = sm.create_secret(Name=name, Description="pkicli CA asset", SecretString=value)
                return r["ARN"]
            except sm.exceptions.ResourceExistsException:
                sm.put_secret_value(SecretId=name, SecretString=value)
                d = sm.describe_secret(SecretId=name)
                return d["ARN"]

        base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""
        # Always store both certificate and private key for CA
        crt_pem = open(crt_path).read()
        key_pem = open(key_path).read()
        crt_arn = _sm_put_plain(f"{base}pki/{name}.crt", crt_pem)
        key_arn = _sm_put_plain(f"{base}pki/{name}.key", key_pem)

        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        ca_doc = {
            "version": "v1",
            "updated_at": now,
            "metadata": meta,
            "rotation": {"status":"active","last_update":now},
            "ca": {"name": name, "version": 1, "history": []},
            "secrets_manager": {"crt_arn": crt_arn, "key_arn": key_arn},
            "secrets_manager_meta": {
                "crt": {"arn": crt_arn, "version_id": None, "stages": []},
                "key": {"arn": key_arn, "version_id": None, "stages": []},
            },
            "tags": tags or [],
            "description": description or ""
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
        if "certs" not in inv:
            inv["certs"] = []
        inv["updated_at"] = now
        s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["created","CA and inventory updated"]]))
    else:
        print(json.dumps({"result":"created","name":name}, indent=2))