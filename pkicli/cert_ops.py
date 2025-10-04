# cert_ops.py
# Certificates: list/show + issue/renew/export/import
import json, os, sys, tempfile, subprocess, boto3, datetime
from .aws_s3 import S3Client
from .render import fmt_table
from .utils import safe_get, days_until, now_utc_str
from typing import List

def cert_list(s3: S3Client, expiring_in: int, out: str):
    inv = s3.get_json(s3.key("cert-inventory.json"))
    certs = inv.get("certs") or []
    rows_data = []
    for c in certs:
        na = safe_get(c, "metadata.not_after", "")
        if expiring_in is not None:
            if not na: continue
            if days_until(na) > expiring_in: continue
        rows_data.append({
            "name": c.get("name",""),
            "not_after": na,
            "ca": safe_get(c, "ca.name", ""),
            "cert_arn": c.get("cert_secret_arn","") or "",
            "key_arn": c.get("key_secret_arn","") or "",
        })
    if out == "table":
        if not rows_data:
            print("No certificates found.")
            return
        rows = [["NAME","NOT_AFTER","CA","CERT_ARN","KEY_ARN"]]
        for r in rows_data:
            rows.append([r["name"], r["not_after"], r["ca"], r["cert_arn"], r["key_arn"]])
        print(fmt_table(rows))
    else:
        print(json.dumps(rows_data, indent=2))

def cert_show(s3: S3Client, name: str, out: str):
    doc = s3.get_json(s3.key(f"{name}.json"))
    if out == "table":
        rows = [["FIELD","VALUE"]]
        rows += [
            ["name", doc.get("name","")],
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

# ---------- helpers ----------

def _run(*args: str) -> str:
    r = subprocess.run(["openssl", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return r.stdout

def _write_tmp(path: str, content: str):
    with open(path, "w") as f: f.write(content)

def _x509_meta_from_file(crt_path: str) -> dict:
    start = _run("x509","-in",crt_path,"-noout","-startdate").split("=",1)[1].strip()
    end   = _run("x509","-in",crt_path,"-noout","-enddate").split("=",1)[1].strip()
    import dateutil.parser as dp, datetime as dt, re
    nbf = dp.parse(start).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    naf = dp.parse(end).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = _run("x509","-in",crt_path,"-noout","-serial").split("=",1)[1].strip()
    sha = _run("x509","-in",crt_path,"-noout","-fingerprint","-sha256").split("=",1)[1].replace(":","").strip()
    text = _run("x509","-in",crt_path,"-noout","-text")
    sig_alg = ""; pub_algo = ""; pub_bits = 0
    for line in text.splitlines():
        if "Signature Algorithm:" in line and not sig_alg:
            sig_alg = line.split("Signature Algorithm:")[-1].strip()
        if "Public Key Algorithm:" in line and not pub_algo:
            pub_algo = line.split("Public Key Algorithm:")[-1].strip()
        import re
        m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", line)
        if m: pub_bits = int(m.group(1))
    skid=""; akid=""
    lines = iter(text.splitlines())
    for ln in lines:
        if "Subject Key Identifier" in ln: skid = next(lines,"").strip()
        if "Authority Key Identifier" in ln:
            v = next(lines,"").strip(); akid = v.split("keyid:",1)[-1].replace(" ","")
    if not akid: akid = skid
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

def _build_extfile(sans: List[str]) -> str:
    lines = ["[ v3_req ]",
             "basicConstraints = critical,CA:FALSE",
             "keyUsage = critical, digitalSignature, keyEncipherment",
             "extendedKeyUsage = serverAuth, clientAuth"]
    if sans:
        lines.append("subjectAltName = @alt_names")
        lines.append("[ alt_names ]")
        i=1
        for s in sans:
            s = (s or "").strip()
            if not s: continue
            if s.replace(".","").isdigit() and s.count(".")==3:
                lines.append(f"IP.{i} = {s}")
            else:
                lines.append(f"DNS.{i} = {s}")
            i+=1
    tf = tempfile.NamedTemporaryFile("w", delete=False)
    tf.write("\n".join(lines) + "\n")
    tf.flush(); tf.close()
    return tf.name

def _sm_put_plain(sm, name: str, value: str) -> str:
    try:
        r = sm.create_secret(Name=name, Description="pkicli cert asset", SecretString=value)
        return r["ARN"]
    except sm.exceptions.ResourceExistsException:
        sm.put_secret_value(SecretId=name, SecretString=value)
        return sm.describe_secret(SecretId=name)["ARN"]

# ---------- ISSUE ----------

def cert_issue(s3: S3Client, args, region: str, sm_prefix: str, out: str):
    # load CA (must exist and have both crt_arn & key_arn)
    ca_doc = s3.get_json(s3.key(f"{args.ca_name}.json"))
    ca_crt_arn = safe_get(ca_doc,"secrets_manager.crt_arn","")
    ca_key_arn = safe_get(ca_doc,"secrets_manager.key_arn","")
    if not (ca_crt_arn and ca_key_arn):
        raise SystemExit("CA does not have both crt_arn and key_arn in Secrets Manager.")

    sm = boto3.client("secretsmanager", region_name=region)
    ca_crt_pem = sm.get_secret_value(SecretId=ca_crt_arn)["SecretString"]
    ca_key_pem = sm.get_secret_value(SecretId=ca_key_arn)["SecretString"]

    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td,"key.pem")
        csr_path = os.path.join(td,"req.csr")
        crt_path = os.path.join(td,"crt.pem")
        ca_crt_path = os.path.join(td,"ca.crt")
        ca_key_path = os.path.join(td,"ca.key")
        _write_tmp(ca_crt_path, ca_crt_pem)
        _write_tmp(ca_key_path, ca_key_pem)

        # key & csr
        if args.key_algo != "rsa":
            raise SystemExit("Only RSA is supported currently.")
        subprocess.run(["openssl","genrsa","-out",key_path,str(args.key_size)], check=True)
        subj = f"/CN={args.subject_cn}" + (f"/O={args.subject_o}" if args.subject_o else "")
        subprocess.run(["openssl","req","-new","-key",key_path,"-out",csr_path,"-subj",subj], check=True)

        # sign
        ext = _build_extfile(args.san or [])
        subprocess.run(["openssl","x509","-req","-in",csr_path,"-CA",ca_crt_path,"-CAkey",ca_key_path,
                        "-CAcreateserial","-out",crt_path,"-days",str(args.validity_days),
                        "-extensions","v3_req","-extfile",ext], check=True)

        # metadata
        meta = _x509_meta_from_file(crt_path)

        base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""
        cert_sm_name = f"{base}pki/{args.name}.crt"
        key_sm_name  = f"{base}pki/{args.name}.key"
        cert_arn = _sm_put_plain(sm, cert_sm_name, open(crt_path).read())
        key_arn  = _sm_put_plain(sm, key_sm_name,  open(key_path).read())

    # build per-cert JSON
    now = now_utc_str()
    state = {
        "version": "v1",
        "name": args.name,
        "subject": {"CN": args.subject_cn, "O": args.subject_o or ""},
        "metadata": meta,
        "ca": {
            "name": args.ca_name,
            "version": int(safe_get(ca_doc,"ca.version",1) or 1),
            "crt_arn": ca_crt_arn,
            "key_arn": ca_key_arn,
            "state_s3": f"s3://{s3.bucket}/{s3.key(f'{args.ca_name}.json')}"
        },
        "cert_secret_arn": cert_arn,
        "key_secret_arn": key_arn,
        "secrets_manager_meta": {
            "cert": {"arn": cert_arn, "version_id": None, "stages": []},
            "key":  {"arn": key_arn,  "version_id": None, "stages": []},
        },
        "san": (args.san or None),
        "key": {"algo": args.key_algo, "size": args.key_size},
        "validity_days": args.validity_days,
        "rotation": {"status":"active","last_update": now},
        "tags": args.tags or [],
        "description": args.description or "",
        "updated_at": now
    }

    # write per-cert state
    s3.put_json_with_meta(s3.key(f"{args.name}.json"), state)

    # update inventory
    try:
        inv = s3.get_json(s3.key("cert-inventory.json"))
    except Exception:
        inv = {}
    certs = inv.get("certs", [])
    certs = [c for c in certs if c.get("name") != args.name]
    certs.append(state)
    inv["certs"] = certs
    inv.setdefault("cas", inv.get("cas", []))
    inv["updated_at"] = now
    s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["issued", f"cert {args.name}"]]))
    else:
        print(json.dumps({"result":"issued","name":args.name}, indent=2))

# ---------- RENEW ----------

def cert_renew(s3: S3Client, args, region: str, sm_prefix: str, out: str):
    name = args.name
    cur = s3.get_json(s3.key(f"{name}.json"))
    class A:
        pass
    a = A()
    a.name = name
    a.subject_cn = safe_get(cur,"subject.CN","")
    a.subject_o  = safe_get(cur,"subject.O","")
    a.san = safe_get(cur,"san",[]) or []
    a.key_algo = safe_get(cur,"key.algo","rsa") or "rsa"
    a.key_size = int(args.key_size or safe_get(cur,"key.size",4096) or 4096)
    a.validity_days = int(args.validity_days or safe_get(cur,"validity_days",825) or 825)
    a.ca_name = safe_get(cur,"ca.name","")
    a.tags = cur.get("tags",[])
    a.description = cur.get("description","")
    cert_issue(s3, a, region, sm_prefix, out)

# ---------- EXPORT ----------

def cert_export(s3: S3Client, name: str, out_file: str, with_secrets: bool, region: str):
    bundle = s3.get_json(s3.key(f"{name}.json"))
    if with_secrets:
        sm = boto3.client("secretsmanager", region_name=region)
        crt_arn = bundle.get("cert_secret_arn","")
        key_arn = bundle.get("key_secret_arn","")
        if crt_arn:
            bundle["crt_pem"] = sm.get_secret_value(SecretId=crt_arn)["SecretString"]
        if key_arn:
            bundle["key_pem"] = sm.get_secret_value(SecretId=key_arn)["SecretString"]
    data = json.dumps(bundle, indent=2)
    if out_file == "-" or out_file == "/dev/stdout":
        print(data)
    else:
        with open(out_file, "w") as f: f.write(data)

# ---------- IMPORT ----------

def cert_import(s3: S3Client, args, region: str, sm_prefix: str, out: str):
    sm = boto3.client("secretsmanager", region_name=region)
    base = (sm_prefix.rstrip("/") + "/") if sm_prefix else ""

    if args.from_bundle:
        # read bundle
        if args.from_bundle == "-" or args.from_bundle == "/dev/stdin":
            bundle = json.load(sys.stdin)
        else:
            with open(args.from_bundle) as f:
                bundle = json.load(f)

        name = bundle.get("name")
        if not name: raise SystemExit("bundle missing 'name'")

        # store PEMs if present (override ARNs)
        cert_arn = bundle.get("cert_secret_arn","")
        key_arn  = bundle.get("key_secret_arn","")
        if "crt_pem" in bundle:
            cert_arn = _sm_put_plain(sm, f"{base}pki/{name}.crt", bundle["crt_pem"])
        if "key_pem" in bundle:
            key_arn = _sm_put_plain(sm, f"{base}pki/{name}.key", bundle["key_pem"])

        # normalize and write state
        bundle.setdefault("version","v1")
        bundle["cert_secret_arn"] = cert_arn or bundle.get("cert_secret_arn","")
        bundle["key_secret_arn"]  = key_arn  or bundle.get("key_secret_arn","")
        bundle["updated_at"] = now_utc_str()
        s3.put_json_with_meta(s3.key(f"{name}.json"), bundle)

        # inventory
        try:
            inv = s3.get_json(s3.key("cert-inventory.json"))
        except Exception:
            inv = {}
        certs = inv.get("certs", [])
        certs = [c for c in certs if c.get("name") != name]
        certs.append(bundle)
        inv["certs"] = certs
        inv.setdefault("cas", inv.get("cas", []))
        inv["updated_at"] = now_utc_str()
        s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

        if out == "table":
            print(fmt_table([["RESULT","DETAIL"],["imported", f"cert {name}"]]))
        else:
            print(json.dumps({"result":"imported","name":name}, indent=2))
        return

    # --from-files path
    name = args.name
    if not (name and args.crt and args.key and args.subject_cn and args.ca_name):
        raise SystemExit("--from-files requires --name, --crt, --key, --subject-cn, --ca-name")

    # store to SM
    cert_arn = _sm_put_plain(sm, f"{base}pki/{name}.crt", open(args.crt).read())
    key_arn  = _sm_put_plain(sm, f"{base}pki/{name}.key",  open(args.key).read())

    # metadata & CA ref
    meta = _x509_meta_from_file(args.crt)
    ca_doc = s3.get_json(s3.key(f"{args.ca_name}.json"))
    state = {
        "version": "v1",
        "name": name,
        "subject": {"CN": args.subject_cn, "O": args.subject_o or ""},
        "metadata": meta,
        "ca": {
            "name": args.ca_name,
            "version": int(safe_get(ca_doc,"ca.version",1) or 1),
            "crt_arn": safe_get(ca_doc,"secrets_manager.crt_arn",""),
            "key_arn": safe_get(ca_doc,"secrets_manager.key_arn",""),
            "state_s3": f"s3://{s3.bucket}/{s3.key(f'{args.ca_name}.json')}"
        },
        "cert_secret_arn": cert_arn,
        "key_secret_arn": key_arn,
        "secrets_manager_meta": {
            "cert": {"arn": cert_arn, "version_id": None, "stages": []},
            "key":  {"arn": key_arn,  "version_id": None, "stages": []},
        },
        "san": (args.san or None),
        "key": {"algo": "rsa", "size": None},
        "validity_days": args.validity_days,
        "rotation": {"status":"active","last_update": now_utc_str()},
        "tags": args.tags or [],
        "description": args.description or "",
        "updated_at": now_utc_str()
    }
    s3.put_json_with_meta(s3.key(f"{name}.json"), state)

    # inventory
    try:
        inv = s3.get_json(s3.key("cert-inventory.json"))
    except Exception:
        inv = {}
    certs = inv.get("certs", [])
    certs = [c for c in certs if c.get("name") != name]
    certs.append(state)
    inv["certs"] = certs
    inv.setdefault("cas", inv.get("cas", []))
    inv["updated_at"] = now_utc_str()
    s3.put_json_with_meta(s3.key("cert-inventory.json"), inv)

    if out == "table":
        print(fmt_table([["RESULT","DETAIL"],["imported", f"cert {name}"]]))
    else:
        print(json.dumps({"result":"imported","name":name}, indent=2))