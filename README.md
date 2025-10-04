# pkicli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

`pkicli` is a small command‑line tool to manage X.509 PKI state stored in **AWS S3** with secrets in **AWS Secrets Manager**.
It is **generic** (not Kubernetes‑specific) and aims to be safe, explicit, and easy to automate.

- State lives in S3 as JSON (per‑CA, per‑certificate, and a single **cert-inventory.json**).
- Secrets (PEM certs/keys or arbitrary strings) live in Secrets Manager as **plain SecretString** (no extra base64).
- All write operations inject S3 object metadata (`s3_meta.version_id`, `s3_meta.etag`) into the JSON by doing a two‑step PUT.

## Requirements

- Python 3.9+
- `openssl` in PATH (for issuing/renewing certs and CA bootstrap/renewal)
- AWS credentials with permissions for S3 + Secrets Manager
- Python packages: `boto3`, `PyYAML`, `python-dateutil`

## Install

```bash
# From a source tree that contains setup.cfg / pyproject.toml
pip install .

# Or in a virtualenv
python3 -m venv .venv && . .venv/bin/activate
pip install .
```

This installs the `pkicli` entry point (e.g. `/usr/local/bin/pkicli`).

## Quick start

Global options:

```bash
pkicli   --region eu-central-1   
         --state-bucket <bucket-name>   
         [--state-prefix pki/state]   [--output json|table|yaml]   <command> ...
```

- If `--state-prefix` is omitted, default is `pki/state`.
- If provided, it **fully overrides** the default.

## Commands

### CA

List CAs (from `cert-inventory.json` → `.cas[]`):
```bash
pkicli ca list --region eu-central-1 --state-bucket <bucket> --output table
```

Show a CA (reads `<prefix>/<name>.json`):
```bash
pkicli ca show --name my-ca --region eu-central-1 --state-bucket <bucket> --output table
```

History:
```bash
pkicli ca history --name my-ca --region eu-central-1 --state-bucket <bucket> --output table
```

Initialize a new CA (stores crt+key in SM, state in S3, updates inventory):
```bash
pkicli ca init --name my-ca --subject-cn "Example Root CA" --subject-o "Example Org" \
  --days 3650 --key-size 4096 --tags prod --tags team:security \
  --description "Primary CA" --sm-prefix company/prod \
  --yes --region eu-central-1 --state-bucket <bucket>
```

Renew an existing CA (rotate CA cert/key, snapshot previous, update inventory):
```bash
pkicli ca renew --name my-ca --days 3650 --key-size 4096 --reason "planned-rotation" \
  --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

**Export CA bundle** (optionally include PEMs from SM):
```bash
pkicli ca export --name my-ca --with-secrets --file ./my-ca.bundle.json \
  --region eu-central-1 --state-bucket <bucket>
```

**Import CA bundle** (writes CA state, stores PEMs if present):
```bash
pkicli ca import --file ./my-ca.bundle.json --yes \
  --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

### Certificates

List certificates:
```bash
pkicli cert list --region eu-central-1 --state-bucket <bucket> --output table
pkicli cert list --expiring-in 30 --region eu-central-1 --state-bucket <bucket> --output table
```

Show one certificate:
```bash
pkicli cert show app-server-1 --region eu-central-1 --state-bucket <bucket> --output table
```

**Issue** a certificate (SM+S3):
```bash
pkicli cert issue --name app-server-1 --subject-cn app.example.com --subject-o "Example Org" \
  --san app.example.com --san 10.0.1.10 --key-algo rsa --key-size 4096 --validity-days 825 \
  --ca-name my-ca --sm-prefix company/prod --tags prod --description "Frontend TLS" \
  --region eu-central-1 --state-bucket <bucket>
```

**Renew** an existing certificate (reissue preserving Subject & SAN):
```bash
pkicli cert renew app-server-1 --validity-days 825 --key-size 4096 \
  --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

Import an existing cert/key (PEM) and write a state JSON for it:
```bash
pkicli cert import   --name legacy-api   --subject-cn "legacy-api"   --subject-o "Example Org"   --san legacy-api --san 10.0.2.15   --crt ./legacy-api.crt --key ./legacy-api.key   --ca my-ca   --sm-prefix company/prod   --tags legacy   --description "Migrated from old tooling"   --yes   --region eu-central-1   --state-bucket <bucket>
```

## S3 layout

```
s3://<STATE_BUCKET>/<STATE_PREFIX>/
  ├── cert-inventory.json
  ├── <ca>.json
  ├── <ca>@<TIMESTAMP>.json  # snapshots on CA rotation/import
  └── <cert-name>.json
```

Inventory contains:
```json
{
  "cas": [    {"name":"my-ca","version":1,"crt_arn":"...","key_arn":"...","state_s3":"s3://.../my-ca.json"}
  ],
  "certs": [
    {"name":"app-server-1", "ca":{"name":"my-ca","version":1,"state_s3":"s3://.../my-ca.json"}, "metadata":{ "...": "..." }, ...}
  ],
  "updated_at": "RFC3339Z",
  "s3_meta": {"version_id":"...","etag":"..."}
}
```

## Notes

- All mutating commands require `--yes` to proceed.
- The tool prefers plain strings in Secrets Manager. PEM values are stored as `SecretString` without extra base64.
- Table output is available for the common read paths; JSON is the default output; YAML requires `PyYAML`.
- The CLI is tolerant of legacy JSON fields; unknown keys are ignored.

## License

This project is licensed under the **MIT License** — you are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, provided that the original copyright notice and this permission notice are included in all copies or substantial portions of the Software.

The software is provided **"as is"**, without warranty of any kind, express or implied, including but not limited to the warranties of **merchantability**, **fitness for a particular purpose**, and **noninfringement**.  
In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

See the [LICENSE.md](LICENSE.md) file for the full text of the MIT License.

## Authors

**Rafał Masiarek** [🌐](https://masiarek.pl)  [🐙](https://github.com/rafalmasiarek) [📧](mailto:rafal@masiarek.pl) – original author & maintainer  

Contributions are welcome! Feel free to open issues, submit pull requests, or suggest new features.