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
pkicli   --region eu-central-1          --state-bucket <bucket-name>          [--state-prefix pki/state]          [--sm-prefix <path/prefix>]          [--output json|table|yaml]          [--target-version v1]          <command> ...
```

- If `--state-prefix` is omitted, default is `pki/state`. If provided, it **fully overrides** the default.
- `--target-version` is the **schema** version (default `v1`).
- Output defaults to `json` unless `--output table` is provided.

---

## Commands

### CA

List CAs (from inventory). Deleted CAs are **hidden** by default:
```bash
pkicli ca list --region eu-central-1 --state-bucket <bucket> --output table
pkicli ca list --expiring-in 90 --region eu-central-1 --state-bucket <bucket> --output table
# Show deleted as well:
pkicli ca list --include-deleted --region eu-central-1 --state-bucket <bucket> --output table
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
pkicli ca init --name my-ca --subject-cn "Example Root CA" --subject-o "Example Org"   --days 3650 --key-size 4096 --tags prod --tags team:security   --description "Primary CA" --sm-prefix company/prod   --region eu-central-1 --state-bucket <bucket>
```

Renew an existing CA (rotate CA cert/key, snapshot previous, update inventory):
```bash
pkicli ca renew --name my-ca --days 3650 --key-size 4096 --reason "planned-rotation"   --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

Soft‑delete (revoke) a CA:
```bash
# Soft-delete: tag 'deleted', status 'revoked', add history entry, schedule SM deletion (default 30 days)
pkicli ca revoke --name my-ca --retention-days 30   --region eu-central-1 --state-bucket <bucket>

# Hard delete: remove state + inventory + SM secrets immediately (irreversible)
pkicli ca revoke --name my-ca --hard   --region eu-central-1 --state-bucket <bucket>
```

**Export CA bundle** (optionally include PEMs from SM):
```bash
pkicli ca export --name my-ca --with-secrets --file ./my-ca.bundle.json   --region eu-central-1 --state-bucket <bucket>
```

**Import CA bundle** (writes CA state, stores PEMs if present):
```bash
pkicli ca import --file ./my-ca.bundle.json   --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

### Certificates

List certificates (deleted/revoked are hidden by default):
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
pkicli cert issue --name app-server-1 --subject-cn app.example.com --subject-o "Example Org"   --san app.example.com --san 10.0.1.10 --key-algo rsa --key-size 4096 --validity-days 825   --ca-name my-ca --sm-prefix company/prod --tags prod --description "Frontend TLS"   --region eu-central-1 --state-bucket <bucket>
```

**Renew** an existing certificate (reissue preserving Subject & SAN):
```bash
pkicli cert renew app-server-1 --validity-days 825 --key-size 4096   --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

Soft‑delete (revoke) a certificate:
```bash
# Soft-delete: tag 'deleted', status 'revoked', add history entry, schedule SM deletion (default 30 days)
pkicli cert revoke --name app-server-1 --retention-days 30   --region eu-central-1 --state-bucket <bucket>

# Hard delete: remove state + inventory + SM secrets immediately (irreversible)
pkicli cert revoke --name app-server-1 --hard   --region eu-central-1 --state-bucket <bucket>
```

**Export** certificate bundle (optionally include PEMs):
```bash
pkicli cert export app-server-1 --with-secrets --file ./app-server-1.bundle.json   --region eu-central-1 --state-bucket <bucket>
```

**Import** certificate (from bundle or PEM files):
```bash
# from bundle
pkicli cert import --from-bundle ./app-server-1.bundle.json   --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>

# from PEMs
pkicli cert import --from-files   --name legacy-api --subject-cn legacy-api --subject-o "Example Org"   --san legacy-api --san 10.0.2.15   --crt ./legacy-api.crt --key ./legacy-api.key   --ca-name my-ca --tags legacy --description "Migrated"   --sm-prefix company/prod --region eu-central-1 --state-bucket <bucket>
```

### Inventory rebuild

Rebuild the inventory using objects found under the configured S3 prefix. Only **active** (non‑revoked) certs are indexed.
```bash
pkicli cert rebuild --region eu-central-1 --state-bucket <bucket> [--state-prefix pki/state] [--target-version v1]
```

---

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
  "cas": [
    {"name":"my-ca","version":1,"crt_arn":"...","key_arn":"...","state_s3":"s3://.../my-ca.json"}
  ],
  "certs": [
    {"name":"app-server-1","ca":{"name":"my-ca","version":1,"state_s3":"s3://.../my-ca.json"},"metadata":{"...":"..."}}
  ],
  "updated_at": "RFC3339Z",
  "s3_meta": {"version_id":"...","etag":"..."}
}
```

---

## Behavior & Guarantees

- **Soft‑delete by default** for `ca revoke` / `cert revoke`:
  - Adds `"status": "revoked"` and `"tags": ["deleted", ...]` to the state JSON.
  - Writes a history/rotation entry.
  - Schedules AWS Secrets Manager deletion (default **30 days**, override with `--retention-days N`).
  - Keeps S3 state for traceability.
- **Hard delete** (`--hard`) removes S3 state and calls Secrets Manager `delete_secret(..., ForceDeleteWithoutRecovery=True)`.
- **Recreate while scheduled for deletion**: if a new CA/cert tries to reuse the same secret name that is scheduled for deletion,
  pkicli will **restore the secret**, update its value, and continue.
- **Listing**: `cert list` and `ca list` **hide deleted/revoked** items by default.
- **Schema vs rotation version**:
  - Schema version is **`v1`** (serde adapter).  
  - CA/cert rotation version is an **integer** stored separately (`ca_version` for CA IR, or per‑object `version` in inventory CA refs).

---

## Troubleshooting

- *"You can't perform this operation because the secret is marked for deletion"*  
  The secret name is scheduled for deletion in Secrets Manager. Re‑running a create/issue operation will trigger an automatic **restore**; alternatively, restore manually from the AWS Console.
- *Validation errors about `pkicli.schemas.ir/1`*  
  Ensure the validator reads **schema** version (`v1`), not IR version (`ir/1`). The serde layer handles conversions.
- OpenSSL failures on CA renew/issue: check that `openssl` is present in PATH and arguments (key size, days, SANs) are valid.

---

## License

This project is licensed under the **MIT License** — you are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, provided that the original copyright notice and this permission notice are included in all copies or substantial portions of the Software.

The software is provided **"as is"**, without warranty of any kind, express or implied, including but not limited to the warranties of **merchantability**, **fitness for a particular purpose**, and **noninfringement**.  
In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

See the [LICENSE.md](LICENSE.md) file for the full text of the MIT License.

## Authors

**Rafał Masiarek** [🌐](https://masiarek.pl)  [🐙](https://github.com/rafalmasiarek) [📧](mailto:rafal@masiarek.pl) – original author & maintainer  

Contributions are welcome! Feel free to open issues, submit pull requests, or suggest new features.