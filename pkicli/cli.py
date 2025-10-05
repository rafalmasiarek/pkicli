# cli.py
# Argument parser and entrypoints wired to ops modules.

import argparse
from .aws_s3 import S3Client
from .ca_ops import (
    ca_list, ca_show, ca_history, ca_init,
    ca_renew, ca_export, ca_import, ca_delete
)
from .cert_ops import (
    cert_list, cert_show, cert_delete,
    cert_issue, cert_renew, cert_export, cert_import
)

from .inventory import rebuild_inventory

def build_parser():
    p = argparse.ArgumentParser(
        prog="pkicli",
        description="Minimal PKI CLI for S3 state + Secrets Manager (universal schema)"
    )
    p.add_argument("--region", required=True, help="AWS region, e.g. eu-central-1")
    p.add_argument("--state-bucket", required=True, help="S3 bucket with state JSONs")
    p.add_argument("--state-prefix", default="pki/state", help="Prefix within the bucket (default: 'pki/state')")
    p.add_argument("--output", choices=["json","table","yaml"], default="json", help="Output format")
    p.add_argument("--sm-prefix", default="", help="Secrets Manager name prefix for assets")
    p.add_argument("--target-version", default="v1", help="Schema version for writes (default: v1)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ---- CA commands ----
    ca = sub.add_parser("ca", help="CA operations")
    ca_sub = ca.add_subparsers(dest="ca_cmd", required=True)

    p_list = ca_sub.add_parser("list", help="List CAs (from inventory.cas[])")
    p_list.add_argument("--expiring-in", type=int, default=None,
                        help="Show only CAs that expire in <= N days")
    p_list.set_defaults(func=cmd_ca_list)

    p_show = ca_sub.add_parser("show", help="Show a CA JSON")
    p_show.add_argument("--name", required=True)
    p_show.set_defaults(func=cmd_ca_show)

    p_hist = ca_sub.add_parser("history", help="Show CA rotation history")
    p_hist.add_argument("--name", required=True)
    p_hist.set_defaults(func=cmd_ca_history)

    p_init = ca_sub.add_parser("init", help="Bootstrap a new CA")
    p_init.add_argument("--name", required=True)
    p_init.add_argument("--subject-cn", required=True)
    p_init.add_argument("--subject-o", required=True)
    p_init.add_argument("--days", type=int, default=3650)
    p_init.add_argument("--key-size", type=int, default=4096)
    p_init.add_argument("--tags", action="append", default=[])
    p_init.add_argument("--description", default="")
    p_init.set_defaults(func=cmd_ca_init)

    p_renew = ca_sub.add_parser("renew", help="Rotate CA keypair & certificate, update history and inventory")
    p_renew.add_argument("--name", required=True)
    p_renew.add_argument("--subject-cn", required=False, help="Override subject CN (else from current CA)")
    p_renew.add_argument("--subject-o", required=False, help="Override subject O (else from current CA)")
    p_renew.add_argument("--days", type=int, default=3650)
    p_renew.add_argument("--key-size", type=int, default=4096)
    p_renew.add_argument("--reason", default="planned-rotation")
    p_renew.add_argument("--tags", action="append", default=[])
    p_renew.add_argument("--description", default=None, help="Optional new description")
    p_renew.set_defaults(func=cmd_ca_renew)

    p_export = ca_sub.add_parser("export", help="Export CA state bundle (optionally with PEMs from SM)")
    p_export.add_argument("--name", required=True)
    p_export.add_argument("--file", default="-", help="Output file or '-' (stdout)")
    p_export.add_argument("--with-secrets", action="store_true")
    p_export.set_defaults(func=cmd_ca_export)

    p_import = ca_sub.add_parser("import", help="Import CA state (bundle JSON) and optionally PEMs")
    p_import.add_argument("--file", default="-", help="Bundle path or '-' for stdin")
    p_import.set_defaults(func=cmd_ca_import)

    p_revoke = ca_sub.add_parser("revoke", help="Revoke (soft-delete) a CA; use --hard for permanent delete")
    p_revoke.add_argument("--name", required=True, help="CA name")
    p_revoke.add_argument("--hard", action="store_true", help="Permanently delete CA state and secrets")
    p_revoke.add_argument("--retention-days", type=int, default=30, help="Secrets Manager recovery window for soft-delete (7–30 days)")
    p_revoke.set_defaults(func=cmd_ca_revoke)

    # ---- Certificate commands ----
    cert = sub.add_parser("cert", help="Certificate operations")
    cert_sub = cert.add_subparsers(dest="cert_cmd", required=True)

    c_list = cert_sub.add_parser("list", help="List certificates")
    c_list.add_argument("--expiring-in", type=int, default=None,
                        help="Show only certificates that expire in <= N days")
    c_list.set_defaults(func=cmd_cert_list)

    c_show = cert_sub.add_parser("show", help="Show a certificate JSON by name")
    c_show.add_argument("name")
    c_show.set_defaults(func=cmd_cert_show)

    c_issue = cert_sub.add_parser("issue", help="Issue a new certificate (SM+S3)")
    c_issue.add_argument("--name", required=True)
    c_issue.add_argument("--subject-cn", required=True)
    c_issue.add_argument("--subject-o", default="")
    c_issue.add_argument("--san", action="append", default=[])
    c_issue.add_argument("--key-algo", choices=["rsa"], default="rsa")
    c_issue.add_argument("--key-size", type=int, default=4096)
    c_issue.add_argument("--validity-days", type=int, default=1825)
    c_issue.add_argument("--ca-name", required=True, help="CA name to sign with")
    c_issue.add_argument("--tags", action="append", default=[])
    c_issue.add_argument("--description", default="")
    c_issue.set_defaults(func=cmd_cert_issue)

    c_renew = cert_sub.add_parser("renew", help="Renew (reissue) an existing certificate preserving subject & SAN")
    c_renew.add_argument("name", help="Certificate logical name")
    c_renew.add_argument("--validity-days", type=int, default=None, help="Override validity (days)")
    c_renew.add_argument("--key-size", type=int, default=None, help="Optionally new key size (RSA)")
    c_renew.set_defaults(func=cmd_cert_renew)

    c_export = cert_sub.add_parser("export", help="Export cert bundle (state + optional PEMs from SM)")
    c_export.add_argument("name")
    c_export.add_argument("--file", default="-")
    c_export.add_argument("--with-secrets", action="store_true")
    c_export.set_defaults(func=cmd_cert_export)

    c_import = cert_sub.add_parser("import", help="Import certificate from bundle or PEM files")
    mode = c_import.add_mutually_exclusive_group(required=True)
    mode.add_argument("--from-bundle", default=None, help="Bundle JSON path or '-'")
    mode.add_argument("--from-files", action="store_true", help="Import from local PEMs")
    c_import.add_argument("--name", help="(files) logical name")
    c_import.add_argument("--subject-cn", help="(files) subject CN")
    c_import.add_argument("--subject-o", default="", help="(files) subject O")
    c_import.add_argument("--san", action="append", default=[], help="(files) SAN entry (repeatable)")
    c_import.add_argument("--crt", help="(files) path to certificate PEM")
    c_import.add_argument("--key", help="(files) path to private key PEM")
    c_import.add_argument("--ca-name", help="(files) CA name this cert belongs to")
    c_import.add_argument("--validity-days", type=int, default=None, help="(files) optional informational field")
    c_import.add_argument("--tags", action="append", default=[], help="optional tags")
    c_import.add_argument("--description", default="", help="optional description")
    c_import.set_defaults(func=cmd_cert_import)

    c_revoke = cert_sub.add_parser("revoke", help="Revoke (soft-delete) a certificate; use --hard for permanent delete")
    c_revoke.add_argument("--name", required=True, help="Certificate name")
    c_revoke.add_argument("--hard", action="store_true", help="Permanently delete certificate state and secrets")
    c_revoke.add_argument("--retention-days", type=int, default=30, help="Secrets Manager recovery window for soft-delete (7–30 days)")
    c_revoke.set_defaults(func=cmd_cert_revoke)

    c_rebuild_inventory = cert_sub.add_parser("rebuild", help="Rebuild active certs in inventory")
    c_rebuild_inventory.set_defaults(func=cmd_cert_rebuild)

    return p

def _s3(args):
    return S3Client(region=args.region, bucket=args.state_bucket,
                    prefix=args.state_prefix or "pki/state")

# CA dispatchers
def cmd_ca_list(args): ca_list(_s3(args), args.expiring_in, args.output)
def cmd_ca_show(args): ca_show(_s3(args), args.name, args.output)
def cmd_ca_history(args): ca_history(_s3(args), args.name, args.output)
def cmd_ca_init(args): ca_init(s3=_s3(args), name=args.name, subject_cn=args.subject_cn, subject_o=args.subject_o, days=args.days, key_size=args.key_size, tags=args.tags, description=args.description, sm_prefix=args.sm_prefix, region=args.region, target_version=args.target_version, out=args.output)
def cmd_ca_revoke(args): ca_delete(_s3(args), name=args.name, region=args.region, sm_prefix=args.sm_prefix, target_version=args.target_version, hard=args.hard, retention_days=args.retention_days, out=args.output)

def cmd_ca_renew(args):    ca_renew(_s3(args), args, args.region, args.sm_prefix, args.target_version, args.output)
def cmd_ca_export(args):   ca_export(_s3(args), args.name, args.file, args.with_secrets, args.region)
def cmd_ca_import(args):   ca_import(_s3(args), args.file, args.region, args.sm_prefix,  args.target_version, args.output)

# Cert dispatchers
def cmd_cert_list(args):   cert_list(_s3(args), args.expiring_in, args.output)
def cmd_cert_show(args):   cert_show(_s3(args), args.name, args.output)
def cmd_cert_issue(args):  cert_issue(_s3(args), args, args.region, args.sm_prefix, args.target_version, args.output)
def cmd_cert_renew(args):  cert_renew(_s3(args), args, args.region, args.sm_prefix, args.output)
def cmd_cert_export(args): cert_export(_s3(args), args.name, args.file, args.with_secrets, args.region)
def cmd_cert_import(args): cert_import(_s3(args), args, args.region, args.sm_prefix, args.output)
def cmd_cert_revoke(args): cert_delete(_s3(args), name=args.name, region=args.region, sm_prefix=args.sm_prefix, target_version=args.target_version, hard=args.hard, retention_days=args.retention_days, out=args.output)
def cmd_cert_rebuild(args):
    rebuild_inventory(_s3(args), target_version=args.target_version)
    print("Rebuilt active certificates.")

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)