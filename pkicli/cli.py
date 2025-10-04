# cli.py
# Argument parser and entrypoints wired to ops modules.

import argparse
from .aws_s3 import S3Client
from .ca_ops import ca_list, ca_show, ca_history, ca_init
from .cert_ops import cert_list, cert_show

def build_parser():
    p = argparse.ArgumentParser(
        prog="pkicli",
        description="Minimal PKI CLI for S3 state + Secrets Manager (universal schema)"
    )
    p.add_argument("--region", required=True, help="AWS region, e.g. eu-central-1")
    p.add_argument("--state-bucket", required=True, help="S3 bucket with state JSONs")
    p.add_argument("--state-prefix", default="pki/state", help="Prefix within the bucket (default: 'pki/state')")
    p.add_argument("--output", choices=["json","table","yaml"], default="json", help="Output format")
    p.add_argument("--yes", action="store_true", help="Confirm mutating actions (e.g., ca init)")
    p.add_argument("--sm-prefix", default="", help="Secrets Manager name prefix for assets (used by ca init)")
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
    # Kept only for compatibility of interface; we always store crt/key in SM.
    p_init.add_argument("--sm-store-ca-crt", action="store_true")
    p_init.add_argument("--sm-store-ca-key", action="store_true")
    p_init.set_defaults(func=cmd_ca_init)

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

    return p

def _s3(args):
    return S3Client(region=args.region, bucket=args.state_bucket,
                    prefix=args.state_prefix or "pki/state")

# CA dispatchers
def cmd_ca_list(args): ca_list(_s3(args), args.expiring_in, args.output)
def cmd_ca_show(args): ca_show(_s3(args), args.name, args.output)
def cmd_ca_history(args): ca_history(_s3(args), args.name, args.output)
def cmd_ca_init(args):
    ca_init(
        s3=_s3(args),
        name=args.name,
        subject_cn=args.subject_cn,
        subject_o=args.subject_o,
        days=args.days,
        key_size=args.key_size,
        tags=args.tags,
        description=args.description,
        sm_store_crt=True,   # enforced
        sm_store_key=True,   # enforced
        sm_prefix=args.sm_prefix,
        region=args.region,
        yes=args.yes,
        out=args.output,
    )

# Cert dispatchers
def cmd_cert_list(args): cert_list(_s3(args), args.expiring_in, args.output)
def cmd_cert_show(args): cert_show(_s3(args), args.name, args.output)

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)