from __future__ import annotations

from .registry import VersionAdapter, register
from ..ir import X509Meta, CAIR, CertIR, InventoryIR, CARef

class V1Adapter(VersionAdapter):
    def _x509_from_doc(self, meta: dict) -> X509Meta:
        return X509Meta(
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
        )

    # ---- to IR ----
    def to_ir_ca(self, doc: dict) -> CAIR:
        ca = doc.get("ca", {}) or {}
        sm = doc.get("secrets_manager", {}) or {}
        return CAIR(
            version="ir/1",
            name=ca.get("name", ""),
            ca_version=int(ca.get("version", 1) or 1),
            metadata=self._x509_from_doc(doc.get("metadata", {}) or {}),
            rotation=doc.get("rotation", {}) or {},
            history=ca.get("history", []) or [],
            secrets_manager={"crt_arn": sm.get("crt_arn"), "key_arn": sm.get("key_arn")},
            secrets_manager_meta=doc.get("secrets_manager_meta", {}) or {},
            tags=doc.get("tags", []) or [],
            description=doc.get("description", "") or "",
            updated_at=doc.get("updated_at"),
            s3_meta=doc.get("s3_meta"),
        )

    def to_ir_cert(self, doc: dict) -> CertIR:
        ca = doc.get("ca") or {}
        return CertIR(
            version="ir/1",
            name=doc.get("name", ""),
            subject=doc.get("subject", {}) or {},
            metadata=self._x509_from_doc(doc.get("metadata", {}) or {}),
            ca=CARef(
                name=ca.get("name", ""),
                version=ca.get("version"),
                crt_arn=ca.get("crt_arn"),
                key_arn=ca.get("key_arn"),
                state_s3=ca.get("state_s3"),
            ) if ca else None,
            cert_secret_arn=doc.get("cert_secret_arn"),
            key_secret_arn=doc.get("key_secret_arn"),
            secret_arn=doc.get("secret_arn"),
            secrets_manager_meta=doc.get("secrets_manager_meta", {}) or {},
            tags=doc.get("tags", []) or [],
            description=doc.get("description", "") or "",
            updated_at=doc.get("updated_at"),
            s3_meta=doc.get("s3_meta"),
        )

    def to_ir_inventory(self, doc: dict) -> InventoryIR:
        cas_refs = []
        for c in doc.get("cas", []) or []:
            cas_refs.append(CARef(
                name=c.get("name", ""),
                version=c.get("version"),
                crt_arn=c.get("crt_arn"),
                key_arn=c.get("key_arn"),
                state_s3=c.get("state_s3"),
            ))
        # Preserve certificates from the source document
        certs_list = doc.get("certs", []) or []

        return InventoryIR(
            version="ir/1",
            cas=cas_refs,
            certs=certs_list,
            updated_at=doc.get("updated_at"),
            s3_meta=doc.get("s3_meta"),
        )

    # ---- from IR ----
    def from_ir_ca(self, cair: CAIR) -> dict:
        return {
            "version": "v1",
            "updated_at": cair.updated_at,
            "metadata": cair.metadata.__dict__,
            "rotation": cair.rotation,
            "ca": {
                "name": cair.name,
                "version": cair.ca_version,
                "history": cair.history,
            },
            "secrets_manager": {
                "crt_arn": cair.secrets_manager.get("crt_arn"),
                "key_arn": cair.secrets_manager.get("key_arn"),
            },
            "secrets_manager_meta": cair.secrets_manager_meta,
            "tags": cair.tags,
            "description": cair.description,
            **({"s3_meta": cair.s3_meta} if cair.s3_meta else {}),
        }

    def from_ir_cert(self, cert: CertIR) -> dict:
        ca = cert.ca
        return {
            "version": "v1",
            "name": cert.name,
            "subject": cert.subject,
            "metadata": cert.metadata.__dict__,
            "ca": ({
                "name": ca.name,
                "version": ca.version,
                "crt_arn": ca.crt_arn,
                "key_arn": ca.key_arn,
                "state_s3": ca.state_s3,
            } if ca else None),
            "secret_arn": cert.secret_arn,
            "cert_secret_arn": cert.cert_secret_arn,
            "key_secret_arn": cert.key_secret_arn,
            "secrets_manager_meta": cert.secrets_manager_meta,
            "tags": cert.tags,
            "description": cert.description,
            "updated_at": cert.updated_at,
            **({"s3_meta": cert.s3_meta} if cert.s3_meta else {}),
        }

    def from_ir_inventory(self, inv: InventoryIR) -> dict:
        return {
            "version": "v1",
            "cas": [
                {
                    "name": c.name,
                    "version": c.version,
                    "crt_arn": c.crt_arn,
                    "key_arn": c.key_arn,
                    "state_s3": c.state_s3,
                } for c in inv.cas
            ],
            # Write back certificates preserved in IR
            "certs": getattr(inv, "certs", []) or [],
            "updated_at": inv.updated_at,
            **({"s3_meta": inv.s3_meta} if inv.s3_meta else {}),
        }

# register adapter on import
register("v1", V1Adapter())