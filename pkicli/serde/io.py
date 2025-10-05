from dataclasses import is_dataclass, asdict
from typing import Any, Dict, Union

from . import v1 

from .validate import validate_doc
from .registry import get as get_adapter
from ..ir import CertIR, CAIR, InventoryIR, CARef
from ..aws_s3 import S3Client



def _detect_version(doc: dict) -> str:
    v = doc.get("version")
    if not v:
        raise ValueError("Missing 'version' field in document")
    return v

def _to_dict(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "dict"):
        return obj.dict()  # type: ignore[attr-defined]
    if hasattr(obj, "model_dump"):
        return obj.model_dump()  # pydantic v2
    return dict(obj)  # last resort for Mapping-like


# ----- schema adapters (in-memory) -----

def load_ca(doc: dict) -> CAIR:
    v = _detect_version(doc)
    ad = get_adapter(v)
    return ad.to_ir_ca(doc)

def load_cert(doc: dict) -> CertIR:
    v = _detect_version(doc)
    ad = get_adapter(v)
    return ad.to_ir_cert(doc)

def load_inventory(doc: dict) -> InventoryIR:
    v = _detect_version(doc)
    ad = get_adapter(v)
    return ad.to_ir_inventory(doc)

def dump_ca(cair: CAIR, target_version: str = "v1") -> dict:
    ad = get_adapter(target_version)
    out = ad.from_ir_ca(cair)
    out.setdefault("version", target_version)
    return out

def dump_cert(cert: CertIR, target_version: str = "v1") -> dict:
    ad = get_adapter(target_version)
    out = ad.from_ir_cert(cert)
    out.setdefault("version", target_version)
    return out

def dump_inventory(inv: InventoryIR, target_version: str = "v1") -> dict:
    ad = get_adapter(target_version)
    out = ad.from_ir_inventory(inv)
    out.setdefault("version", target_version)
    return out


# ----- S3-backed IO -----

def read_ca(s3: S3Client, name: str) -> dict:
    raw = s3.get_json(s3.key(f"{name}.json"))
    ir = load_ca(raw)
    return _to_dict(ir)

def write_cert(s3: S3Client, cert: Union[CertIR, dict], schema_version: str = "v1") -> None:
    # Always convert IR -> schema doc before validation and write
    ad = get_adapter(schema_version)
    if isinstance(cert, CertIR):
        doc = ad.from_ir_cert(cert)
    else:
        v = cert.get("version")
        if isinstance(v, str) and v.startswith("ir/"):
            ir = ad.to_ir_cert(cert)   # normalize dict to IR using adapter
            doc = ad.from_ir_cert(ir)  # then back to schema doc
        else:
            doc = cert

    # Validate the **serialized** (schema) document, not IR
    validate_doc(doc, doc.get("version", schema_version), "cert")

    s3.put_json_with_meta(s3.key(f"{doc['name']}.json"), doc)

def read_cert(s3: S3Client, name: str) -> dict:
    raw = s3.get_json(s3.key(f"{name}.json"))
    ir = load_cert(raw)
    return _to_dict(ir)

def read_inventory(s3: S3Client) -> dict:
    raw = s3.get_json(s3.key("cert-inventory.json"))
    ir = load_inventory(raw)
    return _to_dict(ir)

def write_inventory(s3: S3Client, inv: Union[InventoryIR, dict], schema_version: str = "v1") -> None:
    """
    Accepts InventoryIR or plain IR dict and writes using the selected schema adapter.
    """
    if isinstance(inv, dict):
        cas = []
        for c in inv.get("cas", []) or []:
            cas.append(CARef(
                name=c.get("name", ""),
                version=c.get("version"),
                crt_arn=c.get("crt_arn"),
                key_arn=c.get("key_arn"),
                state_s3=c.get("state_s3"),
            ))
        inv_ir = InventoryIR(
            version="ir/1",
            cas=cas,
            certs=inv.get("certs", []) or [],
            updated_at=inv.get("updated_at"),
            s3_meta=inv.get("s3_meta")
        )
    else:
        inv_ir = inv  # already InventoryIR

    doc = dump_inventory(inv_ir, target_version=schema_version)
    s3.put_json_with_meta(s3.key("cert-inventory.json"), doc)

def write_ca(s3: S3Client, cair: Union[CAIR, dict], schema_version: str = "v1") -> None:
    # Always convert IR -> schema doc before validation and write
    ad = get_adapter(schema_version)
    if isinstance(cair, CAIR):
        doc = ad.from_ir_ca(cair)
    else:
        # If a dict is passed but it looks like IR (version startswith 'ir/'),
        # convert it via adapter before persisting.
        v = cair.get("version")
        if isinstance(v, str) and v.startswith("ir/"):
            ir = ad.to_ir_ca(cair)  # normalize dict to IR using adapter
            doc = ad.from_ir_ca(ir) # then back to schema doc
        else:
            doc = cair

    # Validate the **serialized** (schema) document, not IR
    validate_doc(doc, doc.get("version", schema_version), "ca")

    s3.put_json_with_meta(s3.key(f"{doc['ca']['name']}.json"), doc)

