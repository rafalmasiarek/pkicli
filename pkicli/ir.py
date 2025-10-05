from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class X509Meta:
    not_before: str
    not_after: str
    serial: str
    sha256: str
    sig_alg: str
    pubkey_algo: str
    pubkey_bits: int
    skid: Optional[str] = None
    akid: Optional[str] = None
    issuer_cn: Optional[str] = None
    subject_cn: Optional[str] = None
    san: Optional[List[str]] = None

@dataclass
class CARef:
    name: str
    version: Optional[int] = None
    crt_arn: Optional[str] = None
    key_arn: Optional[str] = None
    state_s3: Optional[str] = None

@dataclass
class SecretsMeta:
    arn: str
    version_id: Optional[str] = None
    stages: List[str] = field(default_factory=list)

@dataclass
class CertIR:
    # wspólne
    version: str = "ir/1"
    name: str = ""
    subject: Dict[str,str] = field(default_factory=dict)   # {"CN": "...", "O": "..."} – O opcjonalne
    metadata: X509Meta = None
    ca: Optional[CARef] = None
    cert_secret_arn: Optional[str] = None
    key_secret_arn: Optional[str] = None
    secret_arn: Optional[str] = None     # np. kubeconfig lub inny „binding” – może być None
    secrets_manager_meta: Dict[str, Optional[SecretsMeta]] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    description: str = ""
    updated_at: Optional[str] = None
    s3_meta: Optional[Dict[str,str]] = None

@dataclass
class CAIR:
    version: str = "ir/1"
    name: str = ""
    ca_version: int = 1
    metadata: X509Meta = None
    rotation: Dict[str, str] = field(default_factory=dict)     # {"status":"active","last_update":"...","reason":"...","actor":"..."}
    history: List[Dict] = field(default_factory=list)          # lista „starych wersji”
    secrets_manager: Dict[str, Optional[str]] = field(default_factory=dict)  # {"crt_arn":"...","key_arn":"..."}
    secrets_manager_meta: Dict[str, Optional[SecretsMeta]] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    description: str = ""
    updated_at: Optional[str] = None
    s3_meta: Optional[Dict[str,str]] = None

@dataclass
class InventoryIR:
    version: str = "ir/1"
    cas: List[CARef] = field(default_factory=list)
    certs: List[CertIR] = field(default_factory=list)
    updated_at: Optional[str] = None
    s3_meta: Optional[Dict[str,str]] = None