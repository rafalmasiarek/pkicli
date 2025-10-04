
import json
from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError

class S3Client:
    """
    Thin wrapper around boto3 S3 client for JSON read/write.
    """
    def __init__(self, region: str, bucket: str, prefix: str = "pki/state"):
        self.region = region
        self.bucket = bucket
        self.prefix = (prefix or "pki/state").strip("/")
        self.s3 = boto3.client("s3", region_name=region)

    def key(self, *parts: str) -> str:
        parts = [p.strip("/") for p in parts if p]
        if self.prefix:
            return f"{self.prefix}/" + "/".join(parts)
        return "/".join(parts)

    def get_text(self, key: str) -> str:
        try:
            r = self.s3.get_object(Bucket=self.bucket, Key=key)
            return r["Body"].read().decode("utf-8")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise FileNotFoundError(f"s3://{self.bucket}/{key}") from e
            raise

    def get_json(self, key: str) -> Dict[str, Any]:
        return json.loads(self.get_text(key))

    def put_json_with_meta(self, key: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        # first put
        body1 = (json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        r1 = self.s3.put_object(Bucket=self.bucket, Key=key, Body=body1, ContentType="application/json", ServerSideEncryption="AES256")
        v1 = r1.get("VersionId")
        et1 = (r1.get("ETag","") or "").strip('"')
        # second put with meta
        doc2 = dict(doc)
        doc2["s3_meta"] = {"version_id": v1, "etag": et1}
        body2 = (json.dumps(doc2, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        r2 = self.s3.put_object(Bucket=self.bucket, Key=key, Body=body2, ContentType="application/json", ServerSideEncryption="AES256")
        v2 = r2.get("VersionId") or v1
        et2 = (r2.get("ETag","") or "").strip('"') or et1
        return {"version_id": v2, "etag": et2}
