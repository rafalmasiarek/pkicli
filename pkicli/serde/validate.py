import json, importlib.resources as pkg
from jsonschema import validate

def _schema(version: str, kind: str) -> dict:
    # kind in {"ca","cert","inventory"}
    with pkg.files(f"pkicli.schemas.{version}").joinpath(f"{kind}.schema.json").open("r", encoding="utf-8") as f:
        return json.load(f)

def validate_doc(doc: dict, version: str, kind: str):
    schema = _schema(version, kind)
    validate(instance=doc, schema=schema)