
import json
try:
    import yaml
except Exception:
    yaml = None

def fmt_table(rows):
    if not rows: 
        return ""
    widths = [max(len(str(c)) for c in col) for col in zip(*rows)]
    def line(cells): return "  ".join(str(c).ljust(w) for c, w in zip(cells, widths))
    out = [line(rows[0]), "  ".join("-"*w for w in widths)]
    out += [line(r) for r in rows[1:]]
    return "\n".join(out)

def output(doc, outfmt):
    if outfmt == "json":
        print(json.dumps(doc, indent=2))
    elif outfmt == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is not installed.")
        print(yaml.safe_dump(doc, sort_keys=False))
    else:
        print(json.dumps(doc, indent=2))
