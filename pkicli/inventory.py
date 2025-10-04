def extract_cas(inv):
    cas = inv.get("cas")
    return cas if isinstance(cas, list) else []

def extract_certs(inv):
    certs = inv.get("certs")
    return certs if isinstance(certs, list) else []
