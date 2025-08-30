import ast, os, json, re
from typing import List, Dict, Any, Set

EXCLUDE = {".git","node_modules","venv",".venv","dist","build","__pycache__",".pytest_cache"}
PY_PATTERNS = {"rsa_keygen": re.compile(r"rsa\.generate_private_key"), "ec_keygen": re.compile(r"ec\.generate_private_key"), "ssl_ctx": re.compile(r"(ssl\.SSLContext|wrap_socket)")}
JS_PATTERNS = {"node_tls": re.compile(r"(tls\.createSecureContext|https\.createServer)"), "webcrypto": re.compile(r"crypto\.subtle\.(importKey|generateKey|sign|deriveKey)")}

def _scan_py(path: str) -> List[Dict[str, Any]]:
    out = []
    try:
        src = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return out
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError:
        tree = None

    if tree:
        class V(ast.NodeVisitor):
            def visit_Call(self, node):
                try: fn = ast.unparse(node.func)
                except Exception: fn = ""
                if "rsa.generate_private_key" in fn:
                    size = None; pubexp = None
                    for kw in node.keywords or []:
                        if kw.arg == "key_size": size = getattr(kw.value, "value", None)
                        if kw.arg == "public_exponent": pubexp = getattr(kw.value, "value", None)
                    out.append({"kind":"rsa_keygen","size":size,"public_exponent":pubexp,"path":path,"line":node.lineno})
                if "ec.generate_private_key" in fn:
                    out.append({"kind":"ec_keygen","path":path,"line":node.lineno})
                if "ssl.SSLContext" in fn or "wrap_socket" in fn:
                    out.append({"kind":"tls_context","path":path,"line":node.lineno})
                self.generic_visit(node)
        V().visit(tree)
    for name, rgx in PY_PATTERNS.items():
        for m in rgx.finditer(src):
            line = src.count("\n", 0, m.start()) + 1
            out.append({"kind":name,"path":path,"line":line})
    return out

def _scan_js(path: str) -> List[Dict[str, Any]]:
    out = []
    try:
        src = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return out
    for name, rgx in JS_PATTERNS.items():
        for m in rgx.finditer(src):
            line = src.count("\n", 0, m.start()) + 1
            out.append({"kind":name,"path":path,"line":line})
    return out

def scan_dir(root: str) -> List[Dict[str, Any]]:
    res = []
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE]
        for f in files:
            p = os.path.join(dp, f)
            if f.endswith(".py"): res += _scan_py(p)
            elif f.endswith((".js",".mjs",".cjs",".ts",".tsx")): res += _scan_js(p)
    return res

def to_bom(findings: List[Dict[str, Any]], base: str, context: Dict[str, Any]) -> Dict[str, Any]:
    obs = []
    for it in findings:
        obs.append({
            "source":"static.sast","source_type":"AST+grep","finding":it.get("kind"),
            "path": os.path.relpath(it.get("path"), base), "line": it.get("line"),
            "size": it.get("size"), "public_exponent": it.get("public_exponent"),
            "asset_id": context.get("asset_id"), "owner": context.get("owner"),
            "data_class": context.get("data_class"), "secrecy_lifetime_years": context.get("secrecy_lifetime_years"),
            "exposure": context.get("exposure"), "confidence": 0.7
        })
    return {"schema":"carnot.v2.1.cryptobom","run_id":"static-"+base,
            "summary":{"assets":1 if context.get("asset_id") else 0, "observations":len(obs)},"observations":obs}

def run(root=".", context=None) -> Dict[str, Any]:
    findings = scan_dir(root)
    ctx = context or {}
    return to_bom(findings, root, ctx)
