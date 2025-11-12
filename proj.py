#!/usr/bin/env python3
"""
safe_audit_ai_full.py

Auditoría pasiva avanzada (AI-aware) + detección de componentes vulnerables + modo agresivo
No destructivo: hace GET/HEAD y seguimientos controlados únicamente.

Instalación:
  pip install requests beautifulsoup4

Ejemplo:
  python3 safe_audit_ai_full.py ejemplo.com --output report.json --aggressive --test-redirect-host=https://example.com
"""
from __future__ import annotations
import argparse, json, re, ssl, socket, time
from urllib.parse import urljoin, urlparse
from datetime import datetime
import requests
from bs4 import BeautifulSoup

# ---------- Config ----------
TIMEOUT = 8
USER_AGENT = "SafeAuditAIFull/4.0"
session = requests.Session()
DEFAULT_DOMAIN = "Tu Dominio"

session.headers.update({"User-Agent": USER_AGENT})
session.verify = True

# Stats & findings
STATS = {"OK": 0, "INFO": 0, "WARN": 0, "ALERTA": 0, "ERR": 0}
FINDINGS = []

def note(level: str, title: str, details=None):
    now = datetime.utcnow().isoformat() + "Z"
    STATS[level] += 1
    entry = {"time": now, "level": level, "title": title, "details": details}
    FINDINGS.append(entry)
    print(f"[{level}] {title}")
    if details:
        if isinstance(details, (dict, list)):
            print("  ->", json.dumps(details, ensure_ascii=False))
        else:
            print("  ->", details)

def section(title: str):
    print("\n" + "="*len(title))
    print(title)
    print("="*len(title))

def safe_get(url: str, **kwargs):
    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except Exception as e:
        note("ERR", f"GET fallo: {url}", str(e))
        return None

def safe_head(url: str, **kwargs):
    try:
        return session.head(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    except Exception as e:
        note("ERR", f"HEAD fallo: {url}", str(e))
        return None

# ---------- Heurísticos de versiones vulnerables (lista local) ----------
# WARNING: esto es una heurística simple. Para certidumbre usar lookup CVE en NVD.
VULN_RULES = {
    "jquery": [
        # (max_version_exclusive, note)
        ("3.5.0", "jQuery < 3.5.0 tiene CVEs críticos relacionados con XSS/CSRF en plugins")
    ],
    "lodash": [
        ("4.17.21", "Lodash < 4.17.21 vulnerable a prototype pollution (varias CVEs)")
    ],
    "bootstrap": [
        ("4.3.1", "Bootstrap <= 4.3 tiene vulnerabilidades en componentes JS/tooltip")
    ],
    "moment": [
        ("2.29.1", "Moment < 2.29.1 tiene issues de locale parsing y dependencias")
    ],
    "react": [
        ("16.14.0", "React < 16.14 puede carecer de fixes importantes; revisar CVEs")
    ]
}

def version_to_tuple(v: str):
    parts = re.findall(r"\d+", v)
    return tuple(int(x) for x in parts) if parts else ()

def is_version_less(v_found: str, v_max: str) -> bool:
    a = version_to_tuple(v_found)
    b = version_to_tuple(v_max)
    if not a or not b:
        return False
    # compare lexicographically
    return a < b

# ---------- Detección de componentes y versiones ----------
CDN_VERSION_PATTERNS = [
    # source, regex to extract lib name and version
    (r"jquery(-|\.)?(\d+\.\d+\.\d+)", "jquery"),
    (r"jquery-(\d+\.\d+\.\d+)", "jquery"),
    (r"jquery@(\d+\.\d+\.\d+)", "jquery"),
    (r"lodash(?:\.min)?(?:-|@)?(\d+\.\d+\.\d+)", "lodash"),
    (r"lodash@(\d+\.\d+\.\d+)", "lodash"),
    (r"bootstrap(?:\.min)?(?:-|@)?(\d+\.\d+\.\d+)", "bootstrap"),
    (r"bootstrap@(\d+\.\d+\.\d+)", "bootstrap"),
    (r"moment(?:\.min)?(?:-|@)?(\d+\.\d+\.\d+)", "moment"),
    (r"react(?:\.min)?(?:-|@)?(\d+\.\d+\.\d+)", "react"),
]

def detect_libs_from_url(url: str) -> list[dict]:
    found = []
    for pat, lib in CDN_VERSION_PATTERNS:
        m = re.search(pat, url, re.I)
        if m:
            ver = m.group(1)
            found.append({"lib": lib, "version": ver, "url": url})
    return found

def analyze_components(base: str):
    section("Detección de componentes (JS/CSS) y versiones desde URLs/CDN")
    r = safe_get(base)
    if not r or not r.text:
        note("WARN", "No se pudo obtener HTML principal para análisis de componentes")
        return
    soup = BeautifulSoup(r.text, "html.parser")
    script_srcs = [urljoin(base, s.get("src")) for s in soup.find_all("script") if s.get("src")]
    css_links = [urljoin(base, l.get("href")) for l in soup.find_all("link", href=True) if l.get("rel") and "stylesheet" in l.get("rel")]
    found_any = []
    # check scripts
    for src in script_srcs + css_links:
        if not src: continue
        libs = detect_libs_from_url(src)
        for libinfo in libs:
            found_any.append(libinfo)
            lib = libinfo["lib"]
            ver = libinfo["version"]
            note("INFO", f"Detected {lib} version {ver}", {"url": src})
            # check against local vuln rules
            rules = VULN_RULES.get(lib.lower())
            if rules:
                for maxv, msg in rules:
                    if is_version_less(ver, maxv):
                        note("ALERTA", f"{lib} {ver} parece vulnerable según heurístico ({maxv})", msg)

    if not found_any:
        # try heuristic by inline scripts content (search for specific globals)
        inline = " ".join([s.get_text(" ", strip=True) or "" for s in soup.find_all("script") if not s.get("src")])
        if "jQuery" in inline or "window.jQuery" in inline:
            note("WARN", "jQuery detectado inline pero no se pudo extraer versión desde CDN URL; revisar manualmente")

# ---------- Checks core (headers, cors, tls, sensitive files) ----------
COMMON_PARAM_NAMES = ["redirect","next","url","return","callback","redirect_uri"]
SENSITIVE_PATHS = ["/robots.txt","/.env","/.git/config","/.htaccess","/config.php","/wp-config.php","/backup.zip","/.DS_Store","/phpinfo.php","/server-status","/notebook.ipynb"]
THIRD_PARTY_WIDGETS = ["hotjar", "intercom", "segment", "mixpanel", "gtag", "analytics.js", "sentry", "fullstory"]

def check_redirect_params(base: str, aggressive: bool=False, test_redirect_host: str=None):
    section("Open Redirect (parámetros comunes)")
    for p in COMMON_PARAM_NAMES:
        test_target = f"{base}/?{p}={test_redirect_host or 'https://example.com'}"
        r = safe_head(test_target)
        if not r:
            continue
        loc = r.headers.get("Location","")
        if 300 <= r.status_code < 400 and ("example.com" in loc or (test_redirect_host and test_redirect_host in loc)):
            note("WARN", f"Parámetro {p} aparece en Location header ({r.status_code})", {"tested": test_target, "location": loc})
            if aggressive:
                # seguir redirecciones controladas (solo 10 max), ver destino final
                try:
                    rr = session.get(test_target, timeout=TIMEOUT, allow_redirects=True)
                    final = rr.url
                    note("INFO", f"Aggressive: seguimiento de redirecciones final -> {final}")
                    # si el final no es same-origin y apunta a test_redirect_host => real open redirect
                    if test_redirect_host and test_redirect_host in final:
                        note("ALERTA", f"Open redirect confirmado (seguimiento) para parámetro {p}", {"final": final})
                except Exception as e:
                    note("ERR", "Error seguimiento redirecciones (aggressive)", str(e))
        else:
            note("OK", f"?{p} no parece redirigir externamente ({r.status_code})")

def check_sensitive_paths(base: str):
    section("Archivos sensibles / Notebooks expuestos")
    for p in SENSITIVE_PATHS:
        u = urljoin(base, p)
        r = safe_head(u)
        if not r: continue
        if r.status_code == 200:
            note("ALERTA", f"Recurso sensible accesible: {p}", {"status": r.status_code, "url": u})
        elif r.status_code in (301,302,307):
            note("INFO", f"{p} redirige ({r.status_code})", {"location": r.headers.get("Location")})
        else:
            note("OK", f"{p}: {r.status_code}")

def check_security_headers(base: str):
    section("Cabeceras de seguridad")
    r = safe_head(base)
    if not r:
        note("ERR", "No se pudo obtener headers para la raíz")
        return
    headers = r.headers
    must = {
        "Strict-Transport-Security":"HSTS",
        "Content-Security-Policy":"CSP",
        "X-Frame-Options":"X-Frame-Options",
        "X-Content-Type-Options":"X-Content-Type-Options",
        "Referrer-Policy":"Referrer-Policy",
        "Permissions-Policy":"Permissions-Policy"
    }
    for h, desc in must.items():
        if h not in headers:
            note("WARN", f"Falta {h} ({desc})")
        else:
            note("OK", f"{h}: {headers[h]}")
    sc = headers.get("Set-Cookie")
    if sc:
        flags = {"Secure": "Secure" in sc, "HttpOnly": "HttpOnly" in sc, "SameSite": "SameSite" in sc}
        if not (flags["Secure"] and flags["HttpOnly"]):
            note("WARN", "Set-Cookie presente sin flags Secure/HttpOnly recomendados", sc)
        else:
            note("OK", "Set-Cookie con flags recomendados detectado")

def check_cors(base: str):
    section("CORS")
    r = safe_head(base, headers={"Origin":"https://evil.example"})
    if not r: return
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    if acao == "*":
        note("ALERTA", "CORS permisivo (ACAO='*')")
    elif acao:
        note("WARN", f"ACAO presente: {acao}")
    else:
        note("OK", "Sin Access-Control-Allow-Origin detectado")
    if acac and acac.lower()=="true":
        note("WARN", "Allow-Credentials=true detectado (revisar orígenes)")

def check_tls(domain: str):
    section("TLS / Certificado")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        na = cert.get("notAfter")
        note("INFO", "Certificado info", {"notAfter": na})
        if na:
            try:
                exp_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                days = (exp_dt - datetime.utcnow()).days
                if days < 30:
                    note("WARN", f"Cert expira pronto ({days} días)")
                else:
                    note("OK", f"Cert expira en {days} días")
            except Exception as e:
                note("WARN", "Formato fecha cert no parseable", na)
    except Exception as e:
        note("ERR", "No se pudo comprobar TLS", str(e))

# ---------- Frontend deep (scripts, secrets, ML references) ----------
API_KEY_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS
    re.compile(r"AIza[0-9A-Za-z-_]{35}"),  # Google API key
    re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),  # stripe-ish
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),  # slack tokens
    re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),  # private key
    re.compile(r"(?i)api[_-]?(key|token)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{8,})")
]

def analyze_frontend_resources(base: str, max_script_fetch=20):
    section("Análisis frontend profundo (scripts, SRI, eval, secrets, ML refs)")
    r = safe_get(base)
    if not r or not r.text:
        note("WARN", "No HTML para análisis frontend")
        return
    soup = BeautifulSoup(r.text, "html.parser")
    # Inline script check
    for s in soup.find_all("script"):
        src = s.get("src")
        if not src:
            code = s.string or ""
            if "eval(" in code or "new Function" in code:
                note("WARN", "Uso de eval()/new Function() en inline script (riesgo XSS)", code[:240])

    # External scripts
    script_srcs = [urljoin(base, s.get("src")) for s in soup.find_all("script") if s.get("src")]
    checked = 0
    for src in script_srcs:
        if checked >= max_script_fetch:
            break
        checked += 1
        rjs = safe_get(src)
        if not rjs or not rjs.text:
            continue
        txt = rjs.text
        # search secrets
        for pat in API_KEY_PATTERNS:
            m = pat.search(txt)
            if m:
                snippet = m.group(0)
                note("ALERTA", "Posible API key / secreto en JS público", {"script": src, "match": snippet[:120]+"..."})
        # search for ML endpoints patterns
        if re.search(r"/(predict|model|inference|embeddings|completion|v1/models)[\b/]", txt, re.I):
            note("WARN", "Patrón de endpoint ML detectado en JS", src)
        # search for eval usage
        if "eval(" in txt or "new Function" in txt:
            note("WARN", "eval() o new Function() en archivo JS", src)
    # check SRI for external scripts (in HTML)
    for s in soup.find_all("script"):
        src = s.get("src")
        if src and src.startswith("http"):
            if not s.get("integrity"):
                note("WARN", "Script externo sin SRI (integrity)", src)
    # detect third-party telemetry widgets
    html_lower = (r.text or "").lower()
    for widget in THIRD_PARTY_WIDGETS:
        if widget in html_lower:
            note("INFO", "Tercero/telemetría detectada en HTML", widget)
    # detect AI provider mentions
    ai_kw = ["openai", "gpt", "huggingface", "replicate", "cohere"]
    for kw in ai_kw:
        if kw in html_lower:
            note("INFO", f"Mención a proveedor AI detectada: {kw}")

# ---------- API/ML endpoints passive checks ----------
def check_api_and_ml(base: str):
    section("Búsqueda pasiva de endpoints API / ML")
    common = ["/api","/api/docs","/swagger.json","/swagger","/openapi.json","/predict","/model","/inference","/v1/predict","/v1/models"]
    for p in common:
        u = urljoin(base, p)
        r = safe_head(u)
        if not r:
            continue
        if r.status_code in (200,401,403):
            note("ALERTA", f"Endpoint sensible detectado: {p}", {"status": r.status_code})
        else:
            note("INFO", f"{p}: {r.status_code}")

# ---------- Additional infra checks ----------
def check_openapi_swagger(base: str):
    section("Buscar OpenAPI/Swagger")
    candidates = ["/openapi.json","/swagger.json","/swagger.yaml","/api/docs","/docs"]
    for p in candidates:
        r = safe_head(urljoin(base, p))
        if r and r.status_code == 200:
            note("ALERTA", "OpenAPI/Swagger pública", p)
        elif r:
            note("INFO", f"{p}: {r.status_code}")

def check_notebooks_and_buckets(base: str):
    section("Buscar notebooks (.ipynb) y enlaces a buckets")
    r = safe_get(base)
    if not r or not r.text:
        return
    if ".ipynb" in r.text:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].endswith(".ipynb"):
                note("ALERTA", "Notebook Jupyter enlazado públicamente", a["href"])
    # buckets
    for m in re.finditer(r"(https?://[0-9a-zA-Z\.\-]+\.s3\.amazonaws\.com/[^\s'\"<>]+)", r.text):
        note("WARN", "Enlace a S3 detectado (revisar permisos)", m.group(1))
    for m in re.finditer(r"(https?://storage.googleapis.com/[^\s'\"<>]+)", r.text):
        note("WARN", "Enlace a GCS detectado (revisar permisos)", m.group(1))

# ---------- Reporting ----------
def export_report(domain: str, outpath: str):
    payload = {
        "domain": domain,
        "scanned_at": datetime.utcnow().isoformat()+"Z",
        "stats": STATS,
        "findings": FINDINGS
    }
    if outpath.endswith(".json"):
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        note("INFO", f"Reporte JSON guardado en {outpath}")
    elif outpath.endswith(".html"):
        html = "<html><head><meta charset='utf-8'><title>SafeAuditAIFull Report</title></head><body>"
        html += f"<h1>SafeAuditAIFull - {domain}</h1>"
        html += f"<p>Scan time: {payload['scanned_at']}</p>"
        html += "<h2>Stats</h2><ul>"
        for k,v in STATS.items():
            html += f"<li>{k}: {v}</li>"
        html += "</ul><h2>Findings</h2><ol>"
        for fnd in FINDINGS:
            html += f"<li><b>{fnd['level']}</b> {fnd['title']}<pre>{json.dumps(fnd.get('details',''), ensure_ascii=False, indent=2)}</pre></li>"
        html += "</ol></body></html>"
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)
        note("INFO", f"Reporte HTML guardado en {outpath}")
    else:
        note("WARN", "Formato salida desconocido. Use .json o .html")

# ---------- Runner ----------
def run_all(domain: str, base: str, aggressive: bool=False, test_redirect_host: str|None=None, out: str|None=None):
    t0 = time.time()
    note("INFO", "Inicio de auditoría", {"domain": domain, "aggressive": aggressive})
    check_security_headers(base)
    check_cors(base)
    check_tls(domain)
    analyze_components(base)
    analyze_frontend_resources(base)
    scan_js_for_secrets = analyze_frontend_resources  # alias - frontend analysis includes secret scanning
    check_sensitive_paths(base)
    check_redirect_params(base, aggressive=aggressive, test_redirect_host=test_redirect_host)
    check_api_and_ml(base)
    check_openapi_swagger(base)
    check_notebooks_and_buckets(base)
    # final summary
    section("RESUMEN FINAL")
    total = sum(STATS.values())
    for k,v in STATS.items():
        print(f"  {k}: {v}")
    if STATS["ALERTA"] > 0:
        note("ALERTA", f"Hallazgos críticos: {STATS['ALERTA']}. Priorizar revisión.")
    elif STATS["WARN"] > 0:
        note("WARN", f"Advertencias: {STATS['WARN']}. Plan de mejora recomendado.")
    else:
        note("OK", "Sin hallazgos críticos detectados (pasivo).")
    if out:
        export_report(domain, out)
    t1 = time.time()
    note("INFO", "Tiempo total", f"{t1-t0:.1f}s")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="SafeAudit AI Full (pasivo, no destructivo)")
    parser.add_argument("domain", nargs="?", default=DEFAULT_DOMAIN, help="Dominio a auditar (sin https://)")
    parser.add_argument("--timeout", type=int, default=TIMEOUT)
    parser.add_argument("--output", "-o", help="Guardar reporte (report.json / report.html)")
    parser.add_argument("--aggressive", action="store_true", help="Modo agresivo ...")
    parser.add_argument("--test-redirect-host", default="https://example.com", help="Host de prueba ...")
    args = parser.parse_args()

    # usar variable local
    timeout = args.timeout

    # si realmente necesitas que TIMEOUT global cambie, hazlo explícito aquí:
    # (opcional)
    globals()['TIMEOUT'] = timeout

    domain = (args.domain or DEFAULT_DOMAIN).replace("https://","").replace("http://","").strip().rstrip("/")
    base = f"https://{domain}"

    # pasar timeout si las funciones lo aceptan, o usar la global ya reasignada
    run_all(domain, base, aggressive=args.aggressive, test_redirect_host=args.test_redirect_host, out=args.output)


if __name__ == "__main__":
    main()

