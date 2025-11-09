# make_report.py — Report generator aligned with the paper's Table 1
# ------------------------------------------------------------------------------------
# Keeps your existing pipeline intact:
# - imports and calls functions from main.py (get_links, check_reflected_xss, check_stored_xss,
#   find_vuln, identify_vuln_places) exactly as-is
# - captures their stdout
# - parses the printed text into structured findings
# - renders a report like in the paper (Table 1 + "Discovered vulnerabilities" + recommendations)
# ------------------------------------------------------------------------------------

import io
import re
import json
import os
from datetime import datetime
from contextlib import redirect_stdout

import requests
from bs4 import BeautifulSoup

# Template rendering (optional)
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except Exception:
    Environment = None

# Import your existing scanner (unchanged logic)
import main as scanner

OUT_DIR = "reports"

# ----------------------------- helpers -----------------------------

def now_utc_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def get_page_title(url: str) -> str:
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        t = soup.title.string.strip() if soup.title and soup.title.string else None
        return t or "Main"
    except Exception:
        # Fallback: last path segment or 'Main'
        try:
            from urllib.parse import urlparse
            path = urlparse(url).path.rstrip("/")
            if not path or path == "/":
                return "Main"
            leaf = path.split("/")[-1]
            return leaf or "Main"
        except Exception:
            return "Main"

def short_recommendations(kind: str):
    """
    Map finding-kind -> brief recommendation text (as in the paper: suggest actions).
    """
    if kind == "reflected-script" or kind == "reflected-img":
        return "Apply strict server-side validation and context-aware output encoding (HTML/Attr/URL/JS)."
    if kind == "reflected-encoded":
        return "Harden filters against encoded payloads; normalize/validate inputs before rendering."
    if kind == "stored":
        return "Sanitize & encode stored content before display; use allow-lists; review persistence flows."
    if kind == "dom":
        return "Avoid dangerous sinks (innerHTML/document.write/attr set) or sanitize with safe DOM APIs."
    return "Review input validation and output encoding per OWASP guidance."

# ----------------------------- parsers -----------------------------

def parse_reflected_output(text_block):
    """
    Parses stdout from check_reflected_xss() as produced by your main.py.
    Returns: list[{
      page, reflections: [{param, payload, alerted:bool, encoding:str}], no_reflect:[param]
    }]
    """
    findings = []
    lines = [ln.strip() for ln in text_block.splitlines() if ln.strip()]
    i = 0
    while i < len(lines):
        ln = lines[i]

        # Header 'checked reflected XSS in {url}:'
        m_hdr = re.match(r'checked reflected XSS in (.+):', ln)
        if m_hdr:
            i += 1
            continue

        # Block starting with 'Checked {url} for reflected XSS.'
        m2 = re.match(r'Checked (.+) for reflected XSS\.', ln)
        if m2:
            url_checked = m2.group(1).strip()
            entry = {"page": url_checked, "reflections": []}
            j = i + 1
            while j < len(lines) and not lines[j].startswith("Checked "):
                line = lines[j]

                # Entered 'payload' in param.
                m_enter = re.search(r"Entered '(.+)' in ([\w\-]+)\.", line)
                if m_enter:
                    payload = m_enter.group(1)
                    param = m_enter.group(2)
                    entry["reflections"].append({
                        "param": param,
                        "payload": payload,
                        "alerted": False,
                        "encoding": "none"
                    })

                # Used single/double encoding + method
                if "Used single encoding" in line or "Used double encoding" in line:
                    m_method = re.search(r"method:\s*([^\s]+)", line)
                    if entry["reflections"] and m_method:
                        entry["reflections"][-1]["encoding"] = m_method.group(1)

                # Alert marker
                if "Got alert - url exposed to reflected XSS" in line:
                    if entry["reflections"]:
                        entry["reflections"][-1]["alerted"] = True

                # Non-reflecting parameter
                if "does not affect the web code" in line:
                    mparam = re.search(r"The (.+) parameter does not affect the web code", line)
                    if mparam:
                        entry.setdefault("no_reflect", []).append(mparam.group(1))

                j += 1

            findings.append(entry)
            i = j
            continue

        i += 1

    return findings

def parse_stored_output(text_block):
    """
    Parses stdout from check_stored_xss() / check_stored_inputs() as produced by your main.py.
    Returns: list of blocks, each:
      {
        final_url, original_url, values: {field: value, ...},
        fields: [ {field, value, alerted:bool, encoding:str|None, double_encoded:bool} ]
      }
    """
    results = []
    lines = [ln.strip() for ln in text_block.splitlines() if ln.strip()]
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"The url we got:\s*(.+), the url we entered:\s*(.+), the values:\s*(\{.+\})", ln)
        if m:
            final_url = m.group(1).strip().rstrip(',')
            orig_url = m.group(2).strip().rstrip(',')
            try:
                all_values = json.loads(m.group(3).replace("'", '"'))
            except Exception:
                try:
                    all_values = eval(m.group(3))
                except Exception:
                    all_values = {}

            entry = {
                "final_url": final_url,
                "original_url": orig_url,
                "values": all_values,
                "fields": []
            }

            j = i + 1
            while j < len(lines) and not lines[j].startswith("The url we got:"):
                line = lines[j]

                # found {value} in {url}. we entered it in {key} tag.
                m_found = re.match(r"found (.+) in (.+)\. we entered it in (.+) tag\.", line)
                if m_found:
                    val = m_found.group(1).strip()
                    page = m_found.group(2).strip()
                    field = m_found.group(3).strip()
                    fentry = {
                        "field": field,
                        "value": val,
                        "reflected": True,
                        "alerted": False,
                        "encoding": None,
                        "double_encoded": False
                    }

                    # consume follow-up lines for this field
                    k = j + 1
                    while k < len(lines) and not lines[k].startswith("found ") and not lines[k].startswith("The url we got:"):
                        l2 = lines[k]

                        if "Got alert in" in l2:
                            if ("<script>alert(1)</script>" in l2) or ("Entered '<script>alert(1)</script>'" in l2):
                                fentry["alerted"] = True
                                fentry["value"] = "<script>alert(1)</script>"
                            if "onerror" in l2:
                                fentry["alerted"] = True
                                fentry["value"] = "<img src=1 onerror=alert(1)>"

                        if "Used single encoding" in l2 or "Used double encoding" in l2:
                            if "double" in l2.lower():
                                fentry["double_encoded"] = True
                            mm = re.search(r"method:\s*([^\s]+)", l2)
                            if mm:
                                fentry["encoding"] = mm.group(1)

                        k += 1

                    entry["fields"].append(fentry)
                    j = k
                    continue

                j += 1

            results.append(entry)
            i = j
            continue

        i += 1

    return results

# ------------------------- capture + build model -------------------------

def capture_stdout(func, *args, **kwargs) -> str:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            func(*args, **kwargs)
    except Exception as e:
        return buf.getvalue() + f"\n[EXCEPTION] {e}\n"
    return buf.getvalue()

def build_rows_like_table1(seed_url: str, pages, parsed_reflected_per_page, parsed_stored_per_page):
    """
    Build rows that look like the paper's Table 1:
      No | Registration Date | Title | URL | XSS | Verify
    A row is created for each concrete finding (reflected/stored) that produced an alert or clear reflection.
    """
    rows = []
    discovered_notes = []  # short textual notes for "Discovered vulnerabilities" section

    idx = 1
    for page in pages:
        # Reflected findings for this page
        for rblk in parsed_reflected_per_page.get(page, []):
            for refl in rblk.get("reflections", []):
                alerted = bool(refl.get("alerted"))
                if not alerted:
                    # keep only verified findings (alerted True)
                    continue

                title = get_page_title(page)
                rows.append({
                    "No": idx,
                    "RegistrationDate": now_utc_iso(),
                    "Title": title,
                    "URL": page,
                    "XSS": "Yes",
                    "Verify": "Yes",
                    "kind": "reflected-script" if "<script" in (refl.get("payload") or "") else "reflected-img",
                    "details": {
                        "param": refl.get("param"),
                        "payload": refl.get("payload"),
                        "encoding": refl.get("encoding", "none")
                    }
                })
                # Note + recommendation
                if "<img" in (refl.get("payload") or ""):
                    discovered_notes.append("Reflected XSS via <img onerror> (client alert observed).")
                else:
                    if refl.get("encoding", "none") != "none":
                        discovered_notes.append(f"Reflected XSS with encoded payload (method={refl.get('encoding')}).")
                    else:
                        discovered_notes.append("Reflected XSS via <script> (client alert observed).")
                idx += 1

        # Stored findings for this page
        for sblk in parsed_stored_per_page.get(page, []):
            for f in sblk.get("fields", []):
                if not f.get("alerted"):
                    continue
                title = get_page_title(page)
                rows.append({
                    "No": idx,
                    "RegistrationDate": now_utc_iso(),
                    "Title": title,
                    "URL": page,
                    "XSS": "Yes",
                    "Verify": "Yes",
                    "kind": "stored",
                    "details": {
                        "field": f.get("field"),
                        "value": f.get("value"),
                        "encoding": f.get("encoding"),
                        "double": f.get("double_encoded", False)
                    }
                })
                if f.get("double_encoded"):
                    discovered_notes.append("Stored XSS triggered after double-encoded payload normalization.")
                else:
                    discovered_notes.append("Stored XSS in persisted field (client alert observed).")
                idx += 1

    return rows, discovered_notes

def recommendations_from_rows(rows):
    recs = []
    for r in rows:
        recs.append(short_recommendations(r.get("kind")))
    # de-duplicate while preserving order
    out = []
    seen = set()
    for x in recs:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

# ------------------------- main reporting flow -------------------------

def make_scan_report(seed_url: str):
    os.makedirs(OUT_DIR, exist_ok=True)

    # 1) Discover links using existing logic
    print("[*] Gathering links from seed url (using your get_links) ...")
    pages, urls_and_values = scanner.get_links(seed_url)

    # 2) Scan each page, capturing stdout of your existing checks
    parsed_reflected_per_page = {}
    parsed_stored_per_page = {}

    for page in pages:
        print(f"[*] Scanning page: {page}")

        ref_out = capture_stdout(scanner.check_reflected_xss, page)
        ref_parsed = parse_reflected_output(ref_out)
        if ref_parsed:
            parsed_reflected_per_page.setdefault(page, []).extend(ref_parsed)

        st_out = capture_stdout(scanner.check_stored_xss, page)
        st_parsed = parse_stored_output(st_out)
        if st_parsed:
            parsed_stored_per_page.setdefault(page, []).extend(st_parsed)

    # 3) Optional: capture the printed summary table from your identify_vuln_places
    summary_out = capture_stdout(
        scanner.identify_vuln_places,
        scanner.find_vuln(pages),
        urls_and_values
    )
    with open(os.path.join(OUT_DIR, "summary_print.txt"), "w", encoding="utf-8") as f:
        f.write(summary_out)

    # 4) Build rows in the exact "Table 1" style + notes + recommendations
    rows, discovered_notes = build_rows_like_table1(seed_url, pages, parsed_reflected_per_page, parsed_stored_per_page)
    recs = recommendations_from_rows(rows)

    # 5) Persist JSON
    tsz = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_path = os.path.join(OUT_DIR, f"xss_scan_{tsz}.json")
    json_doc = {
        "generated": tsz,
        "seed": seed_url,
        "table1_rows": rows,
        "discovered_vulnerabilities": discovered_notes,
        "recommendations": recs
    }
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(json_doc, jf, ensure_ascii=False, indent=2)
    print(f"[*] JSON report written to: {json_path}")

    # 6) Render HTML like the paper’s layout
    html_path = os.path.join(OUT_DIR, f"xss_scan_{tsz}.html")
    if Environment is not None:
        template_folder = os.path.join(os.path.dirname(__file__), "templates")
        os.makedirs(template_folder, exist_ok=True)
        template_path = os.path.join(template_folder, "xss_report_table1.html.j2")
        if not os.path.exists(template_path):
            with open(template_path, "w", encoding="utf-8") as tf:
                tf.write("""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>XSS Scan Report</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;padding:16px}
    h1,h2,h3{margin:10px 0}
    table{border-collapse:collapse;width:100%;margin:8px 0}
    th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}
    th{background:#f2f2f2}
    code{white-space:pre-wrap}
    .muted{color:#666}
    .section{margin:16px 0}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#eef;border:1px solid #cde;margin-right:6px}
  </style>
</head>
<body>
  <h1>XSS Scan Report</h1>
  <div class="muted">Seed: {{ seed }} &nbsp;|&nbsp; Generated: {{ generated }}</div>

  <h2>Table 1. Sample of a generated report</h2>
  <table>
    <thead>
      <tr>
        <th>No</th>
        <th>Registration Date</th>
        <th>Title</th>
        <th>URL</th>
        <th>XSS</th>
        <th>Verify</th>
      </tr>
    </thead>
    <tbody>
    {% for r in rows %}
      <tr>
        <td>{{ r.No }}</td>
        <td>{{ r.RegistrationDate }}</td>
        <td>{{ r.Title }}</td>
        <td><a href="{{ r.URL }}" target="_blank" rel="noopener">{{ r.URL }}</a></td>
        <td>{{ r.XSS }}</td>
        <td>{{ r.Verify }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section">
    <h3>Discovered vulnerabilities</h3>
    <ol>
      {% for n in notes %}
        <li>{{ n }}</li>
      {% endfor %}
    </ol>
    <div><strong>Total found on page:</strong> {{ rows|length }}</div>
  </div>

  <div class="section">
    <h3>Recommendations</h3>
    <ul>
      {% for rec in recs %}
        <li>{{ rec }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="section">
    <h3>Technical appendix</h3>
    <p class="muted">For each finding, details (kind/param/payload/encoding/double-encoding) are available in the JSON.</p>
  </div>
</body>
</html>""")
        env = Environment(loader=FileSystemLoader(template_folder),
                          autoescape=select_autoescape(['html','xml']))
        tpl = env.get_template("xss_report_table1.html.j2")
        html = tpl.render(
            seed=seed_url,
            generated=tsz,
            rows=rows,
            notes=discovered_notes,
            recs=recs
        )
        with open(html_path, "w", encoding="utf-8") as hf:
            hf.write(html)
        print(f"[*] HTML report written to: {html_path}")
    else:
        # Minimal HTML fallback without Jinja2
        lines = []
        lines.append("<!doctype html><meta charset='utf-8'><title>XSS Scan Report</title>")
        lines.append("<style>body{font-family:Arial;padding:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px}th{background:#f2f2f2}</style>")
        lines.append(f"<h1>XSS Scan Report</h1><div>Seed: {seed_url} | Generated: {tsz}</div>")
        lines.append("<h2>Table 1. Sample of a generated report</h2>")
        lines.append("<table><thead><tr><th>No</th><th>Registration Date</th><th>Title</th><th>URL</th><th>XSS</th><th>Verify</th></tr></thead><tbody>")
        for r in rows:
            lines.append(f"<tr><td>{r['No']}</td><td>{r['RegistrationDate']}</td><td>{r['Title']}</td><td>{r['URL']}</td><td>{r['XSS']}</td><td>{r['Verify']}</td></tr>")
        lines.append("</tbody></table>")
        lines.append("<h3>Discovered vulnerabilities</h3><ol>")
        for n in discovered_notes:
            lines.append(f"<li>{n}</li>")
        lines.append("</ol>")
        lines.append(f"<div><strong>Total found on page:</strong> {len(rows)}</div>")
        lines.append("<h3>Recommendations</h3><ul>")
        for rec in recs:
            lines.append(f"<li>{rec}</li>")
        lines.append("</ul>")
        with open(html_path, "w", encoding="utf-8") as hf:
            hf.write("\n".join(lines))
        print(f"[*] HTML report written to: {html_path}")

    return json_path

# ----------------------------- CLI -----------------------------

if __name__ == "__main__":
    seed = input("Enter seed URL (or press Enter to use default in main.py): ").strip()
    if not seed:
        try:
            seed = scanner.__dict__.get('__main_seed__', None)
        except Exception:
            seed = None
    if not seed:
        try:
            import inspect, re as _re
            src = inspect.getsource(scanner)
            m = _re.search(r"url\s*=\s*['\"]([^'\"]+)['\"]", src)
            if m:
                seed = m.group(1)
        except Exception:
            seed = None
    if not seed:
        seed = input("Couldn't determine default seed. Please paste the seed URL: ").strip()

    print(f"Using seed: {seed}")
    out_json = make_scan_report(seed)
    print("Done. JSON report at:", out_json)
