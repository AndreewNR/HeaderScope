import json
import html
from pathlib import Path
from string import Template

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = BASE_DIR / "templates" / "report.html"
REPORTS_DIR = BASE_DIR / "reports"

MODERN_HEADERS = {
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
}

def _safe(v):
    return html.escape(str(v)) if v is not None else "—"

def _human_status(status: str) -> str:
    if status == "present":
        return "Presente"
    if status == "missing":
        return "Ausente"
    return status or "—"

def _build_table(items, is_cookie=False):
    rows = ""

    for it in items:
        name = _safe(it.get("name", "—"))
        status = it.get("status", "—")
        severity = _safe(it.get("severity", "—"))
        issue = _safe(it.get("issue", "—"))
        recommendation = _safe(it.get("recommendation", "—"))
        impact = _safe(it.get("impact", ""))

        status_color = "ok" if status == "present" else "danger"
        status_txt = _safe(_human_status(status))

        detail_html = f"<div class='muted'>{issue}</div>"
        if impact and impact != "—":
            detail_html += f"<div class='muted'><strong>Impacto:</strong> {impact}</div>"

        rows += f"""
        <tr>
            <td>{name}</td>
            <td class="{status_color}">{status_txt}</td>
            <td>{severity}</td>
            <td>{detail_html}</td>
            <td><div class="muted">{recommendation}</div></td>
        </tr>
        """
    if not rows:
        rows = """
        <tr>
            <td colspan="5" style="text-align:center;color:#888">
                No se detectaron datos
            </td>
        </tr>
        """

    return f"""
    <table>
      <thead>
        <tr>
          <th>{'Cookie' if is_cookie else 'Cabecera'}</th>
          <th>Estado</th>
          <th>Severidad</th>
          <th>Detalle</th>
          <th>Recomendación</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
    """

def export_to_html(json_file: str) -> str:
    REPORTS_DIR.mkdir(exist_ok=True)

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    target = data.get("target", {})
    score_obj = data.get("score", {})
    score_total = score_obj.get("total", 0)

    if score_total < 40:
        risk_level = "alto"
        risk_label = "RIESGO ALTO"
    elif score_total < 70:
        risk_level = "medio"
        risk_label = "RIESGO MEDIO"
    else:
        risk_level = "bajo"
        risk_label = "RIESGO BAJO"

    classic = data.get("headers", {}).get("classic", [])
    modern = data.get("headers", {}).get("modern", [])
    cookies_items = data.get("cookies", {}).get("items", [])

    headers_total = len(classic)
    modern_total = len(modern)
    cookies_total = len(cookies_items)

    severity_count = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for item in classic + modern + cookies_items:
        sev = item.get("severity")
        if sev in severity_count:
            severity_count[sev] += 1

    charts_data = {
        "headers": {
            "classic": headers_total,
            "modern": modern_total,
            "cookies": cookies_total,
        },
        "severity": severity_count,
        "score": score_total,
    }

    charts_script = f"""
    <script>
      window.HEADERSCOPE_DATA = {json.dumps(charts_data)};
    </script>
    """

    table_headers = _build_table(classic)
    table_modern = _build_table(modern)
    table_cookies = _build_table(cookies_items, is_cookie=True)

    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = Template(f.read())

    html_content = template.safe_substitute(
        url=_safe(target.get("url")),
        domain=_safe(target.get("domain")),
        ip=_safe(target.get("ip")),
        server=_safe(target.get("server")),
        score=score_total,
        headers_total=headers_total,
        modern_total=modern_total,
        cookies_total=cookies_total,
        risk_level=risk_level,
        risk_label=risk_label,
        table_headers=table_headers,
        table_modern=table_modern,
        table_cookies=table_cookies,
        charts_data=charts_script,
    )

    output_file = REPORTS_DIR / f"headerscope_{target.get('domain', 'report')}.html"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    return str(output_file)
