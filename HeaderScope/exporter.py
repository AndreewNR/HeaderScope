import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Cabeceras modernas
MODERN_HEADERS = {
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
}

def export_to_json(url, target_info, findings, score):
    """
    Exporta el resultado del análisis HeaderScope a un archivo JSON.
    El archivo se guarda en /reports y se nombra según el dominio.
    """

    parsed = urlparse(url)
    domain = parsed.hostname or "unknown"

    output = {
        "tool": "HeaderScope",
        "version": "1.0",
        "scan_date": datetime.utcnow().isoformat() + "Z",

        "target": {
            "url": url,
            "domain": target_info.get("domain"),
            "ip": target_info.get("ip"),
            "server": target_info.get("server"),
        },

        "score": {
            "total": score,
            "max": 100,
            "rating": _score_rating(score),
        },

        "headers": {
            "classic": [],
            "modern": []
        },

        "cookies": {
            "detected": False,
            "items": []
        }
    }

    for f in findings:

        if f.get("type") == "header":
            header_entry = {
                "name": f.get("header"),
                "status": f.get("status"),
                "severity": f.get("severity"),
                "issue": f.get("issue"),
                "impact": f.get("impact"),
                "recommendation": f.get("recommendation"),
            }

            if f.get("header") in MODERN_HEADERS:
                output["headers"]["modern"].append(header_entry)
            else:
                output["headers"]["classic"].append(header_entry)

        elif f.get("type") == "cookie":
            output["cookies"]["detected"] = True
            output["cookies"]["items"].append({
                "name": f.get("header"),
                "status": f.get("status"),
                "severity": f.get("severity"),
                "issue": f.get("issue"),
                "recommendation": f.get("recommendation"),
            })

    output_path = REPORTS_DIR / f"headerscope_{domain}.json"

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    return str(output_path)


def _score_rating(score: int) -> str:
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"
