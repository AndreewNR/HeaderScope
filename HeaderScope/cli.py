import argparse
from HeaderScope.fetcher import fetch_headers
from HeaderScope.analyzer import analyze_headers
from HeaderScope.scorer import calculate_score
from HeaderScope.utils import print_console_report
from HeaderScope.exporter import export_to_json
from HeaderScope.html_report import export_to_html

def main():
    parser = argparse.ArgumentParser(
        prog="HeaderScope",
        description=(
            "HeaderScope — Herramienta de análisis de seguridad en cabeceras HTTP.\n\n"
            "Analiza cabeceras de seguridad HTTP, cookies y políticas modernas "
            "Cross-Origin para identificar configuraciones inseguras, "
            "asignar un puntaje de riesgo y generar reportes técnicos.\n\n"
            "Ejemplo de uso:\n"
            "  python -m HeaderScope.cli https://example.com \n"
            "  python -m HeaderScope.cli https://example.com --json\n"
            "  python -m HeaderScope.cli https://example.com --json --html\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "url",
        help="URL objetivo a analizar (ejemplo: https://example.com)"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Exporta los resultados del análisis en formato JSON.\n"
            "Incluye cabeceras evaluadas, cookies, severidades y score final."
        )
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help=(
            "Genera un reporte HTML visual a partir del JSON.\n"
            "Este reporte incluye gráficos, tablas y recomendaciones.\n"
            "Requiere usar también el flag --json."
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version="HeaderScope v1.0"
    )

    args = parser.parse_args()

    # 1. Obtener información del objetivo
    headers, target_info = fetch_headers(args.url)

    # 2. Analizar cabeceras HTTP
    findings = analyze_headers(headers)

    # 3. Calcular puntuación
    score = calculate_score(findings)

    # 4. Mostrar resultado en consola
    print_console_report(
        args.url,
        findings,
        score,
        target_info
    )

    json_file = None

    # 5. Exportar JSON
    if args.json:
        json_file = export_to_json(
            args.url,
            target_info,
            findings,
            score
        )
        print(f"\n[✔] Resultado exportado en JSON: {json_file}")

    # 6. Exportar HTML (requiere JSON)
    if args.html:
        if not json_file:
            print("\n[✘] El parámetro --html requiere usar también --json")
            print("    Ejemplo correcto:")
            print("    python -m HeaderScope.cli https://example.com --json --html")
            return

        html_file = export_to_html(json_file)
        print(f"[✔] Reporte HTML generado: {html_file}")


if __name__ == "__main__":
    main()
