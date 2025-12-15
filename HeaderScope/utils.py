from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

ASCII_BANNER = r"""
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗  ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗ ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝ ███████╗██║     ██║   ██║██████╔╝█████╗  
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗ ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║ ███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝

HeaderScope — Análisis de Seguridad de Cabeceras HTTP
"""

MODERN_HEADERS = {
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
}


def print_console_report(url, findings, score, target_info=None):

    console.print(ASCII_BANNER, style="bold cyan")

    console.print(
        Panel(
            "🔍 [bold]¿Qué hace HeaderScope?[/bold]\n\n"
            "• Analiza cabeceras HTTP clásicas y modernas\n"
            "• Evalúa aislamiento Cross-Origin (COOP, CORP, COEP)\n"
            "• Detecta configuraciones inseguras en cookies HTTP\n"
            "• Calcula una puntuación de seguridad (0–100)\n\n"
            "📌 Ideal para auditorías rápidas, pentesting web y hardening.",
            title="Información de la Herramienta",
            border_style="cyan",
        )
    )

    if target_info:
        console.print(
            Panel(
                f"[bold]URL analizada:[/bold] {url}\n"
                f"[bold]Dominio:[/bold] {target_info.get('domain')}\n"
                f"[bold]IP resuelta:[/bold] {target_info.get('ip')}\n"
                f"[bold]Servidor:[/bold] {target_info.get('server')}",
                title="Objetivo Analizado",
                border_style="blue",
            )
        )

    console.print(f"[bold]Puntuación de seguridad:[/bold] {score}/100\n")

    console.print("[bold cyan]Cabeceras de Seguridad[/bold cyan]")

    headers_table = Table(show_header=True, header_style="bold", expand=True)
    headers_table.add_column("Cabecera", style="cyan")
    headers_table.add_column("Estado")
    headers_table.add_column("Severidad")
    headers_table.add_column("Detalle")

    has_headers = False

    for f in findings:
        if f.get("type") != "header":
            continue
        if f["header"] in MODERN_HEADERS:
            continue

        has_headers = True
        status = "✓ Presente" if f["status"] == "present" else "✗ Ausente"
        status_color = "green" if f["status"] == "present" else "red"

        headers_table.add_row(
            f["header"],
            f"[{status_color}]{status}[/{status_color}]",
            f["severity"],
            f.get("issue", "—"),
        )

    console.print(headers_table if has_headers else "[yellow]No se detectaron cabeceras de seguridad.[/yellow]")

    console.print("\n[bold cyan]Cabeceras Modernas (Aislamiento Cross-Origin)[/bold cyan]")

    modern_table = Table(show_header=True, header_style="bold", expand=True)
    modern_table.add_column("Cabecera", style="cyan")
    modern_table.add_column("Estado")
    modern_table.add_column("Severidad")
    modern_table.add_column("Detalle")

    has_modern = False

    for f in findings:
        if f.get("type") != "header":
            continue
        if f["header"] not in MODERN_HEADERS:
            continue

        has_modern = True
        status = "✓ Presente" if f["status"] == "present" else "✗ Ausente"
        status_color = "green" if f["status"] == "present" else "red"

        modern_table.add_row(
            f["header"],
            f"[{status_color}]{status}[/{status_color}]",
            f["severity"],
            f.get("issue", "—"),
        )

    console.print(modern_table if has_modern else "[yellow]No se detectaron cabeceras modernas.[/yellow]")

    console.print("\n[bold cyan]Cookies HTTP[/bold cyan]")

    cookies_table = Table(show_header=True, header_style="bold", expand=True)
    cookies_table.add_column("Cookie", style="cyan")
    cookies_table.add_column("Estado")
    cookies_table.add_column("Severidad")
    cookies_table.add_column("Detalle")

    has_cookies = False

    for f in findings:
        if f.get("type") != "cookie":
            continue

        has_cookies = True
        status = "✓ Presente" if f["status"] == "present" else "✗ Ausente"
        status_color = "green" if f["status"] == "present" else "red"

        cookies_table.add_row(
            f["header"],
            f"[{status_color}]{status}[/{status_color}]",
            f["severity"],
            f.get("issue", "—"),
        )

    console.print(cookies_table if has_cookies else "[yellow]No se detectaron cookies HTTP.[/yellow]")