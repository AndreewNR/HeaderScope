# HeaderScope/analyzer.py

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "impact": "Permite ataques de SSL Stripping y downgrade a HTTP.",
        "recommendation": (
            "Configurar Strict-Transport-Security con "
            "max-age=31536000; includeSubDomains; preload"
        ),
    },
    "Content-Security-Policy": {
        "severity": "High",
        "impact": "Incrementa el riesgo de ataques XSS y de inyección de contenido.",
        "recommendation": (
            "Definir una Content-Security-Policy restrictiva, "
            "evitando 'unsafe-inline' y 'unsafe-eval'."
        ),
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "impact": "Permite ataques de clickjacking si se usa incorrectamente.",
        "recommendation": "Usar X-Frame-Options: DENY o SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "impact": "Permite ataques de MIME sniffing.",
        "recommendation": "Configurar X-Content-Type-Options: nosniff.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "impact": "Puede filtrar URLs internas o sensibles.",
        "recommendation": "Configurar Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "severity": "Medium",
        "impact": (
            "Permite el uso innecesario de APIs del navegador "
            "(cámara, micrófono, geolocalización)."
        ),
        "recommendation": (
            "Restringir APIs del navegador, por ejemplo: "
            "camera=(), microphone=(), geolocation=()."
        ),
    },
}

MODERN_HEADERS = {
    "Cross-Origin-Opener-Policy": {
        "severity": "Medium",
        "impact": (
            "Sin COOP, la aplicación puede ser vulnerable a "
            "XS-Leaks y ataques de aislamiento de contexto."
        ),
        "recommendation": (
            "Configurar Cross-Origin-Opener-Policy: same-origin "
            "para habilitar aislamiento de contexto."
        ),
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "Medium",
        "impact": (
            "Sin COEP, no se garantiza aislamiento completo "
            "entre recursos cross-origin."
        ),
        "recommendation": (
            "Configurar Cross-Origin-Embedder-Policy: require-corp "
            "para recursos sensibles."
        ),
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "Low",
        "impact": (
            "Permite que recursos puedan ser embebidos desde "
            "otros orígenes sin restricciones."
        ),
        "recommendation": (
            "Configurar Cross-Origin-Resource-Policy: same-origin "
            "o same-site según el caso."
        ),
    },
}

def _analyze_csp(value: str):
    issues = []
    severity = "Info"
    v = value.lower()

    if "unsafe-inline" in v:
        issues.append("Uso de 'unsafe-inline' (riesgo de XSS)")
        severity = "Medium"

    if "unsafe-eval" in v:
        issues.append("Uso de 'unsafe-eval' (riesgo de ejecución de código)")
        severity = "High"

    if "frame-ancestors" not in v:
        issues.append("No se define frame-ancestors (riesgo de clickjacking)")
        if severity == "Info":
            severity = "Medium"

    return severity, issues


def _analyze_hsts(value: str):
    issues = []
    severity = "Info"
    v = value.lower()

    if "max-age=31536000" not in v:
        issues.append("max-age menor a 31536000")
        severity = "Medium"

    if "includesubdomains" not in v:
        issues.append("Falta includeSubDomains")
        severity = "Medium"

    if "preload" not in v:
        issues.append("No se incluye preload (recomendado)")
        if severity == "Info":
            severity = "Low"

    return severity, issues


def _analyze_cookies(headers: dict) -> list:
    findings = []

    raw_cookie = headers.get("Set-Cookie")

    if not raw_cookie:
        return [{
            "type": "cookie",
            "header": "Set-Cookie",
            "status": "missing",
            "severity": "Medium",
            "issue": "No se detectaron cookies HTTP",
            "impact": "No es posible evaluar la seguridad de cookies de sesión.",
            "recommendation": (
                "Si la aplicación usa sesiones, configurar cookies con "
                "Secure, HttpOnly y SameSite."
            ),
        }]

    cookies = []
    current = ""

    for part in raw_cookie.split(","):
        if part.lower().strip().startswith("expires="):
            current += "," + part
        elif "=" in part and current:
            cookies.append(current)
            current = part
        else:
            current += "," + part

    if current:
        cookies.append(current)

    for cookie in cookies:
        cookie_lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()

        issues = []
        severity = "Info"

        if "httponly" not in cookie_lower:
            issues.append("Cookie sin flag HttpOnly")
            severity = "High"

        if "secure" not in cookie_lower:
            issues.append("Cookie sin flag Secure")
            severity = "High"

        if "samesite" not in cookie_lower:
            issues.append("Cookie sin atributo SameSite")
            if severity != "High":
                severity = "Medium"

        if "samesite=none" in cookie_lower and "secure" not in cookie_lower:
            issues.append("SameSite=None sin Secure")
            severity = "High"

        findings.append({
            "type": "cookie",
            "header": cookie_name,
            "status": "present",
            "severity": severity,
            "issue": "; ".join(issues) if issues else "Configuración adecuada",
            "impact": (
                "Cookies mal configuradas pueden permitir robo o fijación "
                "de sesión."
            ) if issues else "Sin impacto significativo",
            "recommendation": (
                "Configurar cookies con Secure; HttpOnly; "
                "SameSite=Strict o Lax."
            ) if issues else "No requiere acción",
            "value": cookie.strip(),
        })

    return findings


def analyze_headers(headers: dict) -> list:
    findings = []

    # Cabeceras de seguridad
    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "type": "header",
                "header": header,
                "status": "missing",
                "severity": meta["severity"],
                "issue": "Cabecera no presente",
                "impact": meta["impact"],
                "recommendation": meta["recommendation"],
            })
            continue

        value = headers.get(header)

        if header == "Content-Security-Policy":
            severity, issues = _analyze_csp(value)
        elif header == "Strict-Transport-Security":
            severity, issues = _analyze_hsts(value)
        else:
            severity = "Info"
            issues = []

        findings.append({
            "type": "header",
            "header": header,
            "status": "present",
            "severity": severity,
            "issue": "; ".join(issues) if issues else "Configuración adecuada",
            "impact": meta["impact"] if issues else "Sin impacto significativo",
            "recommendation": meta["recommendation"] if issues else "No requiere acción",
            "value": value,
        })

        # Cabeceras modernas (COOP / COEP / CORP)
    for header, meta in MODERN_HEADERS.items():
        if header not in headers:
            findings.append({
                "type": "header",
                "header": header,
                "status": "missing",
                "severity": meta["severity"],
                "issue": "Cabecera no presente",
                "impact": meta["impact"],
                "recommendation": meta["recommendation"],
            })
            continue

        value = headers.get(header)

        findings.append({
            "type": "header",
            "header": header,
            "status": "present",
            "severity": "Info",
            "issue": "Configuración adecuada",
            "impact": "Sin impacto significativo",
            "recommendation": "No requiere acción",
            "value": value,
        })

    # Cookies HTTP (separadas)
    findings.extend(_analyze_cookies(headers))

    return findings
