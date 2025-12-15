# 🛡️ HeaderScope

Herramienta de análisis de seguridad enfocada en la evaluación de **cabeceras HTTP**, **cookies** y **políticas modernas Cross-Origin**, diseñada para identificar configuraciones inseguras, clasificar riesgos y generar reportes técnicos reutilizables.

HeaderScope está orientada a **auditorías de seguridad**, **pentesting web**, **hardening de servidores** y validaciones rápidas de seguridad HTTP en entornos productivos o de pruebas.

---

## 🧠 ¿Qué hace esta herramienta?

`HeaderScope` analiza de forma pasiva un objetivo web y evalúa:

- Cabeceras HTTP de seguridad clásicas
- Cabeceras modernas de aislamiento Cross-Origin (COOP, COEP, CORP)
- Cookies HTTP (Secure, HttpOnly, SameSite)
- Severidad de cada hallazgo (High / Medium / Low / Info)
- Puntaje global de seguridad (Score 0–100)

Además, genera **reportes técnicos en JSON y HTML**, listos para ser reutilizados en informes, auditorías o entregables a clientes.

---

## 🎯 Casos de uso

- Auditorías de seguridad web
- Pentesting / AppSec
- Hardening de servidores web
- Validación de configuraciones HTTP
- Reportes técnicos para clientes
- Revisión rápida de riesgos en aplicaciones web

---

## 🚀 Requisitos

- Python 3.9+
- Librerías:
  - `requests`
  - `rich`
  - `chart.js` (incluido vía CDN para reportes HTML)

---

## 📥 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/AndreewNR/HeaderScope.git
cd HeaderScope
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

## ⚙️ Uso

Sintaxis General:

```bash
python -m HeaderScope.cli <URL> [--json] [--html]
```

Ejemplo completo:

```bash
python -m HeaderScope.cli http://example.com --json --html
```

### 🧪 Ejemplo de uso

  [+] Analizando: https://example.com
  
  [+] Cabeceras clásicas evaluadas
  
  [+] Cabeceras modernas evaluadas
  
  [+] Cookies HTTP analizadas
  
  [+] Score de seguridad: 72/100

  [✔] Resultado exportado en JSON: reports/headerscope_example.com.json
  
  [✔] Reporte HTML generado: reports/headerscope_example.com.html

### 🆘 Ayuda integrada
HeaderScope incluye ayuda integrada mediante --help:

```bash
python -m HeaderScope.cli http://example.com --help
```

Salida Esperada:

```bash
usage: HeaderScope [-h] [--json] [--html] url

HeaderScope - Análisis de Seguridad de Cabeceras HTTP

positional arguments:
  url           URL objetivo (ejemplo: https://example.com)

optional arguments:
  -h, --help    Muestra este mensaje de ayuda
  --json        Exportar el resultado en formato JSON
  --html        Exportar el resultado en formato HTML (requiere --json)
```
