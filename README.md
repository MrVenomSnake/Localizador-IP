# Localizador IP

Analizador de IP orientado a investigación de accesos a cuentas de correo.

Características:
- Consulta geolocalización (ip-api.com)
- DNS reverso
- Verificación básica de reputación (mensajes) y recomendaciones de seguridad
- Validación robusta de IPv4/IPv6
- Modo verbose para salida de depuración

Instalación:
```powershell
python -m pip install -r requirements.txt
```

Uso:
```powershell
# Analizar IP como argumento
python .\ip_analyzer.py 8.8.8.8

# Ejecutar en modo interactivo
python .\ip_analyzer.py

# Habilitar modo verbose (más info / logs)
python .\ip_analyzer.py 8.8.8.8 --verbose

# Salida JSON y guardar a archivo
# Output JSON to stdout
python .\ip_analyzer.py 8.8.8.8 --json

# Guardar resultado JSON a archivo
python .\ip_analyzer.py 8.8.8.8 --json --output-file resultado.json
```

Configuración del entorno (recomendada):
```powershell
# Crear y activar un entorno virtual (Windows PowerShell)
python -m venv .venv; .\.venv\Scripts\Activate.ps1
# Instalar dependencias y dev-deps
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Ejecutar tests:
```powershell
python -m pytest -q
```
Conveniencia — script PowerShell para preparar entorno y ejecutar tests:

```powershell
# Desde la raíz del repositorio (Windows PowerShell):
.\scripts\setup_and_test.ps1

# Forzar recreación del venv y volver a instalar todo:
.\scripts\setup_and_test.ps1 -Recreate
```

Notas:
- Respeta siempre la legalidad y privacidad cuando investigues accesos o IPs.
- Para funciones avanzadas de reputación (AbuseIPDB, VirusTotal) necesitarás registrarte y usar sus APIs.
 
## AbuseIPDB integration

You can get additional reputation information from AbuseIPDB by creating a free account and generating an API key. The script accepts the key via the CLI flag `--abuse-key` or via the environment variable `ABUSEIPDB_API_KEY`.

Examples:

```powershell
# Export a key for the current session
$env:ABUSEIPDB_API_KEY = 'your_api_key_here'

# Or pass directly on the command line
python .\ip_analyzer.py 8.8.8.8 --json --abuse-key your_api_key_here
```

## Legal / ethics note

This tool only collects public information from IP reputation APIs, geolocation data and reverse DNS. It does NOT attempt to access devices (no port scanning, no login attempts, no web requests to router admin panels). Do not attempt to access routers or devices you do not own or have explicit permission to probe — doing so may be illegal.

## VirusTotal integration

You can also query VirusTotal (v3) for additional intelligence about an IP. Get an API key from VirusTotal and pass it with the CLI flag `--vt-key` or via the environment variable `VIRUSTOTAL_API_KEY`.

Example:

```powershell
# Set environment variable for session
$env:VIRUSTOTAL_API_KEY = 'your_virustotal_key'
python .\ip_analyzer.py 8.8.8.8 --json --output-file vt_out.json
```

VirusTotal returns aggregated analysis results from many engines (malicious/suspicious counts, community verdicts). Use these counts together with AbuseIPDB's confidence score to get a broad view of risk.

## How to investigate a scammer IP (suggested steps)

1. Start with `--json` output and save it to a file for evidence-tracking:

```powershell
python .\ip_analyzer.py 8.8.8.8 --json --output-file evidence.json
```

2. Check AbuseIPDB's `abuseConfidenceScore` — higher values indicate repeated abusive reports (spam, scam, etc.).
3. Check VirusTotal's `last_analysis_stats` — if `malicious` or `suspicious` > 0, treat with caution.
4. Cross-check reverse DNS and ISP/org — a residential ISP + home-sounding hostname suggests a consumer device; datacenter ISP indicates likely an infrastructure host.
5. Aggregate and document: save timestamps, API responses and relevant headers as evidence. Keep a copy of `evidence.json` externally for reporting.
6. Report to providers: if you confirm abuse, use AbuseIPDB to file a report and contact the ISP/hosting provider if possible.

Always follow legal and ethical guidelines when investigating or reporting suspected scammers.

## Web interface (lightweight)

This repo now includes a small Flask web interface to run analyses and view/download results. It stores JSON analysis outputs and text reports in the `data/` directory.

Run the app in development (local machine):

```powershell
# Windows PowerShell - from repo root
.\.venv\Scripts\Activate.ps1
python web_app.py

# By default Flask will listen on http://127.0.0.1:5000
```

Then point your browser to http://127.0.0.1:5000 — you can submit IPs, add case metadata, see the dashboard and download JSON/reports.

SecurityTrails and abuse.ch
--------------------------
SecurityTrails optional integration uses `SEC_TRAILS_API_KEY` environment variable. abuse.ch checks are passive lookups and do not require keys; the web UI will include these feeds in the generated JSON when available.

