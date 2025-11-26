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
