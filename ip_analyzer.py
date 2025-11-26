#!/usr/bin/env python3
"""
Script de Análisis de IP para Investigación de Seguridad
Analiza direcciones IP que han accedido a tu correo electrónico
"""

import json
import sys
import socket
import argparse
import ipaddress
import logging
import os
from datetime import datetime

try:
    import requests
except Exception:
    requests = None


def validate_ip(ip: str) -> bool:
    """Valida si la cadena es una dirección IP válida (IPv4 o IPv6).

    Retorna True si es válida, False en caso contrario.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def gather_ip_info(ip: str) -> dict:
    """Recolecta información de la IP y devuelve un dict con los resultados.

    Esta función hace llamadas a servicios externos y debe ser testeable mediante monkeypatch.
    """
    from datetime import datetime as dt
    info = {'ip': ip, 'analyzed_at': dt.utcnow().isoformat()}

    # ip-api
    try:
        if requests is None:
            info['ip_api'] = {'error': 'requests missing'}
        else:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            info['ip_api'] = r.json() if r.status_code == 200 else {'error': f'status {r.status_code}'}
    except Exception as e:
        info['ip_api'] = {'error': str(e)}

    # reverso DNS
    try:
        hostname = socket.gethostbyaddr(ip)
        info['reverse_dns'] = {'hostname': hostname[0]}
    except Exception as e:
        info['reverse_dns'] = {'error': str(e)}

    # ipinfo
    try:
        if requests is None:
            info['ipinfo'] = {'error': 'requests missing'}
        else:
            r2 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            info['ipinfo'] = r2.json() if r2.status_code == 200 else {'error': f'status {r2.status_code}'}
    except Exception as e:
        info['ipinfo'] = {'error': str(e)}

    return info


def query_abuseipdb(ip: str, api_key: str | None = None, max_age_days: int = 90) -> dict:
    """Query AbuseIPDB for reputation if api_key is provided.

    Returns a dict with API response, or {'error': <msg>} when missing or failing.
    """
    if not api_key:
        return {'error': 'no_api_key'}

    if requests is None:
        return {'error': 'requests_missing'}

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': max_age_days}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {'error': f'status_{r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def query_virustotal(ip: str, api_key: str | None = None) -> dict:
    """Query VirusTotal v3 for IP reputation if api_key provided.

    Returns parsed key metrics or error dict when missing/failing.
    """
    if not api_key:
        return {'error': 'no_api_key'}

    if requests is None:
        return {'error': 'requests_missing'}

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # Pull some common fields if present
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats')
            return {'status': 'ok', 'attributes': attributes, 'last_analysis_stats': last_analysis_stats}
        return {'error': f'status_{r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def parse_router_likelihood(info: dict) -> dict:
    """Heurística simple para indicar si la IP parece un router/gateway o residencial/datacenter.

    No intenta acceder a dispositivos; solo analiza campos devueltos por APIs públicas.
    """
    reasons = []
    isp = None
    hostname = None
    if 'ip_api' in info and isinstance(info['ip_api'], dict):
        isp = info['ip_api'].get('isp') or info['ip_api'].get('org')
    if 'ipinfo' in info and isinstance(info['ipinfo'], dict):
        hostname = info['ipinfo'].get('hostname')
        isp = isp or info['ipinfo'].get('org')
    if 'reverse_dns' in info and isinstance(info['reverse_dns'], dict):
        hostname = hostname or info['reverse_dns'].get('hostname')

    hostname_lower = (hostname or '').lower()
    isp_lower = (isp or '').lower()

    # Common router-ish hostname tokens
    router_tokens = ['router', 'gateway', 'cpe', 'home', 'user', 'dsl', 'brarokaa', 'ppp', 'client']
    for t in router_tokens:
        if t in hostname_lower:
            reasons.append(f"hostname contains '{t}'")
            break

    # Datacenter indicators
    datacenter_tokens = ['amazon', 'amazonaws', 'digitalocean', 'linode', 'hetzner', 'ovh', 'vultr', 'google', 'microsoft']
    for t in datacenter_tokens:
        if t in isp_lower:
            reasons.append(f"isp/org contains datacenter token '{t}'")
            break

    # Simple classification
    if any(tok in isp_lower for tok in datacenter_tokens):
        classification = 'datacenter'
    elif reasons and any('hostname' in r for r in reasons):
        classification = 'residential/router'
    else:
        classification = 'likely_residential_or_isp'

    return {'classification': classification, 'reasons': reasons, 'isp': isp, 'hostname': hostname}

def analizar_ip(ip_address):
    """
    Analiza una dirección IP usando APIs públicas gratuitas
    """
    print(f"\n{'='*60}")
    print(f"ANÁLISIS DE SEGURIDAD PARA IP: {ip_address}")
    print(f"Fecha de análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # 1. Información geográfica y de ISP (ip-api.com)
    print("[+] Obteniendo información geográfica y de ISP...")
    try:
        if requests is None:
            raise RuntimeError("La librería 'requests' no está disponible. Instálala con: pip install requests")

        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                print(f"\n📍 UBICACIÓN GEOGRÁFICA:")
                print(f"   País: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
                print(f"   Región: {data.get('regionName', 'N/A')}")
                print(f"   Ciudad: {data.get('city', 'N/A')}")
                print(f"   Código Postal: {data.get('zip', 'N/A')}")
                print(f"   Coordenadas: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
                print(f"   Zona Horaria: {data.get('timezone', 'N/A')}")
                print(f"\n🌐 INFORMACIÓN DE RED:")
                print(f"   ISP: {data.get('isp', 'N/A')}")
                print(f"   Organización: {data.get('org', 'N/A')}")
                print(f"   AS: {data.get('as', 'N/A')}")
            else:
                print(f"   ⚠️  No se pudo obtener información: {data.get('message', 'Error desconocido')}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # 2. Verificación de reputación (AbuseIPDB requiere API key gratuita)
    print(f"\n[+] Información adicional de reputación...")
    print("   💡 Para verificar reputación completa, registra una cuenta gratuita en:")
    print("      - AbuseIPDB: https://www.abuseipdb.com/")
    print("      - VirusTotal: https://www.virustotal.com/")
    
    # 3. Información DNS reverso
    print(f"\n[+] Intentando DNS reverso...")
    try:
        hostname = socket.gethostbyaddr(ip_address)
        print(f"   Hostname: {hostname[0]}")
    except Exception:
        print(f"   Sin hostname reverso disponible")
    
    # 4. Verificar si es proxy/VPN (usando ipinfo.io básico)
    print(f"\n[+] Verificando tipo de conexión...")
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"   Hostname: {data.get('hostname', 'N/A')}")
            if 'privacy' in data:
                print(f"   🔒 Información de privacidad detectada")
    except Exception as e:
        print(f"   ⚠️  No disponible")
    
    # Recomendaciones de seguridad
    print(f"\n{'='*60}")
    print("🔐 RECOMENDACIONES DE SEGURIDAD:")
    print('='*60)
    print("""
1. Si no reconoces esta IP o ubicación:
   - Cambia inmediatamente tu contraseña
   - Activa la autenticación de dos factores (2FA)
   - Revisa los dispositivos conectados a tu cuenta
   - Cierra todas las sesiones activas

2. Verifica la actividad:
   - Revisa el historial de acceso en tu correo
   - Comprueba si hay emails enviados que no reconoces
   - Verifica cambios en configuración de cuenta

3. Acciones adicionales:
   - Reporta el acceso no autorizado al proveedor de correo
   - Si es necesario, reporta la IP en AbuseIPDB
   - Considera activar alertas de inicio de sesión
    """)
    
    print(f"{'='*60}\n")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     ANALIZADOR DE IP - SEGURIDAD DE CORREO              ║
    ║     Uso legítimo: Investigación de accesos propios     ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(description="Analizador de IP - Seguridad de correo")
    parser.add_argument('ip', nargs='?', help='Dirección IP (v4 o v6) a analizar')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose: muestra logs de depuración')
    parser.add_argument('--log-file', '-l', help='Guardar logs en archivo especificado')
    parser.add_argument('--json', action='store_true', help='Emitir salida en JSON (para uso programático)')
    parser.add_argument('--output-file', '-o', help='Guardar resultado (texto o JSON si --json) en archivo')
    parser.add_argument('--abuse-key', help='AbuseIPDB API key (si no se pone, buscará env ABUSEIPDB_API_KEY)')
    parser.add_argument('--vt-key', help='VirusTotal API key (si no se pone, buscará env VIRUSTOTAL_API_KEY)')
    args = parser.parse_args()

    if args.ip:
        ip = args.ip.strip()
    else:
        ip = input("Ingresa la dirección IP a analizar: ").strip()

    # Configurar logging según flags
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.log_file:
        logging.basicConfig(filename=args.log_file, level=log_level, format='%(asctime)s [%(levelname)s] %(message)s')
    else:
        logging.basicConfig(level=log_level, format='%(asctime)s [%(levelname)s] %(message)s')

    # Validación robusta de IP (IPv4 / IPv6)
    if not validate_ip(ip):
        print("❌ Dirección IP inválida — formato no reconocido")
        return
    
    try:
        logging.debug('Iniciando análisis para %s', ip)

        # si el usuario pidió JSON, recolectamos la información y la guardamos/mostramos
        if args.json:
            from datetime import datetime as dt
            # reusar lógica interna: crear un diccionario con la información
            def gather():
                info = {'ip': ip, 'analyzed_at': dt.utcnow().isoformat()}

                # ip-api
                try:
                    if requests is None:
                        info['ip_api'] = {'error': "requests missing"}
                    else:
                        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                        info['ip_api'] = r.json() if r.status_code == 200 else {'error': f'status {r.status_code}'}
                except Exception as e:
                    info['ip_api'] = {'error': str(e)}

                # reverso DNS
                try:
                    hostname = socket.gethostbyaddr(ip)
                    info['reverse_dns'] = {'hostname': hostname[0]}
                except Exception as e:
                    info['reverse_dns'] = {'error': str(e)}

                # ipinfo
                try:
                    if requests is None:
                        info['ipinfo'] = {'error': "requests missing"}
                    else:
                        r2 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                        info['ipinfo'] = r2.json() if r2.status_code == 200 else {'error': f'status {r2.status_code}'}
                except Exception as e:
                    info['ipinfo'] = {'error': str(e)}

                return info

            result = gather_ip_info(ip)

            # add analysis heuristics
            try:
                result['analysis'] = parse_router_likelihood(result)
            except Exception:
                result['analysis'] = {'error': 'analysis_failure'}

            # AbuseIPDB integration (optional)
            abuse_key = args.abuse_key or os.environ.get('ABUSEIPDB_API_KEY')
            if abuse_key:
                result['abuseipdb'] = query_abuseipdb(ip, abuse_key)

            vt_key = args.vt_key or os.environ.get('VIRUSTOTAL_API_KEY')
            if vt_key:
                result['virustotal'] = query_virustotal(ip, vt_key)

            # simple combined risk summary
            try:
                risk_score = 0
                if 'abuseipdb' in result and isinstance(result['abuseipdb'], dict):
                    data = result['abuseipdb'].get('data') or {}
                    conf = data.get('abuseConfidenceScore')
                    if isinstance(conf, (int, float)):
                        risk_score += int(conf / 10)
                if 'virustotal' in result and isinstance(result['virustotal'], dict):
                    last = result['virustotal'].get('last_analysis_stats') or {}
                    malicious = last.get('malicious', 0) or 0
                    risk_score += 1 if malicious > 0 else 0
                result['summary'] = {'risk_score_estimate': risk_score}
            except Exception:
                result['summary'] = {'error': 'summary_failure'}

            if args.output_file:
                # guardar JSON en archivo
                try:
                    with open(args.output_file, 'w', encoding='utf-8') as f:
                        json.dump(result, f, ensure_ascii=False, indent=2)
                    print(f"✅ Resultado guardado en {args.output_file}")
                except Exception as e:
                    print(f"❌ No se pudo guardar el archivo: {e}")
            else:
                print(json.dumps(result, ensure_ascii=False, indent=2))

        else:
            analizar_ip(ip)

        logging.debug('Análisis finalizado para %s', ip)
    except Exception as e:
        print(f"\n❌ Ocurrió un error inesperado durante el análisis: {e}")
        return
    
    # Opciones adicionales
    print("\n📋 SIGUIENTES PASOS:")
    print("1. Guarda esta información para tus registros")
    print("2. Compara con accesos legítimos conocidos")
    print("3. Toma medidas de seguridad si es necesario")

if __name__ == "__main__":
    main()
