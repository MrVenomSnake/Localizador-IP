import json
import sys
from datetime import datetime

if len(sys.argv) < 2:
    print('Usage: generate_report.py <json-file> [out-file]')
    sys.exit(1)

json_file = sys.argv[1]
out_file = sys.argv[2] if len(sys.argv) > 2 else f'report_{json_file.replace(".json","")}.txt'

with open(json_file, 'r', encoding='utf-8') as f:
    d = json.load(f)

with open(out_file, 'w', encoding='utf-8') as rf:
    rf.write(f"IP Analysis Report - {d.get('ip')}\nGenerated: {d.get('analyzed_at', datetime.now().isoformat())}\n\n")
    rf.write('SUMMARY\n-------\n')
    rf.write(f"Classification: {d.get('analysis',{}).get('classification')}\n")
    rf.write(f"Risk score estimate: {d.get('summary',{}).get('risk_score_estimate')}\n\n")
    ipapi = d.get('ip_api', {})
    rf.write('GEO & NETWORK\n-------------\n')
    rf.write(f"Country: {ipapi.get('country')}\nRegion: {ipapi.get('regionName')}\nCity: {ipapi.get('city')}\nTimezone: {ipapi.get('timezone')}\n")
    rf.write(f"ISP: {ipapi.get('isp')}\nOrganization: {ipapi.get('org')}\nAS: {ipapi.get('as')}\n\n")

    rdap = d.get('rdap', {})
    if 'data' in rdap:
        rf.write('RDAP / Abuse contacts\n----------------------\n')
        entities = rdap['data'].get('entities', []) if isinstance(rdap['data'], dict) else []
        for e in entities:
            roles = e.get('roles', [])
            if 'abuse' in roles or 'registrant' in roles:
                v = e.get('vcardArray', [])
                if len(v) > 1:
                    for item in v[1]:
                        if item[0] == 'email':
                            rf.write(f"Abuse email: {item[3]}\n")
                        if item[0] == 'tel':
                            rf.write(f"Contact tel: {item[3]}\n")
        rf.write('\n')

    rf.write('ABUSEIPDB\n--------\n')
    a = d.get('abuseipdb', {})
    if 'data' in a:
        ad = a['data']
        rf.write(f"abuseConfidenceScore: {ad.get('abuseConfidenceScore')}\nReports: {ad.get('totalReports')}\n")
    else:
        rf.write('No AbuseIPDB data\n')

    rf.write('\nVIRUSTOTAL\n---------\n')
    vt = d.get('virustotal', {})
    if vt.get('last_analysis_stats'):
        rf.write(str(vt.get('last_analysis_stats')) + '\n')
    else:
        rf.write('No VirusTotal data\n')

print('Generated', out_file)
