import json
import pytest

from ip_analyzer import analizar_ip


class DummyResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self._text = text

    def json(self):
        return json.loads(self._text)


def test_analizar_ip_with_ip_api_and_ipinfo(monkeypatch, capsys):
    # Mock ip-api response (success)
    ip_api_payload = json.dumps({
        'status': 'success',
        'country': 'Testland',
        'countryCode': 'TL',
        'regionName': 'TestRegion',
        'city': 'TestCity',
        'zip': '00000',
        'lat': 1.23,
        'lon': 4.56,
        'timezone': 'UTC',
        'isp': 'TestISP',
        'org': 'TestOrg',
        'as': 'AS12345 TestOrg'
    })

    # Mock ipinfo response
    ipinfo_payload = json.dumps({
        'hostname': 'test.example',
        'privacy': True
    })

    # Patch requests.get to return the right payloads depending on URL
    def fake_get(url, timeout=10):
        if 'ip-api.com' in url:
            return DummyResponse(200, ip_api_payload)
        if 'ipinfo.io' in url:
            return DummyResponse(200, ipinfo_payload)
        raise RuntimeError('Unexpected URL: ' + url)

    monkeypatch.setattr('ip_analyzer.requests.get', fake_get)

    # Also patch socket.gethostbyaddr to return a hostname
    monkeypatch.setattr('ip_analyzer.socket.gethostbyaddr', lambda ip: ('host.test', [], []))

    # Run analysis and capture output
    analizar_ip('1.2.3.4')

    out = capsys.readouterr().out
    assert 'Testland' in out
    assert 'TestISP' in out
    assert 'test.example' in out
    assert 'host.test' in out
