import json
import ip_analyzer


def test_query_rdap_success(monkeypatch):
    class Dummy:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
        def json(self):
            return self._payload

    def fake_get(url, timeout=8):
        if 'arin' in url:
            return Dummy(404, {})
        if 'ripe' in url:
            return Dummy(200, {'objectClassName': 'ip network', 'handle': 'TEST'})
        raise RuntimeError('unexpected')

    monkeypatch.setattr(ip_analyzer, 'requests', type('R', (), {'get': staticmethod(fake_get)}))
    out = ip_analyzer.query_rdap('1.2.3.4')
    assert out.get('data', {}).get('objectClassName') == 'ip network'


def test_query_rdap_no_requests(monkeypatch):
    monkeypatch.setattr(ip_analyzer, 'requests', None)
    out = ip_analyzer.query_rdap('1.2.3.4')
    assert out.get('error') == 'requests_missing'
