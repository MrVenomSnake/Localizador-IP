import json
import sys
import ip_analyzer


def test_query_virustotal(monkeypatch):
    class Dummy:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
        def json(self):
            return self._payload

    def fake_get(url, headers=None, timeout=10):
        assert 'virustotal' in url
        assert headers and 'x-apikey' in headers
        payload = {'data': {'attributes': {'last_analysis_stats': {'malicious': 3, 'suspicious': 1}}}}
        return Dummy(200, payload)

    monkeypatch.setattr(ip_analyzer, 'requests', type('R', (), {'get': staticmethod(fake_get)}))

    res = ip_analyzer.query_virustotal('1.2.3.4', api_key='vt_key')
    assert res.get('status') == 'ok'
    assert res['last_analysis_stats']['malicious'] == 3


def test_main_json_with_virustotal(monkeypatch, tmp_path):
    class Dummy:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
        def json(self):
            return self._payload

    def fake_get(url, headers=None, params=None, timeout=10):
        if 'ip-api.com' in url:
            return Dummy(200, {'status': 'success', 'country': 'V'})
        if 'ipinfo.io' in url:
            return Dummy(200, {'hostname': 'host.vt'})
        if 'virustotal' in url:
            return Dummy(200, {'data': {'attributes': {'last_analysis_stats': {'malicious': 0}}}})
        raise RuntimeError('unexpected')

    monkeypatch.setattr(ip_analyzer, 'requests', type('R', (), {'get': staticmethod(fake_get)}))
    monkeypatch.setattr(ip_analyzer.socket, 'gethostbyaddr', lambda ip: ('host.vt', [], []))

    out = tmp_path / 'out.json'
    argv = ['ip_analyzer.py', '1.2.3.4', '--json', '--abuse-key', 'abc', '--abuse-key', 'abc', '--output-file', str(out), '--abuse-key', 'abc', '--abuse-key', 'abc']
    # also pass virus key in env
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'vt_key')
    monkeypatch.setattr(sys, 'argv', ['ip_analyzer.py', '1.2.3.4', '--json', '--output-file', str(out)])

    ip_analyzer.main()

    assert out.exists()
    data = json.loads(out.read_text(encoding='utf-8'))
    assert 'virustotal' in data
    assert data['virustotal']['last_analysis_stats']['malicious'] == 0
