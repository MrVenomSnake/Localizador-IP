import json
import sys
import ip_analyzer


def test_gather_ip_info(monkeypatch):
    # Fake responses
    class Dummy:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
        def json(self):
            return self._payload

    def fake_get(url, timeout=10):
        if 'ip-api.com' in url:
            return Dummy(200, {'status': 'success', 'country': 'Mockland'})
        if 'ipinfo.io' in url:
            return Dummy(200, {'hostname': 'mock.host', 'privacy': True})
        raise RuntimeError('unexpected')

    monkeypatch.setattr(ip_analyzer, 'requests', type('R', (), {'get': staticmethod(fake_get)}))
    monkeypatch.setattr(ip_analyzer.socket, 'gethostbyaddr', lambda ip: ('host.mock', [], []))

    info = ip_analyzer.gather_ip_info('1.2.3.4')
    assert info['ip'] == '1.2.3.4'
    assert 'ip_api' in info and info['ip_api'].get('country') == 'Mockland'
    assert 'ipinfo' in info and info['ipinfo'].get('hostname') == 'mock.host'
    assert info['reverse_dns']['hostname'] == 'host.mock'


def test_main_json_writes_file(monkeypatch, tmp_path, capsys):
    # Prepare fake requests/socket as above
    class Dummy:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
        def json(self):
            return self._payload

    def fake_get(url, timeout=10):
        if 'ip-api.com' in url:
            return Dummy(200, {'status': 'success', 'country': 'Fileland'})
        if 'ipinfo.io' in url:
            return Dummy(200, {'hostname': 'file.host'})
        raise RuntimeError('unexpected')

    monkeypatch.setattr(ip_analyzer, 'requests', type('R', (), {'get': staticmethod(fake_get)}))
    monkeypatch.setattr(ip_analyzer.socket, 'gethostbyaddr', lambda ip: ('host.file', [], []))

    dest = tmp_path / 'out.json'
    argv = ['ip_analyzer.py', '1.2.3.4', '--json', '--output-file', str(dest)]
    monkeypatch.setattr(sys, 'argv', argv)

    # run main which should write file
    ip_analyzer.main()

    # check file
    assert dest.exists()
    data = json.loads(dest.read_text(encoding='utf-8'))
    assert data['ip'] == '1.2.3.4'
    assert data['ip_api']['country'] == 'Fileland'
    assert data['ipinfo']['hostname'] == 'file.host'
