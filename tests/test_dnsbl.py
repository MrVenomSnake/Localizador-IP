import ip_analyzer
import socket


def test_check_dnsbl_not_ipv4():
    res = ip_analyzer.check_dnsbl('::1')
    assert res.get('error') == 'not_ipv4'


def test_check_dnsbl_with_listings(monkeypatch):
    # simulate socket.gethostbyname returning a value for one BL
    def fake_gethost(name):
        if 'zen.spamhaus.org' in name:
            return '127.0.0.2'
        raise Exception('not found')

    monkeypatch.setattr(ip_analyzer.socket, 'gethostbyname', fake_gethost)
    res = ip_analyzer.check_dnsbl('1.2.3.4')
    assert isinstance(res.get('listed'), list)
    assert any(item['dnsbl'] == 'zen.spamhaus.org' for item in res['listed'])
