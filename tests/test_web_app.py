import json
import os
import tempfile
import ip_analyzer
from web_app import app


def test_index_page():
    client = app.test_client()
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'Localizador IP - Web' in resp.data


def test_analyze_post(monkeypatch, tmp_path):
    # mock gather_ip_info to return small dict
    def fake_gather(ip):
        return {'ip': ip, 'analysis': {'classification': 'test'}, 'summary': {'risk_score_estimate': 0}, 'analyzed_at': '2025-01-01T00:00:00'}

    monkeypatch.setattr(ip_analyzer, 'gather_ip_info', fake_gather)

    client = app.test_client()
    data = {'ip': '8.8.8.8', 'case_id': 'CASE1', 'reporter': 'me@example.com'}
    resp = client.post('/analyze', data=data, follow_redirects=True)
    assert resp.status_code == 200
    assert b'Dashboard' in resp.data
    # Check that file created in data dir
    files = [f for f in os.listdir(os.path.join(os.path.dirname(__file__), '..', 'data')) if '8.8.8.8' in f]
    assert len(files) > 0
