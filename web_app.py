from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
import os
from datetime import datetime
import json
from ip_analyzer import validate_ip, gather_ip_info

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    ip = request.form.get('ip', '').strip()
    case_id = request.form.get('case_id', '').strip() or None
    reporter = request.form.get('reporter', '').strip() or None
    if not ip:
        flash('IP is required', 'error')
        return redirect(url_for('index'))
    if not validate_ip(ip):
        flash('Invalid IP', 'error')
        return redirect(url_for('index'))

    # Gather info
    info = gather_ip_info(ip)
    info['meta'] = {'case_id': case_id, 'reporter': reporter, 'collected_at': datetime.utcnow().isoformat()}

    fname = f"{ip}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.json"
    path = os.path.join(DATA_DIR, fname)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(info, f, ensure_ascii=False, indent=2)

    # generate a simple text report
    report_name = fname.replace('.json', '.txt')
    report_path = os.path.join(DATA_DIR, report_name)
    with open(report_path, 'w', encoding='utf-8') as rf:
        rf.write(f"IP Analysis Report - {ip}\nGenerated: {info.get('analyzed_at')}\n\n")
        rf.write(json.dumps(info, ensure_ascii=False, indent=2))

    flash('Analysis completed', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    files = [f for f in os.listdir(DATA_DIR) if f.endswith('.json')]
    # sort newest first
    files.sort(reverse=True)
    entries = []
    for f in files[:50]:
        path = os.path.join(DATA_DIR, f)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            data = {}
        entries.append({'file': f, 'ip': data.get('ip'), 'summary': data.get('summary'), 'analyzed_at': data.get('analyzed_at')})

    return render_template('dashboard.html', entries=entries)


@app.route('/download/<path:filename>')
def download(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
