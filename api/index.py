"""Public, stateless synthetic demo; no authentication or production data.

Each request owns a disposable SQLite database. Browser-provided settings are
validated and replayed, never trusted as authorization or evaluation evidence.
"""
import json
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import Application, RULES
from core import Problem


def validate_settings(value):
    if not isinstance(value, dict) or set(value) != {'rules', 'version', 'runs', 'last'}:
        raise Problem(400, 'Invalid demo settings. Reset the demo to continue.')
    def policy(p):
        if not isinstance(p, dict) or set(p) != {'rules', 'version'}:
            raise Problem(400, 'Invalid policy settings.')
        if not isinstance(p['rules'], dict) or set(p['rules']) != set(RULES) or any(type(v) is not bool for v in p['rules'].values()):
            raise Problem(400, 'Supply four boolean controls.')
        if type(p['version']) is not int or not 1 <= p['version'] <= 10000:
            raise Problem(400, 'Invalid policy version. Reset the demo.')
    policy({'rules': value['rules'], 'version': value['version']})
    if type(value['runs']) is not int or not 0 <= value['runs'] <= 10000:
        raise Problem(400, 'Invalid replay count.')
    if value['last'] is not None:
        policy(value['last'])
        if value['runs'] == 0 or value['last']['version'] > value['version']:
            raise Problem(400, 'Invalid replay settings.')
    return value


def defaults():
    return {'rules': dict(RULES), 'version': 1, 'runs': 0, 'last': None}


def set_policy(app, rules, version):
    with app.store.connect() as db:
        db.execute('DELETE FROM policies')
        db.execute('INSERT INTO policies VALUES(?,?,?)', (version, json.dumps(rules), time.time()))


def replay(app, count):
    result = app.evaluate()
    result['run_id'] = count
    with app.store.connect() as db:
        db.execute('UPDATE runs SET summary=? WHERE id=(SELECT MAX(id) FROM runs)', (json.dumps(result),))
    return result


def dispatch(method, path, body, settings):
    settings = validate_settings(settings)
    if path not in ('/api/state', '/api/logs', '/api/policy', '/api/evaluate', '/api/report', '/api/export', '/api/reset'):
        raise Problem(404, 'Endpoint does not exist.')
    user = {'name': 'Public demo', 'role': 'security_admin', 'csrf': ''}
    if method == 'POST' and path == '/api/reset':
        return {'ok': True, '_demo': defaults()}
    with tempfile.TemporaryDirectory(prefix='policy-lens-') as directory:
        app = Application(Path(directory) / 'demo.sqlite')
        if settings['last'] is not None:
            set_policy(app, settings['last']['rules'], settings['last']['version'])
            replay(app, settings['runs'])
        set_policy(app, settings['rules'], settings['version'])
        if method == 'POST' and path == '/api/evaluate':
            settings['runs'] += 1
            settings['last'] = {'rules': dict(settings['rules']), 'version': settings['version']}
            validate_settings(settings)
            result = replay(app, settings['runs'])
        else:
            result = app.route(method, path, body, user)
            if method == 'POST' and path == '/api/policy':
                settings['rules'] = result['rules']
                settings['version'] = result['version']
                validate_settings(settings)
        result['_demo'] = settings
        return result


class handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def respond(self, code, value, content_type='application/json; charset=utf-8'):
        data = json.dumps(value, allow_nan=False).encode() if isinstance(value, dict) else value
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def handle_request(self):
        try:
            parts = urlsplit(self.path)
            endpoint = parse_qs(parts.query).get('endpoint', [None])[0]
            path = '/api/' + endpoint if endpoint else parts.path
            if self.command == 'GET' and not path.startswith('/api/'):
                name = 'index.html' if path == '/' else path.lstrip('/')
                types = {'index.html': 'text/html', 'app.js': 'text/javascript', 'style.css': 'text/css', 'favicon.svg': 'image/svg+xml'}
                if name not in types:
                    raise Problem(404, 'Not found.')
                return self.respond(200, (ROOT / 'public' / name).read_bytes(), types[name] + '; charset=utf-8')
            origin = self.headers.get('Origin')
            if (origin and urlsplit(origin).netloc != self.headers.get('Host')) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
                raise Problem(403, 'Cross-origin requests are not allowed.')
            raw = self.headers.get('X-Demo-State', '')
            if len(raw) > 2048:
                raise Problem(413, 'Demo settings are too large.')
            settings = json.loads(raw) if raw else defaults()
            body = {}
            if self.command == 'POST':
                if not self.headers.get('Content-Type', '').startswith('application/json'):
                    raise Problem(415, 'Use application/json.')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= 4096:
                    raise Problem(413, 'Request is too large.')
                body = json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(body, dict):
                    raise Problem(400, 'A JSON object is required.')
            self.respond(200, dispatch(self.command, path, body, settings))
        except Problem as exc:
            self.respond(exc.status, {'error': exc.message})
        except (ValueError, TypeError, KeyError):
            self.respond(400, {'error': 'Invalid demo request. Reset the demo to continue.'})
        except Exception:
            import traceback
            traceback.print_exc()
            self.respond(500, {'error': 'The demo could not complete this request. Please retry.'})

    do_GET = handle_request
    do_POST = handle_request
