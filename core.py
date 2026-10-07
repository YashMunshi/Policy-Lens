"""Small localhost-only HTTP foundation; Python 3.10+, no third-party packages."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Problem(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 180000).hex()


class Store:
    def __init__(self, path):
        self.path = str(path)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        return db

    def initialize(self):
        with self.connect() as db:
            db.executescript('''
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS users (
                name TEXT PRIMARY KEY, department TEXT, role TEXT, salt TEXT, password TEXT);
              CREATE TABLE IF NOT EXISTS sessions (
                digest TEXT PRIMARY KEY, username TEXT REFERENCES users(name), csrf TEXT, expires REAL);
              CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, timestamp REAL, actor TEXT, event TEXT,
                resource TEXT, decision TEXT, reason TEXT);
              CREATE TABLE IF NOT EXISTS login_limits (name TEXT PRIMARY KEY, attempts INTEGER, until REAL);
            ''')
            for name, department, role in [('alice','sales','employee'), ('bob','finance','employee'),
                                            ('admin','security','security_admin')]:
                salt = secrets.token_hex(16)
                db.execute('INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)',
                           (name,department,role,salt,password_hash('DemoPass!2026',salt)))

    def log(self, actor, event, resource, decision, reason):
        with self.connect() as db:
            db.execute('INSERT INTO audit VALUES(NULL,?,?,?,?,?,?)',
                       (time.time(),actor,event,resource,decision,reason))

    def login(self, name, password):
        now = time.time()
        with self.connect() as db:
            limit = db.execute('SELECT * FROM login_limits WHERE name=?',(name,)).fetchone()
            if limit and limit['attempts'] >= 8 and limit['until'] > now:
                raise Problem(429,'Too many attempts. Try again in 60 seconds.')
            user = db.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
            salt = user['salt'] if user else '00'*16
            valid = hmac.compare_digest(password_hash(password,salt), user['password'] if user else '00'*32)
            if not valid:
                count = limit['attempts'] + 1 if limit and limit['until'] > now else 1
                db.execute('INSERT OR REPLACE INTO login_limits VALUES (?,?,?)',(name,count,now+60))
                # Commit before raising, otherwise sqlite rolls back the rate limiter.
                db.commit()
                raise Problem(401,'Invalid username or password.')
            db.execute('DELETE FROM login_limits WHERE name=?',(name,))
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            db.execute('INSERT INTO sessions VALUES (?,?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(),name,csrf,now+3600))
        return token, csrf, {k:user[k] for k in ('name','department','role')}

    def session(self, token):
        with self.connect() as db:
            row = db.execute('''SELECT u.name,u.department,u.role,s.csrf,s.expires FROM sessions s
                                JOIN users u ON u.name=s.username WHERE digest=?''',
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or row['expires'] <= time.time():
            raise Problem(401,'Sign in to continue.')
        return dict(row)

    def audit(self):
        with self.connect() as db:
            return [dict(x) for x in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 80')]


def admin(user):
    if user['role'] != 'security_admin':
        raise Problem(403,'A security administrator must approve this action.')


def serve(application, directory, port):
    root = Path(directory).resolve()
    cookie_name = 'session_' + str(port)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def headers_common(self):
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',
                             "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                             "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

        def respond(self, code, data, cookie=None):
            body = json.dumps(data,allow_nan=False).encode()
            self.send_response(code)
            self.headers_common()
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Content-Length',str(len(body)))
            if cookie:
                self.send_header('Set-Cookie',cookie)
            self.end_headers()
            self.wfile.write(body)

        def validate_origin(self):
            expected = f'127.0.0.1:{port}'
            host = self.headers.get('Host','')
            if host not in (expected,f'localhost:{port}'):
                raise Problem(403,'Only the localhost demo origin is supported.')
            origin = self.headers.get('Origin')
            if origin and origin != 'http://' + host:
                raise Problem(403,'Cross-origin requests are not allowed.')

        def handle_api(self):
            try:
                self.validate_origin()
                body = {}
                if self.command == 'POST':
                    if not self.headers.get('Content-Type','').startswith('application/json'):
                        raise Problem(415,'Use application/json.')
                    length = int(self.headers.get('Content-Length','0'))
                    if length < 0 or length > 65536:
                        raise Problem(413,'Request is too large.')
                    body = json.loads(self.rfile.read(length) or b'{}')
                    if not isinstance(body,dict):
                        raise Problem(400,'A JSON object is required.')
                if self.path == '/api/login' and self.command == 'POST':
                    token, csrf, user = application.store.login(str(body.get('name',''))[:100],str(body.get('password',''))[:500])
                    application.store.log(user['name'],'login','session','allow','Authenticated demo account')
                    return self.respond(200,{'user':user,'csrf':csrf},
                                        cookie_name+'='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600')
                jar = SimpleCookie(self.headers.get('Cookie',''))
                token = jar[cookie_name].value if cookie_name in jar else ''
                # The gateway also accepts an agent bearer token at its execution boundary.
                if self.path == '/api/execute' and self.command == 'POST' and hasattr(application,'execute_bearer') and self.headers.get('Authorization','').startswith('Bearer '):
                    result = application.execute_bearer(self.headers['Authorization'][7:],body)
                    return self.respond(200,result)
                user = application.store.session(token)
                if self.command == 'POST' and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),user['csrf']):
                    raise Problem(403,'CSRF token is missing or invalid.')
                if self.path == '/api/logout' and self.command == 'POST':
                    with application.store.connect() as db:
                        db.execute('DELETE FROM sessions WHERE digest=?',(hashlib.sha256(token.encode()).hexdigest(),))
                    return self.respond(200,{'ok':True},cookie_name+'=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
                result = application.route(self.command,self.path,body,user)
                self.respond(200,result)
            except Problem as exc:
                self.respond(exc.status,{'error':exc.message})
            except (ValueError,TypeError,KeyError,json.JSONDecodeError):
                self.respond(400,{'error':'Invalid request fields.'})
            except Exception:
                import traceback
                traceback.print_exc()
                self.respond(500,{'error':'An internal error occurred.'})

        def do_POST(self):
            self.handle_api()

        def do_GET(self):
            if self.path.startswith('/api/'):
                return self.handle_api()
            try:
                self.validate_origin()
                name = self.path.split('?')[0]
                name = 'index.html' if name == '/' else name.lstrip('/')
                if name not in ('index.html','app.js','style.css','favicon.svg'):
                    raise Problem(404,'Not found.')
                file = root/name
                data = file.read_bytes()
                self.send_response(200)
                self.headers_common()
                content_type = {'html':'text/html','js':'text/javascript','css':'text/css','svg':'image/svg+xml'}[file.suffix[1:]]
                self.send_header('Content-Type',content_type+'; charset=utf-8')
                self.send_header('Content-Length',str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Problem as exc:
                self.respond(exc.status,{'error':exc.message})

    server = ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print(f'Open http://127.0.0.1:{port} — Ctrl+C to stop',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
