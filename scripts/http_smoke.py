"""Exercise a real Gunicorn server with curl and disposable SQLite data."""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secure_api import create_app, password_hasher  # noqa: E402
from secure_api.db import get_db, init_db  # noqa: E402


def run():
    with tempfile.TemporaryDirectory(prefix="lab1-smoke-") as directory:
        env = os.environ.copy()
        env["JWT_SECRET_KEY"] = secrets.token_hex(32)
        env["DATABASE_PATH"] = str(Path(directory) / "smoke.db")
        password = secrets.token_urlsafe(24)
        app = create_app({"JWT_SECRET_KEY": env["JWT_SECRET_KEY"], "DATABASE": env["DATABASE_PATH"]})
        with app.app_context():
            init_db()
            db = get_db()
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       ("smoke-user", password_hasher.hash(password)))
            db.commit()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"

        def curl(path, expected, payload=None, token=None):
            args = ["curl", "--silent", "--show-error", "--max-time", "5", "--write-out", "\n%{http_code}", base + path]
            if payload is not None:
                args += ["--header", "Content-Type: application/json", "--data-binary", "@-"]
            if token:
                args += ["--header", "Authorization: Bearer " + token]
            response = subprocess.run(args, input=json.dumps(payload) if payload else None,
                                      text=True, capture_output=True, check=True)
            body, code = response.stdout.rsplit("\n", 1)
            if int(code) != expected:
                raise RuntimeError(f"{path}: expected {expected}, got {code}: {body}")
            print(f"{'POST' if payload else 'GET'} {path}: {code}")
            return json.loads(body)

        with open(Path(directory) / "gunicorn.log", "w+") as log:
            server = subprocess.Popen(
                [sys.executable, "-m", "gunicorn", "--workers", "1", "--bind", f"127.0.0.1:{port}", "wsgi:app"],
                cwd=ROOT, env=env, stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError("Gunicorn stopped before startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Gunicorn startup timed out")
                curl("/api/data", 401)
                curl("/auth/login", 401, {"username": "' OR 1=1 --", "password": "wrong"})
                login = curl("/auth/login", 200, {"username": "smoke-user", "password": password})
                token = login["access_token"]
                note = curl("/api/data", 201, {"title": "<script>alert(1)</script>", "body": "curl smoke"}, token)
                assert "<" not in note["data"]["title"]
                notes = curl("/api/data", 200, token=token)
                assert notes["data"] == [note["data"]]
                print("HTTP smoke passed: authentication, SQLi rejection, XSS escaping, SQLite persistence.")
            finally:
                server.terminate()
                server.wait(timeout=10)
                if sys.exc_info()[0]:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)


if __name__ == "__main__":
    run()
