"""Application factory for a small authenticated notes API."""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from uuid import uuid4

import click
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, current_app, g, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from werkzeug.exceptions import HTTPException

from .db import close_db, get_db, init_db

password_hasher = PasswordHasher()
AUTH_SCHEME = "Bearer"


def error(message, status):
    return jsonify(error=message), status


def json_body():
    """Accept JSON objects only; Flask handles malformed or oversized input."""
    body = request.get_json()
    return body if isinstance(body, dict) else None


def text_field(body, name, maximum):
    value = body.get(name) if body is not None else None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        return None
    return value


def require_token(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token or len(token) > 4096:
            return error("Требуется Bearer-токен", 401)
        try:
            claims = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
                issuer="secure-notes-api",
                audience="secure-notes-client",
                options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]},
            )
        except jwt.InvalidTokenError:
            return error("Недействительный или просроченный токен", 401)
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject.isascii() or not subject.isdigit():
            return error("Недействительный токен", 401)
        # Bound the SQLite integer conversion, even for a signed but invalid subject.
        if len(subject) > 18:
            return error("Недействительный токен", 401)
        user = get_db().execute("SELECT id FROM users WHERE id = ?", (int(subject),)).fetchone()
        if user is None:
            return error("Недействительный токен", 401)
        g.user_id = user["id"]
        return view(*args, **kwargs)

    return wrapped


def serialize_note(row):
    # Explicit HTML escaping is required by this lab, even though the API emits JSON.
    return {
        "id": row["id"],
        "title": str(escape(row["title"])),
        "body": str(escape(row["body"])),
        "created_at": row["created_at"],
    }


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "notes.db")),
        MAX_CONTENT_LENGTH=16 * 1024,
        RATELIMIT_STORAGE_URI="memory://",
        RATELIMIT_HEADERS_ENABLED=True,
    )
    if test_config:
        app.config.update(test_config)
    secret = app.config["JWT_SECRET_KEY"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise RuntimeError("JWT_SECRET_KEY must contain at least 32 bytes; generate a random secret")
    Path(app.instance_path).mkdir(mode=0o700, parents=True, exist_ok=True)
    app.teardown_appcontext(close_db)
    # Unknown users still perform a real Argon2 verification to reduce timing leaks.
    dummy_hash = password_hasher.hash(uuid4().hex)
    limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["120 per minute"])
    app.extensions["request_limiter"] = limiter

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        if response.status_code == 401:
            response.headers["WWW-Authenticate"] = AUTH_SCHEME
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return error(exc.name, exc.code)

    @app.errorhandler(500)
    def internal_error(_exc):
        return error("Внутренняя ошибка сервера", 500)

    @app.post("/auth/login")
    @limiter.limit("5 per minute; 20 per hour")
    def login():
        body = json_body()
        username = text_field(body, "username", 64)
        password = text_field(body, "password", 128)
        if username is None or password is None:
            return error("Нужны username (1–64 символа) и password (1–128 символов)", 400)
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        try:
            password_hasher.verify(user["password_hash"] if user else dummy_hash, password)
        except (VerificationError, InvalidHashError):
            return error("Неверный логин или пароль", 401)
        if user is None:
            return error("Неверный логин или пароль", 401)
        if password_hasher.check_needs_rehash(user["password_hash"]):
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hasher.hash(password), user["id"]),
            )
            db.commit()
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": str(user["id"]), "iat": now, "nbf": now,
             "exp": now + timedelta(minutes=15), "iss": "secure-notes-api",
             "aud": "secure-notes-client", "jti": uuid4().hex},
            app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        return jsonify({"access_token": token, "token_type": AUTH_SCHEME, "expires_in": 900})

    @app.get("/api/data")
    @require_token
    def list_notes():
        raw_limit = request.args.get("limit", "20")
        raw_offset = request.args.get("offset", "0")
        try:
            limit, offset = int(raw_limit), int(raw_offset)
        except ValueError:
            return error("Некорректная пагинация", 400)
        if not 1 <= limit <= 100 or not 0 <= offset <= 1_000_000:
            return error("limit: 1–100, offset: 0–1000000", 400)
        rows = get_db().execute(
            "SELECT id, title, body, created_at FROM notes WHERE user_id = ? "
            "ORDER BY id DESC LIMIT ? OFFSET ?", (g.user_id, limit, offset),
        ).fetchall()
        return jsonify(data=[serialize_note(row) for row in rows], limit=limit, offset=offset)

    @app.post("/api/data")
    @require_token
    def create_note():
        body = json_body()
        title = text_field(body, "title", 120)
        content = text_field(body, "body", 5000)
        if title is None or content is None:
            return error("Нужны title (1–120 символов) и body (1–5000 символов)", 400)
        db = get_db()
        cursor = db.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (g.user_id, title, content),
        )
        db.commit()
        row = db.execute(
            "SELECT id, title, body, created_at FROM notes WHERE id = ? AND user_id = ?",
            (cursor.lastrowid, g.user_id),
        ).fetchone()
        return jsonify(data=serialize_note(row)), 201

    @app.cli.command("init-db")
    def init_db_command():
        """Create missing tables without deleting data."""
        init_db()
        click.echo("SQLite initialized.")

    @app.cli.command("create-user")
    @click.option("--username", prompt=True)
    @click.password_option(confirmation_prompt=True)
    def create_user(username, password):
        """Create an account locally; the password is prompted without echo."""
        if not username.strip() or len(username) > 64 or not 12 <= len(password) <= 128:
            raise click.ClickException("Username: 1–64 chars; password: 12–128 chars")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hasher.hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise click.ClickException("Username already exists") from exc
        click.echo("User created.")

    return app
