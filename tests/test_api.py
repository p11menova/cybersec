import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from secure_api import create_app, password_hasher
from secure_api.db import get_db, init_db
from tests.conftest import auth_header


def test_login_and_password_storage(app, client):
    response = client.post("/auth/login", json={"username": "alice", "password": "test-passphrase-123"})
    assert response.status_code == 200
    assert response.json["expires_in"] == 900
    claims = jwt.decode(response.json["access_token"], app.config["JWT_SECRET_KEY"],
                        algorithms=["HS256"], audience="secure-notes-client", issuer="secure-notes-api")
    assert claims["sub"] == "1"
    assert claims["exp"] - claims["iat"] == 900
    with app.app_context():
        value = get_db().execute("SELECT password_hash FROM users WHERE id = 1").fetchone()[0]
        assert value.startswith("$argon2id$")
        assert password_hasher.verify(value, "test-passphrase-123")


@pytest.mark.parametrize("username,password", [
    ("alice", "wrong"), ("missing", "wrong"), ("' OR 1=1 --", "wrong"),
])
def test_bad_credentials(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json == {"error": "Неверный логин или пароль"}


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("authorization", [None, "Basic abc", "Bearer invalid", "Bearer ", "Bearer " + "x" * 4097])
def test_authentication_required(client, method, authorization):
    headers = {"Authorization": authorization} if authorization else {}
    response = getattr(client, method)("/api/data", headers=headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def signed_token(app, **changes):
    now = datetime.now(timezone.utc)
    claims = {"sub": "1", "iat": now, "nbf": now, "exp": now + timedelta(minutes=15),
              "iss": "secure-notes-api", "aud": "secure-notes-client", "jti": "test"}
    claims.update(changes)
    return jwt.encode(claims, app.config["JWT_SECRET_KEY"], algorithm="HS256")


@pytest.mark.parametrize("changes", [
    {"exp": 1}, {"nbf": 9999999999}, {"iat": 9999999999},
    {"iss": "other"}, {"aud": "other"}, {"sub": "999"}, {"sub": "x"},
    {"sub": "9" * 50}, {"sub": "١"}, {"sub": 1},
])
def test_invalid_claims(app, client, changes):
    response = client.get("/api/data", headers={"Authorization": "Bearer " + signed_token(app, **changes)})
    assert response.status_code == 401


@pytest.mark.parametrize("missing", ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"])
def test_required_claims(app, client, missing):
    claims = jwt.decode(signed_token(app), app.config["JWT_SECRET_KEY"], algorithms=["HS256"], audience="secure-notes-client")
    del claims[missing]
    token = jwt.encode(claims, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    assert client.get("/api/data", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_signature_and_algorithm(app, client):
    claims = {"sub": "1"}
    for token in [jwt.encode(claims, "another-key-" * 4, algorithm="HS256"),
                  jwt.encode(claims, "", algorithm="none"),
                  jwt.encode(claims, app.config["JWT_SECRET_KEY"], algorithm="HS512")]:
        assert client.get("/api/data", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_create_list_xss_and_ownership(app, client, headers):
    payload = {"title": '<script>alert("x")</script>', "body": "'); DROP TABLE users; -- & <img onerror='x'>"}
    response = client.post("/api/data", json=payload, headers=headers)
    assert response.status_code == 201
    note = response.json["data"]
    assert "<" not in note["title"] and "<" not in note["body"]
    assert "&lt;script&gt;" in note["title"] and "&amp;" in note["body"]
    assert client.get("/api/data", headers=headers).json["data"] == [note]
    assert client.get("/api/data", headers=auth_header(client, "bob")).json["data"] == []
    with app.app_context():
        assert get_db().execute("SELECT count(*) FROM users").fetchone()[0] == 2
        assert get_db().execute("SELECT title FROM notes").fetchone()[0] == payload["title"]


@pytest.mark.parametrize("payload", [None, [], "text", 42, {}, {"username": []},
    {"username": "alice", "password": "x" * 129}, {"username": "x" * 65, "password": "p"}])
def test_login_validation(client, payload):
    response = client.post("/auth/login", data=json.dumps(payload), content_type="application/json")
    assert response.status_code == 400


@pytest.mark.parametrize("payload", [{}, [], {"title": 1, "body": "x"},
    {"title": "x", "body": " "}, {"title": "x" * 121, "body": "x"},
    {"title": "x", "body": "x" * 5001}])
def test_note_validation(client, headers, payload):
    assert client.post("/api/data", json=payload, headers=headers).status_code == 400


def test_malformed_json_and_size(client, headers):
    assert client.post("/api/data", data="{bad", content_type="application/json", headers=headers).status_code == 400
    assert client.post("/api/data", data="text", headers=headers).status_code == 415
    assert client.post("/api/data", data="x" * 17000, content_type="application/json", headers=headers).status_code == 413


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "offset=1000001", "limit=x", "offset=' OR 1=1"])
def test_bad_pagination(client, headers, query):
    assert client.get("/api/data?" + query, headers=headers).status_code == 400


def test_pagination_and_spoofed_owner(client, headers):
    for n in range(3):
        assert client.post("/api/data", json={"title": str(n), "body": "body", "user_id": 2}, headers=headers).status_code == 201
    response = client.get("/api/data?limit=1&offset=1", headers=headers)
    assert len(response.json["data"]) == 1
    assert response.json["data"][0]["title"] == "1"
    assert client.get("/api/data", headers=auth_header(client, "bob")).json["data"] == []


def test_security_headers_and_json_errors(client):
    for path in ["/api/data", "/does-not-exist"]:
        response = client.get(path)
        assert response.is_json
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Frame-Options"] == "DENY"


@pytest.mark.parametrize("secret", [None, "short", ""])
def test_secret_required(secret):
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_app({"JWT_SECRET_KEY": secret})


def test_login_rate_limit(tmp_path):
    app = create_app({"TESTING": True, "JWT_SECRET_KEY": "test-only-key-" * 4,
                      "DATABASE": str(tmp_path / "rate.db")})
    with app.app_context():
        init_db()
    client = app.test_client()
    for _ in range(5):
        assert client.post("/auth/login", json={"username": "no-user", "password": "wrong"}).status_code == 401
    response = client.post("/auth/login", json={"username": "no-user", "password": "wrong"})
    assert response.status_code == 429
    assert response.is_json and "Retry-After" in response.headers


def test_cli(app):
    runner = app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code == 0
    result = runner.invoke(args=["create-user", "--username", "new-user"], input="long-passphrase-123\nlong-passphrase-123\n")
    assert result.exit_code == 0
    duplicate = runner.invoke(args=["create-user", "--username", "new-user"], input="long-passphrase-123\nlong-passphrase-123\n")
    assert duplicate.exit_code != 0 and "already exists" in duplicate.output
    bad = runner.invoke(args=["create-user", "--username", "bad-user"], input="short\nshort\n")
    assert bad.exit_code != 0
