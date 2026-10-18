import secrets

import pytest

from secure_api import create_app, password_hasher
from secure_api.db import get_db, init_db


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "RATELIMIT_ENABLED": False,
    })
    with app.app_context():
        init_db()
        db = get_db()
        db.executemany(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            [(name, password_hasher.hash("test-passphrase-123")) for name in ("alice", "bob")],
        )
        db.commit()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def auth_header(client, username="alice"):
    response = client.post("/auth/login", json={
        "username": username, "password": "test-passphrase-123",
    })
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json["access_token"]}


@pytest.fixture
def headers(client):
    return auth_header(client)
