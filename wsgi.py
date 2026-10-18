"""Gunicorn entry point (debug mode is never enabled here)."""

from secure_api import create_app

app = create_app()
