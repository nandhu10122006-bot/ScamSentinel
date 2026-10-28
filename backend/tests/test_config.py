from __future__ import annotations

import pytest

from app.config import load_settings


def test_production_requires_postgresql_database_url(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="PostgreSQL DATABASE_URL"):
        load_settings()

    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/cybersentry-production.db")
    with pytest.raises(ValueError, match="PostgreSQL DATABASE_URL"):
        load_settings()


def test_production_postgresql_url_is_normalized(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@db.example.test/cybersentry")
    settings = load_settings()
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.app_env == "production"


def test_development_may_use_local_sqlite(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    settings = load_settings()
    assert settings.database_url.startswith("sqlite:///")