"""Tests for the AgentShield API."""

from fastapi.testclient import TestClient

from src.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "timestamp" in data


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "AgentShield" in response.json()["message"]
