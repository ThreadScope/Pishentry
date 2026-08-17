import pytest
from fastapi.testclient import TestClient
from app.main import app, startup_event

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "brands_loaded" in data

def test_brands_endpoint():
    with TestClient(app) as client:
        response = client.get("/brands")
        assert response.status_code == 200
        brands = response.json()
        assert isinstance(brands, list)
        assert len(brands) >= 1

def test_scan_malformed_url():
    with TestClient(app) as client:
        response = client.post("/scan", json={"url": "not-a-valid-url-without-domain"})
        assert response.status_code == 400
