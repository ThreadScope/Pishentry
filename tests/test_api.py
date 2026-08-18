import pytest
from fastapi.testclient import TestClient
from app.main import app

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

def test_brand_dom_endpoint():
    with TestClient(app) as client:
        response = client.get("/brands/paypal/dom")
        assert response.status_code == 200
        assert "<html" in response.text.lower() or "<form" in response.text.lower()

