from app import app


def test_index():
    resp = app.test_client().get("/")
    assert resp.status_code == 200
    assert resp.get_json()["app"] == "pr-demo-app"


def test_health():
    assert app.test_client().get("/health").get_json()["healthy"] is True
