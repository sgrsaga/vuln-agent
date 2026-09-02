from app import app, fib


def test_fib_base_cases():
    assert fib(0) == 0
    assert fib(1) == 1


def test_fib_sequence():
    assert [fib(n) for n in range(8)] == [0, 1, 1, 2, 3, 5, 8, 13]


def test_fib_rejects_negative():
    try:
        fib(-1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative n")


def test_health_endpoint():
    client = app.test_client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_fib_endpoint():
    client = app.test_client()
    resp = client.get("/fib/10")
    assert resp.status_code == 200
    assert resp.get_json() == {"n": 10, "value": 55}
