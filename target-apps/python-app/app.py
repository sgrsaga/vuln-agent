from flask import Flask, jsonify

app = Flask(__name__)


def fib(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/fib/<int:n>")
def fib_endpoint(n: int):
    return jsonify(n=n, value=fib(n))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
