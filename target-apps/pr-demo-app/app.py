from flask import Flask, jsonify

app = Flask(__name__)

# Bumped to force a new image digest for rebuild/testing runs (2026-09-07).
APP_VERSION = "1.0.1"


@app.get("/")
def index():
    return jsonify(app="pr-demo-app", status="ok", version=APP_VERSION)


@app.get("/health")
def health():
    return jsonify(healthy=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
