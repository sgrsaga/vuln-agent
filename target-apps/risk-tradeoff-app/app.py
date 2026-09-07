import hashlib

from ecdsa import NIST256p, SigningKey
from flask import Flask, jsonify, request

app = Flask(__name__)

# Demo signing key (generated per process — fixture app, not real key handling).
_key = SigningKey.generate(curve=NIST256p)


def sign(payload: bytes) -> str:
    return _key.sign(payload, hashfunc=hashlib.sha256).hex()


@app.post("/sign")
def sign_endpoint():
    payload = request.get_data() or b""
    return jsonify(signature=sign(payload))


# Bumped to force a new image digest for rebuild/testing runs (2026-09-07).
APP_VERSION = "1.0.1"


@app.get("/health")
def health():
    return jsonify(healthy=True, version=APP_VERSION)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
