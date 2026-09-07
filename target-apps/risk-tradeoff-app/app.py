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


@app.get("/health")
def health():
    return jsonify(healthy=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
