from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(app="pr-demo-app", status="ok")


@app.get("/health")
def health():
    return jsonify(healthy=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
