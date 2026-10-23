"""
VULNERABLE FIXTURE APP — DO NOT DEPLOY PUBLICLY
------------------------------------------------
A minimal "notes" app used as a controlled test target for VibeShield's
IDOR exploit-verification engine. This app is intentionally vulnerable.

Vulnerability: GET /api/notes/<note_id> returns any note by ID without
checking whether the requesting user actually owns it (classic IDOR /
CWE-639). Any logged-in user can enumerate note_id and read other users'
private notes.

Run:
    pip install -r requirements.txt
    python app.py
Then hit http://localhost:5000
"""

from flask import Flask, request, jsonify, g
import sqlite3
import uuid
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            token TEXT UNIQUE
        )"""
    )
    db.execute(
        """CREATE TABLE notes (
            id TEXT PRIMARY KEY,
            owner_id TEXT,
            title TEXT,
            body TEXT
        )"""
    )

    # Two seeded users so the IDOR is provable cross-account
    alice_id, bob_id = str(uuid.uuid4()), str(uuid.uuid4())
    db.execute(
        "INSERT INTO users VALUES (?, ?, ?)",
        (alice_id, "alice", "token-alice-demo"),
    )
    db.execute(
        "INSERT INTO users VALUES (?, ?, ?)",
        (bob_id, "bob", "token-bob-demo"),
    )

    # Bob has a private note that Alice should NOT be able to read
    secret_note_id = "1001"
    db.execute(
        "INSERT INTO notes VALUES (?, ?, ?, ?)",
        (secret_note_id, bob_id, "Bob's private note", "My SSN is 123-45-6789"),
    )
    # Alice has her own note for baseline/legit-access testing
    db.execute(
        "INSERT INTO notes VALUES (?, ?, ?, ?)",
        (str(uuid.uuid4()), alice_id, "Alice's note", "Grocery list: eggs, milk"),
    )
    db.commit()
    db.close()
    print(f"[fixture] seeded DB. Bob's secret note id = {secret_note_id}")


def get_user_from_token(token):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    return row


@app.route("/api/login", methods=["POST"])
def login():
    """Trivial demo login — returns a static bearer token per username."""
    username = request.json.get("username")
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row:
        return jsonify({"error": "unknown user"}), 401
    return jsonify({"token": row["token"], "user_id": row["id"]})


@app.route("/api/notes/<note_id>", methods=["GET"])
def get_note(note_id):
    """
    *** VULNERABLE ENDPOINT ***
    Returns a note by ID as long as the caller has ANY valid token.
    It never checks note.owner_id against the authenticated user.
    This is the IDOR your exploit engine should be able to prove.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return jsonify({"error": "not found"}), 404

    # BUG: no check that note["owner_id"] == user["id"]
    return jsonify(
        {"id": note["id"], "title": note["title"], "body": note["body"]}
    )


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
