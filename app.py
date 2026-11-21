"""Aplicación deliberadamente vulnerable para la evaluación OCY1102 EV3.

Solo debe ejecutarse en el laboratorio local. El alumnado debe revisar y corregir
los defectos; estos comentarios no enumeran las respuestas de la evaluación.
"""

import os
import sqlite3
import time
from pathlib import Path
import hmac
import secrets
import threading

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash


HTTP_REQUESTS = Counter(
    "securedev_http_requests_total",
    "Solicitudes HTTP de la aplicación",
    ["endpoint", "method", "status"],
)
HTTP_DURATION = Histogram(
    "securedev_http_request_duration_seconds",
    "Duración de solicitudes HTTP",
    ["endpoint"],
)
LOGIN_FAILURES = Counter(
    "securedev_login_failures_total",
    "Intentos de acceso fallidos",
)
LOGIN_BLOCKED = Counter(
    "securedev_login_blocked_total",
    "Intentos de acceso bloqueados por exceso de fallos",
)

# Protección contra fuerza bruta: tras MAX_FAILED_LOGINS fallos seguidos de la misma
# IP contra el mismo usuario, se bloquea el acceso durante LOCKOUT_SECONDS.
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300


def create_app(database_path=None):
    app = Flask(__name__)
    # La clave que firma las sesiones nunca va en el código: se exige por variable de
    # entorno (archivo .env, fuera de Git) y debe tener al menos 32 caracteres.
    secret_key = os.getenv("SECRET_KEY", "")
    if len(secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY no definida o demasiado corta (mínimo 32 caracteres). "
            "Defínala en el archivo .env (ver .env.example)."
        )
    app.config["SECRET_KEY"] = secret_key
    # Cookie de sesión endurecida: no accesible desde JavaScript y no enviada en
    # peticiones entre sitios. SECURE se activa con SESSION_COOKIE_SECURE=1 cuando hay HTTPS.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    )
    app.config["DATABASE_PATH"] = str(
        database_path or os.getenv("DATABASE_PATH", str(Path(__file__).with_name("securedev.db")))
    )

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.before_request
    def start_request_timer():
        g.request_started_at = time.perf_counter()
        # Nonce aleatorio por petición: autoriza solo el bloque <style> de la plantilla.
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_csp_nonce():
        return {"csp_nonce": g.get("csp_nonce", "")}

    @app.before_request
    def csrf_protect():
        # Todo POST debe traer el token de la sesión (protección CSRF).
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400)

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.after_request
    def record_request(response):
        # Cabeceras de seguridad (corrigen los hallazgos de OWASP ZAP).
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; style-src 'self' 'nonce-{g.get('csp_nonce', '')}'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Server"] = "SecureDev"  # no revelar versiones de Werkzeug/Python
        if request.endpoint != "metrics":
            endpoint = request.endpoint or "unknown"
            HTTP_REQUESTS.labels(endpoint, request.method, str(response.status_code)).inc()
            HTTP_DURATION.labels(endpoint).observe(time.perf_counter() - g.request_started_at)
        return response

    with app.app_context():
        Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
        connection = db()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                ticket_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [
                    (1, "ana", generate_password_hash("ana123")),
                    (2, "bruno", generate_password_hash("bruno123")),
                ],
            )
            connection.executemany(
                "INSERT INTO tickets (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, "Revisión de despliegue", "Preparar evidencias de CI/CD."),
                    (2, 2, "Acceso al panel", "Revisar registros de acceso."),
                ],
            )
        connection.commit()

    def current_user():
        return session.get("user_id")

    failed_logins = {}  # (ip, usuario) -> (cantidad de fallos, inicio de la ventana)
    failed_logins_lock = threading.Lock()

    def login_is_locked(key):
        with failed_logins_lock:
            count, started = failed_logins.get(key, (0, 0.0))
            if count and time.time() - started >= LOCKOUT_SECONDS:
                failed_logins.pop(key, None)  # la ventana venció: se reinicia el contador
                return False
            return count >= MAX_FAILED_LOGINS

    def register_failed_login(key):
        with failed_logins_lock:
            count, started = failed_logins.get(key, (0, time.time()))
            failed_logins[key] = (count + 1, started)

    def clear_failed_logins(key):
        with failed_logins_lock:
            failed_logins.pop(key, None)

    @app.route("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? ORDER BY id", (current_user(),)
        ).fetchall()
        return render_template("index.html", tickets=tickets)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            key = (request.remote_addr, username.lower())
            if login_is_locked(key):
                LOGIN_BLOCKED.inc()
                app.logger.warning("Login bloqueado ip=%s usuario=%r", request.remote_addr, username)
                return render_template(
                    "login.html", error="Demasiados intentos fallidos. Intente de nuevo en 5 minutos."
                ), 429
            user = db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                clear_failed_logins(key)
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("index"))
            LOGIN_FAILURES.inc()
            register_failed_login(key)
            app.logger.warning("Login fallido ip=%s usuario=%r", request.remote_addr, username)
            error = "Credenciales inválidas"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/tickets/<int:ticket_id>")
    def ticket(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        item = db().execute(
            "SELECT id, owner_id, title, body FROM tickets WHERE id = ?", (ticket_id,)
        ).fetchone()
        if item is None:
            abort(404)
        # Control de acceso: solo el dueño puede ver el ticket (evita IDOR).
        # Se responde 404 para no revelar que el ticket existe.
        if item["owner_id"] != current_user():
            abort(404)
        comments = db().execute(
            "SELECT body FROM comments WHERE ticket_id = ? ORDER BY id", (ticket_id,)
        ).fetchall()
        return render_template("ticket.html", ticket=item, comments=comments)

    @app.post("/tickets/<int:ticket_id>/comments")
    def add_comment(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        owner = db().execute("SELECT owner_id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        # Solo se puede comentar en tickets propios (evita IDOR).
        if owner is None or owner["owner_id"] != current_user():
            abort(404)
        body = request.form.get("body", "")
        db().execute(
            "INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
            (ticket_id, current_user(), body),
        )
        db().commit()
        return redirect(url_for("ticket", ticket_id=ticket_id))

    @app.get("/search")
    def search():
        if not current_user():
            return redirect(url_for("login"))
        query = request.args.get("q", "")
        # Consulta parametrizada: el texto del usuario nunca se interpreta como SQL.
        # Además se limita a los tickets del usuario autenticado.
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? AND title LIKE ? ORDER BY id",
            (current_user(), f"%{query}%"),
        ).fetchall()
        return render_template("search.html", tickets=tickets, query=query)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        # Solo Prometheus puede leer las métricas: exige "Authorization: Bearer <METRICS_TOKEN>".
        # Si el token no está configurado, el acceso se niega (falla cerrado).
        expected = os.getenv("METRICS_TOKEN", "")
        sent = request.headers.get("Authorization", "")
        if not expected or not hmac.compare_digest(sent, f"Bearer {expected}"):
            app.logger.warning("Acceso no autorizado a /metrics ip=%s", request.remote_addr)
            abort(401)
        return app.response_class(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8000)
