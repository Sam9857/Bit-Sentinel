import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import timedelta

# ── Basic Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ── Flask App Setup ──────────────────────────────────────────────────────────
app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB max upload

# ⚠️ Use strong secret key in production
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    os.urandom(32)  # safer default instead of hardcoded string
)

# Session stability settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # Set True if using HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# ── Hardcoded Admin Credentials ───────────────────────────────────────────────
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# ── Auth Helper ───────────────────────────────────────────────────────────────
def is_authenticated():
    return session.get("authenticated") is True

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if not is_authenticated():
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()  # prevent session fixation
            session["authenticated"] = True
            session["username"] = username
            session.permanent = True
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials. Please try again."

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Security Headers ─────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response

# ── Error Handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large"}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests"}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ── Lazy-load Blueprints ──────────────────────────────────────────────────────
def register_blueprints(app):
    blueprints = [
        ("routes.api_routes", "api"),
        ("routes.prevention_routes", "prevention"),
        ("routes.stream_routes", "stream"),
        ("routes.monitor_routes", "live_bp"),
    ]

    for module_path, bp_name in blueprints:
        try:
            module = __import__(module_path, fromlist=[bp_name])
            blueprint = getattr(module, bp_name)
            app.register_blueprint(blueprint)
            logger.info(f"Registered {bp_name}")
        except Exception as e:
            logger.error(f"Failed to register {bp_name}: {e}")

register_blueprints(app)

# ── Lazy-load Rate Limiter ────────────────────────────────────────────────────
def init_rate_limiter():
    try:
        from models.prevention_engine import get_config
        from utils.rate_limiter import limiter

        _cfg = get_config()
        limiter.update_config(
            max_requests=_cfg.get("rate_limit_max_requests", 100),
            window_seconds=_cfg.get("rate_limit_window_seconds", 60),
        )
        logger.info("Rate limiter initialized")
    except Exception as e:
        logger.warning(f"Rate limiter setup skipped: {e}")

init_rate_limiter()

# ── Lazy-load Traffic Tap ─────────────────────────────────────────────────────
def init_traffic_tap():
    try:
        import utils.traffic_tap as traffic_tap
        traffic_tap.register(app)
        logger.info("Traffic tap registered")
    except Exception as e:
        logger.warning(f"Traffic tap not registered: {e}")

init_traffic_tap()

# ── Run Flask App ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting Flask app...")

    # ❌ DO NOT use debug=True in production
    DEBUG_MODE = os.environ.get("FLASK_DEBUG", "False") == "True"

    app.run(
        debug=DEBUG_MODE,
        host="0.0.0.0",
        port=5000,
        threaded=True
    )