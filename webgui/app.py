import os
import re
import time
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from passlib.hash import sha512_crypt

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST", "mysql")
DB_NAME = os.environ.get("DB_NAME", "mailrelay")
DB_USER = os.environ.get("DB_USER", "mailrelay")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/postfix/mail.log")
LOG_MAX_LINES = 1000

# Gemeinsames Volume mit dem Postfix-Container, ueber das die
# Smarthost-Konfiguration (Relayhost + SASL-Zugangsdaten) uebergeben wird.
SHARED_DIR = os.environ.get("SHARED_DIR", "/shared")
LOGO_FILENAMES = {
    ".png": "logo.png",
    ".jpg": "logo.jpg",
    ".jpeg": "logo.jpeg",
    ".gif": "logo.gif",
    ".webp": "logo.webp",
}
LOGO_MIMETYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}

# Nur zur einmaligen Erstbefuellung der "settings"-Tabelle, falls noch leer.
BOOTSTRAP_SMARTHOST = os.environ.get("SMARTHOST", "")
BOOTSTRAP_SMARTHOST_PORT = os.environ.get("SMARTHOST_PORT", "587")
BOOTSTRAP_SMARTHOST_USER = os.environ.get("SMARTHOST_USER", "")
BOOTSTRAP_SMARTHOST_PASSWORD = os.environ.get("SMARTHOST_PASSWORD", "")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
# Eine geschuetzte Seite leitet direkt zum Login weiter, ohne eine irrefuehrende
# Standardmeldung auf der Login-Seite einzublenden.
login_manager.login_message = None


# ---------------------------------------------------------------------------
# Modelle
# ---------------------------------------------------------------------------
class SmtpUser(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(190), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # SHA512-CRYPT Hash
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, plain_password: str):
        # Erzeugt einen Hash im Dovecot-kompatiblen SHA512-CRYPT-Format
        self.password = sha512_crypt.hash(plain_password)


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True, default=1)
    smarthost = db.Column(db.String(255), nullable=False)
    smarthost_port = db.Column(db.Integer, nullable=False, default=587)
    smarthost_user = db.Column(db.String(255), nullable=True)
    smarthost_password = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Es gibt bewusst KEIN eigenes Admin-User-Modell in der DB - der GUI-Login
# nutzt einen einzelnen Admin-Account aus den Umgebungsvariablen.
class AdminUser(UserMixin):
    id = "admin"


@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return AdminUser()
    return None


def get_logo_path():
    """Return the persisted logo file and its extension, if configured."""
    for extension, filename in LOGO_FILENAMES.items():
        path = os.path.join(SHARED_DIR, filename)
        if os.path.isfile(path):
            return path, extension
    return None, None


def save_logo(logo):
    """Persist an uploaded logo in the shared Docker volume."""
    extension = os.path.splitext(logo.filename.lower())[1]
    if extension not in LOGO_FILENAMES:
        raise ValueError("Bitte PNG, JPG, GIF oder WebP als Logo hochladen.")

    os.makedirs(SHARED_DIR, exist_ok=True)
    target = os.path.join(SHARED_DIR, LOGO_FILENAMES[extension])
    temporary = f"{target}.upload"
    logo.save(temporary)
    os.replace(temporary, target)

    for filename in LOGO_FILENAMES.values():
        old_logo = os.path.join(SHARED_DIR, filename)
        if old_logo != target and os.path.isfile(old_logo):
            os.remove(old_logo)


@app.context_processor
def inject_logo():
    path, _ = get_logo_path()
    if path:
        return {"logo_url": url_for("logo", v=int(os.path.getmtime(path)))}
    return {"logo_url": None}


# ---------------------------------------------------------------------------
# Auth-Routen
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            login_user(AdminUser())
            return redirect(url_for("users_list"))
        flash("Benutzername oder Passwort falsch.", "danger")
    return render_template("login.html")


@app.route("/logo")
def logo():
    path, extension = get_logo_path()
    if not path:
        return "", 404
    return send_file(path, mimetype=LOGO_MIMETYPES[extension], conditional=True)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Benutzerverwaltung (SMTP-Auth-User in MySQL)
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    return redirect(url_for("users_list"))


@app.route("/users")
@login_required
def users_list():
    users = SmtpUser.query.order_by(SmtpUser.username).all()
    return render_template("users.html", users=users)


@app.route("/users/new", methods=["GET", "POST"])
@login_required
def user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        active = bool(request.form.get("active"))

        if not username or not password:
            flash("Benutzername und Passwort sind Pflichtfelder.", "danger")
            return render_template("user_form.html", user=None)

        if SmtpUser.query.filter_by(username=username).first():
            flash("Dieser Benutzername existiert bereits.", "danger")
            return render_template("user_form.html", user=None)

        user = SmtpUser(username=username, active=active)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f"Benutzer '{username}' wurde angelegt.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", user=None)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(user_id):
    user = SmtpUser.query.get_or_404(user_id)

    if request.method == "POST":
        password = request.form.get("password", "")
        user.active = bool(request.form.get("active"))
        if password:
            user.set_password(password)
        db.session.commit()
        flash(f"Benutzer '{user.username}' wurde aktualisiert.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", user=user)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def user_delete(user_id):
    user = SmtpUser.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"Benutzer '{user.username}' wurde geloescht.", "success")
    return redirect(url_for("users_list"))


# ---------------------------------------------------------------------------
# Smarthost-Konfiguration
# ---------------------------------------------------------------------------
def write_postfix_config(settings: "Settings"):
    """Schreibt die aktuelle Smarthost-Konfiguration auf das mit Postfix
    geteilte Volume. Der Postfix-Container erkennt Aenderungen per Watcher
    und laedt sich automatisch neu (kein manueller Restart noetig).

    Ist kein Benutzername hinterlegt, wird eine leere sasl_passwd-Datei
    geschrieben: Postfix liefert dann laut Doku ohne SASL-Authentifizierung
    an diesen Smarthost aus (z.B. bei IP-Whitelisting statt Auth)."""
    os.makedirs(SHARED_DIR, exist_ok=True)

    relayhost_line = f"[{settings.smarthost}]:{settings.smarthost_port}"
    with open(os.path.join(SHARED_DIR, "relayhost.txt"), "w") as f:
        f.write(relayhost_line + "\n")

    sasl_path = os.path.join(SHARED_DIR, "sasl_passwd")
    if settings.smarthost_user:
        # texthash-Format: "<lookup-key> <wert>" - kein postmap noetig
        sasl_line = f"{relayhost_line} {settings.smarthost_user}:{settings.smarthost_password or ''}"
        with open(sasl_path, "w") as f:
            f.write(sasl_line + "\n")
    else:
        # Keine Zugangsdaten hinterlegt -> Datei leeren, damit evtl. vorher
        # gespeicherte Credentials nicht weiter verwendet werden
        open(sasl_path, "w").close()


def get_settings() -> "Settings":
    settings = Settings.query.get(1)
    if settings is None:
        settings = Settings(
            id=1,
            smarthost=BOOTSTRAP_SMARTHOST,
            smarthost_port=int(BOOTSTRAP_SMARTHOST_PORT or 587),
            smarthost_user=BOOTSTRAP_SMARTHOST_USER,
            smarthost_password=BOOTSTRAP_SMARTHOST_PASSWORD,
        )
        db.session.add(settings)
        db.session.commit()
    return settings


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    settings = get_settings()

    if request.method == "POST":
        smarthost = request.form.get("smarthost", "").strip()
        smarthost_port = request.form.get("smarthost_port", "587").strip()
        smarthost_user = request.form.get("smarthost_user", "").strip()
        smarthost_password = request.form.get("smarthost_password", "")
        logo = request.files.get("logo")

        if not smarthost or not smarthost_port:
            flash("Server und Port sind Pflichtfelder.", "danger")
            return render_template("settings.html", settings=settings)
        if logo and logo.filename:
            extension = os.path.splitext(logo.filename.lower())[1]
            if extension not in LOGO_FILENAMES:
                flash("Bitte PNG, JPG, GIF oder WebP als Logo hochladen.", "danger")
                return render_template("settings.html", settings=settings)

        settings.smarthost = smarthost
        settings.smarthost_port = int(smarthost_port)
        settings.smarthost_user = smarthost_user or None
        # Passwort nur ueberschreiben, wenn ein neues eingegeben wurde
        if smarthost_password:
            settings.smarthost_password = smarthost_password
        elif not smarthost_user:
            # Kein Benutzername mehr -> auch gespeichertes Passwort verwerfen
            settings.smarthost_password = None

        db.session.commit()
        write_postfix_config(settings)

        if logo and logo.filename:
            save_logo(logo)

        flash("Einstellungen gespeichert. Postfix uebernimmt Smarthost-"
              "Aenderungen innerhalb weniger Sekunden automatisch.", "success")
        return redirect(url_for("settings_page"))

    return render_template("settings.html", settings=settings)


# ---------------------------------------------------------------------------
# Log-Ansicht
# ---------------------------------------------------------------------------
@app.route("/logs")
@login_required
def logs():
    search = request.args.get("q", "").strip()
    lines = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", errors="replace") as f:
            all_lines = f.readlines()[-5000:]  # nur die letzten 5000 Zeilen einlesen

        if search:
            pattern = re.compile(re.escape(search), re.IGNORECASE)
            all_lines = [l for l in all_lines if pattern.search(l)]

        lines = all_lines[-LOG_MAX_LINES:]
        lines.reverse()  # neueste zuerst

    return render_template("logs.html", lines=lines, search=search, log_file=LOG_FILE)


# ---------------------------------------------------------------------------


def wait_for_database(max_retries=30, delay=2):
    """Wait until MariaDB accepts queries before creating application tables."""
    app.logger.info(
        "Warte auf MariaDB unter %s (maximal %d Versuche).",
        DB_HOST,
        max_retries,
    )
    for attempt in range(1, max_retries + 1):
        try:
            with db.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            app.logger.info("MariaDB ist nach %d Versuch(en) erreichbar.", attempt)
            return
        except SQLAlchemyError as exc:
            if attempt == max_retries:
                app.logger.error(
                    "MariaDB war nach %d Versuchen nicht erreichbar: %s",
                    max_retries,
                    exc,
                )
                raise RuntimeError("MariaDB konnte nicht erreicht werden.") from exc
            app.logger.warning(
                "MariaDB noch nicht erreichbar (%d/%d): %s. Neuer Versuch in %d Sekunden.",
                attempt,
                max_retries,
                exc,
                delay,
            )
            time.sleep(delay)

with app.app_context():
    wait_for_database()
    app.logger.info("Initialisiere Datenbankschema.")
    db.create_all()
    # Beim Start sicherstellen, dass Postfix eine aktuelle Konfiguration
    # vorfindet - auch wenn seit dem letzten GUI-Save nichts geaendert wurde
    # (z.B. nach einem "docker compose down/up" mit frischem Postfix-Volume).
    try:
        _settings = get_settings()
        if _settings.smarthost:
            write_postfix_config(_settings)
    except Exception as exc:  # pragma: no cover
        app.logger.warning("Konnte Smarthost-Konfiguration nicht schreiben: %s", exc)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
