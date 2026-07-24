import os
import re
import time
import ipaddress
import json
import threading
import uuid
from datetime import timedelta
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
CLIENT_ACCESS_FILE = os.path.join(SHARED_DIR, "client_access")
SENDER_LOGIN_MAP_FILE = os.path.join(SHARED_DIR, "sender_login_maps")
MAIL_QUEUE_FILE = os.path.join(SHARED_DIR, "mail_queue.json")
MAIL_QUEUE_COMMAND_DIR = os.path.join(SHARED_DIR, "queue_commands")
QUEUE_ID_PATTERN = re.compile(r"^[A-Za-z0-9]{1,64}$")
LOGIN_FAILURE_PATTERN = re.compile(
    r"\[(?P<ip>[^\]]+)\]: SASL .*authentication failed", re.IGNORECASE
)

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
    allowed_sender_domain = db.Column(db.String(255), nullable=True)
    allow_any_sender = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    sender_addresses = db.relationship(
        "UserSenderAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="UserSenderAddress.sender_address",
    )

    def set_password(self, plain_password: str):
        # Erzeugt einen Hash im Dovecot-kompatiblen SHA512-CRYPT-Format
        self.password = sha512_crypt.hash(plain_password)


class UserSenderAddress(db.Model):
    __tablename__ = "user_sender_addresses"
    __table_args__ = (
        db.UniqueConstraint("user_id", "sender_address", name="uq_user_sender_address"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    sender_address = db.Column(db.String(320), nullable=False)
    user = db.relationship("SmtpUser", back_populates="sender_addresses")


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True, default=1)
    smarthost = db.Column(db.String(255), nullable=False)
    smarthost_port = db.Column(db.Integer, nullable=False, default=587)
    smarthost_user = db.Column(db.String(255), nullable=True)
    smarthost_password = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecuritySettings(db.Model):
    __tablename__ = "security_settings"

    id = db.Column(db.Integer, primary_key=True, default=1)
    max_login_failures = db.Column(db.Integer, nullable=False, default=5)
    block_duration_minutes = db.Column(db.Integer, nullable=False, default=30)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LoginBlock(db.Model):
    __tablename__ = "login_blocks"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    first_failure_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_failure_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    blocked_until = db.Column(db.DateTime, nullable=True)


class LogMonitorState(db.Model):
    __tablename__ = "log_monitor_state"

    id = db.Column(db.Integer, primary_key=True, default=1)
    log_inode = db.Column(db.String(64), nullable=True)
    log_offset = db.Column(db.BigInteger, nullable=False, default=0)


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


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@+-]+$")
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
DOMAIN_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def parse_sender_rules():
    """Validate and normalize the sender restrictions from the user form."""
    raw_addresses = request.form.get("sender_addresses", "")
    addresses = []
    for value in re.split(r"[\r\n,;]+", raw_addresses):
        address = value.strip().lower()
        if address and address not in addresses:
            addresses.append(address)

    invalid_addresses = [address for address in addresses if not EMAIL_PATTERN.fullmatch(address)]
    domain = request.form.get("allowed_sender_domain", "").strip().lower()
    if domain.startswith("@"):
        domain = domain[1:]
    allow_any = bool(request.form.get("allow_any_sender"))

    if invalid_addresses:
        return None, None, None, (
            "Ungueltige Absenderadresse(n): " + ", ".join(invalid_addresses)
        )
    if domain and not DOMAIN_PATTERN.fullmatch(domain):
        return None, None, None, "Die erlaubte Absenderdomain ist ungueltig."
    if not allow_any and not addresses and not domain:
        return None, None, None, (
            "Mindestens eine Absenderadresse, eine Domain oder die Ausnahme "
            "fuer beliebige Absender ist erforderlich."
        )
    return addresses, domain or None, allow_any, None


def apply_sender_rules(user, addresses, domain, allow_any):
    user.allowed_sender_domain = domain
    user.allow_any_sender = allow_any
    user.sender_addresses = [
        UserSenderAddress(sender_address=address) for address in addresses
    ]


@app.route("/users/new", methods=["GET", "POST"])
@login_required
def user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        active = bool(request.form.get("active"))
        addresses, domain, allow_any, sender_error = parse_sender_rules()

        if not username or not password:
            flash("Benutzername und Passwort sind Pflichtfelder.", "danger")
            return render_template("user_form.html", user=None)

        if not USERNAME_PATTERN.fullmatch(username):
            flash("Der Benutzername enthaelt unzulaessige Zeichen.", "danger")
            return render_template("user_form.html", user=None)

        if sender_error:
            flash(sender_error, "danger")
            return render_template("user_form.html", user=None)

        if SmtpUser.query.filter_by(username=username).first():
            flash("Dieser Benutzername existiert bereits.", "danger")
            return render_template("user_form.html", user=None)

        user = SmtpUser(username=username, active=active)
        user.set_password(password)
        apply_sender_rules(user, addresses, domain, allow_any)
        db.session.add(user)
        db.session.commit()
        write_sender_login_map()
        flash(f"Benutzer '{username}' wurde angelegt.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", user=None)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(user_id):
    user = SmtpUser.query.get_or_404(user_id)

    if request.method == "POST":
        password = request.form.get("password", "")
        addresses, domain, allow_any, sender_error = parse_sender_rules()
        if sender_error:
            flash(sender_error, "danger")
            return render_template("user_form.html", user=user)

        user.active = bool(request.form.get("active"))
        if password:
            user.set_password(password)
        apply_sender_rules(user, addresses, domain, allow_any)
        db.session.commit()
        write_sender_login_map()
        flash(f"Benutzer '{user.username}' wurde aktualisiert.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", user=user)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def user_delete(user_id):
    user = SmtpUser.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    write_sender_login_map()
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


def get_security_settings() -> "SecuritySettings":
    settings = SecuritySettings.query.get(1)
    if settings is None:
        settings = SecuritySettings(id=1)
        db.session.add(settings)
        db.session.commit()
    return settings


def write_client_access_map():
    """Write active IP blocks for Postfix' dynamically read texthash map."""
    os.makedirs(SHARED_DIR, exist_ok=True)
    now = datetime.utcnow()
    active_blocks = LoginBlock.query.filter(
        LoginBlock.blocked_until.isnot(None),
        LoginBlock.blocked_until > now,
    ).order_by(LoginBlock.ip_address).all()

    temporary = f"{CLIENT_ACCESS_FILE}.tmp"
    with open(temporary, "w") as access_map:
        for block in active_blocks:
            access_map.write(f"{block.ip_address} REJECT\n")
    os.replace(temporary, CLIENT_ACCESS_FILE)


def write_sender_login_map():
    """Write Postfix regexp ownership rules for authenticated envelope senders."""
    os.makedirs(SHARED_DIR, exist_ok=True)
    users = SmtpUser.query.filter_by(active=True).order_by(SmtpUser.username).all()
    any_owners = {user.username for user in users if user.allow_any_sender}
    domain_owners = {}
    address_owners = {}

    for user in users:
        if user.allowed_sender_domain:
            domain_owners.setdefault(user.allowed_sender_domain.lower(), set()).add(user.username)
        for sender in user.sender_addresses:
            address_owners.setdefault(sender.sender_address.lower(), set()).add(user.username)

    lines = []
    for address, owners in sorted(address_owners.items()):
        address_domain = address.rsplit("@", 1)[1]
        all_owners = owners | domain_owners.get(address_domain, set()) | any_owners
        pattern = re.escape(address)
        lines.append(f"/^{pattern}$/i {','.join(sorted(all_owners))}\n")

    for domain, owners in sorted(domain_owners.items()):
        all_owners = owners | any_owners
        pattern = re.escape(domain)
        lines.append(f"/^[^@]+@{pattern}$/i {','.join(sorted(all_owners))}\n")

    if any_owners:
        lines.append(f"/^.+$/ {','.join(sorted(any_owners))}\n")

    temporary = f"{SENDER_LOGIN_MAP_FILE}.tmp"
    with open(temporary, "w") as sender_map:
        sender_map.writelines(lines)
    os.replace(temporary, SENDER_LOGIN_MAP_FILE)


def expire_login_blocks():
    expired = LoginBlock.query.filter(
        LoginBlock.blocked_until.isnot(None),
        LoginBlock.blocked_until <= datetime.utcnow(),
    ).all()
    if expired:
        for block in expired:
            db.session.delete(block)
        db.session.commit()
        write_client_access_map()


def record_login_failure(ip_address):
    """Count a failed SASL login and block the address at the configured limit."""
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return

    now = datetime.utcnow()
    security = get_security_settings()
    block = LoginBlock.query.filter_by(ip_address=ip_address).first()
    if block and block.blocked_until and block.blocked_until > now:
        return
    if block is None:
        block = LoginBlock(
            ip_address=ip_address,
            failed_attempts=0,
            first_failure_at=now,
            last_failure_at=now,
        )
        db.session.add(block)

    block.failed_attempts = (block.failed_attempts or 0) + 1
    block.last_failure_at = now
    if block.failed_attempts >= security.max_login_failures:
        block.blocked_until = now + timedelta(minutes=security.block_duration_minutes)
        db.session.commit()
        write_client_access_map()
        app.logger.warning(
            "IP-Adresse %s bis %s wegen fehlgeschlagener Anmeldungen gesperrt.",
            ip_address,
            block.blocked_until.isoformat(),
        )
    else:
        db.session.commit()


def scan_login_failures():
    """Read only newly appended Postfix log lines and record SASL failures."""
    if not os.path.exists(LOG_FILE):
        return

    file_stat = os.stat(LOG_FILE)
    inode = str(file_stat.st_ino)
    state = LogMonitorState.query.get(1)
    if state is None:
        # Existing log history is not treated as a new attack after upgrades.
        state = LogMonitorState(id=1, log_inode=inode, log_offset=file_stat.st_size)
        db.session.add(state)
        db.session.commit()
        return

    if state.log_inode != inode or file_stat.st_size < state.log_offset:
        state.log_inode = inode
        state.log_offset = 0

    with open(LOG_FILE, "r", errors="replace") as log_file:
        log_file.seek(state.log_offset)
        lines = log_file.readlines()
        state.log_offset = log_file.tell()
    state.log_inode = inode

    for line in lines:
        match = LOGIN_FAILURE_PATTERN.search(line)
        if match:
            record_login_failure(match.group("ip"))
    db.session.commit()


def monitor_login_failures():
    """Ensure exactly one Gunicorn worker monitors the shared Postfix log."""
    while True:
        lock_connection = None
        try:
            with app.app_context():
                lock_connection = db.engine.raw_connection()
                cursor = lock_connection.cursor()
                cursor.execute("SELECT GET_LOCK('hermes_login_failure_monitor', 0)")
                acquired = cursor.fetchone()[0] == 1
                cursor.close()
            if not acquired:
                lock_connection.close()
                time.sleep(5)
                continue

            app.logger.info("Starte Monitor fuer fehlgeschlagene SMTP-Anmeldungen.")
            while True:
                with app.app_context():
                    try:
                        expire_login_blocks()
                        scan_login_failures()
                    except Exception as exc:  # pragma: no cover
                        app.logger.warning("Login-Schutzmonitor fehlgeschlagen: %s", exc)
                    finally:
                        db.session.remove()
                time.sleep(5)
        except Exception as exc:  # pragma: no cover
            app.logger.warning("Login-Schutzmonitor nicht verfuegbar: %s", exc)
            time.sleep(5)
        finally:
            if lock_connection is not None:
                try:
                    lock_connection.close()
                except Exception:
                    pass


def start_login_failure_monitor():
    threading.Thread(
        target=monitor_login_failures,
        name="login-failure-monitor",
        daemon=True,
    ).start()


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    settings = get_settings()
    security_settings = get_security_settings()

    if request.method == "POST":
        smarthost = request.form.get("smarthost", "").strip()
        smarthost_port = request.form.get("smarthost_port", "587").strip()
        smarthost_user = request.form.get("smarthost_user", "").strip()
        smarthost_password = request.form.get("smarthost_password", "")
        logo = request.files.get("logo")
        max_login_failures = request.form.get("max_login_failures", "").strip()
        block_duration_minutes = request.form.get("block_duration_minutes", "").strip()

        if not smarthost or not smarthost_port:
            flash("Server und Port sind Pflichtfelder.", "danger")
            return render_template("settings.html", settings=settings,
                                   security_settings=security_settings)
        try:
            max_login_failures = int(max_login_failures)
            block_duration_minutes = int(block_duration_minutes)
            if max_login_failures < 1 or block_duration_minutes < 1:
                raise ValueError
        except ValueError:
            flash("Anzahl der Fehlversuche und Sperrdauer muessen positiv sein.", "danger")
            return render_template("settings.html", settings=settings,
                                   security_settings=security_settings)
        if logo and logo.filename:
            extension = os.path.splitext(logo.filename.lower())[1]
            if extension not in LOGO_FILENAMES:
                flash("Bitte PNG, JPG, GIF oder WebP als Logo hochladen.", "danger")
                return render_template("settings.html", settings=settings,
                                       security_settings=security_settings)

        settings.smarthost = smarthost
        settings.smarthost_port = int(smarthost_port)
        settings.smarthost_user = smarthost_user or None
        # Passwort nur ueberschreiben, wenn ein neues eingegeben wurde
        if smarthost_password:
            settings.smarthost_password = smarthost_password
        elif not smarthost_user:
            # Kein Benutzername mehr -> auch gespeichertes Passwort verwerfen
            settings.smarthost_password = None

        security_settings.max_login_failures = max_login_failures
        security_settings.block_duration_minutes = block_duration_minutes

        db.session.commit()
        write_postfix_config(settings)

        if logo and logo.filename:
            save_logo(logo)

        flash("Einstellungen gespeichert. Postfix uebernimmt Smarthost-"
              "Aenderungen innerhalb weniger Sekunden automatisch.", "success")
        return redirect(url_for("settings_page"))

    return render_template("settings.html", settings=settings,
                           security_settings=security_settings)


@app.route("/security/blocks")
@login_required
def blocked_ips():
    expire_login_blocks()
    blocks = LoginBlock.query.filter(
        LoginBlock.blocked_until.isnot(None),
        LoginBlock.blocked_until > datetime.utcnow(),
    ).order_by(LoginBlock.blocked_until).all()
    return render_template("blocked_ips.html", blocks=blocks)


@app.route("/security/blocks/<int:block_id>/unlock", methods=["POST"])
@login_required
def unlock_ip(block_id):
    block = LoginBlock.query.get_or_404(block_id)
    ip_address = block.ip_address
    db.session.delete(block)
    db.session.commit()
    write_client_access_map()
    flash(f"IP-Adresse {ip_address} wurde entsperrt.", "success")
    return redirect(url_for("blocked_ips"))


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


def read_mail_queue():
    """Read Postfix' line-delimited JSON queue snapshot."""
    messages = []
    if not os.path.isfile(MAIL_QUEUE_FILE):
        return messages, None

    try:
        snapshot_time = datetime.fromtimestamp(os.path.getmtime(MAIL_QUEUE_FILE))
        with open(MAIL_QUEUE_FILE, "r", encoding="utf-8") as queue_file:
            for line in queue_file:
                if not line.strip():
                    continue
                message = json.loads(line)
                arrival_time = message.get("arrival_time")
                message["arrival_datetime"] = (
                    datetime.fromtimestamp(arrival_time) if arrival_time else None
                )
                messages.append(message)
        messages.sort(key=lambda item: item.get("arrival_time", 0))
        return messages, snapshot_time
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        app.logger.warning("Mailqueue-Snapshot konnte nicht gelesen werden: %s", exc)
        return [], None


@app.route("/queue")
@login_required
def mail_queue():
    messages, snapshot_time = read_mail_queue()
    total_size = sum(message.get("message_size", 0) for message in messages)
    return render_template(
        "queue.html",
        messages=messages,
        snapshot_time=snapshot_time,
        total_size=total_size,
    )


@app.route("/queue/<queue_id>/retry", methods=["POST"])
@login_required
def retry_queued_mail(queue_id):
    if not QUEUE_ID_PATTERN.fullmatch(queue_id):
        flash("Ungueltige Queue-ID.", "danger")
        return redirect(url_for("mail_queue"))

    messages, _ = read_mail_queue()
    queued_message = next(
        (message for message in messages if message.get("queue_id") == queue_id),
        None,
    )
    if queued_message is None or queued_message.get("queue_name") != "deferred":
        flash(
            "Die Nachricht ist nicht mehr in der Deferred-Queue.",
            "warning",
        )
        return redirect(url_for("mail_queue"))

    write_queue_command(queue_id, "retry")

    flash(
        f"Die erneute Zustellung von Queue-Eintrag {queue_id} wurde angefordert.",
        "success",
    )
    return redirect(url_for("mail_queue"))


def write_queue_command(queue_id, command):
    """Atomically hand a validated queue command to the Postfix container."""
    os.makedirs(MAIL_QUEUE_COMMAND_DIR, exist_ok=True)
    request_name = f"{uuid.uuid4().hex}.{command}"
    target = os.path.join(MAIL_QUEUE_COMMAND_DIR, request_name)
    temporary = f"{target}.tmp"
    with open(temporary, "w", encoding="ascii") as request_file:
        request_file.write(queue_id + "\n")
    os.replace(temporary, target)


@app.route("/queue/<queue_id>/delete", methods=["POST"])
@login_required
def delete_queued_mail(queue_id):
    if not QUEUE_ID_PATTERN.fullmatch(queue_id):
        flash("Ungueltige Queue-ID.", "danger")
        return redirect(url_for("mail_queue"))

    messages, _ = read_mail_queue()
    if not any(message.get("queue_id") == queue_id for message in messages):
        flash("Die Nachricht ist nicht mehr in der Mailqueue.", "warning")
        return redirect(url_for("mail_queue"))

    write_queue_command(queue_id, "delete")
    flash(
        f"Das Loeschen von Queue-Eintrag {queue_id} wurde angefordert.",
        "success",
    )
    return redirect(url_for("mail_queue"))


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


def ensure_sender_rule_columns():
    """Add sender-rule columns when a database was initialized by an older image."""
    statements = (
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
        "allowed_sender_domain VARCHAR(255) NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
        "allow_any_sender TINYINT(1) NOT NULL DEFAULT 0",
    )
    with db.engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


with app.app_context():
    wait_for_database()
    app.logger.info("Initialisiere Datenbankschema.")
    db.create_all()
    ensure_sender_rule_columns()
    # Beim Start sicherstellen, dass Postfix eine aktuelle Konfiguration
    # vorfindet - auch wenn seit dem letzten GUI-Save nichts geaendert wurde
    # (z.B. nach einem "docker compose down/up" mit frischem Postfix-Volume).
    try:
        _settings = get_settings()
        get_security_settings()
        if _settings.smarthost:
            write_postfix_config(_settings)
        write_client_access_map()
        write_sender_login_map()
    except Exception as exc:  # pragma: no cover
        app.logger.warning("Konnte Smarthost-Konfiguration nicht schreiben: %s", exc)

    start_login_failure_monitor()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
