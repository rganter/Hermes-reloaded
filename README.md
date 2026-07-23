# Hermes 2.0.1 - SMTP-Relay mit User-Authentifizierung (Postfix + Dovecot-SASL + MariaDB + WebGUI)

Ein schlanker SMTP-Relay-Server für interne Systeme (z.B. Scanner, Applikationen),
die per Benutzername/Passwort authentifiziert Mails über einen vorgelagerten
Smarthost (z.B. Exchange/M365/Provider) versenden sollen. Kein Postfach-Empfang,
kein IMAP/POP3, kein Kalender.

## Architektur

```
Scanner/System --(SMTP + Auth, Port 587)--> Postfix --(SASL-Check)--> Dovecot --> MySQL
                                                |
                                                +--(Auth + TLS)--> Smarthost (Exchange/M365/...)
```

- **Postfix**: reiner Relay, nimmt auf Port 25 UND Port 587 (Submission)
  authentifizierte Verbindungen an und leitet alles an den konfigurierten
  Smarthost weiter. Auf beiden Ports ist Auth Pflicht.
- **Dovecot**: läuft NUR als SASL-Auth-Server (kein IMAP/POP3), prüft
  Benutzer/Passwort gegen die MySQL-Tabelle `users`.
- **MySQL/MariaDB**: speichert die Benutzer (Passwort als SHA512-CRYPT-Hash)
  sowie die Smarthost-Konfiguration (Tabelle `settings`).
- **WebGUI (Flask)**: Verwaltung der Benutzer (Anlegen/Bearbeiten/Löschen/
  Aktivieren-Deaktivieren), Pflege der Smarthost-Zugangsdaten, sowie
  Ansicht/Filterung der Postfix-Logs.

### Dynamische Smarthost-Konfiguration

Die Smarthost-Zugangsdaten (Server, Port, Benutzer, Passwort) werden nicht
mehr nur einmalig aus `.env` gelesen, sondern liegen in der MySQL-Tabelle
`settings` und sind über den Menüpunkt **Smarthost** in der WebGUI pflegbar.

Beim Speichern schreibt die WebGUI die Konfiguration zusätzlich auf ein mit
Postfix geteiltes Docker-Volume (`smarthost_config`). Ein kleiner Watcher im
Postfix-Container prüft alle 5 Sekunden, ob sich diese Dateien geändert haben,
übernimmt die Werte per `postconf -e` und führt automatisch `postfix reload`
aus – ganz ohne Container-Neustart.

**Authentifizierung gegenüber dem Smarthost ist optional.** Benutzername und
Passwort können in der WebGUI leer gelassen werden – dann liefert Postfix
ohne SASL-Auth an den Smarthost aus (z.B. wenn dieser stattdessen die
Absender-IP whitelisted). Sobald ein Benutzername hinterlegt wird, verlangt
Postfix wieder eine Authentifizierung gegenüber dem Smarthost.

Die `.env`-Werte `SMARTHOST`/`SMARTHOST_PORT`/`SMARTHOST_USER`/
`SMARTHOST_PASSWORD` dienen nur noch als **einmalige Erstbefüllung** beim
allerersten Start (wenn die `settings`-Tabelle noch leer ist). Danach ist
ausschließlich die WebGUI/Datenbank maßgeblich.

## Einrichtung

1. `.env.example` nach `.env` kopieren und ausfüllen:
   ```bash
   cp .env.example .env
   ```
   Wichtige Werte:
   - `SMARTHOST`, `SMARTHOST_PORT`, `SMARTHOST_USER`, `SMARTHOST_PASSWORD`:
     Zugangsdaten für den vorgelagerten Mailserver.
   - `MAIL_DOMAIN`: eure Absenderdomain.
   - `POSTFIX_FQDN`: vollständiger Hostname von Postfix, z.B.
     `relay.example.com`. Ohne Angabe wird `relay.<MAIL_DOMAIN>` verwendet.
   - `SMTP_PORT` / `SUBMISSION_PORT` / `WEBGUI_PORT`: nach außen
     veröffentlichte Host-Ports für SMTP, Submission und WebGUI; standardmäßig
     `25`, `587` und `8080`. Die Container verwenden intern weiterhin die
     Standardports 25, 587 und 8080.
   - `TZ`: IANA-Zeitzone für Container-Logs und Zeitstempel, z.B.
     `Europe/Berlin` (Standard) oder `UTC`.
   - `MYNETWORKS`: i.d.R. auf `127.0.0.0/8` belassen, dann muss **jeder**
     Client sich per SASL authentifizieren. Nur erweitern, wenn ihr bestimmten
     IP-Netzen zusätzlich ohne Auth vertrauen wollt.
   - `ADMIN_USER` / `ADMIN_PASSWORD`: Login für die WebGUI.
   - `SECRET_KEY`: langer Zufallsstring (z.B. `openssl rand -hex 32`).

2. Starten:
   ```bash
   docker compose up -d --build
   ```

   Docker Compose wartet mit Dovecot und der WebGUI, bis MariaDB ihren
   Healthcheck bestanden hat. Die WebGUI prueft beim Start zusaetzlich per
   Datenbankabfrage bis zu 30-mal im Abstand von zwei Sekunden, bevor sie ihr
   Schema anlegt.

3. WebGUI aufrufen: `http://<server>:8080` und mit `ADMIN_USER`/`ADMIN_PASSWORD`
   anmelden. Dort Benutzer für die Scanner/Systeme anlegen.

4. Scanner/System konfigurieren:
   - Server: `<docker-host>`
   - Port: `587` (STARTTLS/Submission) **oder** `25` (klassisches SMTP) –
     beide verlangen SASL-Authentifizierung
   - Authentifizierung: der in der WebGUI angelegte Benutzer

## Sicherheitshinweise

- Der Auth-Socket zwischen Postfix und Dovecot liegt auf einem gemeinsamen
  Docker-Volume mit `mode 0666`, da beide Container unterschiedliche
  UID-Namespaces haben. Das ist für ein internes, isoliertes Docker-Netz
  unkritisch, sollte aber nicht in geteilten/Multi-Tenant-Umgebungen so
  bleiben.
- Für Produktivbetrieb: TLS-Zertifikat für Postfix hinterlegen (aktuell
  `smtpd_tls_security_level = may`, d.h. TLS ist möglich aber nicht
  erzwungen) und Port 587 nicht ungeschützt ins Internet exponieren.
- Passwörter werden als `SHA512-CRYPT` gespeichert (kompatibel mit
  Dovecots `passdb sql`), niemals im Klartext.
- Die WebGUI hat aktuell einen einzelnen Admin-Account aus den
  Umgebungsvariablen. Für mehrere Admins müsste ein echtes Admin-User-Modell
  ergänzt werden.

## Logs

Die WebGUI liest `/var/log/postfix/mail.log` (per Docker-Volume aus dem
Postfix-Container gemountet) und zeigt die letzten Einträge, mit einfacher
Volltextfilterung (z.B. nach Benutzername, Absender oder Statuscode).

## Datenbank-Initialisierung

`mysql/init.sql` wird beim ersten Start eines **leeren** MariaDB-Datenvolumes
ausgefuehrt. Das gesamte Verzeichnis `mysql/` wird in das offizielle
MariaDB-Init-Verzeichnis eingebunden; dadurch wird die Datei auch unter Docker
Desktop verlaesslich als SQL-Datei erkannt. Bestehende Volumes werden von
MariaDB absichtlich nicht erneut initialisiert.

## Struktur

```
smtp-relay/
├── docker-compose.yml
├── .env.example
├── postfix/          # Relay + eingehende SASL-Auth + ausgehende Smarthost-Auth
├── dovecot/           # SASL-Auth-Server gegen MySQL
├── mysql/init.sql     # Tabelle "users"
└── webgui/             # Flask-App zur Benutzer-/Log-Verwaltung
```
