# Changelog

## 2.0.1 - 2026-07-23

### Behoben

- WebGUI wartet mit nachvollziehbaren Retry-Logs auf eine abfragebereite MariaDB.
- Docker Compose verwendet Healthchecks, bevor abhaengige Dienste starten.
- Die MariaDB-Initialisierung bindet das Init-Verzeichnis robust ein.
- Postfix verwendet den aktuellen `postlog`-Service und eine explizite
  `compatibility_level = 3.6`-Konfiguration ohne Upgrade-Warnungen.
- Der Postfix-Start prueft die Konfiguration, ohne den fehleranfaelligen
  `set-permissions`-Integritaetscheck erneut auszufuehren.
