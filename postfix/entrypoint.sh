#!/bin/bash
set -e

# Bestehende Installationen ohne POSTFIX_FQDN behalten ihr bisheriges
# Hostnamensschema bei.
POSTFIX_FQDN="${POSTFIX_FQDN:-relay.${MAIL_DOMAIN}}"

envsubst '${MAIL_DOMAIN} ${MYNETWORKS} ${POSTFIX_FQDN}' \
  < /etc/postfix/main.cf.template \
  > /etc/postfix/main.cf

mkdir -p /var/log/postfix /var/spool/postfix-auth
chown postfix:postfix /var/log/postfix

# ---------------------------------------------------------------------------
# Smarthost-Konfiguration wird von der WebGUI in /shared abgelegt:
#   /shared/relayhost.txt   -> Inhalt: "[host]:port"
#   /shared/sasl_passwd     -> Inhalt: "[host]:port user:password" (Klartext)
# "texthash:" braucht keine kompilierte .db-Datei und kann daher direkt aus
# dem gemeinsamen Volume gelesen werden - kein postmap noetig.
# ---------------------------------------------------------------------------
apply_smarthost_config() {
  if [ -f /shared/relayhost.txt ]; then
    RELAYHOST="$(cat /shared/relayhost.txt)"
    postconf -e "relayhost = ${RELAYHOST}"
  elif [ -n "${SMARTHOST}" ]; then
    # Fallback, falls die WebGUI noch keine Konfiguration geschrieben hat
    postconf -e "relayhost = [${SMARTHOST}]:${SMARTHOST_PORT}"
  fi

  if [ -f /shared/sasl_passwd ]; then
    postconf -e "smtp_sasl_password_maps = texthash:/shared/sasl_passwd"
  fi

  if [ -f /shared/client_access ]; then
    postconf -e "smtpd_client_restrictions = check_client_access texthash:/shared/client_access"
  fi
}

apply_smarthost_config

# Die Paketinstallation setzt die erforderlichen Dateirechte bereits. Ein
# erneutes "postfix set-permissions" in einem Container fuehrt bei aktuellen
# Postfix-Versionen zu einem fehlgeschlagenen Integritaetscheck. Stattdessen
# pruefen wir die fertige Konfiguration einmal vor dem Start.
postfix check

# Hintergrund-Watcher: erkennt Aenderungen an der Smarthost-Konfiguration
# (von der WebGUI geschrieben) und laedt Postfix automatisch neu - kein
# manueller Container-Restart noetig.
(
  LAST_HASH=""
  while true; do
    sleep 5
    CUR_HASH="$(cat /shared/relayhost.txt /shared/sasl_passwd /shared/client_access 2>/dev/null | md5sum)"
    if [ "$CUR_HASH" != "$LAST_HASH" ]; then
      LAST_HASH="$CUR_HASH"
      apply_smarthost_config
      postfix reload 2>/dev/null || true
    fi
  done
) &

exec /usr/sbin/postfix start-fg
