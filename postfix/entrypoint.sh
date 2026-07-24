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

# Die WebGUI erzeugt diese Map aus den Benutzerregeln. Beim allerersten Start
# kurz darauf warten, damit Postfix nicht mit einer fehlenden Lookup-Datei
# startet. Eine leere Map ist absichtlich "deny by default".
WAIT_COUNT=0
while [ ! -f /shared/sender_login_maps ] && [ "$WAIT_COUNT" -lt 30 ]; do
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 1))
done

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
    CUR_HASH="$(cat /shared/relayhost.txt /shared/sasl_passwd /shared/client_access /shared/sender_login_maps 2>/dev/null | md5sum)"
    if [ "$CUR_HASH" != "$LAST_HASH" ]; then
      LAST_HASH="$CUR_HASH"
      apply_smarthost_config
      postfix reload 2>/dev/null || true
    fi
  done
) &

# Queue-Snapshot fuer die WebGUI sowie kontrollierte Retry- und Loeschauftraege.
# Queue-IDs werden auch hier validiert, sodass das gemeinsame Volume keine
# beliebigen Kommandos in den Postfix-Container einschleusen kann.
mkdir -p /shared/queue_commands
(
  while true; do
    sleep 5

    if postqueue -j > /shared/mail_queue.json.tmp 2>/dev/null; then
      mv /shared/mail_queue.json.tmp /shared/mail_queue.json
    else
      rm -f /shared/mail_queue.json.tmp
    fi

    for QUEUE_COMMAND in /shared/queue_commands/*.retry /shared/queue_commands/*.delete; do
      [ -e "$QUEUE_COMMAND" ] || continue
      QUEUE_ID="$(tr -d '\r\n' < "$QUEUE_COMMAND")"
      case "$QUEUE_ID" in
        ""|*[!A-Za-z0-9]*)
          ;;
        *)
          case "$QUEUE_COMMAND" in
            *.retry)
              postqueue -i "$QUEUE_ID" 2>/dev/null || true
              ;;
            *.delete)
              postqueue -d "$QUEUE_ID" 2>/dev/null || true
              ;;
          esac
          ;;
      esac
      rm -f "$QUEUE_COMMAND"
    done
  done
) &

exec /usr/sbin/postfix start-fg
