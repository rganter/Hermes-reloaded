#!/bin/bash
set -e

envsubst '${DB_HOST} ${DB_NAME} ${DB_USER} ${DB_PASSWORD}' \
  < /etc/dovecot/dovecot-sql.conf.ext.template \
  > /etc/dovecot/dovecot-sql.conf.ext

chmod 600 /etc/dovecot/dovecot-sql.conf.ext

mkdir -p /var/spool/postfix-auth
mkdir -p /var/run/dovecot

exec dovecot -F
