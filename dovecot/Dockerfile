FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends dovecot-core dovecot-mysql gettext-base && \
    rm -rf /var/lib/apt/lists/*

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY dovecot-sql.conf.ext.template /etc/dovecot/dovecot-sql.conf.ext.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
