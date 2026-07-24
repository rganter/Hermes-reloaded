FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix libsasl2-modules gettext-base openssl tzdata && \
    rm -rf /var/lib/apt/lists/*

COPY main.cf.template /etc/postfix/main.cf.template
COPY master.cf /etc/postfix/master.cf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 587
ENTRYPOINT ["/entrypoint.sh"]
