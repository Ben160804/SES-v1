FROM debian:bookworm-slim

# 1. Install Dovecot, OpenSSL, and network diagnostic tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      dovecot-imapd \
      dovecot-pop3d \
      dovecot-core \
      openssl \
      ca-certificates \
      net-tools \
      iproute2 \
      procps && \
    rm -rf /var/lib/apt/lists/*

# 2. Create vmail user and mail spool directory
RUN groupadd -g 5000 vmail && \
    useradd -g vmail -u 5000 -d /var/mail -m vmail && \
    mkdir -p /var/mail/user@test.local/Maildir && \
    chown -R vmail:vmail /var/mail

# 3. Create deterministic test user database
RUN echo "user@test.local:{PLAIN}password:5000:5000::/var/mail/user@test.local::" > /etc/dovecot/users && \
    chmod 644 /etc/dovecot/users

# 4. Bootstrap certificate for initial daemon boot
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/dovecot/baseline_key.pem \
    -out /etc/dovecot/baseline_cert.pem \
    -subj "/CN=mail.test.local"

# 5. Copy baseline dovecot.conf
COPY templates/dovecot.conf.base /etc/dovecot/dovecot.conf

# 6. Expose standard IMAP (143, 993, 1143) and POP3 (110, 995, 1110)
EXPOSE 143 993 1143 110 995 1110

# 7. Foreground execution
CMD ["dovecot", "-F"]
