FROM debian:bookworm-slim

# 1. Install Postfix, OpenSSL, and network diagnostic tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix \
      openssl \
      ca-certificates \
      net-tools \
      iproute2 \
      procps && \
    rm -rf /var/lib/apt/lists/*

# 2. Bootstrap certificate for initial daemon boot (placeholder until PKI exists)
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/postfix/baseline_key.pem \
    -out /etc/postfix/baseline_cert.pem \
    -subj "/CN=mail.test.local"

# 3. Copy base main.cf
COPY templates/main.cf.base /etc/postfix/main.cf

# 4. Use Postfix's built-in postconf tool to safely configure Debian's master.cf:
#    - Disable chroot for all services for container stability
#    - Enable 25 (smtp)
#    - Enable 587 (submission) with baseline security level inherited from main.cf
#    - Enable 465 (smtps) with implicit TLS wrappermode
#    - Enable 2525 (non-standard cleartext/STARTTLS SMTP)
#    - Enable 2526 (non-standard implicit TLS SMTP for PCAP-070)
RUN postconf -F '*/*/chroot=n' && \
    postconf -M smtp/inet="smtp inet n - n - - smtpd" && \
    postconf -M submission/inet="submission inet n - n - - smtpd" && \
    postconf -M smtps/inet="smtps inet n - n - - smtpd -o smtpd_tls_wrappermode=yes" && \
    postconf -M 2525/inet="2525 inet n - n - - smtpd" && \
    postconf -M 2526/inet="2526 inet n - n - - smtpd -o smtpd_tls_wrappermode=yes" && \
    newaliases

EXPOSE 25 587 465 2525 2526

# 5. Foreground operation with container stdout logging
CMD ["postfix", "start-fg"]
