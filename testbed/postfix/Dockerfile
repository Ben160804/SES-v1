# ==============================================================================
# SECUREMAILSCOPE TESTBED - POSTFIX SERVER CONTAINER
# ==============================================================================
# Base image: Debian Bookworm Slim
# Provides:
#   - Postfix 3.7+ (supports modern smtpd_tls_chain_files, TLS 1.3, TLS 1.2, etc.)
#   - rsyslog (required for Postfix daemon logging to /var/log/mail.log)
#   - Minimal footprint, reproducible configuration
# ==============================================================================

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Postfix, rsyslog, and networking diagnostics
# ponytail: minimal package set needed to run and log Postfix.
RUN apt-get update && apt-get install -y --no-install-recommends \
    postfix \
    rsyslog \
    ca-certificates \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Fix Debian Postfix chroot trap (RFC 5280 / TLS certificate path accessibility):
# Debian package defaults to chrooted smtpd/cleanup/anvil in master.cf.
# Inside a Docker container, chroot prevents Postfix from resolving DNS,
# reaching /dev/log, and reading mounted TLS certificates.
# We explicitly set column 5 (chroot) to 'n' for all services.
RUN sed -i 's/^\([a-z0-9]*\s\+[a-z0-9]\+\s\+[y-]\s\+[y-]\s\+\)[y-]/\1n/' /etc/postfix/master.cf

# Create directory structure for active scenario mounting and logging
RUN mkdir -p /etc/mailtest/active /var/spool/postfix /var/log

# Copy entrypoint runner
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Standard Mail Submission Ports:
#   25  - SMTP (Opportunistic STARTTLS or plaintext)
#   587 - Submission (STARTTLS)
#   465 - SMTPS / Submissions (Implicit TLS via smtpd_tls_wrappermode=yes)
EXPOSE 25 587 465

ENTRYPOINT ["/entrypoint.sh"]
