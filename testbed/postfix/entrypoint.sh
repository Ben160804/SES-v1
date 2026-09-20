#!/bin/bash
set -e

# ==============================================================================
# SECUREMAILSCOPE TESTBED - POSTFIX ENTRYPOINT
# ==============================================================================
# Lifecycle:
#   1. Start rsyslog daemon in the background to capture /dev/log.
#   2. Check if an active scenario has mounted custom main.cf / master.cf.
#   3. Sync configuration into /etc/postfix/.
#   4. Execute Postfix in foreground mode (postfix start-fg).
# ==============================================================================

# Start rsyslog daemon so /var/log/mail.log captures TLS handshake negotiation
rsyslogd

# Apply active scenario configuration if mounted
if [ -f "/etc/mailtest/active/main.cf" ]; then
    echo "[mailtest-postfix] Loading scenario main.cf..."
    cp -f /etc/mailtest/active/main.cf /etc/postfix/main.cf
fi

if [ -f "/etc/mailtest/active/master.cf" ]; then
    echo "[mailtest-postfix] Loading scenario master.cf..."
    cp -f /etc/mailtest/active/master.cf /etc/postfix/master.cf
fi

# Sanity check Postfix file permissions and spool directories
postfix check || true

echo "[mailtest-postfix] Postfix daemon starting..."
exec postfix start-fg
