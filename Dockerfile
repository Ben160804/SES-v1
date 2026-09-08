FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y postfix rsyslog
COPY main.cf /etc/postfix/main.cf
COPY cert.pem /etc/postfix/cert.pem
COPY key.pem /etc/postfix/key.pem
RUN sed -i 's/^smtp[[:space:]]*inet[[:space:]]*n[[:space:]]*-[[:space:]]*y/smtp       inet  n       -       n/' /etc/postfix/master.cf
RUN newaliases
EXPOSE 25
CMD rsyslogd -n &
CMD ["sh", "-c", "rsyslogd && postfix start-fg"]

