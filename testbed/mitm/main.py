#!/usr/bin/env python3
"""
testbed/mitm/main.py
====================
Multi-protocol MITM Proxy Supervisor.
Spawns and manages both SMTP (port 25) and POP3 (port 110) MITM proxies.
"""

import multiprocessing
import signal
import sys

try:
    from testbed.mitm.smtp_proxy import run_proxy as run_smtp_proxy
    from testbed.mitm.pop3_proxy import run_proxy as run_pop3_proxy
except ImportError:
    from smtp_proxy import run_proxy as run_smtp_proxy
    from pop3_proxy import run_proxy as run_pop3_proxy


def main():
    smtp_proc = multiprocessing.Process(
        target=run_smtp_proxy,
        kwargs={
            "listen_host": "0.0.0.0",
            "listen_port": 25,
            "upstream_host": "172.28.0.10",
            "upstream_port": 25,
            "strip_mode": True,
            "single_session": False,
        },
        name="smtp_mitm_proxy",
    )
    pop3_proc = multiprocessing.Process(
        target=run_pop3_proxy,
        kwargs={
            "listen_host": "0.0.0.0",
            "listen_port": 110,
            "upstream_host": "172.28.0.11",
            "upstream_port": 110,
            "strip_mode": True,
            "single_session": False,
        },
        name="pop3_mitm_proxy",
    )

    def shutdown(signum, frame):
        smtp_proc.terminate()
        pop3_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    smtp_proc.start()
    pop3_proc.start()

    smtp_proc.join()
    pop3_proc.join()


if __name__ == "__main__":
    main()
