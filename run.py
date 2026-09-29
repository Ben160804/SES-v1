#!/usr/bin/env python3
"""
SecureMailScope API launcher.

Run from the repo root (SES-v1/):
    python run.py
    python run.py --port 8080
    python run.py --reload      # dev mode with auto-reload

The `analysis` package is imported as a package (relative imports intact).
Equivalent manual command:
    uvicorn analysis.api:app --host 127.0.0.1 --port 8000
"""

import argparse
import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureMailScope API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development only)")
    args = parser.parse_args()

    uvicorn.run(
        "analysis.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
