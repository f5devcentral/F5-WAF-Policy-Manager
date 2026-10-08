#!/usr/bin/env python3
"""
F5 WAF Policy Manager for NGINX
CLI entrypoint and server runner.
"""

import argparse
import sys
import threading
import time
import webbrowser
import uvicorn

from f5_waf_editor.config import settings
from f5_waf_editor.storage import init_storage


def parse_args():
    parser = argparse.ArgumentParser(
        description="F5 WAF for NGINX Policy Manager - UI & Redis Management Server"
    )
    parser.add_argument(
        "--host",
        default=settings.app_host,
        help=f"HTTP Server bind host (default: {settings.app_host})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.app_port,
        help=f"HTTP Server port (default: {settings.app_port})",
    )
    parser.add_argument(
        "--redis-host",
        default=settings.redis_host,
        help=f"Redis host (default: {settings.redis_host})",
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=settings.redis_port,
        help=f"Redis port (default: {settings.redis_port})",
    )
    parser.add_argument(
        "--redis-db",
        type=int,
        default=settings.redis_db,
        help=f"Redis DB index (default: {settings.redis_db})",
    )
    parser.add_argument(
        "--redis-password",
        default=settings.redis_password,
        help="Redis password (if protected)",
    )
    parser.add_argument(
        "--force-memory",
        action="store_true",
        help="Force in-memory storage (skips connecting to Redis)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the browser on start",
    )
    return parser.parse_args()


def open_browser(url: str):
    time.sleep(1.2)
    webbrowser.open(url)


def main():
    args = parse_args()

    # Apply CLI arguments to settings
    settings.app_host = args.host
    settings.app_port = args.port
    settings.redis_host = args.redis_host
    settings.redis_port = args.redis_port
    settings.redis_db = args.redis_db
    settings.redis_password = args.redis_password

    # Pre-initialize storage with configured args
    storage = init_storage(
        host=args.redis_host,
        port=args.redis_port,
        db=args.redis_db,
        password=args.redis_password,
        force_memory=args.force_memory,
    )
    health = storage.get_health()

    url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}"
    print("=" * 72)
    print("  🛡️  F5 WAF for NGINX Policy Manager")
    print("=" * 72)
    print(f"  • Web UI URL:       {url}")
    print(f"  • Storage Backend:  {health.get('backend', 'unknown').upper()}")
    if health.get("backend") == "redis":
        status_str = "CONNECTED" if health.get("connected") else "DISCONNECTED"
        print(f"  • Redis Target:     {args.redis_host}:{args.redis_port} (DB {args.redis_db}) [{status_str}]")
    else:
        print("  • Note:             Using Resilient In-Memory storage (Redis offline/fallback)")
    print("=" * 72)

    if not args.no_browser:
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    uvicorn.run(
        "f5_waf_editor.app:app",
        host=args.host,
        port=args.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
