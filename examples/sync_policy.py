#!/usr/bin/env python3
"""
Companion daemon/script to synchronize F5 WAF Policies from Redis to F5 WAF for NGINX.
Reads policies from Redis where key = policy_name and value = JSON content,
writes them to local disk, verifies nginx configuration, and reloads nginx.
"""

import argparse
import os
import subprocess
import sys
import time
import redis


def sync_policies(redis_client, target_dir: str, reload_nginx: bool = True):
    os.makedirs(target_dir, exist_ok=True)
    keys = redis_client.keys("*")
    updated = False

    print(f"[*] Found {len(keys)} policy keys in Redis")
    for key in keys:
        policy_name = key if isinstance(key, str) else key.decode("utf-8")
        raw_json = redis_client.get(key)
        if not raw_json:
            continue

        target_file = os.path.join(target_dir, f"{policy_name}.json")
        current_content = None
        if os.path.exists(target_file):
            with open(target_file, "r", encoding="utf-8") as f:
                current_content = f.read()

        if current_content != raw_json:
            print(f"[+] Syncing updated policy: {policy_name} -> {target_file}")
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(raw_json)
            updated = True

    if updated and reload_nginx:
        print("[*] Verifying NGINX configuration syntax...")
        res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
        if res.returncode == 0:
            print("[*] Reloading NGINX worker processes...")
            subprocess.run(["nginx", "-s", "reload"], check=True)
            print("[✓] NGINX reloaded successfully with updated WAF policies!")
        else:
            print(f"[!] NGINX configuration test failed:\n{res.stderr}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Sync F5 WAF Policies from Redis to NGINX")
    parser.add_argument("--redis-host", default="localhost", help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    parser.add_argument("--redis-db", type=int, default=0, help="Redis DB index")
    parser.add_argument("--redis-password", default=None, help="Redis password")
    parser.add_argument(
        "--target-dir",
        default="/etc/app_protect/conf/policies",
        help="Local directory where policy JSON files are saved",
    )
    parser.add_argument("--watch", type=int, default=0, help="Polling interval in seconds (0 for one-shot)")
    parser.add_argument("--no-reload", action="store_true", help="Skip nginx reload")

    args = parser.parse_args()
    client = redis.Redis(
        host=args.redis_host,
        port=args.redis_port,
        db=args.redis_db,
        password=args.redis_password,
        decode_responses=True,
    )

    if args.watch > 0:
        print(f"[*] Starting Redis-to-NGINX policy syncer daemon (interval: {args.watch}s)...")
        while True:
            try:
                sync_policies(client, args.target_dir, not args.no_reload)
            except Exception as e:
                print(f"[!] Sync error: {e}", file=sys.stderr)
            time.sleep(args.watch)
    else:
        sync_policies(client, args.target_dir, not args.no_reload)


if __name__ == "__main__":
    main()
