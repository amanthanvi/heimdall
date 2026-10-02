"""Deterministically generate large-100.toml (100 destinations)."""
from pathlib import Path

lines = ['schema_version = 1', 'name = "large"', 'revision = 1', '']
for i in range(100):
    lines += [
        '[[destinations]]',
        f'id = "dst_{i:03d}"',
        f'alias = "host-{i:03d}-{["web", "db", "lab", "ci"][i % 4]}"',
        f'host = "h{i:03d}.example.internal"',
        f'port = {22 if i % 3 else 2200 + i}',
        f'account = "{["aman", "deploy", "root"][i % 3]}"',
        f'labels = ["{["homelab", "vps", "ci"][i % 3]}"]',
        '',
    ]
Path(__file__).with_name("large-100.toml").write_text("\n".join(lines), encoding="utf-8")
