"""Rules 14-15: fetch, transform, health-check and publish the subscription.

    python scripts/build.py

Environment overrides:
    SOURCE_URL        upstream list to start from
    XRAY_BIN          path to the Xray-core binary (default: search PATH, then bin/xray)
    OUTPUT_DIR        where configs.txt is written (default: repository root)
    SKIP_HEALTHCHECK  set to 1 to skip rule 14, for local dry runs
    HEALTHCHECK_ROUNDS number of independent rounds a node must pass (default 3)
"""

from __future__ import annotations

import base64
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import healthcheck  # noqa: E402
import transform  # noqa: E402
from nodes import parse_line  # noqa: E402

SOURCE_URL = os.environ.get(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", REPO_ROOT)
OUTPUT_FILE = "configs.txt"
OUTPUT_FILE_BASE64 = "configs_base64.txt"

PROFILE_TITLE = "Free-Configs"
PROFILE_PAGE = "https://github.com/patterniha/Free-Configs"
UPDATE_INTERVAL_HOURS = 24

FETCH_ATTEMPTS = 4
FETCH_TIMEOUT = 45

# An unattended daily job must never publish an empty subscription: if a run
# yields fewer than this, the previous configs.txt is left in place and the
# workflow fails loudly instead.
MIN_HEALTHY_NODES = 1


def fetch(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "Free-Configs/1.0 (+https://github.com/patterniha)"}
            )
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                return response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            print(f"  fetch attempt {attempt}/{FETCH_ATTEMPTS} failed: {error}")
            if attempt < FETCH_ATTEMPTS:
                time.sleep(3 * attempt)
    raise SystemExit(f"could not fetch {url}: {last_error}")


def locate_xray() -> str:
    explicit = os.environ.get("XRAY_BIN")
    if explicit:
        if not os.path.exists(explicit):
            raise SystemExit(f"XRAY_BIN points at a missing file: {explicit}")
        return explicit
    found = shutil.which("xray")
    if found:
        return found
    for candidate in (
        os.path.join(REPO_ROOT, "bin", "xray"),
        os.path.join(REPO_ROOT, "bin", "xray.exe"),
    ):
        if os.path.exists(candidate):
            return candidate
    raise SystemExit(
        "Xray-core binary not found. Set XRAY_BIN, or place it at bin/xray. "
        "v26.6.22 or newer is required: earlier builds reject the fragment "
        "'lengths'/'delays' arrays used by the fm parameter."
    )


def existing_links(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def render(links: list[str], counts: dict) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        f"#profile-title: {PROFILE_TITLE}",
        f"#profile-update-interval: {UPDATE_INTERVAL_HOURS // 24}",
        f"#profile-web-page-url: {PROFILE_PAGE}",
        f"# {len(links)} nodes"
        f" ({counts.get('final_443', 0)} on 443, {counts.get('final_8080', 0)} on 8080"
        " before health check)",
        f"# generated {stamp} from {SOURCE_URL}",
        f"# criterion: a real proxied request to https://{healthcheck.TEST_HOST}"
        f"{healthcheck.TEST_PATH} succeeded in all"
        f" {counts.get('rounds', healthcheck.ROUNDS)} independent runs",
    ]
    if "flaky_percent" in counts:
        header.append(
            f"# {counts['flaky_percent']}% of nodes that worked at least once"
            " failed at least one run"
        )
    return "\n".join(header + links) + "\n"


def main() -> int:
    counts: dict = {}

    print(f"Fetching {SOURCE_URL}")
    raw = fetch(SOURCE_URL)
    lines = raw.splitlines()
    print(f"  {len(lines)} lines")

    nodes = []
    for line in lines:
        node = parse_line(line)
        if node is not None:
            nodes.append(node)
    counts["parsed"] = len(nodes)
    print(f"  {len(nodes)} parsed as vless/trojan/vmess")

    print("Applying rules 1-13")
    transformed = transform.transform(nodes, counts)
    for key in (
        "dropped_vmess_cannot_carry_fm",
        "dropped_rule_1_security",
        "dropped_rule_2_transport",
        "dropped_rule_3_no_host",
        "dropped_rule_4_port",
        "dropped_rule_7_8080_with_tls",
        "dropped_rule_8_443_without_tls",
        "kept_after_rules_1_to_8",
        "mirrors_added_rule_9",
        "dropped_duplicate",
    ):
        if counts.get(key):
            print(f"  {key}: {counts[key]}")
    print(
        f"  {counts['final_total']} nodes to test"
        f" ({counts['final_443']} on 443, {counts['final_8080']} on 8080)"
    )

    if os.environ.get("SKIP_HEALTHCHECK") == "1":
        print("Skipping rule 14 (SKIP_HEALTHCHECK=1)")
        healthy = transformed
    else:
        rounds = int(os.environ.get("HEALTHCHECK_ROUNDS", healthcheck.ROUNDS))
        counts["rounds"] = rounds
        xray = locate_xray()
        print(f"Health check via {xray} ({rounds} rounds)")
        healthy = healthcheck.check(xray, transformed, counts, rounds=rounds)
        healthy_443 = sum(1 for node in healthy if node.port == "443")
        print(
            f"  {len(healthy)} healthy"
            f" ({healthy_443} on 443, {len(healthy) - healthy_443} on 8080)"
        )

    if len(healthy) < MIN_HEALTHY_NODES:
        print(
            f"ERROR: only {len(healthy)} healthy nodes"
            f" (minimum {MIN_HEALTHY_NODES}); leaving {OUTPUT_FILE} untouched",
            file=sys.stderr,
        )
        return 1

    links = [node.to_link() for node in healthy]
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    base64_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE_BASE64)

    if links == existing_links(output_path):
        print(f"{OUTPUT_FILE} already up to date ({len(links)} nodes); not rewriting")
        return 0

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    document = render(links, counts)
    with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(document)
    with open(base64_path, "w", encoding="ascii", newline="\n") as handle:
        handle.write(base64.b64encode(document.encode("utf-8")).decode("ascii") + "\n")

    print(f"Wrote {output_path} ({len(links)} nodes) and {base64_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
