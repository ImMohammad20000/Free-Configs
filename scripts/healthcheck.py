"""Rule 14: keep only nodes that actually carry traffic.

Reimplements the criterion the upstream project publishes in its own header --
"a real proxied request to https://cp.cloudflare.com/generate_204 succeeded in
ALL 3 independent runs" -- directly against Xray-core rather than a wrapper, so
the ``fm`` / ``cs`` / ``fp=unsafe`` parameters in the emitted links are the ones
being exercised.

Shape of a round: nodes are grouped into batches; each batch becomes one Xray
process with one loopback HTTP inbound per node, routed to that node's outbound.
Every node is then probed concurrently through its own inbound. Three rounds run
and only the intersection survives, because a single run misgrades a substantial
fraction of nodes -- upstream measured 25-64% of working nodes as flaky.

The default outbound is a blackhole, so a node whose routing rule somehow fails
to match cannot fall through to a direct connection and report itself healthy.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import transform
from nodes import Node

TEST_HOST = "cp.cloudflare.com"
TEST_PATH = "/generate_204"
EXPECTED_STATUS = 204
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

ROUNDS = 3                 # a node must pass every round
REQUEST_TIMEOUT = 5.0      # seconds, matches upstream's 5000ms budget
BATCH_SIZE = 32            # nodes per Xray process
PROBE_WORKERS = 32         # concurrent probes within a batch
BASE_PORT = 21080          # first loopback inbound port
STARTUP_TIMEOUT = 15.0     # seconds to wait for Xray to bind its inbounds
SHUTDOWN_TIMEOUT = 5.0
PAUSE_BETWEEN_ROUNDS = 3.0


class HealthCheckError(RuntimeError):
    pass


def _build_config(batch: list[Node], base_port: int) -> dict:
    inbounds: list[dict] = []
    # The blackhole is listed first so it is Xray's default outbound: anything
    # not matched by an explicit rule is dropped rather than sent out directly.
    outbounds: list[dict] = [{"tag": "block", "protocol": "blackhole"}]
    rules: list[dict] = []

    for index, node in enumerate(batch):
        in_tag = f"in-{index}"
        out_tag = f"out-{index}"
        inbounds.append(
            {
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": base_port + index,
                "protocol": "http",
                "settings": {},
            }
        )
        outbounds.append(node.to_outbound(out_tag))
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "block"})
    return {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }


def _write_config(config: dict, directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False)
    return path


def _config_accepted(xray: str, config: dict, directory: str) -> bool:
    """True when Xray parses and builds this config. ``run -test`` validates
    without binding anything, so it is safe to call on overlapping ports."""
    path = _write_config(config, directory, "validate.json")
    try:
        result = subprocess.run(
            [xray, "run", "-test", "-c", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def validate_nodes(
    xray: str, nodes: list[Node], directory: str
) -> tuple[list[Node], list[Node]]:
    """Split ``nodes`` into those Xray accepts and those it rejects.

    Validating a whole group at once costs one process; only when a group fails
    is it bisected, so one malformed node cannot take a whole batch down with it.
    """

    def group_builds(group: list[Node]) -> bool:
        try:
            config = _build_config(group, BASE_PORT)
        except Exception:
            # A node whose outbound cannot even be rendered -- unparseable fm,
            # say -- is a node to reject, not a reason to abandon the run. The
            # bisect below then narrows it down to the one at fault.
            return False
        return _config_accepted(xray, config, directory)

    def recurse(group: list[Node]) -> tuple[list[Node], list[Node]]:
        if not group:
            return [], []
        if group_builds(group):
            return list(group), []
        if len(group) == 1:
            return [], list(group)
        middle = len(group) // 2
        left_ok, left_bad = recurse(group[:middle])
        right_ok, right_bad = recurse(group[middle:])
        return left_ok + right_ok, left_bad + right_bad

    accepted: list[Node] = []
    rejected: list[Node] = []
    for start in range(0, len(nodes), BATCH_SIZE):
        chunk_ok, chunk_bad = recurse(nodes[start : start + BATCH_SIZE])
        accepted.extend(chunk_ok)
        rejected.extend(chunk_bad)
    return accepted, rejected


def preflight(xray: str) -> list[str]:
    """Check that this core understands everything the emitted links rely on.

    Without this, an unsupported parameter shows up as "every node is dead"
    three rounds later, with nothing pointing at the cause. Each probe uses the
    same config shape the health check builds, so a core that accepts these
    accepts the real thing.

    ``cs`` maps to Xray's ``cipherSuites``, which is undocumented, and the
    ``fm`` fragment's ``lengths``/``delays`` arrays only exist in cores based on
    v26.6.22 or newer -- both are worth proving rather than assuming.
    """
    try:
        version = subprocess.run(
            [xray, "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        # Every later check shells out to this binary, and a failure there would
        # look like "no node works" rather than "the binary is unusable".
        return [f"running '{xray} version' failed: {error}"]
    if version.returncode != 0:
        return [f"'{xray} version' exited {version.returncode}"]
    print(f"  core: {version.stdout.decode('utf-8', 'replace').splitlines()[0]}")

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="xray-preflight-") as directory:
        for description, node in preflight_probes():
            if not _config_accepted(xray, _build_config([node], BASE_PORT), directory):
                failures.append(description)
    return failures


def preflight_probes() -> list[tuple[str, Node]]:
    """The two configurations the pipeline actually emits: a TLS node carrying
    the full masking set, and a plaintext node on the public exit address.

    The addresses come from transform's rule 10 constants rather than being
    written out again here, so repointing either exit address repoints what the
    preflight tests along with it.
    """
    blank_uuid = "00000000-0000-0000-0000-000000000000"
    return [
        (
            "port 443 masking (fp=unsafe + fm fragment + cs cipherSuites)",
            Node(
                scheme="vless",
                uid=blank_uuid,
                address=transform.ADDRESS_FOR_PORT_443,
                port="443",
                params={
                    "encryption": "none",
                    "security": "tls",
                    "type": "ws",
                    "host": "example.com",
                    "path": "/",
                    "sni": "example.com",
                    "fp": transform.FP_443,
                    "fm": transform.FM_443,
                    "cs": transform.CS_443,
                },
            ),
        ),
        (
            "port 8080 unencrypted outbound to a public address (fm fragment)",
            Node(
                scheme="vless",
                uid=blank_uuid,
                address=transform.ADDRESS_FOR_PORT_8080,
                port="8080",
                params={
                    "encryption": "none",
                    "security": "none",
                    "type": "ws",
                    "host": "example.com",
                    "path": "/",
                    "fm": transform.FM_8080,
                },
            ),
        ),
    ]


def _wait_until_listening(
    ports: list[int], deadline: float, process: subprocess.Popen | None = None
) -> bool:
    for port in ports:
        while True:
            if process is not None and process.poll() is not None:
                return False  # Xray exited; no point waiting out the deadline
            if time.monotonic() > deadline:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.05)
    return True


def _log_tail(path: str, lines: int = 6) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            tail = [l.rstrip() for l in handle if l.strip()][-lines:]
        return "\n".join("      " + l[:200] for l in tail)
    except OSError:
        return "      (no log)"


def _probe(port: int) -> tuple[bool, float]:
    """Fetch the test URL through the loopback proxy on ``port``.

    ``HTTPSConnection`` + ``set_tunnel`` issues a CONNECT to Xray's HTTP inbound
    and then completes TLS end-to-end with the target, so a node that cannot
    carry a real TLS session cannot pass.
    """
    started = time.monotonic()
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT)
    try:
        connection.set_tunnel(TEST_HOST, 443)
        connection.request(
            "GET", TEST_PATH, headers={"User-Agent": USER_AGENT, "Connection": "close"}
        )
        response = connection.getresponse()
        response.read()
        elapsed = (time.monotonic() - started) * 1000.0
        return response.status == EXPECTED_STATUS, elapsed
    except Exception:
        return False, (time.monotonic() - started) * 1000.0
    finally:
        try:
            connection.close()
        except Exception:
            pass


def _run_batch(
    xray: str, batch: list[Node], directory: str, label: str
) -> dict[int, float]:
    """Return ``{index within batch: latency ms}`` for the nodes that passed."""
    config = _build_config(batch, BASE_PORT)
    config_path = _write_config(config, directory, f"{label}.json")
    log_path = os.path.join(directory, f"{label}.log")

    with open(log_path, "wb") as log_handle:
        process = subprocess.Popen(
            [xray, "run", "-c", config_path],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            ports = [BASE_PORT, BASE_PORT + len(batch) - 1]
            deadline = time.monotonic() + STARTUP_TIMEOUT
            if not _wait_until_listening(ports, deadline, process):
                # Distinguish "Xray never came up" from "every node failed" --
                # otherwise a bind error silently reads as 32 dead nodes.
                print(
                    f"  ! {label}: Xray did not start (exit={process.poll()});"
                    f" {len(batch)} nodes not tested this round"
                )
                print(_log_tail(log_path))
                return {}
            with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
                results = list(pool.map(lambda i: _probe(BASE_PORT + i), range(len(batch))))
        finally:
            process.terminate()
            try:
                process.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    return {i: latency for i, (ok, latency) in enumerate(results) if ok}


def check(
    xray: str, nodes: list[Node], stats: dict | None = None, rounds: int = ROUNDS
) -> list[Node]:
    """Return the nodes that passed a real proxied request in every round,
    ordered fastest-first by median latency across the rounds."""
    counts: dict = stats if stats is not None else {}
    if not nodes:
        counts["healthy"] = 0
        return []

    with tempfile.TemporaryDirectory(prefix="xray-healthcheck-") as directory:
        accepted, rejected = validate_nodes(xray, nodes, directory)
        counts["rejected_by_xray"] = len(rejected)
        counts["validated"] = len(accepted)
        for node in rejected:
            print(f"  ! Xray rejected: {node.tag or node.to_link()[:80]}")
        if not accepted:
            counts["healthy"] = 0
            return []

        latencies: dict[int, list[float]] = {i: [] for i in range(len(accepted))}
        survivors = set(range(len(accepted)))

        for round_number in range(1, rounds + 1):
            passed: set[int] = set()
            for start in range(0, len(accepted), BATCH_SIZE):
                batch = accepted[start : start + BATCH_SIZE]
                label = f"r{round_number}-b{start // BATCH_SIZE}"
                for offset, latency in _run_batch(xray, batch, directory, label).items():
                    index = start + offset
                    passed.add(index)
                    latencies[index].append(latency)
            counts[f"round_{round_number}_passed"] = len(passed)
            survivors &= passed
            print(
                f"  round {round_number}/{rounds}: {len(passed)}/{len(accepted)} passed, "
                f"{len(survivors)} still perfect"
            )
            if round_number < rounds:
                time.sleep(PAUSE_BETWEEN_ROUNDS)

    ever_passed = sum(1 for values in latencies.values() if values)
    if ever_passed:
        counts["flaky_percent"] = round(
            100.0 * (ever_passed - len(survivors)) / ever_passed, 2
        )
    counts["healthy"] = len(survivors)

    ordered = sorted(survivors, key=lambda i: (statistics.median(latencies[i]), i))
    for index in ordered:
        accepted[index].latency_ms = round(statistics.median(latencies[index]))
    return [accepted[i] for i in ordered]
