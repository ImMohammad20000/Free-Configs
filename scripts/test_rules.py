"""Tests for the share-link parser and the health-check pipeline.

    python scripts/test_rules.py

No test framework needed. Nodes are no longer rewritten by this pipeline --
they are parsed, deduplicated, health-checked and published exactly as their
sources wrote them -- so these tests cover the parser, the Xray outbound
renderer, the health check itself, and the build's fetch/dedup/cap/publish
behaviour.
"""

from __future__ import annotations

import base64
import contextlib
import http.client
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build  # noqa: E402
from nodes import Node, parse_line  # noqa: E402

FAILURES: list[str] = []
PASSED = 0


def check(condition: bool, label: str) -> None:
    global PASSED
    if condition:
        PASSED += 1
    else:
        FAILURES.append(label)


def link(**kwargs) -> str:
    """Build a vless link from keyword parts, for compact test cases."""
    uid = kwargs.pop("uid", "11111111-1111-1111-1111-111111111111")
    address = kwargs.pop("address", "1.2.3.4")
    port = kwargs.pop("port", "443")
    tag = kwargs.pop("tag", "name")
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in kwargs.items() if v is not None)
    return f"vless://{uid}@{address}:{port}?{query}#{tag}"


BASE = dict(security="tls", type="ws", host="a.example", path="/")


# --- parser edge cases -----------------------------------------------------

node = parse_line("vless://uid@[2001:db8::1]:443?type=ws&host=a.example&security=tls#n")
check(node is not None and node.address == "2001:db8::1", "parser: bracketed IPv6 address")
check(node is not None and node.port == "443", "parser: port after IPv6 brackets")
check("[2001:db8::1]:443" in node.to_link(), "parser: IPv6 is re-bracketed on output")

node = parse_line("trojan://pa:ss@word@host.example:443?type=ws&host=a.example")
check(node is not None and node.address == "host.example", "parser: userinfo containing @ and :")
check(node is not None and node.uid == "pa:ss@word", "parser: password preserved verbatim")

node = parse_line("vless://uid@h.example:443?path=/a%3Db&type=ws&host=a.example")
check(node is not None and node.get("path") == "/a=b", "parser: '=' inside an encoded value")

node = parse_line("vless://uid@h.example:443?type=ws&host=a.example")
check(node is not None and node.tag == "", "parser: missing fragment is empty, not an error")

node = parse_line("vless://uid@h.example:443#n")
check(node is not None and node.params == {}, "parser: empty query")

check(parse_line("") is None, "parser: blank line")
check(parse_line("#comment") is None, "parser: comment line")
check(parse_line("ss://whatever@h:443") is None, "parser: unsupported scheme")
check(parse_line("vmess://not-base64!!!") is None, "parser: malformed vmess")
check(parse_line("garbage") is None, "parser: no scheme separator")

node = parse_line("vless://uid@h.example:443?Host=Cap.example&type=ws&security=tls#n")
check(node is not None and node.host == "Cap.example", "parser: capitalised Host is found")

node = parse_line("vless://uid@h.example:8080?type=ws&host=a.example&security=reality#n")
check(node is not None and node.security == "reality", "parser: any security value parses, unfiltered")

node = parse_line("vless://uid@h.example:9999?type=grpc&host=a.example#n")
check(node is not None and node.port == "9999", "parser: any port parses, unfiltered")

# Round trip: emitting and re-parsing must be stable.
node = parse_line(link(**BASE))
emitted = node.to_link()
reparsed = parse_line(emitted)
check(reparsed is not None and reparsed.to_link() == emitted, "parser: emit/parse round trip")

# --- vmess -------------------------------------------------------------------

VMESS = (
    "vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1aWQiLCJhaWQi"
    "OiIwIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJhLmV4YW1wbGUiLCJwYXRoIjoiLyIsInRscyI6InRs"
    "cyJ9"
)
node = parse_line(VMESS)
check(node is not None and node.scheme == "vmess", "vmess: parses")
check(node is not None and node.transport == "ws", "vmess: net maps to transport")
check(node is not None and node.security == "tls", "vmess: tls maps to security")
check(node is not None and node.host == "a.example", "vmess: host")

VMESS_FULL = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "original name", "add": "9.9.9.9", "port": "2053",
    "id": "33333333-3333-3333-3333-333333333333", "aid": "0", "scy": "aes-128-gcm",
    "net": "ws", "type": "none", "host": "vm.example", "path": "/vm",
    "tls": "tls", "sni": "vm.example", "alpn": "", "fp": "chrome",
}).encode()).decode()

vm = parse_line(VMESS_FULL)
check(vm is not None, "vmess: a full link parses")
again = parse_line(vm.to_link())
check(again is not None, "vmess: re-parses after serialisation")
for field in ("scheme", "uid", "address", "port", "tag"):
    check(getattr(again, field) == getattr(vm, field), f"vmess: {field} survives a round trip")
for key in ("type", "security", "host", "path", "sni", "headerType"):
    check(again.get(key) == vm.get(key), f"vmess: {key} survives a round trip")
check(again.extra.get("scy") == "aes-128-gcm", "vmess: the cipher survives a round trip")

outbound = vm.to_outbound("t")
user = outbound["settings"]["vnext"][0]["users"][0]
check(outbound["protocol"] == "vmess", "vmess: outbound protocol")
check(user["alterId"] == 0 and user["security"] == "aes-128-gcm",
      "vmess: alterId and cipher reach the outbound")
check(outbound["streamSettings"]["network"] == "ws", "vmess: net maps to the stream network")

# --- Xray outbound rendering: nodes are rendered as-is, nothing is injected ---

node = parse_line(link(**BASE, fp="chrome", cs="TLS_AES_128_GCM_SHA256"))
outbound = json.loads(json.dumps(node.to_outbound("t")))
stream = outbound["streamSettings"]
check(outbound["protocol"] == "vless", "outbound: protocol")
check(stream["network"] == "ws", "outbound: network")
check(stream["wsSettings"]["host"] == "a.example", "outbound: ws host header")
check(stream["security"] == "tls", "outbound: security is carried through as-is")
check(stream["tlsSettings"]["fingerprint"] == "chrome",
      "outbound: fp is carried through from the source, not overwritten")
check(stream["tlsSettings"]["cipherSuites"] == "TLS_AES_128_GCM_SHA256",
      "outbound: cs is carried through from the source, not overwritten")
check(stream["tlsSettings"]["allowInsecure"] is False,
      "outbound: allowInsecure defaults to false when the source did not ask for it")
check("finalmask" not in stream,
      "outbound: no fm is injected when the source did not provide one")

insecure_node = parse_line(link(**{**BASE, "allowinsecure": "1"}))
check(
    insecure_node.to_outbound("t")["streamSettings"]["tlsSettings"]["allowInsecure"] is True,
    "outbound: allowInsecure follows the source's own allowinsecure param, unstripped",
)

FM_VALUE = json.dumps({"tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}]})
fm_node = parse_line(link(**{**BASE, "fm": FM_VALUE}))
check(fm_node.get("fm") == FM_VALUE, "parser: a source-provided fm value round-trips")
check(
    "finalmask" in fm_node.to_outbound("t")["streamSettings"],
    "outbound: fm is rendered when the source itself provides one",
)

plain_node = parse_line(link(**{**BASE, "security": "none"}))
check(plain_node.to_outbound("t")["streamSettings"]["security"] == "none",
      "outbound: security=none is honoured, not forced to tls")

grpc_node = parse_line(link(**{**BASE, "type": "grpc", "serviceName": "gs"}))
outbound = grpc_node.to_outbound("t")
check(outbound["streamSettings"]["network"] == "grpc", "outbound: grpc network")
check(
    outbound["streamSettings"]["grpcSettings"]["authority"] == "a.example",
    "outbound: grpc authority comes from host",
)

# reality: not part of the old TLS-only shape, but common upstream and must be
# tested faithfully rather than mis-rendered as plaintext.
REALITY = (
    "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
    "?security=reality&type=tcp&sni=r.example&pbk=PUBKEY&sid=ab12"
    "&fp=chrome&flow=xtls-rprx-vision#reality"
)
reality_node = parse_line(REALITY)
check(reality_node is not None and reality_node.security == "reality", "parser: reality security parses")
r_outbound = reality_node.to_outbound("t")
r_stream = r_outbound["streamSettings"]
check(r_stream["security"] == "reality", "outbound: reality security is honoured")
r_settings = r_stream["realitySettings"]
check(r_settings["serverName"] == "r.example", "outbound: reality serverName comes from sni")
check(r_settings["publicKey"] == "PUBKEY", "outbound: reality publicKey comes from pbk")
check(r_settings["shortId"] == "ab12", "outbound: reality shortId comes from sid")
check(r_settings["fingerprint"] == "chrome", "outbound: reality fingerprint comes from fp")
check("tlsSettings" not in r_stream, "outbound: reality does not also carry tlsSettings")
check(
    r_outbound["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision",
    "outbound: flow reaches the outbound",
)
reparsed_reality = parse_line(reality_node.to_link())
check(
    reparsed_reality is not None and reparsed_reality.get("pbk") == "PUBKEY"
    and reparsed_reality.get("sid") == "ab12",
    "parser: reality params round-trip through emit/parse",
)

# --- health check: routing safety and bisection ------------------------------
# These do not need a network or an Xray binary, but they guard the property
# everything else rests on: a node must only be able to pass by carrying real
# traffic through its own outbound.

import healthcheck  # noqa: E402

batch = [
    parse_line(link(**{**BASE, **spec}))
    for spec in ({}, {"host": "b.example"}, {"host": "c.example"})
]
batch_ports = healthcheck._placeholder_ports(len(batch))
config = healthcheck._build_config(batch, batch_ports)

# If the default outbound were freedom rather than blackhole, traffic that
# missed its rule would go out directly and EVERY node would look healthy.
check(config["outbounds"][0]["protocol"] == "blackhole",
      "healthcheck: the default outbound is a blackhole, so nothing leaks direct")
check(not any(o.get("protocol") == "freedom" for o in config["outbounds"]),
      "healthcheck: no freedom outbound exists to fall through to")
check(config["routing"]["rules"][-1]["outboundTag"] == "block",
      "healthcheck: a catch-all rule blocks anything unmatched")

rules = config["routing"]["rules"][:-1]
check(len(rules) == len(batch), "healthcheck: every node gets exactly one routing rule")
check(
    all(r["inboundTag"] == [f"in-{i}"] and r["outboundTag"] == f"out-{i}"
        for i, r in enumerate(rules)),
    "healthcheck: inbound N routes to outbound N, never to a neighbour",
)
ports = [i["port"] for i in config["inbounds"]]
check(ports == batch_ports, "healthcheck: each inbound binds the port it was given")
check(len(set(ports)) == len(ports), "healthcheck: no two inbounds share a port")
check(all(i["listen"] == "127.0.0.1" for i in config["inbounds"]),
      "healthcheck: inbounds bind loopback only")
check(
    [o["tag"] for o in config["outbounds"][1:]] == [f"out-{i}" for i in range(len(batch))],
    "healthcheck: outbound order matches node order",
)

# Bisection must isolate exactly the offending node, keeping the rest.
POISON = "deadbeef-dead-beef-dead-beefdeadbeef"
poisoned = batch[0].copy()
poisoned.uid = POISON
mixed = batch[:2] + [poisoned] + batch[2:]


def _stub_accepted(xray, cfg, directory):
    """Stand in for Xray: reject any config containing the poisoned node."""
    for outbound in cfg["outbounds"]:
        for target in outbound.get("settings", {}).get("vnext", []):
            for user in target.get("users", []):
                if user.get("id") == POISON:
                    return False
    return True


real_accepted = healthcheck._config_accepted
try:
    healthcheck._config_accepted = _stub_accepted
    ok, bad = healthcheck.validate_nodes("xray", mixed, tempfile.gettempdir())
    check(len(bad) == 1 and bad[0].uid == POISON,
          "healthcheck: bisection isolates exactly the rejected node")
    check(len(ok) == len(mixed) - 1 and all(n.uid != POISON for n in ok),
          "healthcheck: the other nodes survive one bad node")

    # A node whose outbound cannot even be rendered must be rejected, not fatal.
    broken = batch[0].copy()
    broken.uid = "broken-node"
    broken.set("fm", "{not valid json")
    ok, bad = healthcheck.validate_nodes("xray", batch[:2] + [broken], tempfile.gettempdir())
    check(len(bad) == 1 and bad[0].uid == "broken-node",
          "healthcheck: an unrenderable outbound is rejected rather than crashing")
    check(len(ok) == 2, "healthcheck: an unrenderable node does not take the batch with it")
finally:
    healthcheck._config_accepted = real_accepted

# _run_batch maps each node to its own loopback port and each result back to
# that node. An off-by-one here would not fail loudly -- it would quietly
# credit one node with another's result and publish the wrong ones.
class _FakeProcess:
    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


probed_ports: list[int] = []
probed_endpoints: list[str] = []
FIXED_PORTS = [50101, 50102, 50103, 50104, 50105, 50106]
real_reserve = healthcheck.reserve_ports
real_popen = healthcheck.subprocess.Popen
real_wait = healthcheck._wait_until_listening
real_probe = healthcheck._probe
try:
    healthcheck.reserve_ports = lambda count: FIXED_PORTS[:count]
    healthcheck.subprocess.Popen = lambda *a, **k: _FakeProcess()
    healthcheck._wait_until_listening = lambda ports, deadline, process=None: True
    # Latency encodes the port, so a mis-mapped result is visible in the output.
    def _record(port, endpoint):
        probed_ports.append(port)
        probed_endpoints.append(endpoint.host)
        return (port % 2 == 0, float(port))

    healthcheck._probe = _record
    base_node = parse_line(link(**BASE))
    scored_batch = [base_node, base_node, base_node]
    mapped = healthcheck._run_batch("xray", scored_batch,
                                    tempfile.gettempdir(), "unit",
                                    healthcheck.TEST_ENDPOINTS[0])
finally:
    healthcheck.reserve_ports = real_reserve
    healthcheck.subprocess.Popen = real_popen
    healthcheck._wait_until_listening = real_wait
    healthcheck._probe = real_probe

check(sorted(probed_ports) == FIXED_PORTS[:len(scored_batch)],
      "healthcheck: each node in a batch is probed on its own reserved port, once")
check(
    all(latency == float(FIXED_PORTS[index]) for index, latency in mapped.items()),
    "healthcheck: a probe result is credited to the node it came from",
)
check(
    set(mapped) == {i for i in range(len(scored_batch)) if FIXED_PORTS[i] % 2 == 0},
    "healthcheck: only the nodes that passed appear in the result",
)
check(set(probed_endpoints) == {healthcheck.TEST_ENDPOINTS[0].host},
      "healthcheck: every node in a batch is measured against the same endpoint")


# Ports come from the OS, not a fixed range: a hardcoded range fails wholesale
# if anything else on the machine already listens in it.
reserved = healthcheck.reserve_ports(8)
check(len(reserved) == 8, "ports: the requested number of ports is reserved")
check(len(set(reserved)) == 8, "ports: reserved ports are distinct")
check(all(1024 < p < 65536 for p in reserved), "ports: reserved ports are usable numbers")
bound = []
try:
    for p_ in reserved:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", p_))
        bound.append(srv)
    check(True, "ports: every reserved port can actually be bound afterwards")
except OSError:
    check(False, "ports: every reserved port can actually be bound afterwards")
finally:
    for srv in bound:
        srv.close()
check(healthcheck.reserve_ports(0) == [], "ports: reserving none is not an error")

# A batch that cannot get ports must not take the whole run down with it: the
# rounds already completed would be lost.
_real_reserve = healthcheck.reserve_ports
try:
    def _refuse(count):
        raise OSError("no ports today")

    healthcheck.reserve_ports = _refuse
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        result = healthcheck._run_batch(
            "xray", [parse_line(link(**BASE))], tempfile.gettempdir(), "unit",
            healthcheck.TEST_ENDPOINTS[0],
        )
    check(result == {}, "ports: a batch that cannot reserve ports is simply untested")
    check("could not reserve" in captured.getvalue(),
          "ports: the reservation failure is reported, not swallowed")
finally:
    healthcheck.reserve_ports = _real_reserve
check(healthcheck._run_batch("xray", [], tempfile.gettempdir(), "unit",
                             healthcheck.TEST_ENDPOINTS[0]) == {},
      "ports: an empty batch is handled without indexing past the end")

# _wait_until_listening only probes the first and last port of a batch. That is
# only safe because Xray refuses to start at all when any one inbound cannot
# bind -- verified against the real core, which exits with "failed to listen
# TCP on <port>" and binds nothing. What makes the shortcut safe is polling the
# process, so a dead process must end the wait immediately rather than at the
# deadline.
class _DeadProcess:
    def poll(self):
        return 1


started = time.monotonic()
check(
    healthcheck._wait_until_listening([1], time.monotonic() + 30, _DeadProcess()) is False,
    "ports: a process that has already exited ends the wait",
)
check(time.monotonic() - started < 5,
      "ports: it notices immediately rather than waiting out the deadline")


class _LingeringProcess:
    def poll(self):
        return None


check(
    healthcheck._wait_until_listening([1], time.monotonic() + 0.5, _LingeringProcess())
    is False,
    "ports: a port that never opens times out rather than hanging",
)

# check() decides what is published. A node must pass EVERY round: passing
# some rounds is what "flaky" means, and publishing those is the mistake the
# three-round design exists to avoid.
scored = [parse_line(link(**{**BASE, "host": f"n{i}.example"})) for i in range(5)]
for index, node in enumerate(scored):
    node.tag = f"node-{index}"

# node-0 and node-4 pass all three rounds; node-1 passes two; node-2 passes
# one; node-3 never passes.
# node-0's latencies are chosen so the median and the final round disagree on
# the ordering: by median it is slower than node-4, by last round it is faster.
ROUND_RESULTS = [
    {0: 300.0, 1: 10.0, 4: 50.0},
    {0: 100.0, 1: 10.0, 4: 50.0},
    {0: 20.0, 2: 10.0, 4: 50.0},
]
rounds_seen: list[str] = []

real_validate = healthcheck.validate_nodes
real_run_batch = healthcheck._run_batch
real_pause = healthcheck.PAUSE_BETWEEN_ROUNDS
real_usable_endpoints = healthcheck.usable_endpoints
try:
    healthcheck.validate_nodes = lambda xray, nodes, directory: (list(nodes), [])
    healthcheck.PAUSE_BETWEEN_ROUNDS = 0
    healthcheck.usable_endpoints = lambda: list(healthcheck.TEST_ENDPOINTS)

    def _stub_run_batch(xray, batch, directory, label, endpoint):
        rounds_seen.append(endpoint.host)
        return ROUND_RESULTS[len(rounds_seen) - 1]

    healthcheck._run_batch = _stub_run_batch
    stats: dict = {}
    # check() narrates its rounds; that belongs in a build log, not here.
    with contextlib.redirect_stdout(io.StringIO()):
        healthy = healthcheck.check("xray", scored, stats, rounds=3)

    survivors = [n.tag for n in healthy]
    check(survivors == ["node-4", "node-0"],
          "healthcheck: only nodes passing every round survive, fastest median first")
    check("node-1" not in survivors and "node-2" not in survivors,
          "healthcheck: a node passing some rounds is not published")
    check("node-3" not in survivors, "healthcheck: a node passing no round is not published")
    check(stats["healthy"] == 2, "healthcheck: the healthy count is recorded")
    check([stats[f"round_{i}_passed"] for i in (1, 2, 3)] == [3, 3, 3],
          "healthcheck: per-round pass counts are recorded")
    # 4 nodes worked at least once, 2 worked every time.
    check(stats["flaky_percent"] == 50.0, "healthcheck: flakiness is measured, not guessed")
    check(healthy[0].latency_ms == 50 and healthy[1].latency_ms == 100,
          "healthcheck: the published latency is the median across rounds")
    check(len(rounds_seen) == 3, "healthcheck: it really runs the requested number of rounds")
    check(rounds_seen == [e.host for e in healthcheck.TEST_ENDPOINTS[:3]],
          "healthcheck: each round uses a different endpoint, in order")
    check(len({e.host for e in healthcheck.TEST_ENDPOINTS}) == len(healthcheck.TEST_ENDPOINTS),
          "healthcheck: the endpoints are distinct hosts")

    # No nodes at all must not explode.
    empty_stats: dict = {}
    with contextlib.redirect_stdout(io.StringIO()):
        empty_result = healthcheck.check("xray", [], empty_stats)
    check(empty_result == [] and empty_stats["healthy"] == 0,
          "healthcheck: an empty node list is handled")
finally:
    healthcheck.validate_nodes = real_validate
    healthcheck._run_batch = real_run_batch
    healthcheck.PAUSE_BETWEEN_ROUNDS = real_pause
    # Leaving this stubbed would silently feed the endpoint tests below.
    healthcheck.usable_endpoints = real_usable_endpoints

# The preflight just has to prove the binary can build a basic config before
# the real pool is spent on it.
probes = healthcheck.preflight_probes()
check(len(probes) == 1, "healthcheck: preflight has one baseline probe")
_, probe_node = probes[0]
check(probe_node.port == "443" and probe_node.security == "tls",
      "healthcheck: the probe is a basic ws+tls outbound")
rendered = json.dumps(healthcheck._build_config([probe_node], healthcheck._placeholder_ports(1)))
check('"network": "ws"' in rendered, "healthcheck: the probe config renders a ws outbound")


# Endpoint selection and the pass/fail decision inside _probe. Both are stubbed
# at the connection layer so the suite stays offline.
class _FakeResponse:
    def __init__(self, status):
        self.status = status

    def read(self):
        return b""


class _FakeHTTPS:
    scripted: dict = {}

    def __init__(self, host, port=None, timeout=None):
        self._target = host

    def set_tunnel(self, host, port):
        self._target = host

    def request(self, method, path, headers=None):
        pass

    def getresponse(self):
        value = _FakeHTTPS.scripted.get(self._target, 599)
        if isinstance(value, Exception):
            raise value
        return _FakeResponse(value)

    def close(self):
        pass


CF, GS, AP = healthcheck.TEST_ENDPOINTS
real_https = healthcheck.http.client.HTTPSConnection
try:
    healthcheck.http.client.HTTPSConnection = _FakeHTTPS
    _FakeHTTPS.scripted = {
        CF.host: 204,                        # healthy
        GS.host: 500,                        # answers, but wrongly
        AP.host: OSError("refused"),         # unreachable
    }
    with contextlib.redirect_stdout(io.StringIO()):
        usable = healthcheck.usable_endpoints()
    check([e.host for e in usable] == [CF.host],
          "endpoints: only endpoints that actually answer correctly are used")

    # A node's verdict follows the endpoint's own expected status, not a
    # hardcoded 204 -- captive.apple.com answers 200 and that must count.
    _FakeHTTPS.scripted = {CF.host: 204}
    check(healthcheck._probe(1, CF)[0], "probe: the expected status passes")
    _FakeHTTPS.scripted = {CF.host: 200}
    check(not healthcheck._probe(1, CF)[0], "probe: a 200 does not pass a 204 endpoint")
    _FakeHTTPS.scripted = {AP.host: 200}
    check(healthcheck._probe(1, AP)[0], "probe: a 200 passes the endpoint that expects 200")
    _FakeHTTPS.scripted = {AP.host: 204}
    check(not healthcheck._probe(1, AP)[0], "probe: a 204 does not pass a 200 endpoint")
    _FakeHTTPS.scripted = {CF.host: OSError("boom")}
    ok, elapsed = healthcheck._probe(1, CF)
    check(not ok and elapsed >= 0, "probe: a connection failure is a clean failure, not a crash")
finally:
    healthcheck.http.client.HTTPSConnection = real_https
    _FakeHTTPS.scripted = {}

# With every endpoint unusable there is nothing to measure, and the run must
# say so rather than reporting that every node is dead.
real_usable = healthcheck.usable_endpoints
try:
    healthcheck.usable_endpoints = lambda: []
    raised = False
    try:
        healthcheck.check("xray", [parse_line(link(**BASE))], {}, rounds=1)
    except healthcheck.HealthCheckError:
        raised = True
    check(raised, "endpoints: no reachable endpoint aborts rather than failing every node")
finally:
    healthcheck.usable_endpoints = real_usable

# The cap on how many nodes reach the health check.
pool = [parse_line(link(**{**BASE, "host": f"t{i}.example"})) for i in range(60)]
check(len(pool) == 60, "cap: test pool built")
check(all(n.port == "443" for n in pool), "cap: every node in the pool is on 443")

check(build.cap_nodes(pool, 500) is pool, "cap: a pool under the limit is returned untouched")
check(len(build.cap_nodes(pool, 60)) == 60, "cap: a pool exactly at the limit is kept whole")

trimmed = build.cap_nodes(pool, 40)
check(len(trimmed) == 40, "cap: an oversized pool is trimmed to exactly the limit")
check(trimmed == pool[:40], "cap: the trim keeps input order, so it is deterministic")
check(len({n.identity() for n in trimmed}) == 40, "cap: trimming introduces no duplicates")

for limit in (1, 7, 39, 59):
    check(len(build.cap_nodes(pool, limit)) == limit,
          f"cap: limit {limit} yields exactly {limit} nodes")
check(build.cap_nodes([], 10) == [], "cap: an empty pool is handled")

# --- fetch retry coverage --------------------------------------------------
# A truncated response raises IncompleteRead, which is an HTTPException and NOT
# an OSError, so a handler catching only OSError silently skips the retry and
# lets the error escape as a traceback.


for exc in (
    http.client.IncompleteRead,
    http.client.BadStatusLine,
    http.client.RemoteDisconnected,
    urllib.error.URLError,
    urllib.error.HTTPError,
    TimeoutError,
    ConnectionResetError,
):
    check(
        issubclass(exc, build.RETRYABLE_FETCH_ERRORS),
        f"fetch: {exc.__name__} is retried rather than fatal",
    )


def _http_error(code: int):
    return urllib.error.HTTPError("http://x", code, "msg", {}, None)


# A wrong URL answers the same way every time; retrying it only delays the
# other sources. 408 and 429 explicitly mean "try again", and 5xx is transient.
for code in (400, 401, 403, 404, 410):
    check(build.is_permanent_http_error(_http_error(code)), f"fetch: HTTP {code} is not retried")
for code in (408, 429, 500, 502, 503):
    check(not build.is_permanent_http_error(_http_error(code)), f"fetch: HTTP {code} is retried")
check(not build.is_permanent_http_error(TimeoutError()), "fetch: a timeout is retried")


# --- sources ----------------------------------------------------------------

check(build.decode_if_base64("vless://x\ntrojan://y") == "vless://x\ntrojan://y",
      "sources: plain text passes through untouched")
encoded = base64.b64encode(b"vless://a\nvless://b").decode()
check(build.decode_if_base64(encoded) == "vless://a\nvless://b",
      "sources: a base64 list is decoded")
check(build.decode_if_base64(encoded.rstrip("=")) == "vless://a\nvless://b",
      "sources: base64 missing its padding still decodes")
check(build.decode_if_base64("not base64 and no scheme") == "not base64 and no scheme",
      "sources: undecodable text is left alone rather than mangled")
check(build.decode_if_base64("") == "", "sources: empty body is handled")
# A list may open with a long comment header, so the plain-text check has to
# scan the whole body rather than a prefix.
long_header = "# " + ("x" * 8000) + "\nvless://uid@1.2.3.4:443?type=ws&host=a.example\n"
check(build.decode_if_base64(long_header) == long_header,
      "sources: plain text is recognised even behind a long header")

saved = {k: os.environ.get(k) for k in ("SOURCE_URLS", "SOURCE_URL")}
try:
    os.environ.pop("SOURCE_URL", None)
    os.environ["SOURCE_URLS"] = "http://a/1.txt, http://b/2.txt"
    check(build.load_sources() == ["http://a/1.txt", "http://b/2.txt"],
          "sources: SOURCE_URLS accepts a comma-separated list")
    os.environ["SOURCE_URLS"] = "http://a/1.txt\nhttp://b/2.txt"
    check(build.load_sources() == ["http://a/1.txt", "http://b/2.txt"],
          "sources: SOURCE_URLS accepts newline separation")
    os.environ["SOURCE_URLS"] = "http://a/1.txt,http://a/1.txt,http://b/2.txt"
    check(build.load_sources() == ["http://a/1.txt", "http://b/2.txt"],
          "sources: a URL listed twice is fetched once, order preserved")
    # Isolates the per-line BOM strip: this path never goes through the
    # utf-8-sig file read, so only _clean can be cleaning it up.
    os.environ["SOURCE_URLS"] = "﻿http://a/1.txt"
    check(build.load_sources() == ["http://a/1.txt"],
          "sources: a stray BOM is stripped even outside the sources file")
    os.environ.pop("SOURCE_URLS")
    os.environ["SOURCE_URL"] = "http://only/1.txt"
    check(build.load_sources() == ["http://only/1.txt"],
          "sources: the older SOURCE_URL still works")
    os.environ.pop("SOURCE_URL")
    # Point at a throwaway file with distinctive URLs. Reading the real
    # sources.txt could not prove anything: it currently holds the same URL as
    # DEFAULT_SOURCES, so ignoring the file entirely would look identical.
    scratch = tempfile.mkdtemp(prefix="free-configs-sources-")
    fake = os.path.join(scratch, "sources.txt")
    with open(fake, "w", encoding="utf-8") as handle:
        handle.write(
            "# a comment\n"
            "\n"
            "https://example.invalid/one.txt\n"
            "   https://example.invalid/two.txt   \n"
            "   # an indented comment\n"
        )
    # Notepad writes UTF-8 with a BOM by default, and an unstripped BOM ends up
    # glued to the first URL, making it unusable.
    bom_file = os.path.join(scratch, "sources-bom.txt")
    with open(bom_file, "w", encoding="utf-8-sig") as handle:
        handle.write("# comment\nhttps://example.invalid/bom.txt\n")

    real_sources_file = build.SOURCES_FILE
    try:
        build.SOURCES_FILE = fake
        check(
            build.load_sources()
            == ["https://example.invalid/one.txt", "https://example.invalid/two.txt"],
            "sources: sources.txt is read, with comments and blank lines skipped",
        )
        build.SOURCES_FILE = bom_file
        check(
            build.load_sources() == ["https://example.invalid/bom.txt"],
            "sources: a byte-order mark does not corrupt the first URL",
        )
    finally:
        build.SOURCES_FILE = real_sources_file
        shutil.rmtree(scratch, ignore_errors=True)

    shipped = build.load_sources()
    check(
        bool(shipped) and all(u.startswith("http") for u in shipped),
        "sources: the repository's own sources.txt yields usable URLs",
    )
finally:
    for key, value in saved.items():
        os.environ.pop(key, None)
        if value is not None:
            os.environ[key] = value

# --- refusing to publish rubbish -------------------------------------------
# A source can return HTTP 200 and still be useless (an error page, or a
# changed format). build.py must fail and leave the previous configs.txt alone
# rather than publishing an empty subscription. Served from loopback so the
# test stays offline.


SERVERS: list[socket.socket] = []


def serve(body: bytes, status: str = "200 OK") -> str:
    """Serve one canned response on a loopback port; return its URL."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    sock.settimeout(30)
    SERVERS.append(sock)
    head = (
        f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()

    def loop() -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(head + body)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return f"http://127.0.0.1:{sock.getsockname()[1]}/list.txt"


def run_build(source_urls: str, **extra_env) -> tuple[subprocess.CompletedProcess, bool, str]:
    """Run build.py against the given sources; report whether a pre-existing
    configs.txt survived, and its final contents."""
    staging = tempfile.mkdtemp(prefix="free-configs-test-")
    sentinel = "#header\nvless://PREEXISTING\n"
    with open(os.path.join(staging, "configs.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(sentinel)
    environment = dict(os.environ)
    environment.pop("SOURCE_URL", None)
    environment.update(
        SOURCE_URLS=source_urls,
        OUTPUT_DIR=staging,
        SKIP_HEALTHCHECK="1",
        PYTHONIOENCODING="utf-8",
        **extra_env,
    )
    completed = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "build.py")],
        capture_output=True,
        text=True,
        env=environment,
        timeout=180,
    )
    with open(os.path.join(staging, "configs.txt"), encoding="utf-8") as fh:
        produced = fh.read()
    shutil.rmtree(staging, ignore_errors=True)
    return completed, produced == sentinel, produced


GOOD_BODY = (
    b"vless://22222222-2222-2222-2222-222222222222@9.9.9.9:2053"
    b"?security=tls&type=ws&host=live.example&path=/#ok\n"
)

# A source can return HTTP 200 and still be useless.
completed, untouched, _ = run_build(serve(b"<html><body>404 Not Found</body></html>"))
check(completed.returncode != 0, "build: an unusable source fails the run")
check(untouched, "build: an unusable source leaves the previous configs.txt intact")
check("Traceback" not in completed.stderr, "build: an unusable source reports, not crashes")
# The message has to name the source as the problem. Reaching the generic
# "not enough healthy nodes" path instead would send someone hunting for dead
# proxies when the real fault is upstream returning something unusable.
check(
    "no usable configs parsed" in completed.stderr,
    "build: an unusable source is diagnosed as a source problem",
)

# One dead source must not sink the others.
completed, _, produced = run_build(
    serve(GOOD_BODY) + "," + serve(b"gone", status="404 Not Found")
)
check(completed.returncode == 0, "sources: a dead source does not fail the build")
check("live.example" in produced, "sources: the surviving source still publishes")
check("unreachable source" in completed.stdout, "sources: the dead source is reported")
check(
    parse_line([l for l in produced.splitlines() if "live.example" in l][0]).port == "2053",
    "sources: a published node keeps its original port, not rewritten to 443",
)

# A URL with no scheme is the likeliest typo in a hand-edited sources.txt.
# urllib raises ValueError for it, which is not a URLError, so left unhandled
# it would abort the whole build -- healthy sources included -- with a
# traceback rather than naming the bad line.
completed, _, produced = run_build("raw.example.com/no-scheme.txt," + serve(GOOD_BODY))
check(completed.returncode == 0, "sources: a URL with no scheme does not sink the build")
check("live.example" in produced, "sources: the valid source still publishes alongside a typo")
check("Traceback" not in completed.stderr, "sources: a malformed URL reports, not crashes")

# Duplicate detection compares what a node IS, not how it is written: the
# #comment is a display name and query-parameter order carries no meaning, so
# neither may make two copies of one node look distinct. The comment on the
# surviving copy still has to reach configs.txt.
UID = "44444444-4444-4444-4444-444444444444"
SAME = (
    f"vless://{UID}@9.9.9.9:2053?security=tls&type=ws&host=live.example&path=/#FIRST NAME\n"
    # identical node, different display name
    f"vless://{UID}@9.9.9.9:2053?security=tls&type=ws&host=live.example&path=/#second name\n"
    # identical node, query parameters in a different order
    f"vless://{UID}@9.9.9.9:2053?path=/&host=live.example&type=ws&security=tls#third name\n"
    # identical node again, both differences at once
    f"vless://{UID}@9.9.9.9:2053?type=ws&security=tls&path=/&host=live.example#fourth\n"
).encode()

completed, _, produced = run_build(serve(SAME))
emitted = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(completed.returncode == 0, "dedup: the four-copy list builds")
check("1 distinct configs parsed" in completed.stdout,
      "dedup: four spellings of one node collapse to one")
check("3 duplicates dropped" in completed.stdout, "dedup: the other three are counted as repeats")
check(len(emitted) == 1, "dedup: four spellings of one node yield one published node")
# Names are percent-encoded on the wire, so decode before comparing.
names = [parse_line(l).tag for l in emitted]
check(all(n.startswith("FIRST NAME") for n in names),
      "dedup: the surviving copy keeps its source comment in the published name, unchanged")

# Order-insensitivity at the identity level, independent of the build.
a = parse_line(f"vless://{UID}@9.9.9.9:443?security=tls&type=ws&host=x.example#one")
b = parse_line(f"vless://{UID}@9.9.9.9:443?host=x.example&type=ws&security=tls#two")
check(a.identity() == b.identity(),
      "dedup: field order does not change a node's identity")
c = parse_line(f"vless://{UID}@9.9.9.9:443?security=tls&type=ws&host=OTHER.example#one")
check(a.identity() != c.identity(),
      "dedup: a genuinely different node keeps a different identity")

# The cap has to be wired into the build, not just implemented.
SIX = "".join(
    f"vless://55555555-5555-5555-5555-55555555555{i}@9.9.9.9:2053"
    f"?security=tls&type=ws&host=c{i}.example&path=/#n{i}\n"
    for i in range(6)
).encode()

completed, _, produced = run_build(serve(SIX), MAX_NODES_TO_TEST="4")
capped = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(completed.returncode == 0, "cap: a capped build succeeds")
check(len(capped) == 4, "cap: the build tests only the capped number of nodes")
check("capped to 4 nodes" in completed.stdout, "cap: the build reports that it capped")
check("2 dropped" in completed.stdout, "cap: the build reports how many it dropped")
check(all(parse_line(l).port == "2053" for l in capped),
      "cap: capped nodes keep their original port, not rewritten")

# Under the cap, nothing is dropped and nothing is reported.
completed, _, produced = run_build(serve(SIX), MAX_NODES_TO_TEST="500")
check(len([l for l in produced.splitlines() if l and not l.startswith("#")]) == 6,
      "cap: a pool under the limit is published whole")
check("capped to" not in completed.stdout, "cap: no cap message when the limit is not reached")

# Every source dead is a different matter.
completed, untouched, _ = run_build(
    serve(b"gone", status="404 Not Found") + "," + serve(b"gone", status="410 Gone")
)
check(completed.returncode != 0, "sources: all sources dead fails the build")
check(untouched, "sources: all sources dead leaves the previous configs.txt intact")

# A base64 source is decoded, and duplicate lines across sources collapse.
completed, _, produced = run_build(
    serve(GOOD_BODY) + "," + serve(base64.b64encode(GOOD_BODY))
)
check(completed.returncode == 0, "sources: a base64 source is accepted")
# The same node listed by two sources -- once plain, once base64-encoded --
# must dedupe to one published node, not two.
emitted = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(len(emitted) == 1, "sources: the same node from two sources is deduped")
check(
    "1 distinct configs parsed" in completed.stdout
    and "1 duplicates dropped" in completed.stdout,
    "sources: a repeated node is dropped once, not parsed twice",
)
check(parse_line(emitted[0]).port == "2053",
      "sources: the surviving node keeps its original port")

for sock in SERVERS:
    sock.close()

# Locating the core, reading the previous file, and tailing a log. Small, but
# each has a failure path a user actually meets: a wrong XRAY_BIN, a missing
# configs.txt on the very first run, and a batch that died before logging.

_saved_xray_bin = os.environ.get("XRAY_BIN")
_scratch = tempfile.mkdtemp(prefix="free-configs-misc-")
try:
    real_binary = os.path.join(_scratch, "xray-stub")
    with open(real_binary, "w", encoding="utf-8") as handle:
        handle.write("stub")

    os.environ["XRAY_BIN"] = real_binary
    check(build.locate_xray() == real_binary, "locate: XRAY_BIN is used when it exists")

    os.environ["XRAY_BIN"] = os.path.join(_scratch, "not-here")
    try:
        build.locate_xray()
        check(False, "locate: a missing XRAY_BIN is rejected")
    except SystemExit as error:
        check("not-here" in str(error),
              "locate: a missing XRAY_BIN is rejected, naming the path")

    # Nothing on PATH and nothing in bin/: the message has to say what is
    # needed, since this is what a broken install step looks like in CI.
    os.environ.pop("XRAY_BIN", None)
    _real_which, _real_root = shutil.which, build.REPO_ROOT
    try:
        build.shutil.which = lambda name: None
        build.REPO_ROOT = _scratch
        try:
            build.locate_xray()
            check(False, "locate: absent core is reported")
        except SystemExit as error:
            check("XRAY_BIN" in str(error),
                  "locate: absent core names the fix")
    finally:
        build.shutil.which = _real_which
        build.REPO_ROOT = _real_root

    # existing_links: what the publish step compares against.
    missing = os.path.join(_scratch, "nope.txt")
    check(build.existing_links(missing) == [],
          "publish: a missing previous file reads as no links, not an error")
    header_only = os.path.join(_scratch, "header.txt")
    with open(header_only, "w", encoding="utf-8") as handle:
        handle.write("#profile-title: x\n# a comment\n\n")
    check(build.existing_links(header_only) == [],
          "publish: a file of only comments reads as no links")
    with_links = os.path.join(_scratch, "some.txt")
    with open(with_links, "w", encoding="utf-8") as handle:
        handle.write("#header\nvless://a\n\nvless://b\n")
    check(build.existing_links(with_links) == ["vless://a", "vless://b"],
          "publish: links are read and comments and blanks skipped")

    # _log_tail: only ever used when something already went wrong.
    check("(no log)" in healthcheck._log_tail(os.path.join(_scratch, "absent.log")),
          "log tail: a missing log does not raise while reporting a failure")
    log_file = os.path.join(_scratch, "x.log")
    with open(log_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(f"line {i}" for i in range(20)) + "\n")
    tail = healthcheck._log_tail(log_file, lines=3)
    check(tail.count("\n") == 2 and "line 19" in tail and "line 16" not in tail,
          "log tail: the last lines are returned, not the first")
finally:
    shutil.rmtree(_scratch, ignore_errors=True)
    os.environ.pop("XRAY_BIN", None)
    if _saved_xray_bin is not None:
        os.environ["XRAY_BIN"] = _saved_xray_bin

# --- report ----------------------------------------------------------------

print(f"{PASSED} checks passed, {len(FAILURES)} failed")
for failure in FAILURES:
    print(f"  FAIL: {failure}")
raise SystemExit(1 if FAILURES else 0)
