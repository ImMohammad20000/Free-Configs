"""Tests for the transform rules and the share-link parser.

    python scripts/test_rules.py

No test framework needed. Every numbered rule from the spec has at least one
test named after it, plus parser edge cases and end-to-end properties.
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
import urllib.error
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import transform  # noqa: E402
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


def one(**kwargs) -> list[Node]:
    """Run the full transform over a single synthetic link."""
    node = parse_line(link(**kwargs))
    assert node is not None, "test input did not parse"
    return transform.transform([node], {})


def survives(**kwargs) -> bool:
    return len(one(**kwargs)) > 0


BASE = dict(security="tls", type="ws", host="a.example", path="/")


# --- rule 1: security ------------------------------------------------------

for value, expected in (("reality", False), ("tls", True), ("none", True), ("xtls", False)):
    got = survives(**{**BASE, "security": value, "port": "443" if value == "tls" else "8080"})
    check(got == expected, f"rule 1: security={value!r} should {'survive' if expected else 'drop'}")

check(survives(security=None, type="ws", host="a.example", port="8080"), "rule 1: absent security survives")

# --- rule 2: transport -----------------------------------------------------

for value in transform.ALLOWED_TRANSPORTS:
    check(survives(**{**BASE, "type": value}), f"rule 2: type={value!r} should survive")
for value in ("tcp", "raw", "kcp", "h2", ""):
    check(not survives(**{**BASE, "type": value}), f"rule 2: type={value!r} should drop")

# --- rule 3: host ----------------------------------------------------------

check(not survives(security="tls", type="ws", path="/", host=None), "rule 3: missing host drops")
check(not survives(**{**BASE, "host": ""}), "rule 3: empty host drops")
check(not survives(**{**BASE, "host": "   "}), "rule 3: whitespace-only host drops")

# --- rules 4/5/6: ports ----------------------------------------------------

for port in transform.PORTS_MAPPED_TO_443:
    result = one(**{**BASE, "port": port})
    check(bool(result), f"rule 4: port {port} accepted")
    check(any(n.port == "443" for n in result), f"rule 5: port {port} maps to 443")

for port in transform.PORTS_MAPPED_TO_8080:
    result = one(**{**BASE, "security": "none", "port": port})
    check(bool(result), f"rule 4: port {port} accepted")
    check(any(n.port == "8080" for n in result), f"rule 6: port {port} maps to 8080")

for port in ("22", "8444", "0", "65536", "443abc", "", "abc"):
    check(not survives(**{**BASE, "port": port}), f"rule 4: port {port!r} rejected")

check(parse_line("vless://uid@1.2.3.4?type=ws&host=a.example").port == "", "rule 4: no port parses as empty")
check(not survives(**{**BASE, "port": " 443"}), "rule 4: padded port rejected")

# --- rules 7/8: security must match the port -------------------------------

check(not survives(security="tls", type="ws", host="a.example", port="8080"),
      "rule 7: 8080 + tls drops")
check(not survives(security="none", type="ws", host="a.example", port="443"),
      "rule 8: 443 + non-tls drops")
check(not survives(type="ws", host="a.example", port="2053"),
      "rule 8: 443-bucket without security drops")

# --- rule 9: mirroring -----------------------------------------------------

result = one(**BASE)
check(len(result) == 2, "rule 9: one input yields the node plus its mirror")
ports = sorted(n.port for n in result)
check(ports == ["443", "8080"], "rule 9: mirror lands on the opposite port")

original = next(n for n in result if n.port == "443")
mirror = next(n for n in result if n.port == "8080")
check(original.security == "tls", "rule 9: original 443 keeps tls")
check(mirror.security == "none", "rule 9: 443->8080 mirror sets security=none")
check(not mirror.get("sni"), "rule 9: 443->8080 mirror removes sni")
check(original.get("sni") == "a.example", "rule 9: original keeps its sni")

result = one(security="none", type="ws", host="b.example", path="/", port="8080")
up = next(n for n in result if n.port == "443")
down = next(n for n in result if n.port == "8080")
check(up.security == "tls", "rule 9: 8080->443 mirror sets security=tls")
check(up.get("sni") == "b.example", "rule 9: 8080->443 mirror sets sni=host")
check(down.security == "none", "rule 9: original 8080 unchanged")

# Mutating one must not touch the other (shared-dict regression guard).
a, b = one(**BASE)
a.set("path", "/mutated")
check(b.get("path") != "/mutated", "rule 9: mirror does not share the params dict")

# rule_9_mirror in isolation. Going through transform() cannot prove rule 9
# removes sni, because rule 13 strips it from plaintext nodes anyway.
probe = parse_line(link(**BASE))
probe.port = "443"
probe.set("sni", "orig.example")
twin = transform.rule_9_mirror(probe)
check(twin.port == "8080", "rule 9 isolated: 443 mirrors to 8080")
check(not twin.get("sni"), "rule 9 isolated: mirror removes sni itself")
check(twin.security == "none", "rule 9 isolated: mirror sets security=none itself")
check(probe.get("sni") == "orig.example", "rule 9 isolated: original keeps its sni")
check(probe.port == "443", "rule 9 isolated: original keeps its port")

probe = parse_line(link(security="none", type="ws", host="c.example", path="/", port="8080"))
probe.port = "8080"
twin = transform.rule_9_mirror(probe)
check(twin.port == "443", "rule 9 isolated: 8080 mirrors to 443")
check(twin.security == "tls", "rule 9 isolated: mirror sets security=tls itself")
check(twin.get("sni") == "c.example", "rule 9 isolated: mirror sets sni=host itself")
check(probe.security == "none", "rule 9 isolated: original stays plaintext")

# --- rule 10: exit address -------------------------------------------------

for node in one(**BASE):
    expected = (
        transform.ADDRESS_FOR_PORT_443 if node.port == "443" else transform.ADDRESS_FOR_PORT_8080
    )
    check(node.address == expected, f"rule 10: port {node.port} uses its own address constant")

# The two constants must be applied by separate functions so either can move.
probe = parse_line(link(**BASE))
probe.port = "443"
probe.address = "0.0.0.0"
transform.rule_10_set_address_for_8080(probe)
check(probe.address == "0.0.0.0", "rule 10: the 8080 setter ignores a 443 node")
transform.rule_10_set_address_for_443(probe)
check(probe.address == transform.ADDRESS_FOR_PORT_443, "rule 10: the 443 setter applies")

# --- rule 11: strip certificate opt-outs -----------------------------------

for spelling in ("allowInsecure", "allow_insecure", "insecure", "ALLOWINSECURE",
                 "AllowInsecure", "ech", "ECH", "Ech"):
    result = one(**{**BASE, spelling: "1"})
    check(
        all(not n.has(spelling) for n in result),
        f"rule 11: {spelling} removed",
    )
    check(
        all(f"{spelling.lower()}=" not in n.to_link().lower() for n in result),
        f"rule 11: {spelling} absent from the emitted link",
    )

# ech is stripped even when it sits beside parameters that must survive.
survivor = one(**{**BASE, "ech": "ip.gs+udp://8.8.8.8"})
for node in survivor:
    check(not node.has("ech"), "rule 11: ech removed from the node")
    check("ech=" not in node.to_link(), "rule 11: ech absent from the emitted link")
    check(node.get("host") == "a.example" and node.get("type") == "ws",
          "rule 11: stripping ech leaves the other parameters intact")
check(len(survivor) == 2, "rule 11: stripping ech does not drop the node")

# --- rules 12/13: masking parameters ---------------------------------------

for node in one(**BASE):
    if node.port == "443":
        check(node.get("fp") == "unsafe", "rule 12: fp=unsafe")
        check(node.get("fm") == transform.FM_443, "rule 12: fm value")
        check(node.get("cs") == transform.CS_443, "rule 12: cs value")
        emitted = node.to_link()
        check(transform.FM_443_ENCODED in emitted, "rule 12: fm is byte-exact in the link")
        check(transform.CS_443_ENCODED in emitted, "rule 12: cs is byte-exact in the link")
        check("fp=unsafe" in emitted, "rule 12: fp is byte-exact in the link")
    else:
        check(node.get("fm") == transform.FM_8080, "rule 13: fm value")
        check(transform.FM_8080_ENCODED in node.to_link(), "rule 13: fm is byte-exact in the link")
        for key in transform.TLS_ONLY_KEYS:
            check(not node.get(key), f"rule 13: {key} stripped from a plaintext node")

# A plaintext node that arrives carrying TLS-only parameters must lose them.
# The mirror path never sets these, so only a source node like this exercises it.
plaintext = one(
    security="none", type="ws", host="c.example", path="/", port="8080",
    alpn="h2,http/1.1", fp="chrome", cs="TLS_AES_128_GCM_SHA256", sni="stale.example",
)
down = next(n for n in plaintext if n.port == "8080")
for key in transform.TLS_ONLY_KEYS:
    check(not down.get(key), f"rule 13: inherited {key} stripped from a plaintext node")
check("alpn" not in down.to_link(), "rule 13: alpn absent from the emitted plaintext link")
up = next(n for n in plaintext if n.port == "443")
check(up.get("fp") == "unsafe", "rule 12: mirror of a plaintext node still gets fp=unsafe")

# Existing values must be overwritten, not kept ("set/change").
for node in one(**{**BASE, "fp": "chrome", "fm": "junk", "cs": "junk"}):
    if node.port == "443":
        check(node.get("fp") == "unsafe", "rule 12: existing fp is overwritten")
        check(node.get("fm") == transform.FM_443, "rule 12: existing fm is overwritten")
    else:
        check(node.get("fm") == transform.FM_8080, "rule 13: existing fm is overwritten")

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

# Round trip: emitting and re-parsing must be stable.
for node in one(**BASE):
    emitted = node.to_link()
    reparsed = parse_line(emitted)
    check(reparsed is not None and reparsed.to_link() == emitted, "parser: emit/parse round trip")

# --- dedup -----------------------------------------------------------------

pair = [parse_line(link(**BASE)), parse_line(link(**BASE))]
check(len(transform.transform(pair, {})) == 2, "dedup: identical inputs collapse to one node + mirror")

differing = [parse_line(link(**BASE)), parse_line(link(**{**BASE, "host": "other.example"}))]
check(len(transform.transform(differing, {})) == 4, "dedup: different hosts stay distinct")

# --- vmess -----------------------------------------------------------------

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
check(transform.INCLUDE_VMESS is False, "vmess: excluded by default (cannot carry fm/cs)")
check(len(transform.transform([parse_line(VMESS)], {})) == 0, "vmess: dropped by the transform")

# vmess serialisation is only reachable when INCLUDE_VMESS is turned on, but a
# toggle nobody exercises is a toggle that breaks silently. These also verify
# the reason it is off: a vmess link genuinely cannot carry fm or cs.

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

real_include = transform.INCLUDE_VMESS
try:
    transform.INCLUDE_VMESS = True
    vm_out = transform.transform([parse_line(VMESS_FULL)], {})
    check(len(vm_out) == 2, "vmess: with the toggle on it survives and gains its mirror")
    vm443 = next(n for n in vm_out if n.port == "443")
    vm8080 = next(n for n in vm_out if n.port == "8080")
    check(vm443.address == transform.ADDRESS_FOR_PORT_443 and vm443.security == "tls",
          "vmess: rules 8 and 10 apply to a vmess node")
    check(vm8080.security == "none" and not vm8080.get("sni"),
          "vmess: rule 9 mirrors a vmess node to plaintext")
    check(vm443.get("fm") == transform.FM_443 and vm443.get("cs") == transform.CS_443,
          "vmess: rule 12 sets fm and cs on the node")

    # The documented limitation, verified rather than assumed: the vmess wire
    # format has a fixed key set with nowhere to put fm or cs, so they are
    # silently lost on serialisation. That is why the toggle defaults to off.
    payload = json.loads(base64.b64decode(
        vm443.to_link().split("://", 1)[1] + "=="
    ).decode("utf-8", "replace"))
    check("fm" not in payload and "cs" not in payload,
          "vmess: the wire format has nowhere to carry fm or cs")
    check(transform.FM_443_ENCODED not in vm443.to_link(),
          "vmess: fm really is absent from the emitted link")
    check(payload["tls"] == "tls" and payload["sni"] == "vm.example",
          "vmess: what the format can carry is still carried")
    check(payload["add"] == transform.ADDRESS_FOR_PORT_443 and payload["port"] == "443",
          "vmess: the rewritten address and port reach the wire format")
finally:
    transform.INCLUDE_VMESS = real_include

# --- masking constants round trip ------------------------------------------

for name, encoded, decoded in (
    ("FM_443", transform.FM_443_ENCODED, transform.FM_443),
    ("CS_443", transform.CS_443_ENCODED, transform.CS_443),
    ("FM_8080", transform.FM_8080_ENCODED, transform.FM_8080),
):
    check(quote(decoded, safe="") == encoded, f"constants: {name} survives a decode/encode cycle")

# --- Xray outbound rendering ----------------------------------------------


for node in one(**BASE):
    outbound = json.loads(json.dumps(node.to_outbound("t")))
    stream = outbound["streamSettings"]
    check(outbound["protocol"] == "vless", "outbound: protocol")
    check(stream["network"] == "ws", "outbound: network")
    check(isinstance(stream.get("finalmask"), dict), "outbound: fm becomes a finalmask object")
    check(stream["wsSettings"]["host"] == "a.example", "outbound: ws host header")
    if node.port == "443":
        check(stream["security"] == "tls", "outbound: 443 uses tls")
        check(stream["tlsSettings"]["fingerprint"] == "unsafe", "outbound: fingerprint")
        check(stream["tlsSettings"]["cipherSuites"] == transform.CS_443, "outbound: cipherSuites")
        check(stream["tlsSettings"]["allowInsecure"] is False, "outbound: never skips verification")
    else:
        check(stream["security"] == "none", "outbound: 8080 is plaintext")

grpc = one(**{**BASE, "type": "grpc", "serviceName": "gs"})
for node in grpc:
    outbound = node.to_outbound("t")
    check(outbound["streamSettings"]["network"] == "grpc", "outbound: grpc network")
    check(
        outbound["streamSettings"]["grpcSettings"]["authority"] == "a.example",
        "outbound: grpc authority comes from host",
    )

# --- health check: routing safety and bisection ------------------------------
# These do not need a network or an Xray binary, but they guard the property
# everything else rests on: a node must only be able to pass by carrying real
# traffic through its own outbound.

import healthcheck  # noqa: E402

batch = [n for spec in ({}, {"host": "b.example"}, {"host": "c.example"}) for n in one(**{**BASE, **spec})]
config = healthcheck._build_config(batch, healthcheck.BASE_PORT)

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
check(ports == list(range(healthcheck.BASE_PORT, healthcheck.BASE_PORT + len(batch))),
      "healthcheck: inbound ports are unique and sequential")
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
real_popen = healthcheck.subprocess.Popen
real_wait = healthcheck._wait_until_listening
real_probe = healthcheck._probe
try:
    healthcheck.subprocess.Popen = lambda *a, **k: _FakeProcess()
    healthcheck._wait_until_listening = lambda ports, deadline, process=None: True
    # Latency encodes the port, so a mis-mapped result is visible in the output.
    def _record(port, endpoint):
        probed_ports.append(port)
        probed_endpoints.append(endpoint.host)
        return (port % 2 == 0, float(port))

    healthcheck._probe = _record
    mapped = healthcheck._run_batch("xray", scored_batch := [n for n in one(**BASE)] * 3,
                                    tempfile.gettempdir(), "unit",
                                    healthcheck.TEST_ENDPOINTS[0])
finally:
    healthcheck.subprocess.Popen = real_popen
    healthcheck._wait_until_listening = real_wait
    healthcheck._probe = real_probe

expected_ports = list(range(healthcheck.BASE_PORT, healthcheck.BASE_PORT + len(scored_batch)))
check(sorted(probed_ports) == expected_ports,
      "healthcheck: each node in a batch is probed on its own port, once")
check(
    all(latency == float(healthcheck.BASE_PORT + index) for index, latency in mapped.items()),
    "healthcheck: a probe result is credited to the node it came from",
)
check(
    set(mapped) == {i for i in range(len(scored_batch))
                    if (healthcheck.BASE_PORT + i) % 2 == 0},
    "healthcheck: only the nodes that passed appear in the result",
)
check(set(probed_endpoints) == {healthcheck.TEST_ENDPOINTS[0].host},
      "healthcheck: every node in a batch is measured against the same endpoint")


# check() decides what is published. A node must pass EVERY round: passing
# some rounds is what "flaky" means, and publishing those is the mistake the
# three-round design exists to avoid.
scored = [n for i in range(5) for n in one(**{**BASE, "host": f"n{i}.example"})][:5]
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

# The preflight has to exercise both shapes the pipeline emits, or it proves
# nothing about the core it is about to trust.
probes = healthcheck.preflight_probes()
check({node.port for _, node in probes} == {"443", "8080"},
      "healthcheck: preflight checks both the TLS and the plaintext shape")
tls_probe = next(node for _, node in probes if node.port == "443")
plain_probe = next(node for _, node in probes if node.port == "8080")
check(
    tls_probe.get("fp") == "unsafe"
    and tls_probe.get("fm") == transform.FM_443
    and tls_probe.get("cs") == transform.CS_443,
    "healthcheck: the TLS probe carries the real fp, fm and cs values",
)
check(plain_probe.get("fm") == transform.FM_8080 and plain_probe.security == "none",
      "healthcheck: the plaintext probe is an unencrypted outbound with the 8080 fm")
check(
    all(node.address == transform.ADDRESS_FOR_PORT_443
        or node.address == transform.ADDRESS_FOR_PORT_8080 for _, node in probes),
    "healthcheck: probes use the real exit address, not a placeholder",
)
for _, node in probes:
    rendered = json.dumps(healthcheck._build_config([node], healthcheck.BASE_PORT))
    check("finalmask" in rendered, f"healthcheck: the port {node.port} probe renders a finalmask")


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
        healthcheck.check("xray", [n for n in one(**BASE)], {}, rounds=1)
    except healthcheck.HealthCheckError:
        raised = True
    check(raised, "endpoints: no reachable endpoint aborts rather than failing every node")
finally:
    healthcheck.usable_endpoints = real_usable

# --- fetch retry coverage --------------------------------------------------
# A truncated response raises IncompleteRead, which is an HTTPException and NOT
# an OSError, so a handler catching only OSError silently skips the retry and
# lets the error escape as a traceback.


import build  # noqa: E402

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


def run_build(source_urls: str) -> tuple[subprocess.CompletedProcess, bool, str]:
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
check(len(emitted) == 2, "dedup: one node in, one node plus its rule 9 mirror out")
# Names are percent-encoded on the wire, so decode before comparing.
names = [parse_line(l).tag for l in emitted]
check(all(n.startswith("FIRST NAME") for n in names),
      "dedup: the surviving copy keeps its source comment in the published name")
check(len(set(names)) == 2,
      "dedup: the node and its mirror are still told apart by name")
check(sorted(n.split(" | ")[1] for n in names) == ["443", "8080"],
      "dedup: what distinguishes them is the port, appended after the comment")

# Order-insensitivity at the identity level, independent of the build.
a = parse_line(f"vless://{UID}@9.9.9.9:443?security=tls&type=ws&host=x.example#one")
b = parse_line(f"vless://{UID}@9.9.9.9:443?host=x.example&type=ws&security=tls#two")
check(a.identity() == b.identity(),
      "dedup: field order does not change a node's identity")
c = parse_line(f"vless://{UID}@9.9.9.9:443?security=tls&type=ws&host=OTHER.example#one")
check(a.identity() != c.identity(),
      "dedup: a genuinely different node keeps a different identity")

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
# One input node listed by both sources must yield exactly two output nodes --
# itself and its rule 9 mirror -- not four.
emitted = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(len(emitted) == 2, "sources: the same node from two sources is deduped")
# Node-level dedup would collapse these anyway, so assert the line-level pass
# actually ran -- it is what keeps a large overlapping source from being
# parsed twice.
check(
    "1 distinct configs parsed" in completed.stdout
    and "1 duplicates dropped" in completed.stdout,
    "sources: a repeated node is dropped once, not parsed twice",
)
check(
    sorted(parse_line(l).port for l in emitted) == ["443", "8080"],
    "sources: the deduped node still gains its mirror",
)

for sock in SERVERS:
    sock.close()

# --- report ----------------------------------------------------------------

print(f"{PASSED} checks passed, {len(FAILURES)} failed")
for failure in FAILURES:
    print(f"  FAIL: {failure}")
raise SystemExit(1 if FAILURES else 0)
