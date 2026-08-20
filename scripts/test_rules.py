"""Tests for the transform rules and the share-link parser.

    python scripts/test_rules.py

No test framework needed. Every numbered rule from the spec has at least one
test named after it, plus parser edge cases and end-to-end properties.
"""

from __future__ import annotations

import os
import shutil
import sys
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

for spelling in ("allowInsecure", "allow_insecure", "insecure", "ALLOWINSECURE", "AllowInsecure"):
    result = one(**{**BASE, spelling: "1"})
    check(
        all(not n.has(spelling) for n in result),
        f"rule 11: {spelling} removed",
    )
    check(
        all("insecure" not in n.to_link().lower() for n in result),
        f"rule 11: {spelling} absent from the emitted link",
    )

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

# --- masking constants round trip ------------------------------------------

for name, encoded, decoded in (
    ("FM_443", transform.FM_443_ENCODED, transform.FM_443),
    ("CS_443", transform.CS_443_ENCODED, transform.CS_443),
    ("FM_8080", transform.FM_8080_ENCODED, transform.FM_8080),
):
    check(quote(decoded, safe="") == encoded, f"constants: {name} survives a decode/encode cycle")

# --- Xray outbound rendering ----------------------------------------------

import json  # noqa: E402

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

# --- fetch retry coverage --------------------------------------------------
# A truncated response raises IncompleteRead, which is an HTTPException and NOT
# an OSError, so a handler catching only OSError silently skips the retry and
# lets the error escape as a traceback.

import http.client  # noqa: E402
import urllib.error  # noqa: E402

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

# --- refusing to publish rubbish -------------------------------------------
# A source can return HTTP 200 and still be useless (an error page, or a
# changed format). build.py must fail and leave the previous configs.txt alone
# rather than publishing an empty subscription. Served from loopback so the
# test stays offline.

import socket  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402


def _serve_once(sock: socket.socket, body: bytes) -> None:
    try:
        conn, _ = sock.accept()
    except OSError:
        return
    with conn:
        try:
            conn.recv(4096)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
                + body
            )
        except OSError:
            pass


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
listener.settimeout(30)
served_port = listener.getsockname()[1]
threading.Thread(
    target=_serve_once, args=(listener, b"<html><body>404 Not Found</body></html>"), daemon=True
).start()

staging = tempfile.mkdtemp(prefix="free-configs-test-")
sentinel = "#header\nvless://PREEXISTING\n"
with open(os.path.join(staging, "configs.txt"), "w", encoding="utf-8", newline="\n") as handle:
    handle.write(sentinel)

environment = dict(os.environ)
environment.update(
    SOURCE_URL=f"http://127.0.0.1:{served_port}/list.txt",
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
listener.close()

with open(os.path.join(staging, "configs.txt"), encoding="utf-8") as handle:
    still_there = handle.read() == sentinel

check(completed.returncode != 0, "build: an unusable source fails the run")
check(still_there, "build: an unusable source leaves the previous configs.txt intact")
check("Traceback" not in completed.stderr, "build: an unusable source reports, not crashes")
# The message has to name the source as the problem. Reaching the generic
# "not enough healthy nodes" path instead would send someone hunting for dead
# proxies when the real fault is upstream returning something unusable.
check(
    "no usable configs parsed" in completed.stderr,
    "build: an unusable source is diagnosed as a source problem",
)
shutil.rmtree(staging, ignore_errors=True)

# --- report ----------------------------------------------------------------

print(f"{PASSED} checks passed, {len(FAILURES)} failed")
for failure in FAILURES:
    print(f"  FAIL: {failure}")
raise SystemExit(1 if FAILURES else 0)
