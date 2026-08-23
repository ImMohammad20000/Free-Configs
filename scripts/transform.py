"""Rules 1-13: turn the upstream list into the Cloudflare-fronted node set.

Every numbered rule from the spec is its own function below, named after its
number, and :func:`transform` applies them in order. Tunables are grouped at
the top of the file.

Three normalisations are applied on top of the numbered rules; each is marked
NORMALISATION where it happens and explained in README.md:

* the port 443 -> 8080 mirror (rule 9) also drops TLS, because a plaintext
  Cloudflare port cannot complete a TLS handshake -- this is the same
  invariant rule 7 enforces on the original nodes;
* every port 443 node gets ``sni`` set to its ``host``, because rule 10
  replaces the address with a Cloudflare IP and Cloudflare routes HTTPS by
  SNI -- an ``sni`` still pointing at the origin server would never connect;
* TLS-only parameters (``sni``, ``alpn``, ``fp``, ``cs``) are dropped from
  port 8080 nodes, where they are inert.
"""

from __future__ import annotations

import hashlib
from urllib.parse import quote, unquote

from nodes import ECH_KEYS, INSECURE_KEYS, Node

# --- rule 10: exit address ------------------------------------------------
# Deliberately two separate constants applied by two separate functions, so
# either port's exit address can be repointed without touching the other.
ADDRESS_FOR_PORT_443 = "188.114.97.6"
ADDRESS_FOR_PORT_8080 = "188.114.97.6"

# --- rules 4-6: port buckets ---------------------------------------------
PORTS_MAPPED_TO_443 = ("443", "2053", "2083", "2087", "2096", "8443")
PORTS_MAPPED_TO_8080 = ("80", "8080", "8880", "2052", "2082", "2086", "2095")

# --- rules 1-2: accepted values ------------------------------------------
ALLOWED_SECURITY = ("", "tls", "none")
ALLOWED_TRANSPORTS = ("ws", "xhttp", "websocket", "httpupgrade", "grpc")

# --- rules 12-13: client-side masking ------------------------------------
# Stored exactly as supplied (percent-encoded), decoded once at import. The
# self-check below proves re-encoding reproduces these strings byte for byte,
# so what lands in configs.txt is what was asked for.
FP_443_ENCODED = "unsafe"
FM_443_ENCODED = (
    "%7B%22tcp%22%3A%20%5B%7B%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22"
    "packets%22%3A%20%22tlshello%22%2C%20%22lengths%22%3A%20%5B%225%22%2C%20%2294%22%2C%20%22"
    "1%22%5D%2C%20%22delays%22%3A%20%5B%220%22%5D%2C%20%22maxSplit%22%3A%20%220%22%7D%7D%2C%7B"
    "%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22packets%22%3A%20%221-1%22%2C"
    "%20%22lengths%22%3A%20%5B%22109%22%2C%20%221%22%5D%2C%20%22delays%22%3A%20%5B%221%22%5D%2C"
    "%20%22maxSplit%22%3A%20%22355%22%7D%7D%5D%7D"
)
CS_443_ENCODED = (
    "TLS_AES_256_GCM_SHA384%3ATLS_CHACHA20_POLY1305_SHA256%3ATLS_AES_128_GCM_SHA256%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384%3ATLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256%3A"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256%3ATLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    "%3ATLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA%3ATLS_ECDHE_RSA_WITH_AES_256_CBC_SHA%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
)
FM_8080_ENCODED = (
    "%7B%22tcp%22%3A%20%5B%7B%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22"
    "packets%22%3A%20%221-1%22%2C%20%22lengths%22%3A%20%5B%221%22%5D%2C%20%22delays%22%3A%20"
    "%5B%224%22%5D%2C%20%22maxSplit%22%3A%20%22355%22%7D%7D%5D%7D"
)

FP_443 = unquote(FP_443_ENCODED)
FM_443 = unquote(FM_443_ENCODED)
CS_443 = unquote(CS_443_ENCODED)
FM_8080 = unquote(FM_8080_ENCODED)

# Parameters that only mean anything under TLS.
TLS_ONLY_KEYS = ("sni", "alpn", "fp", "cs")

# A vmess share link is base64'd JSON with a fixed key set, and that key set has
# nowhere to put fm or cs -- so a vmess node cannot satisfy rules 12-13 and would
# ship without the fragmentation every other node gets. They are dropped rather
# than published as silent exceptions. Set True to publish them unmasked anyway.
INCLUDE_VMESS = False

# Keep each source's own comment (everything after "#") in the published name.
# It cannot stand alone as the name, though: rule 9 gives every node a twin on
# the other port, and one source labels all of its several thousand nodes
# "@DeltaKroneckerGithub", so on its own the comment would leave most entries
# indistinguishable in a client. The port and a short content hash are appended
# to tell them apart. Set KEEP_SOURCE_COMMENT False for generated names only.
RENAME_NODES = True
KEEP_SOURCE_COMMENT = True
NAME_PREFIX = ""


def _self_check() -> None:
    """Fail loudly at import if a masking constant would not survive a
    decode/encode round trip, which would silently corrupt configs.txt."""
    for name, encoded, decoded in (
        ("FM_443", FM_443_ENCODED, FM_443),
        ("CS_443", CS_443_ENCODED, CS_443),
        ("FM_8080", FM_8080_ENCODED, FM_8080),
    ):
        if quote(decoded, safe="") != encoded:
            raise AssertionError(f"{name} does not round-trip through percent-encoding")


_self_check()


# --- filters (rules 1-4) --------------------------------------------------


def rule_1_security_allowed(node: Node) -> bool:
    """Keep security=tls, security=none, or no security at all. Drops reality."""
    return node.security in ALLOWED_SECURITY


def rule_2_transport_allowed(node: Node) -> bool:
    return node.transport in ALLOWED_TRANSPORTS


def rule_3_has_host(node: Node) -> bool:
    return bool(node.host.strip())


def rule_4_port_allowed(node: Node) -> bool:
    return node.port in PORTS_MAPPED_TO_443 or node.port in PORTS_MAPPED_TO_8080


# --- port normalisation (rules 5-6) ---------------------------------------


def rule_5_normalise_to_443(node: Node) -> None:
    if node.port in PORTS_MAPPED_TO_443:
        node.port = "443"


def rule_6_normalise_to_8080(node: Node) -> None:
    if node.port in PORTS_MAPPED_TO_8080:
        node.port = "8080"


# --- post-normalisation filters (rules 7-8) -------------------------------


def rule_7_drop_plaintext_port_with_tls(node: Node) -> bool:
    """False (drop) when port 8080 carries security=tls."""
    return not (node.port == "8080" and node.security == "tls")


def rule_8_drop_tls_port_without_tls(node: Node) -> bool:
    """False (drop) when port 443 does not carry security=tls."""
    return not (node.port == "443" and node.security != "tls")


# --- rule 9: mirror -------------------------------------------------------


def rule_9_mirror(node: Node) -> Node:
    """Return the opposite-transport twin of ``node``; the original is untouched."""
    twin = node.copy()
    twin.is_mirror = True
    if twin.port == "8080":
        twin.port = "443"
        twin.set("security", "tls")
        twin.set("sni", twin.host)
    elif twin.port == "443":
        twin.port = "8080"
        twin.pop("sni")
        # NORMALISATION: a plaintext Cloudflare port cannot serve TLS, so the
        # mirror drops it -- the same invariant rule 7 enforces on originals.
        twin.set("security", "none")
    return twin


# --- rule 10: exit address ------------------------------------------------


def rule_10_set_address_for_443(node: Node) -> None:
    if node.port == "443":
        node.address = ADDRESS_FOR_PORT_443


def rule_10_set_address_for_8080(node: Node) -> None:
    if node.port == "8080":
        node.address = ADDRESS_FOR_PORT_8080


# --- rule 11: strip certificate opt-outs and ECH --------------------------

# Everything rule 11 removes from every node, whatever its spelling or case.
STRIPPED_KEYS = INSECURE_KEYS + ECH_KEYS


def rule_11_strip_insecure(node: Node) -> None:
    for key in list(node.params):
        if key.lower() in STRIPPED_KEYS:
            del node.params[key]


# --- rules 12-13: masking parameters --------------------------------------


def rule_12_apply_443_masking(node: Node) -> None:
    if node.port != "443":
        return
    node.set("fp", FP_443)
    node.set("fm", FM_443)
    node.set("cs", CS_443)
    # NORMALISATION: rule 10 puts a Cloudflare IP in the address field, and
    # Cloudflare selects the origin by SNI, so SNI has to be the fronted host.
    node.set("sni", node.host)


def rule_13_apply_8080_masking(node: Node) -> None:
    if node.port != "8080":
        return
    node.set("fm", FM_8080)
    # NORMALISATION: TLS-only parameters are inert on a plaintext port.
    for key in TLS_ONLY_KEYS:
        node.pop(key)


# --- naming ---------------------------------------------------------------


def make_tag(node: Node) -> str:
    """The published name: the source's own comment, then the port and a short
    content hash. The hash is derived from the node itself, so the same node
    always gets the same name and an unchanged upstream produces an unchanged
    configs.txt."""
    digest = hashlib.sha256(repr(node.identity()).encode("utf-8")).hexdigest()[:6]
    parts = []
    comment = node.tag.strip()
    if KEEP_SOURCE_COMMENT and comment:
        parts.append(comment)
    else:
        transport = "ws" if node.transport == "websocket" else node.transport
        parts.append(f"{node.host} | {node.scheme}-{transport}")
    parts += [node.port, digest]
    return NAME_PREFIX + " | ".join(parts)


# --- driver ---------------------------------------------------------------


def transform(nodes: list[Node], stats: dict | None = None) -> list[Node]:
    """Apply rules 1-13 and return the deduplicated result."""
    counts: dict = stats if stats is not None else {}

    def bump(key: str, amount: int = 1) -> None:
        counts[key] = counts.get(key, 0) + amount

    kept: list[Node] = []
    for node in nodes:
        if not INCLUDE_VMESS and node.scheme == "vmess":
            bump("dropped_vmess_cannot_carry_fm")
            continue
        if not rule_1_security_allowed(node):
            bump("dropped_rule_1_security")
            continue
        if not rule_2_transport_allowed(node):
            bump("dropped_rule_2_transport")
            continue
        if not rule_3_has_host(node):
            bump("dropped_rule_3_no_host")
            continue
        if not rule_4_port_allowed(node):
            bump("dropped_rule_4_port")
            continue

        rule_5_normalise_to_443(node)
        rule_6_normalise_to_8080(node)

        if not rule_7_drop_plaintext_port_with_tls(node):
            bump("dropped_rule_7_8080_with_tls")
            continue
        if not rule_8_drop_tls_port_without_tls(node):
            bump("dropped_rule_8_443_without_tls")
            continue

        kept.append(node)

    bump("kept_after_rules_1_to_8", len(kept))

    # Rule 9: each survivor gains its opposite-transport twin.
    mirrors = [rule_9_mirror(node) for node in kept]
    bump("mirrors_added_rule_9", len(mirrors))
    everything = kept + mirrors

    for node in everything:
        rule_10_set_address_for_443(node)
        rule_10_set_address_for_8080(node)
        rule_11_strip_insecure(node)
        rule_12_apply_443_masking(node)
        rule_13_apply_8080_masking(node)

    deduped: list[Node] = []
    seen: set[tuple] = set()
    for node in everything:
        key = node.identity()
        if key in seen:
            bump("dropped_duplicate")
            continue
        seen.add(key)
        if RENAME_NODES:
            node.tag = make_tag(node)
        deduped.append(node)

    bump("final_443", sum(1 for n in deduped if n.port == "443"))
    bump("final_8080", sum(1 for n in deduped if n.port == "8080"))
    bump("final_total", len(deduped))
    return deduped
