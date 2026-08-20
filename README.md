# Free-Configs

A daily-rebuilt Xray subscription. It takes a public config list, rewrites every
node to exit through a Cloudflare address with client-side fragmentation, throws
away anything that does not actually carry traffic, and publishes the result.

## Subscription links

```
https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt
```

Base64, for clients that require it:

```
https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs_base64.txt
```

Rebuilt every 24 hours by [`.github/workflows/build.yml`](.github/workflows/build.yml),
on a `schedule:` cron — no manual step is involved. GitHub queues scheduled runs
and can delay or skip them under load, so treat it as "about once a day" rather
than a precise clock.

> One operational caveat: GitHub disables scheduled workflows in a repository
> that has had **no new commits for 60 days**, and emails the owner. This
> workflow commits whenever the healthy set changes, which resets that timer, so
> it only becomes a risk if the published list is byte-identical (or the build
> fails) for 60 consecutive days.

> **Client requirement:** use [patterniha/Xray-core](https://github.com/patterniha/Xray-core),
> not the upstream core. Two reasons:
>
> - Upstream refuses to build a VLESS or Trojan outbound that has no transport
>   security when the server address is a public IP
>   (`validateOutboundTransportSecurity` in `infra/conf/xray.go`). Every port
>   8080 node here is exactly that, so upstream cannot run — or test — them.
>   The fork comments the check out.
> - The `fm` parameter uses Xray's `finalmask` fragment with `lengths`/`delays`
>   arrays, which needs a core based on **v26.6.22 or newer**. Older cores
>   reject it, and every v26.4+ upstream release is tagged as a pre-release, so
>   the newest *stable* upstream release is not new enough.
>
> `cs` is Xray's `cipherSuites`; it works but is currently undocumented.

## Pipeline

`scripts/build.py` runs four stages:

1. **Fetch** the upstream list (`SOURCE_URL`).
2. **Transform** — rules 1-13, in [`scripts/transform.py`](scripts/transform.py).
3. **Health-check** — rule 14, in [`scripts/healthcheck.py`](scripts/healthcheck.py).
4. **Publish** — write `configs.txt` and `configs_base64.txt`, then commit.

### Rules 1-13

Each rule is its own function in `transform.py`, named after its number.

| # | Rule |
|---|------|
| 1 | Keep `security=tls`, `security=none`, or no `security`; drop `reality` |
| 2 | Keep `type` in ws, xhttp, websocket, httpupgrade, grpc |
| 3 | Keep only nodes that have a `host` |
| 4 | Drop nodes with no port, or a port outside the accepted set |
| 5 | 443, 2053, 2083, 2087, 2096, 8443 → **443** |
| 6 | 80, 8080, 8880, 2052, 2082, 2086, 2095 → **8080** |
| 7 | Drop port 8080 nodes carrying `security=tls` |
| 8 | Drop port 443 nodes not carrying `security=tls` |
| 9 | Duplicate every node into its opposite-transport twin |
| 10 | Point port 443 at `ADDRESS_FOR_PORT_443`, port 8080 at `ADDRESS_FOR_PORT_8080` |
| 11 | Strip `allowInsecure` / `allow_insecure` / `insecure` |
| 12 | Port 443: set `fp=unsafe`, `fm=…`, `cs=…` |
| 13 | Port 8080: set `fm=…` |

The two exit addresses are separate constants applied by two separate functions
(`rule_10_set_address_for_443` and `rule_10_set_address_for_8080`), so either
can be repointed without touching the other:

```python
ADDRESS_FOR_PORT_443 = "188.114.97.6"
ADDRESS_FOR_PORT_8080 = "188.114.97.6"
```

The `fm` and `cs` values are stored percent-encoded exactly as specified and
decoded once at import. A self-check at import time asserts that re-encoding
reproduces the original string byte for byte, so the build fails loudly rather
than silently emitting a mangled parameter.

### Normalisations on top of the numbered rules

Three adjustments are applied that the numbered rules do not spell out. Each is
marked `NORMALISATION` in the source.

- **The 443 → 8080 mirror also sets `security=none`.** A plaintext Cloudflare
  port cannot complete a TLS handshake; this is the same invariant rule 7
  enforces on the original nodes.
- **Every port 443 node gets `sni` set to its `host`.** Rule 10 replaces the
  address with a Cloudflare IP, and Cloudflare selects the origin by SNI, so an
  `sni` still pointing at the original server would never connect.
- **TLS-only parameters (`sni`, `alpn`, `fp`, `cs`) are dropped from port 8080
  nodes**, where they have no effect.

Nodes are also renamed to `port | host | protocol-transport | hash`. The
upstream country flags become misleading once rule 10 sends every node to the
same address, and rule 9 would otherwise give a node and its twin the same name.
The hash is derived from the node's own contents, so the same node always gets
the same name. Nodes are then ordered fastest-first by median latency. Because
that order drifts between runs, the "did anything change?" check compares the
set of links rather than their order — an unchanged set means the file is left
alone and the day produces no commit.

### vmess is excluded by default

A `vmess://` link is base64'd JSON with a fixed key set, and that key set has
nowhere to put `fm` or `cs`. Such nodes cannot satisfy rules 12-13 and would
ship without the fragmentation every other node gets, so they are dropped. To
publish them anyway, unmasked, set `INCLUDE_VMESS = True` in `transform.py`.

### Rule 14: the health check

The upstream project publishes its own criterion in its file header — *a real
proxied request to `https://cp.cloudflare.com/generate_204` succeeded in all 3
independent runs*. That is reimplemented here directly against
[patterniha/Xray-core](https://github.com/patterniha/Xray-core) rather than
through a wrapper, so the `fm` / `cs` / `fp=unsafe` parameters in the emitted
links are the ones actually exercised, and the non-TLS nodes can be tested at
all.

The workflow resolves the **newest release of the fork at run time**, so
publishing a release there is all it takes for the next build to use it. It
falls back to the most recent release of any kind if `/releases/latest` finds
none (which happens when every release is a pre-release), then verifies the
archive against the SHA2-256 the release publishes beside it. That catches a
truncated or corrupted download; because both files come from the same release
it is not a defence against the release itself being replaced.

Before testing anything, `build.py` **preflights the core**: it asks Xray to
validate one port 443 config carrying `fp=unsafe` + `fm` + `cs`, and one port
8080 config that is an unencrypted outbound to a public address. If the core
rejects either, the build stops with that specific message instead of spending
three rounds discovering that every node is "dead". `cs` maps to Xray's
`cipherSuites`, which is undocumented, and the `fm` fragment's
`lengths`/`delays` arrays need a core based on v26.6.22 or newer — both are
worth proving rather than assuming.

For each round, nodes are grouped into batches; each batch becomes one Xray
process with one loopback HTTP inbound per node, routed to that node's outbound,
and every node is probed concurrently through its own inbound. Three rounds run
and only the intersection survives — a single run misgrades a large fraction of
nodes, which is why the upstream project stamps a flakiness percentage into its
output and this one does too.

Two safeguards worth knowing about:

- The **default outbound is a blackhole**, so a node whose routing rule somehow
  fails to match cannot fall through to a direct connection and report itself
  healthy.
- Configs are **validated before use** with `xray run -test`. A group that fails
  is bisected, so one malformed node cannot take a whole batch down with it.

If a run yields fewer than `MIN_HEALTHY_NODES`, the previous `configs.txt` is
left in place and the workflow fails, rather than publishing an empty
subscription.

## Running it locally

```bash
SKIP_HEALTHCHECK=1 python scripts/build.py
```

With the health check, pointing at a downloaded core:

```bash
XRAY_BIN=/path/to/xray python scripts/build.py
```

| Variable | Meaning |
|---|---|
| `SOURCE_URL` | upstream list to start from |
| `XRAY_BIN` | path to the Xray-core binary (default: `PATH`, then `bin/xray`) |
| `OUTPUT_DIR` | where `configs.txt` is written (default: repository root) |
| `SKIP_HEALTHCHECK` | `1` skips rule 14 |
| `HEALTHCHECK_ROUNDS` | rounds a node must pass (default 3) |

## Tests

```bash
python scripts/test_rules.py
```

[`scripts/test_rules.py`](scripts/test_rules.py) covers every numbered rule,
the parser's edge cases (bracketed IPv6, userinfo containing `@` and `:`,
encoded `=` inside a value, missing fragment, malformed input), deduplication,
and the rendered Xray outbound. It needs no test framework and runs in the
workflow before anything else, so a broken rule fails the build instead of
publishing bad configs.

The suite was checked by mutation testing — deliberately breaking each rule in a
copy of the source and confirming the tests fail. That found two blind spots
worth knowing about, both now covered: rule 13 strips `sni` from plaintext nodes
anyway, so going through `transform()` cannot prove rule 9 removes it (there is
now a test calling `rule_9_mirror` directly), and the TLS-only stripping is only
exercised by a source node that *arrives* carrying `alpn`/`fp`/`cs`, not by a
mirrored one.

### A note on testing from a censored network

Health-check results are only meaningful from an unfiltered vantage point. On a
network that intercepts plaintext HTTP, every port 8080 node will fail locally
even when the node is fine — the interception answers with `400 Bad Request`
and a spoofed `Server: cloudflare` header before the request ever reaches
Cloudflare. The workflow runs on a GitHub runner precisely so the published list
reflects the nodes' real state rather than one network's filtering.
