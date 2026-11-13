# ADR-0003: Intentional deviations from upstream tang behaviour

- Status: Accepted
- Date: 2026-11-13
- Issue: #2

## Context

Pocket Tang aims to be wire-compatible with upstream `latchset/tang` and the `clevis` client. The
interop suite (`tools/interop.sh`) compares the HTTP status code of Pocket Tang and upstream
`tangd` (tang 14, jose 13) for the same request on identical keys. Upstream behaviour is partly
an accident of `libjose` internals; in a few hostile-input corners matching it would mean
accepting input that no legitimate client sends.

## Decision

Pocket Tang matches upstream status codes, content types, routing (including `//adv//`,
query strings → 404, `HEAD` → 405), JWS serialisation (flattened for one signer, general for
several, duplicate signer for `/adv/{active signing kid}`) and `/rec` reply bytes, with these
deliberate exceptions:

| Request | upstream tangd 14 | Pocket Tang | Rationale |
|---------|-------------------|-------------|-----------|
| `POST /rec/{kid}` whose JWK contains a valid private scalar `d` | 200 (scalar ignored) | 400 | A request never needs private key material; refusing it keeps the parser simple (no scalar validation on the request path) and fails closed. Clevis never sends `d`. |
| `POST /rec/{kid}` with a body over 2048 bytes | 413 at a larger limit | 413 at 2048 bytes | A clevis request is about 230 bytes; a small bound protects the device. |
| `GET /version` | 404 (tang 14) | 200 `{"name":"pocket-tang","version":...}` | Upstream added `/version` in later releases; useful for diagnostics. |
| `POST /rec/{kid}` while the kill switch is on | n/a | 403 | Feature specific to Pocket Tang (Home Assistant "lock" switch). |

The `/rec` reply includes `tang_pub` (as upstream tang ≥ 15 does) by default; clevis 20 accepts
both forms. It can be disabled at build/run time.

## Consequences

The interop suite encodes the first row as an expected deviation. Any other status mismatch
against upstream fails CI.
