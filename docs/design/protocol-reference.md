# Tang protocol reference (as implemented by upstream)

This page records the exact behaviour of upstream `tangd` (tang 14, jose 13, Ubuntu 24.04) as
observed on 2026-11-13, together with the upstream source it comes from (`latchset/tang`
`src/tangd.c`, `src/keys.c`; `latchset/jose` `lib/jwk.c`, `lib/openssl/ecmr.c`). Pocket Tang is
tested against it automatically: `core/tests/test_tang.c` (recorded fixtures in
`core/tests/fixtures/tang14`) and `tools/interop.sh` (live comparison).

## Keys

`tangd-keygen` creates two P-521 keys with `jose jwk gen -i '{"alg":"ES512"}'` and
`-i '{"alg":"ECMR"}'`. Files are named after the S256 thumbprint; a leading `.` marks a rotated key.

```json
{"alg":"ES512","crv":"P-521","d":"...","key_ops":["sign","verify"],"kty":"EC","x":"...","y":"..."}
{"alg":"ECMR","crv":"P-521","d":"...","key_ops":["deriveKey"],"kty":"EC","x":"...","y":"..."}
```

Key ids (`kid`) are RFC 7638 thumbprints of `{"crv","kty","x","y"}`. tangd accepts S1, S224, S256,
S384 and S512 thumbprints; clevis uses S256 and falls back to S1.

## Routes

| Route | Method | Notes |
|-------|--------|-------|
| `^/+adv/*$` | GET | advertisement signed by every active signing key |
| `^/+adv/+([0-9A-Za-z_-]+)$` | GET | same payload, additionally signed by the signing key `kid` (active or rotated) |
| `^/+rec/+([0-9A-Za-z_-]+)$` | POST | McCallum-Relyea recovery with exchange key `kid` (active or rotated) |

A path that matches a route with the wrong method gets 405, anything else 404 (a query string
makes the path not match).

## `GET /adv`

`Content-Type: application/jose+json`. One signer: flattened JWS JSON serialisation
`{"payload":...,"protected":...,"signature":...}`. Several signers: general serialisation
`{"payload":...,"signatures":[{"protected":...,"signature":...},...]}`.

- Protected header: `{"alg":"ES512","cty":"jwk-set+json"}`.
- Payload: `{"keys":[...]}` with the public part of every *active* key; the signing key's
  `key_ops` become `["verify"]`, the exchange key keeps `["deriveKey"]`, `alg` is kept.
- `/adv/{kid}` for the active signing key lists that key twice in `signatures`.

## `POST /rec/{kid}`

Request (clevis): `{"alg":"ECMR","crv":"P-521","kty":"EC","x":"...","y":"..."}`
(`Content-Type: application/jwk+json`, not checked by tangd).

Validation order and status codes:

1. body is not JSON → 400
2. `jose_jwk_prm(req, deriveKey)` false → 403 (`key_ops` without `deriveKey`; `use` present with no `key_ops`)
3. `kty` ≠ `EC` → 400; `alg` present and ≠ `ECMR` → 400
4. no keys → 500; `kid` unknown → 404
5. server key not usable for `deriveKey` / not ECMR (e.g. a signing key's kid) → 403
6. exchange fails (other curve, point not on curve, malformed) → 400

Reply `200`, `Content-Type: application/jwk+json`:

```json
{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"...","y":"..."}
```

where `(x, y) = d_server · (x_req, y_req)`. tang ≥ 15 additionally includes `"tang_pub"`, the
server's public exchange key.

## Pocket Tang differences

See [ADR-0003](../adr/0003-deviations-from-upstream-tang.md).
