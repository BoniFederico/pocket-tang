# JOSE: JWK, JWA, JWS, JWE and thumbprints

Tang and Clevis encode everything on the wire with the **JOSE** family of standards (JSON Object
Signing and Encryption). The previous page described the mathematics. This page explains how
keys, signatures and ciphertexts are written down, and the exact encoding rules a server must
follow to interoperate byte for byte.

| RFC | Name | Used for |
|-----|------|----------|
| 7517 | JSON Web Key (JWK) | Tang keys, the `/rec` request and reply |
| 7518 | JSON Web Algorithms (JWA) | `ES512` signatures, `ECDH-ES` and `A256GCM` in Clevis JWEs |
| 7515 | JSON Web Signature (JWS) | The `/adv` advertisement |
| 7516 | JSON Web Encryption (JWE) | The Clevis ciphertext stored in the LUKS2 token |
| 7638 | JWK Thumbprint | Key identifiers (`kid`) and the trust anchor `thp` |
| 4648 §5 | base64url | Every binary value inside JSON |

## 1. base64url without padding

Binary values (coordinates, signatures, hashes) are encoded with the URL-safe base64 alphabet
(`A–Z a–z 0–9 - _`) of RFC 4648 §5, **with the trailing `=` padding removed** (RFC 7515 §2). An
$n$-byte value becomes $\lceil 8n/6 \rceil$ characters:

| Value | Bytes | Characters |
|-------|-------|------------|
| P-521 coordinate or scalar | 66 | 88 |
| ES512 signature $r \,\|\, s$ | 132 | 176 |
| SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 thumbprint | 20 / 28 / 32 / 48 / 64 | 27 / 38 / 43 / 64 / 86 |

The decoder in `core/src/pt_b64url.c` is **strict**. It rejects padding, whitespace, the
standard-alphabet characters `+` and `/`, impossible lengths ($4k+1$ characters), and encodings
whose unused trailing bits are not zero. The last rule makes the encoding canonical: every byte
string has exactly one accepted encoding. The fuzz target `fuzz_b64url` checks this property:
whenever `decode(x)` succeeds, `encode(decode(x)) == x`.

## 2. JSON Web Key (RFC 7517)

A JWK is a JSON object that describes one key. For elliptic-curve keys (RFC 7518 §6.2):

| Member | Meaning |
|--------|---------|
| `kty` | Key type, `"EC"` |
| `crv` | Curve, `"P-521"` |
| `x`, `y` | Public point coordinates, base64url, **full length**: 66 bytes for P-521 (RFC 7518 §6.2.1.2) |
| `d` | Private scalar, base64url, 66 bytes (private keys only) |
| `alg` | Optional intended algorithm, for example `"ES512"` or `"ECMR"` |
| `use` | Optional intended use: `"sig"` or `"enc"` |
| `key_ops` | Optional array of permitted operations: `sign`, `verify`, `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, `deriveKey`, `deriveBits` |

The two Tang keys, as created by `tangd-keygen` (from the [protocol reference](protocol-reference.md)):

```json
{"alg":"ES512","crv":"P-521","d":"...","key_ops":["sign","verify"],"kty":"EC","x":"...","y":"..."}
{"alg":"ECMR","crv":"P-521","d":"...","key_ops":["deriveKey"],"kty":"EC","x":"...","y":"..."}
```

`ECMR` is not an IANA-registered JWA algorithm. It is a private value understood by libjose, tang
and clevis that marks a McCallum-Relyea exchange key.

### 2.1 `use` versus `key_ops`, and the libjose mapping

RFC 7517 defines two overlapping ways to restrict a key: the coarse `use` and the fine-grained
`key_ops`. It recommends not using both. Upstream tang decides permissions with libjose's
`jose_jwk_prm()`, and status codes on `/rec` depend on it (403 for a refused permission). Pocket
Tang therefore reproduces libjose's rule exactly in `pt_jwk_permits()`:

1. If **neither** `key_ops` nor `use` is present, the operation is permitted unless the caller
   marks the permission as *required*. `/rec` does not require it.
2. If `key_ops` is an array containing the operation name, it is permitted.
3. Otherwise, if `use` is present, it maps to operations as follows:
   - `"sig"` → `sign`, `verify`;
   - `"enc"` → `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, **never** `deriveKey`.
4. Everything else is refused. A `use` that is not a string, or a duplicated member, also
   refuses.

The consequence for `/rec`, which needs `deriveKey`, is shown below. The cases are asserted in
`core/tests/test_tang.c` and compared against upstream in the interop matrix.

| Request JWK contains | Verdict | `/rec` status |
|----------------------|---------|---------------|
| neither `key_ops` nor `use` (what clevis sends) | permitted | continues (200 if valid) |
| `"key_ops":["deriveKey"]` | permitted | continues |
| `"key_ops":["sign"]` | refused | 403 |
| `"use":"sig"` | refused | 403 |
| `"use":"enc"` | refused (`enc` never implies `deriveKey`) | 403 |

### 2.2 Strict parsing in Pocket Tang

`pt_jwk_parse()` (in `core/src/pt_jwk.c`) accepts only `kty` `"EC"` with `crv` `"P-521"`.
Another curve yields `PT_ERR_UNSUPPORTED`, which `/rec` maps to 400. The coordinates must be
unescaped, canonical, exactly 66 bytes long, and form a valid curve point (see
[McCallum-Relyea §6](mcallum-relyea.md#6-point-validation-and-invalid-curve-attacks)). Duplicate
members are errors, and unknown members are ignored, as RFC 7517 requires. A `d` member in a
request is refused. Upstream ignores it, so this is a documented deviation
([ADR-0003](../adr/0003-deviations-from-upstream-tang.md)).

## 3. JWA: ES512 (RFC 7518 §3.4)

`ES512` is ECDSA over P-521 with SHA-512. To sign a message $m$ with private key $d$:

$$
k \in [1, n-1],\quad (x_1, y_1) = kG,\quad r = x_1 \bmod n,\quad
s = k^{-1}\big(H(m) + r d\big) \bmod n,
$$

where $H(m)$ is the SHA-512 digest interpreted as an integer. (SHA-512 output is 512 bits, shorter
than $n$, so no truncation applies.) Verification recomputes
$u_1 = H(m) s^{-1}$, $u_2 = r s^{-1}$ and checks that the $x$-coordinate of $u_1 G + u_2 Q$
equals $r$ modulo $n$.

**JOSE encoding differs from X.509/TLS.** The JWS signature is *not* DER. It is the fixed-width
concatenation

$$
\mathrm{sig} = \mathrm{I2OSP}(r, 66) \,\|\, \mathrm{I2OSP}(s, 66) \qquad (132 \text{ bytes}),
$$

that is, both integers big-endian and left-padded to 66 bytes. `pt_es512_sign()` writes exactly
this layout (`PT_ES512_SIG_LEN` = 132).

Pocket Tang computes $k$ deterministically from $d$ and $H(m)$ (RFC 6979). The reasons are given
in [Cryptography details](crypto.md#5-deterministic-ecdsa).

## 4. JWS serialisations (RFC 7515)

A JWS signs a **payload** together with a **protected header**. The signature is computed over
the *signing input*

$$
\mathrm{ASCII}\big(\mathrm{b64u}(\text{protected}) \,\|\, \texttt{"."} \,\|\, \mathrm{b64u}(\text{payload})\big).
$$

The same signed content can be serialised in three ways:

| Serialisation | Shape | Signers |
|---------------|-------|---------|
| Compact (§7.1) | `b64u(protected).b64u(payload).b64u(signature)` | exactly one |
| JSON, general (§7.2.1) | `{"payload":..., "signatures":[{"protected":..., "signature":...}, ...]}` | one or more |
| JSON, flattened (§7.2.2) | `{"payload":..., "protected":..., "signature":...}` | exactly one |

### 4.1 The Tang advertisement

`GET /adv` returns a JWS with `Content-Type: application/jose+json` (from the
[protocol reference](protocol-reference.md)):

- **Protected header**, identical for every signer:
  `{"alg":"ES512","cty":"jwk-set+json"}`. Its base64url form is the constant
  `eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9` in `core/src/pt_tang.c`.
- **Payload**: a JWK Set `{"keys":[...]}` with the public part of every *active* key. The signing
  key is listed with `"key_ops":["verify"]` and the exchange key with `"key_ops":["deriveKey"]`.
  Both keep their `alg`.
- **Serialisation**: flattened when there is exactly one signer, general when there are several.
  `GET /adv/{kid}` adds the signing key `kid` as an extra signer, even if it is already the
  active one. In that case the active key appears twice in `signatures`, exactly as upstream
  does.

```json
{"payload":"eyJrZXlzIjpb...","protected":"eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9",
 "signature":"<176 base64url characters>"}
```

Rotated signing keys are not advertised. They can still sign `/adv/{kid}`, so a client that
pinned an old `thp` can verify a fresh advertisement. Pocket Tang precomputes one signature per
ES512 key (active and rotated) whenever the key store changes ([Implementation](implementation.md)).

## 5. JWE as produced by Clevis (RFC 7516, RFC 7518 §4.6)

The server never parses a JWE. It is still useful to know what the client stores, because the
security argument of the previous page refers to its fields.

Clevis's `tang` pin produces a JWE in **compact serialisation**:

```text
b64u(protected) . b64u(encrypted_key) . b64u(iv) . b64u(ciphertext) . b64u(tag)
```

with `"alg":"ECDH-ES"` and `"enc":"A256GCM"` in the protected header. Besides `alg` and `enc`,
the header carries the ephemeral public key `epk` (the point $C$ of the previous page), the `kid`
of the server's exchange key, and a `clevis` member recording the pin, the server URL and the
advertisement used at binding time.

**ECDH-ES in direct key-agreement mode.** The key agreement output is used directly as the
content-encryption key (CEK), so `encrypted_key` is empty. The CEK is derived with the Concat KDF
of NIST SP 800-56A §5.8.1:

$$
\mathrm{CEK} = \mathrm{SHA\text{-}256}\big(\texttt{00 00 00 01} \,\|\, Z \,\|\, \mathit{OtherInfo}\big)
\quad\text{truncated to 256 bits},
$$

where

- $Z$ is the shared secret: the $x$-coordinate of $K = cS$, 66 bytes for P-521;
- $\mathit{OtherInfo} = \mathit{AlgorithmID} \,\|\, \mathit{PartyUInfo} \,\|\,
  \mathit{PartyVInfo} \,\|\, \mathit{SuppPubInfo}$. In direct mode $\mathit{AlgorithmID}$ is the
  length-prefixed `enc` value (`"A256GCM"`), the party infos are the length-prefixed `apu`/`apv`
  values (empty if absent), and $\mathit{SuppPubInfo}$ is the key length in bits (256) as a 32-bit
  big-endian integer.

Since 256 bits fit into one SHA-256 output, a single hash round suffices. `A256GCM` then encrypts
the secret with a 96-bit IV and appends a 128-bit authentication tag. The protected header is the
additional authenticated data. This tag is what makes a wrong $K$ fail loudly at recovery time.

## 6. JWK thumbprints (RFC 7638)

A thumbprint is a hash of a key's **required public members**, serialised canonically. For
`kty` `"EC"` the required members are `crv`, `kty`, `x` and `y`. The canonical form is:

1. only the required members, no others: no `alg`, `key_ops` or `d`;
2. members in **lexicographic order** of their names;
3. no whitespace, UTF-8 encoding.

The thumbprint is the base64url of the hash of this string. Because optional members are
excluded, a key has the same thumbprint whether it is listed with `"key_ops":["verify"]` in
`/adv` or with `"key_ops":["sign","verify"]` in the key file.

### 6.1 Worked example

The exchange key of the recorded upstream fixture (`core/tests/fixtures/tang14/exc.jwk`) has
these public members. The canonical input is the single line

```text
{"crv":"P-521","kty":"EC","x":"AP7Ra9nX5zM7ie2ZCPgXqEyGb_DMNEP7Mw4Aat7zZaJQwOn2OowmkbgDJB9b8D-5O8P7XVkZoYy7bBUNv3kBza6p","y":"AVBgfS0W2MfdJTza-IDPdXy9e41H9TKxf-rZ1xUyYjWzjBcAjetNc4z64rkuOd1xh5-6Iq-qCCGy0YNQKRIDQpOz"}
```

Hashing it gives the thumbprints recorded from `jose jwk thp` in
`core/tests/fixtures/tang14/thumbprints.txt`, for example

| Hash | Thumbprint (base64url) |
|------|------------------------|
| S1 (SHA-1) | `heCfiLiCixtMC56xV7M1dml9fLk` |
| S256 (SHA-256) | `BCcYRlKmK017L6ml2GIiQtXp05lrX1S-AQhqmiduonM` |

`test_thumbprints_match_jose` in `core/tests/test_jwk.c` recomputes all five hashes for both
fixture keys and compares them with the recorded values.

In the code, `pt_jwk_thumbprint()` builds this string with the same JSON writer that serialises
public keys (`pt_jwk_write_public()` with no `alg` and no `key_ops`). The writer always emits
members in lexicographic order, so the canonical form needs no extra sorting step
([ADR-0002](../adr/0002-own-json-parser.md)).

### 6.2 Thumbprints as key identifiers

Tang names keys by thumbprint: the key files are named after the S256 thumbprint, the `/rec/{kid}`
and `/adv/{kid}` paths carry one, and the Clevis `thp` parameter pins the signing key by one.

**Why several hash algorithms?** A `kid` does not say which hash produced it. Upstream `tangd`
therefore accepts thumbprints under S1, S224, S256, S384 and S512. Clevis tries S256 first and
falls back to S1 (see the [protocol reference](protocol-reference.md)). The point of this is
compatibility: a binding created by a client that used another thumbprint hash, for example an
older client using SHA-1, keeps working.

Pocket Tang caches all five thumbprints of every key when the key is created or loaded
(`pt_key_t.thp`). It identifies the hash from the decoded length of the `kid`. The five digest
lengths (20, 28, 32, 48 and 64 bytes) are all different, so the length alone selects the hash,
and the lookup compares against one cached digest per key. Thumbprints are public values, so a
plain `memcmp` is used, not a constant-time comparison.

## References

1. RFC 7515, *JSON Web Signature (JWS)*. <https://www.rfc-editor.org/rfc/rfc7515>
2. RFC 7516, *JSON Web Encryption (JWE)*. <https://www.rfc-editor.org/rfc/rfc7516>
3. RFC 7517, *JSON Web Key (JWK)*. <https://www.rfc-editor.org/rfc/rfc7517>
4. RFC 7518, *JSON Web Algorithms (JWA)*, §3.4 (ES512), §4.6 (ECDH-ES), §6.2 (EC keys).
   <https://www.rfc-editor.org/rfc/rfc7518>
5. RFC 7638, *JSON Web Key (JWK) Thumbprint*. <https://www.rfc-editor.org/rfc/rfc7638>
6. RFC 4648, *The Base16, Base32, and Base64 Data Encodings*, §5.
   <https://www.rfc-editor.org/rfc/rfc4648>
7. RFC 8259, *The JavaScript Object Notation (JSON) Data Interchange Format*.
   <https://www.rfc-editor.org/rfc/rfc8259>
8. RFC 6979, *Deterministic Usage of DSA and ECDSA*. <https://www.rfc-editor.org/rfc/rfc6979>
9. NIST SP 800-56A Rev. 3, *Recommendation for Pair-Wise Key-Establishment Schemes Using
   Discrete Logarithm Cryptography*, §5.8. <https://csrc.nist.gov/pubs/sp/800/56/a/r3/final>
10. IANA, *JSON Object Signing and Encryption (JOSE)* registries.
    <https://www.iana.org/assignments/jose/jose.xhtml>
11. libjose, `lib/jwk.c` (`jose_jwk_prm`). <https://github.com/latchset/jose>
