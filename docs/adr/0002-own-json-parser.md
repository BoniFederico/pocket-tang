# ADR-0002: Own strict, bounded JSON parser instead of cJSON or jsmn

- Status: Accepted
- Date: 2026-11-13
- Issue: #1

## Context

The core parses JSON from untrusted network clients (`POST /rec/{kid}` bodies) and from persistent
storage. Requirements: no ESP-IDF dependency, no heap allocation in the request path, strict RFC 8259
syntax, hard bounds on size, nesting depth and token count, deterministic worst-case behaviour, and
fuzzability. The only JSON documents the server ever has to understand are small JWKs.

## Options considered

1. **cJSON** (ESP-IDF's `json` component): heap-based tree, recursive parser, permissive in places
   (e.g. nesting limited only by a compile-time constant, numbers parsed with `strtod`), and it is an
   ESP-IDF component, so the host build would need a separate copy.
2. **jsmn**: tiny token parser, but non-strict unless `JSMN_STRICT`, no escape decoding, no writer,
   historically subject to edge-case bugs; still needs a validation layer on top.
3. **Own parser/writer (~500 lines)**: iterative (no recursion), token array in caller memory, explicit
   limits (bytes, tokens, depth), strict grammar, limited escape support, duplicate-key detection for
   the members we care about, plus a bounded writer that emits members in lexicographic order so that
   RFC 7638 thumbprint input is produced directly.

## Decision

Option 3. The parser is small enough to be reviewed line by line, is fuzzed with libFuzzer, and gives
the core full control over limits and failure modes (fail closed).

## Consequences

- Only the JSON subset needed by JOSE is supported (objects, arrays, strings with `\"`, `\`, `\/`,
  `\uXXXX` for BMP code points, numbers accepted but not evaluated, `true`/`false`/`null`). Unknown
  members are skipped, as required for JWK forward compatibility.
- Any change to the parser requires the fuzz corpus to be re-run in CI.
