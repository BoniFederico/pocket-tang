# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository scaffolding, contribution guidelines, security policy, issue and PR templates.
- ADR-0001 (ESP-IDF v5.5 with Mbed TLS 3.6) and ADR-0002 (own strict JSON parser).
- Hardware notes for the reference board.
- CI skeleton: formatting, static analysis, host build and tests, firmware build matrix.
- Core: strict, bounded, non-recursive JSON tokenizer and bounded JSON writer.
- Core: strict base64url codec (rejects padding and non-canonical encodings).
- libFuzzer harnesses for JSON and base64url, run for 60 s per target in CI.
