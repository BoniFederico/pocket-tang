# Contributing to Pocket Tang

Thank you for considering a contribution. This project protects disk-encryption keys, so correctness and
reviewability matter more than speed.

## Ground rules

- **Trunk-based development.** `main` is always releasable. Work on a short-lived branch
  (`feat/...`, `fix/...`, `docs/...`, `chore/...`) and open a pull request. Every PR must pass CI and is
  squash-merged.
- **Conventional Commits.** Commit messages and PR titles follow
  `type(scope): summary` (`feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `perf`, `build`).
- **Link issues.** Every PR references the issue it addresses (`Closes #N`).
- **No secrets.** Never commit Wi-Fi credentials, keys, `.env*` files or hardware test artefacts.
- **Portable core stays portable.** Code under `core/` must not include any ESP-IDF or FreeRTOS header.
  Platform behaviour goes through `pt_platform.h`.
- **Hostile input.** All parsers are bounded, non-recursive and fuzzed. New parsing code needs a fuzz target.
- **Secrets in memory.** Zeroize key material after use; compare secrets in constant time; never log them.

## Development setup

See [docs/dev-setup.md](docs/dev-setup.md) for the host (Linux / WSL) and ESP-IDF toolchain.

Quick host loop:

```sh
cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug -DPT_SANITIZE=ON
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

Formatting and static analysis:

```sh
tools/lint.sh            # clang-format --dry-run, cppcheck, clang-tidy
tools/lint.sh --fix      # apply clang-format
```

## Pull request checklist

- [ ] Tests added or updated; `ctest` passes with ASan/UBSan
- [ ] Fuzz target added for any new parser
- [ ] Documentation updated (`docs/`, doc comments on public APIs)
- [ ] `CHANGELOG.md` updated under *Unreleased*
- [ ] No ESP-IDF includes under `core/`

## Architecture decisions

Significant decisions are recorded as ADRs in `docs/adr/`. If your change alters an architectural choice,
add a new ADR rather than editing an accepted one.
