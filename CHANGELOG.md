# Changelog

All notable changes to the `mitm_maintenance_sendmail` component will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Flaky unit tests (mainly with `-race`): the fake scheduler socket of the tests closed its listener while IPC connections were still waiting in the listen backlog, so audit events got lost (e.g. `TestProcessMailDir_PermissionWarnings` saw one instead of two warnings). The listener now drains the backlog before it is closed. Test code only.

## [v0.1.0] - 2026-11-10

### Added
- **Maintenance SendMail Job**: Go 1.27+ port of the C++ `send_mail` application as a scheduled CLI batch utility.
- Scheduler integration via Unix Domain Socket (`get_credentials` for `MASTER_KEY` and `MITM_DB_CONFIG_JSON`, nil-safe `status` and `audit` IPC reporting).
- Envelope decryption of `source_credentials` (`config_payload`) using the wrapped DEK from `storage_keys` and the 32-byte KEK.
- **Header-Block & Outbox Support** ([Issue #1](https://github.com/Zheng-Bote/mitm_maintenance_sendmail/issues/1)):
  - Support for header-block `*.SendMail` files (`To`, `Cc`, `Subject`, `X-MitM-*` headers) with arbitrary unique filenames alongside legacy `<recipient>.SendMail` files.
  - Multiple comma-separated recipients in `To` and `Cc`, forwarding of `X-MitM-*` headers, and CR/LF / control-character header injection rejection.
  - Ignores `*.tmp` files for atomic producer writes.
  - Per-file attempt tracking (`*.attempts`) up to `max_attempts` (default `5`), renaming permanently failing or malformed files to `*.failed` with `ERROR:` audit events, while aborting with exit code `1` on unreachable SMTP servers without incrementing per-file attempts.
  - Permission warnings (`WARNING:` audit event) when `mail_dir` (`0700`) or `*.SendMail` files (`0600`) are accessible by group or others.
  - Recipient email masking (`o***@example.com`) across all log and IPC audit messages and final outbox health reporting (`pending`, `failed_files`, `oldest_pending_age`).
