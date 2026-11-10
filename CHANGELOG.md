# Changelog

All notable changes to the `mitm_maintenance_sendmail` component will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-11-10

### Added
- **Maintenance SendMail Job**: Go 1.27+ port of the C++ `send_mail` application as a scheduled CLI batch utility.
- Scheduler integration via Unix Domain Socket (`get_credentials` for `MASTER_KEY` and `MITM_DB_CONFIG_JSON`, nil-safe `status` and `audit` IPC reporting).
- Envelope decryption of `source_credentials` (`config_payload`) using the wrapped DEK from `storage_keys` and the 32-byte KEK.
- Single-pass processing of `*.SendMail` files in the configured mail directory (`mail_dir` / `watch_dir`), SMTP transmission with `STARTTLS` and `AUTH LOGIN` / `PLAIN`, and deletion of successfully sent files.
