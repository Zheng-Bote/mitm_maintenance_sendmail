# MitM Maintenance SendMail (`mitm_maintenance_sendmail`)

`mitm_maintenance_sendmail` is a standalone Go 1.27+ CLI batch utility in the **Maintenance Layer** of the MitM Data Aggregator. It acts as the mail outbox dispatcher (e.g., for `mitm_maintenance_monitor` alerts) and is adapted to the MitM Scheduler IPC and Envelope Encryption architecture (`collector_concept.md` / `collector_creation_guide.md`).

## Workflow

1. **Bootstrap & IPC Credentials**: When executed by `mitm_scheduler-server` (`RUN_ID` and `SCHEDULER_SOCKET_PATH`), the binary requests `MITM_DB_CONFIG_JSON` and `MASTER_KEY` (KEK) via the `get_credentials` Unix Domain Socket message. For standalone execution, it falls back to environment variables.
2. **Envelope Decryption**: Connects to the MitM PostgreSQL database, loads the encrypted SMTP configuration for `source_name` from `source_credentials` and its wrapped DEK from `storage_keys`, unwraps the DEK with the 32-byte KEK (AES-GCM), and decrypts `config_payload`.
3. **Permission & Outbox Scan**:
   - Ensures `mail_dir` (`watch_dir` / `mail_dir`) exists as a writable directory with mode `0700`: creates missing directories (including parents) with mode `0700`, and corrects non-`0700` permissions while emitting a `WARNING:` audit event. Also checks each `*.SendMail` file (expected `0600`), emitting a `WARNING:` audit event if group/other permissions are set.
   - Ignores `*.tmp` (in-flight atomic writes), `*.attempts`, and `*.failed` files.
4. **Header-Block & Legacy Parsing**:
   - **Header-Block Format**: Any unique filename ending in `.SendMail` (e.g. `mitm-monitor_3f2a9c.SendMail`) starting with a header block (`To`, optional `Cc`, `Subject`, optional `X-MitM-*` headers) followed by an empty line and the message body. Multiple comma-separated addresses in `To` and `Cc` are supported; `X-MitM-*` headers are forwarded unchanged. Header values with CR/LF or control characters, or missing `To`/`Subject`, cause the file to be renamed to `*.failed` with an `ERROR:` audit event.
   - **Legacy Format**: A file named `<recipient>.SendMail` without a header block is sent to `<recipient>` with the job's configured `mail_subject`.
5. **SMTP Dispatch, Retry & Failed Handling**:
   - Connects via TCP with `STARTTLS` and authenticates via `AUTH LOGIN` (or `PLAIN`).
   - If the SMTP server is unreachable or authentication fails, the job emits a `failed` status event and `ERROR:` audit event and exits with code `1` without incrementing per-file attempt counters.
   - Message-level delivery failures increment `<name>.attempts`; once `max_attempts` (default `5`) is reached, the file is renamed to `<name>.failed` and an `ERROR:` audit event is emitted.
   - Successfully sent `*.SendMail` files (and their `.attempts` sidecars) are deleted.
6. **Privacy & Outbox Health Audit**:
   - Mail bodies are never logged, and recipient addresses are masked in all log and IPC outputs (`o***@example.com`).
   - At the end of each run, an audit event reports `sent`, `failed`, `pending` (`*.SendMail`), `failed_files` (`*.failed`), and `oldest_pending_age`.

## Mail File Format

### Header-Block Format (Recommended)

File name: `<unique_id>.SendMail` (written atomically via `<unique_id>.tmp` + rename, mode `0600`):

```text
To: ops@example.com, admin@example.com
Cc: security@example.com
Subject: [MitM][ERROR] Job Collector mirror-dev Employee DE failed (RunID 3732)
X-MitM-Severity: ERROR
X-MitM-Source: program_runs/3732

Job:      Collector mirror-dev Employee DE
Run:      3732, exit code 1, 2026-11-09 16:42:59 UTC
Reason:   Employee: mirror-dev_employee: ERROR: Failed to execute query …
```

### Legacy Format

File name: `recipient@example.com.SendMail` containing only the plain-text message body.

## Configuration

### 1. Decrypted `source_credentials.config_payload` JSON

```json
{
  "smtp_server": "digidocu-dev.netcup-mail.de",
  "smtp_port": 587,
  "smtp_username": "admin@digidocu.dev",
  "smtp_password": "secret_password",
  "smtp_from": "admin@digidocu.dev",
  "smtp_starttls": true,
  "watch_dir": "../data"
}
```

### 2. Scheduler Job Arguments (`os.Args[1]`)

```json
{
  "source_name": "SENDMAIL_SMTP",
  "mail_dir": "../data",
  "mail_subject": "New Message from SendMail",
  "topic": "maintenance.sendmail",
  "max_attempts": 5
}
```

- `source_name`: Lookup key in `source_credentials` (default: `"SENDMAIL_SMTP"`).
- `mail_dir`: Directory containing `*.SendMail` files; overrides `watch_dir` from `source_credentials`.
- `mail_subject`: Fallback email subject for legacy files without a header block (default: `"New Message from SendMail"`).
- `topic`: Topic prefix for IPC status and audit messages (default: `"maintenance.sendmail"`).
- `max_attempts`: Maximum message-level send attempts before renaming a file to `*.failed` (default: `5`).

## Build & Test

```sh
go test ./...
./build.sh
```
