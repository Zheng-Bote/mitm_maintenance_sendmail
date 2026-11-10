# MitM Maintenance SendMail (`mitm_maintenance_sendmail`)

`mitm_maintenance_sendmail` is a standalone Go 1.27+ CLI batch utility in the **Maintenance Layer** of the MitM Data Aggregator. It is a scheduled, non-resident port of the C++ `send_mail` utility, adapted to the MitM Scheduler IPC and Envelope Encryption architecture (`collector_concept.md` / `collector_creation_guide.md`).

## Workflow

1. **Bootstrap & IPC Credentials**: When executed by `mitm_scheduler-server` (`RUN_ID` and `SCHEDULER_SOCKET_PATH`), the binary requests `MITM_DB_CONFIG_JSON` and `MASTER_KEY` (KEK) via the `get_credentials` Unix Domain Socket message. For standalone execution, it falls back to environment variables.
2. **Envelope Decryption**: Connects to the MitM PostgreSQL database, loads the encrypted SMTP configuration for `source_name` from `source_credentials` and its wrapped DEK from `storage_keys`, unwraps the DEK with the 32-byte KEK (AES-GCM), and decrypts `config_payload`.
3. **Directory Scan**: Scans the effective mail directory (`mail_dir` from CLI JSON overrides `watch_dir` from `source_credentials`) for regular files matching `<recipient>.SendMail` (e.g., `user@example.com.SendMail`).
4. **SMTP Dispatch & Cleanup**: Sends each file's UTF-8 content as an email to `<recipient>` using the configured `mail_subject`, `STARTTLS`, and `AUTH LOGIN` (or `PLAIN`). On successful delivery, the `.SendMail` file is deleted from disk; failed files remain on disk for the next scheduled run.
5. **Status & Audit Reporting**: Emits `status` (`job_status_events`) and `audit` (`job_audit_logs`) events over the nil-safe scheduler IPC socket.

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
  "topic": "maintenance.sendmail"
}
```

- `source_name`: Lookup key in `source_credentials` (default: `"SENDMAIL_SMTP"`).
- `mail_dir`: Directory containing `*.SendMail` files; overrides `watch_dir` from `source_credentials`.
- `mail_subject`: Email subject line (default: `"New Message from SendMail"`).
- `topic`: Topic prefix for IPC status and audit messages (default: `"maintenance.sendmail"`).

## Build & Test

```sh
go test ./...
./build.sh
```
