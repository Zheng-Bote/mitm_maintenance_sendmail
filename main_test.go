/**
 * SPDX-FileComment: MitM Maintenance SendMail Unit Tests
 * SPDX-FileType: SOURCE
 * SPDX-FileContributor: ZHENG Robert
 * SPDX-FileCopyrightText: 2026 ZHENG Robert
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main_test.go
 * @brief Unit tests for KEK validation, envelope decryption, header/legacy parsing, retry/failed handling, masking, and IPC audit events.
 * @version 0.1.0
 * @date 2026-11-10
 *
 * @author ZHENG Robert (robert@hase-zheng.net)
 * @copyright Copyright (c) 2026 ZHENG Robert
 * @license Apache-2.0
 */

package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startMockIPCServer starts a fake scheduler socket. getEvents returns every event sent so far:
// IPCClient sends synchronously (dial, write, close), so when getEvents is called all connections
// are already accepted or waiting in the listen backlog. stopServer first drains that backlog and
// only then closes the listener; closing it right away would drop queued connections and their
// events (flaky tests, mainly under -race).
func startMockIPCServer(t *testing.T) (*IPCClient, func() []StatusEvent) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "scheduler.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}

	var (
		mu         sync.Mutex
		events     []StatusEvent
		wg         sync.WaitGroup // connection handlers
		acceptDone sync.WaitGroup // accept loop
		closeOne   sync.Once
	)

	acceptDone.Add(1)
	go func() {
		defer acceptDone.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					var ev StatusEvent
					if err := json.Unmarshal(scanner.Bytes(), &ev); err == nil {
						mu.Lock()
						events = append(events, ev)
						mu.Unlock()
					}
				}
			}(conn)
		}
	}()

	stopServer := func() {
		closeOne.Do(func() {
			// Accept() keeps returning queued connections and fails only once the backlog is
			// empty and the deadline has passed; then the accept loop ends.
			_ = ln.SetDeadline(time.Now().Add(100 * time.Millisecond))
			acceptDone.Wait()
			_ = ln.Close()
			wg.Wait()
		})
	}
	t.Cleanup(stopServer)

	ipc := &IPCClient{
		SocketPath: sockPath,
		RunID:      42,
		Component:  componentName,
		Topic:      defaultTopic,
		SourceName: defaultSource,
	}

	getEvents := func() []StatusEvent {
		stopServer()
		mu.Lock()
		defer mu.Unlock()
		out := make([]StatusEvent, len(events))
		copy(out, events)
		return out
	}

	return ipc, getEvents
}

func TestValidateKEK(t *testing.T) {
	rawKey := "0123456789abcdef0123456789abcdef"
	got, err := validateKEK(rawKey)
	if err != nil {
		t.Fatalf("expected valid raw 32-byte KEK, got error: %v", err)
	}
	if string(got) != rawKey {
		t.Fatalf("unexpected KEK bytes: %q", string(got))
	}

	b64Key := base64.StdEncoding.EncodeToString([]byte(rawKey))
	gotB64, err := validateKEK(b64Key)
	if err != nil {
		t.Fatalf("expected valid base64 KEK, got error: %v", err)
	}
	if string(gotB64) != rawKey {
		t.Fatalf("unexpected decoded KEK: %q", string(gotB64))
	}

	if _, err := validateKEK(""); err == nil {
		t.Fatal("expected error for empty MASTER_KEY")
	}
	if _, err := validateKEK("too-short"); err == nil {
		t.Fatal("expected error for short MASTER_KEY")
	}
}

func TestParseArgs(t *testing.T) {
	defaults, err := parseArgs("")
	if err != nil {
		t.Fatalf("unexpected error on empty args: %v", err)
	}
	if defaults.SourceName != defaultSource || defaults.MailSubject != defaultSubject || defaults.Topic != defaultTopic || defaults.MaxAttempts != 5 {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}

	customJSON := `{"source_name":"NETCUP_SMTP","mail_dir":"/var/spool/sendmail","mail_subject":"System Alert","topic":"ops.mail","max_attempts":3}`
	custom, err := parseArgs(customJSON)
	if err != nil {
		t.Fatalf("unexpected error on custom args: %v", err)
	}
	if custom.SourceName != "NETCUP_SMTP" || custom.MailDir != "/var/spool/sendmail" || custom.MailSubject != "System Alert" || custom.Topic != "ops.mail" || custom.MaxAttempts != 3 {
		t.Fatalf("unexpected parsed args: %+v", custom)
	}

	if _, err := parseArgs(`{"max_attempts":-1}`); err == nil {
		t.Fatal("expected error on negative max_attempts")
	}
	if _, err := parseArgs("{invalid-json"); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestParseSourceConfig(t *testing.T) {
	nativeJSON := []byte(`{
		"smtp_server": "digidocu-dev.netcup-mail.de",
		"smtp_port": 587,
		"smtp_username": "admin@digidocu.dev",
		"smtp_password": "secret",
		"smtp_from": "admin@digidocu.dev",
		"smtp_starttls": true,
		"watch_dir": "../data"
	}`)
	cfg, err := parseSourceConfig(nativeJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SMTPServer != "digidocu-dev.netcup-mail.de" || cfg.SMTPPort != 587 || !cfg.SMTPStartTLS || cfg.WatchDir != "../data" {
		t.Fatalf("unexpected parsed config: %+v", cfg)
	}

	envStyleJSON := []byte(`{
		"SMTP_SERVER": "digidocu-dev.netcup-mail.de",
		"SMTP_PORT": "465",
		"SMTP_USERNAME": "admin@digidocu.dev",
		"SMTP_PASSWORD": "secret",
		"SMTP_FROM": "admin@digidocu.dev",
		"SMTP_STARTTLS": "false",
		"WATCH_DIR": "/tmp/mail"
	}`)
	cfgEnv, err := parseSourceConfig(envStyleJSON)
	if err != nil {
		t.Fatalf("unexpected error on env-style JSON: %v", err)
	}
	if cfgEnv.SMTPPort != 465 || cfgEnv.SMTPStartTLS != false || cfgEnv.WatchDir != "/tmp/mail" {
		t.Fatalf("unexpected env-style parsed config: %+v", cfgEnv)
	}
}

func TestEnvelopeDecryptionRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		t.Fatal(err)
	}

	kekBlock, _ := aes.NewCipher(kek)
	kekGCM, _ := cipher.NewGCM(kekBlock)
	dekNonce := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, dekNonce)
	wrappedDEK := append(dekNonce, kekGCM.Seal(nil, dekNonce, dek, nil)...)

	dekBlock, _ := aes.NewCipher(dek)
	dekGCM, _ := cipher.NewGCM(dekBlock)
	cfgNonce := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, cfgNonce)
	plaintext := []byte(`{"smtp_server":"smtp.example.org","smtp_port":587,"smtp_from":"noreply@example.org"}`)
	ciphertext := dekGCM.Seal(nil, cfgNonce, plaintext, nil)

	unwrappedDEK, err := unwrapDEK(kek, wrappedDEK)
	if err != nil {
		t.Fatalf("unwrapDEK failed: %v", err)
	}
	decrypted, err := decryptPayload(unwrappedDEK, cfgNonce, ciphertext)
	if err != nil {
		t.Fatalf("decryptPayload failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted payload mismatch: got %s", string(decrypted))
	}
}

func TestMaskEmailAndFileName(t *testing.T) {
	if got := maskEmail("ops@example.com"); got != "o***@example.com" {
		t.Fatalf("expected o***@example.com, got %q", got)
	}
	if got := maskEmail("a@example.com"); got != "a***@example.com" {
		t.Fatalf("expected a***@example.com, got %q", got)
	}
	if got := maskEmail("invalid"); got != "***" {
		t.Fatalf("expected ***, got %q", got)
	}
	if got := maskFileName("ops@example.com.SendMail"); got != "o***@example.com.SendMail" {
		t.Fatalf("expected o***@example.com.SendMail, got %q", got)
	}
	if got := maskFileName("20261110T164259Z_3f2a9c.SendMail"); got != "20261110T164259Z_3f2a9c.SendMail" {
		t.Fatalf("expected non-email filename to remain unchanged, got %q", got)
	}
}

func TestParseMailFile_HeaderBlockAndLegacy(t *testing.T) {
	headerContent := []byte(
		"To: ops@example.com, admin@example.com\n" +
			"Cc: security@example.com\n" +
			"Subject: [MitM][ERROR] Job Collector mirror-dev Employee DE failed (RunID 3732)\n" +
			"X-MitM-Severity: ERROR\n" +
			"X-MitM-Source: program_runs/3732\n" +
			"X-Unknown-Header: ignored-value\n" +
			"\n" +
			"Job:      Collector mirror-dev Employee DE\n" +
			"Run:      3732, exit code 1\n",
	)

	parsed, err := parseMailFile("20261110T164259Z_3f2a9c.SendMail", headerContent, defaultSubject)
	if err != nil {
		t.Fatalf("unexpected error parsing header-block file: %v", err)
	}
	if !parsed.HasHeader {
		t.Fatal("expected HasHeader=true")
	}
	if len(parsed.To) != 2 || parsed.To[0] != "ops@example.com" || parsed.To[1] != "admin@example.com" {
		t.Fatalf("unexpected To: %+v", parsed.To)
	}
	if len(parsed.Cc) != 1 || parsed.Cc[0] != "security@example.com" {
		t.Fatalf("unexpected Cc: %+v", parsed.Cc)
	}
	if parsed.Subject != "[MitM][ERROR] Job Collector mirror-dev Employee DE failed (RunID 3732)" {
		t.Fatalf("unexpected Subject: %q", parsed.Subject)
	}
	if len(parsed.ExtraHeaders) != 2 || parsed.ExtraHeaders[0][0] != "X-MitM-Severity" || parsed.ExtraHeaders[1][0] != "X-MitM-Source" {
		t.Fatalf("unexpected ExtraHeaders: %+v", parsed.ExtraHeaders)
	}
	if !strings.HasPrefix(parsed.Body, "Job:      Collector mirror-dev Employee DE\n") {
		t.Fatalf("unexpected Body: %q", parsed.Body)
	}

	// Legacy file with a colon in the first body line must still be treated as legacy
	legacyBody := []byte("Note: Server maintenance tonight\n\nDetails follow.")
	legacy, err := parseMailFile("recipient@example.com.SendMail", legacyBody, "Custom Default Subject")
	if err != nil {
		t.Fatalf("unexpected error parsing legacy file: %v", err)
	}
	if legacy.HasHeader {
		t.Fatal("expected HasHeader=false for legacy file")
	}
	if len(legacy.To) != 1 || legacy.To[0] != "recipient@example.com" || legacy.Subject != "Custom Default Subject" {
		t.Fatalf("unexpected legacy parsed result: %+v", legacy)
	}

	// Header block missing Subject -> error
	if _, err := parseMailFile("alert1.SendMail", []byte("To: ops@example.com\n\nBody"), defaultSubject); err == nil {
		t.Fatal("expected error for missing Subject in header block")
	}
	// Header block missing To -> error
	if _, err := parseMailFile("alert2.SendMail", []byte("Subject: Test\n\nBody"), defaultSubject); err == nil {
		t.Fatal("expected error for missing To in header block")
	}
	// Header injection via embedded CR inside header value -> error
	if _, err := parseMailFile("alert3.SendMail", []byte("To: ops@example.com\nSubject: Bad\rBcc: evil@example.com\n\nBody"), defaultSubject); err == nil {
		t.Fatal("expected error for CR injection in header value")
	}
}

func TestBuildMimeMessage_MultipleRecipientsAndXMitmHeaders(t *testing.T) {
	mail := ParsedMail{
		To:      []string{"ops@example.com", "admin@example.com"},
		Cc:      []string{"security@example.com"},
		Subject: "Test Subject",
		ExtraHeaders: [][2]string{
			{"X-MitM-Severity", "ERROR"},
			{"X-MitM-Source", "program_runs/3732"},
		},
		Body: "Line 1\nLine 2",
	}
	raw, err := buildMimeMessage("sender@example.com", mail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := string(raw)
	if !strings.Contains(msg, "From: <sender@example.com>\r\n") {
		t.Fatalf("missing From header in %q", msg)
	}
	if !strings.Contains(msg, "To: <ops@example.com>, <admin@example.com>\r\n") {
		t.Fatalf("missing To header in %q", msg)
	}
	if !strings.Contains(msg, "Cc: <security@example.com>\r\n") {
		t.Fatalf("missing Cc header in %q", msg)
	}
	if !strings.Contains(msg, "X-MitM-Severity: ERROR\r\n") || !strings.Contains(msg, "X-MitM-Source: program_runs/3732\r\n") {
		t.Fatalf("missing X-MitM-* headers in %q", msg)
	}
	if !strings.HasSuffix(msg, "\r\n\r\nLine 1\r\nLine 2\r\n") {
		t.Fatalf("unexpected body formatting in %q", msg)
	}

	// Reject CR/LF in programmatic buildMimeMessage call
	badMail := mail
	badMail.Subject = "Injected\r\nBcc: attacker@example.com"
	if _, err := buildMimeMessage("sender@example.com", badMail); err == nil {
		t.Fatal("expected buildMimeMessage to reject CR/LF in Subject")
	}
}

func TestProcessMailDir_HeaderLegacyTmpCollisionAndMasking(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ipc, getEvents := startMockIPCServer(t)

	// 1 & 3. Two header-block files to the same recipient + Cc
	file1 := filepath.Join(tmpDir, "20261110T164259Z_001.SendMail")
	file2 := filepath.Join(tmpDir, "20261110T164300Z_002.SendMail")
	// 2. Legacy file
	legacyFile := filepath.Join(tmpDir, "legacy.user@example.com.SendMail")
	// 4. .tmp file (must be ignored)
	tmpFile := filepath.Join(tmpDir, "writing_in_progress.tmp")

	content1 := "To: ops@example.com, admin@example.com\nCc: security@example.com\nSubject: Alert 1\nX-MitM-Severity: ERROR\n\nSecretBodyOne"
	content2 := "To: ops@example.com\nSubject: Alert 2\n\nSecretBodyTwo"
	legacyContent := "SecretLegacyBody"

	for path, data := range map[string]string{
		file1:      content1,
		file2:      content2,
		legacyFile: legacyContent,
		tmpFile:    "To: ops@example.com\nSubject: Incomplete\n\nTmp",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var sentMails []ParsedMail
	mockSender := func(_ context.Context, _ SourceConfig, mail ParsedMail) error {
		sentMails = append(sentMails, mail)
		return nil
	}

	stats, err := processMailDir(context.Background(), tmpDir, defaultSubject, 5, SourceConfig{SMTPFrom: "noreply@example.com"}, mockSender, ipc)
	if err != nil {
		t.Fatalf("processMailDir failed: %v", err)
	}
	if stats.Sent != 3 || stats.Failed != 0 || stats.Pending != 0 || stats.FailedFiles != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(sentMails) != 3 {
		t.Fatalf("expected 3 sent mails, got %d", len(sentMails))
	}

	// Verify .tmp file was ignored and still exists
	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("expected .tmp file to be untouched: %v", err)
	}

	// Verify no unmasked recipient address or mail body appears in IPC events
	events := getEvents()
	if len(events) == 0 {
		t.Fatal("expected IPC audit events to be recorded")
	}
	foundOutboxStatus := false
	for _, ev := range events {
		for _, forbidden := range []string{
			"ops@example.com",
			"admin@example.com",
			"security@example.com",
			"legacy.user@example.com",
			"SecretBodyOne",
			"SecretBodyTwo",
			"SecretLegacyBody",
		} {
			if strings.Contains(ev.Message, forbidden) {
				t.Fatalf("IPC event leaked sensitive content %q in message: %q", forbidden, ev.Message)
			}
		}
		if strings.Contains(ev.Message, "Outbox status for") {
			foundOutboxStatus = true
		}
	}
	if !foundOutboxStatus {
		t.Fatal("expected final Outbox status audit event")
	}
}

func TestProcessMailDir_MaxAttemptsAndFailedRename(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0o700)

	ipc, getEvents := startMockIPCServer(t)

	mailFile := filepath.Join(tmpDir, "alert_retry.SendMail")
	invalidHeaderFile := filepath.Join(tmpDir, "invalid_header.SendMail")

	if err := os.WriteFile(mailFile, []byte("To: ops@example.com\nSubject: Retry Test\n\nBody"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Missing To: -> must be renamed to .failed immediately on first run
	if err := os.WriteFile(invalidHeaderFile, []byte("Subject: Missing To\n\nBody"), 0o600); err != nil {
		t.Fatal(err)
	}

	alwaysFailSender := func(_ context.Context, _ SourceConfig, _ ParsedMail) error {
		return errors.New("550 mailbox unavailable")
	}

	// Run 1 (max_attempts = 3): invalid_header -> .failed immediately; alert_retry -> attempt 1/3
	stats1, err := processMailDir(context.Background(), tmpDir, defaultSubject, 3, SourceConfig{SMTPFrom: "noreply@example.com"}, alwaysFailSender, ipc)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	if stats1.Pending != 1 || stats1.FailedFiles != 1 {
		t.Fatalf("expected pending=1, failed_files=1 after run 1; got %+v", stats1)
	}
	if got := readAttempts(mailFile); got != 1 {
		t.Fatalf("expected 1 recorded attempt, got %d", got)
	}

	// Run 2: alert_retry -> attempt 2/3
	stats2, err := processMailDir(context.Background(), tmpDir, defaultSubject, 3, SourceConfig{SMTPFrom: "noreply@example.com"}, alwaysFailSender, ipc)
	if err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}
	if stats2.Pending != 1 || stats2.FailedFiles != 1 {
		t.Fatalf("expected pending=1, failed_files=1 after run 2; got %+v", stats2)
	}
	if got := readAttempts(mailFile); got != 2 {
		t.Fatalf("expected 2 recorded attempts, got %d", got)
	}

	// Run 3: alert_retry reaches max_attempts (3) -> renamed to alert_retry.failed, .attempts removed
	stats3, err := processMailDir(context.Background(), tmpDir, defaultSubject, 3, SourceConfig{SMTPFrom: "noreply@example.com"}, alwaysFailSender, ipc)
	if err != nil {
		t.Fatalf("run 3 failed: %v", err)
	}
	if stats3.Pending != 0 || stats3.FailedFiles != 2 {
		t.Fatalf("expected pending=0, failed_files=2 after run 3; got %+v", stats3)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "alert_retry.failed")); err != nil {
		t.Fatalf("expected alert_retry.failed to exist: %v", err)
	}
	if _, err := os.Stat(attemptsFilePath(mailFile)); !os.IsNotExist(err) {
		t.Fatal("expected .attempts sidecar file to be removed after renaming to .failed")
	}

	// Check that ERROR: audit events were emitted
	errorAuditCount := 0
	for _, ev := range getEvents() {
		if strings.Contains(ev.Message, "ERROR:") {
			errorAuditCount++
		}
	}
	if errorAuditCount < 2 {
		t.Fatalf("expected at least 2 ERROR: audit events, got %d", errorAuditCount)
	}
}

func TestProcessMailDir_SMTPConnectionErrorDoesNotIncrementAttempts(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0o700)

	mailFile := filepath.Join(tmpDir, "alert_conn.SendMail")
	if err := os.WriteFile(mailFile, []byte("To: ops@example.com\nSubject: Conn Test\n\nBody"), 0o600); err != nil {
		t.Fatal(err)
	}

	connFailSender := func(_ context.Context, _ SourceConfig, _ ParsedMail) error {
		return &smtpConnectionError{err: errors.New("dial tcp: connection refused")}
	}

	_, err := processMailDir(context.Background(), tmpDir, defaultSubject, 3, SourceConfig{SMTPFrom: "noreply@example.com"}, connFailSender, nil)
	if err == nil || !isSMTPConnectionError(err) {
		t.Fatalf("expected smtpConnectionError, got %v", err)
	}
	if got := readAttempts(mailFile); got != 0 {
		t.Fatalf("expected attempts to remain 0 on SMTP connection error, got %d", got)
	}
	if _, statErr := os.Stat(mailFile); statErr != nil {
		t.Fatalf("expected mail file to remain pending: %v", statErr)
	}
}

func TestProcessMailDir_PermissionWarnings(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}

	ipc, getEvents := startMockIPCServer(t)

	mailFile := filepath.Join(tmpDir, "perm_test.SendMail")
	if err := os.WriteFile(mailFile, []byte("To: ops@example.com\nSubject: Perm Test\n\nBody"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mailFile, 0o644); err != nil {
		t.Fatal(err)
	}

	noopSender := func(_ context.Context, _ SourceConfig, _ ParsedMail) error {
		return nil
	}

	if _, err := processMailDir(context.Background(), tmpDir, defaultSubject, 5, SourceConfig{SMTPFrom: "noreply@example.com"}, noopSender, ipc); err != nil {
		t.Fatalf("processMailDir failed: %v", err)
	}

	dirInfo, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("failed to stat tmpDir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("expected mail_dir permissions to be corrected to 0700, got %04o", dirInfo.Mode().Perm())
	}

	warnings := 0
	for _, ev := range getEvents() {
		if strings.Contains(ev.Message, "WARNING:") {
			warnings++
		}
	}
	if warnings < 2 {
		t.Fatalf("expected permission WARNING audit events for both directory and file, got %d", warnings)
	}
}

func TestEnsureMailDir_CreatesMissingDirectoryWithMode0700(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "nested", "outbox")
	ipc, getEvents := startMockIPCServer(t)

	noopSender := func(_ context.Context, _ SourceConfig, _ ParsedMail) error {
		return nil
	}

	if _, err := processMailDir(context.Background(), missingDir, defaultSubject, 5, SourceConfig{SMTPFrom: "noreply@example.com"}, noopSender, ipc); err != nil {
		t.Fatalf("processMailDir failed to create missing mail_dir: %v", err)
	}

	info, err := os.Stat(missingDir)
	if err != nil {
		t.Fatalf("expected missingDir to be created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected created path to be a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("expected created directory to have mode 0700, got %04o", info.Mode().Perm())
	}

	foundCreatedAudit := false
	for _, ev := range getEvents() {
		if strings.Contains(ev.Message, "Created mail_dir") && strings.Contains(ev.Message, "0700") {
			foundCreatedAudit = true
			break
		}
	}
	if !foundCreatedAudit {
		t.Fatal("expected audit event confirming creation of mail_dir with mode 0700")
	}
}

func TestLoginAuth(t *testing.T) {
	auth := newLoginAuth("admin@digidocu.dev", "secret", "digidocu-dev.netcup-mail.de")
	respUser, err := auth.Next([]byte("Username:"), true)
	if err != nil || string(respUser) != "admin@digidocu.dev" {
		t.Fatalf("unexpected username response: %q, err=%v", string(respUser), err)
	}
	respPass, err := auth.Next([]byte("Password:"), true)
	if err != nil || string(respPass) != "secret" {
		t.Fatalf("unexpected password response: %q, err=%v", string(respPass), err)
	}
}
