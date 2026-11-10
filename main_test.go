/**
 * SPDX-FileComment: MitM Maintenance SendMail Unit Tests
 * SPDX-FileType: SOURCE
 * SPDX-FileContributor: ZHENG Robert
 * SPDX-FileCopyrightText: 2026 ZHENG Robert
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main_test.go
 * @brief Unit tests for KEK validation, envelope decryption, configuration parsing, and mail directory processing.
 * @version 0.1.0
 * @date 2026-11-10
 *
 * @author ZHENG Robert (robert@hase-zheng.net)
 * @copyright Copyright (c) 2026 ZHENG Robert
 * @license Apache-2.0
 */

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if defaults.SourceName != defaultSource || defaults.MailSubject != defaultSubject || defaults.Topic != defaultTopic {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}

	customJSON := `{"source_name":"NETCUP_SMTP","mail_dir":"/var/spool/sendmail","mail_subject":"System Alert","topic":"ops.mail"}`
	custom, err := parseArgs(customJSON)
	if err != nil {
		t.Fatalf("unexpected error on custom args: %v", err)
	}
	if custom.SourceName != "NETCUP_SMTP" || custom.MailDir != "/var/spool/sendmail" || custom.MailSubject != "System Alert" || custom.Topic != "ops.mail" {
		t.Fatalf("unexpected parsed args: %+v", custom)
	}

	if _, err := parseArgs("{invalid-json"); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestParseSourceConfig(t *testing.T) {
	// Native JSON types
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

	// String-typed port and starttls (as in SendMail.env)
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

	// Wrap DEK with KEK
	kekBlock, _ := aes.NewCipher(kek)
	kekGCM, _ := cipher.NewGCM(kekBlock)
	dekNonce := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, dekNonce)
	wrappedDEK := append(dekNonce, kekGCM.Seal(nil, dekNonce, dek, nil)...)

	// Encrypt SourceConfig with DEK
	dekBlock, _ := aes.NewCipher(dek)
	dekGCM, _ := cipher.NewGCM(dekBlock)
	cfgNonce := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, cfgNonce)
	plaintext := []byte(`{"smtp_server":"smtp.example.org","smtp_port":587,"smtp_from":"noreply@example.org"}`)
	ciphertext := dekGCM.Seal(nil, cfgNonce, plaintext, nil)

	// Unwrap and decrypt
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

func TestProcessMailDir_SuccessAndFailure(t *testing.T) {
	tmpDir := t.TempDir()

	okFile := filepath.Join(tmpDir, "alice@example.com.SendMail")
	failFile := filepath.Join(tmpDir, "bob@example.com.SendMail")
	ignoredFile := filepath.Join(tmpDir, "notes.txt")

	if err := os.WriteFile(okFile, []byte("Hello Alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(failFile, []byte("Hello Bob"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ignoredFile, []byte("Ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}

	var dispatched []string
	mockSender := func(_ context.Context, _ SourceConfig, to, subject, body string) error {
		if to == "bob@example.com" {
			return errors.New("simulated SMTP error")
		}
		dispatched = append(dispatched, to+"|"+subject+"|"+body)
		return nil
	}

	sent, failed, err := processMailDir(context.Background(), tmpDir, "Alert Subject", SourceConfig{SMTPFrom: "sender@example.com"}, mockSender, nil)
	if err != nil {
		t.Fatalf("processMailDir returned unexpected error: %v", err)
	}
	if sent != 1 || failed != 1 {
		t.Fatalf("expected sent=1, failed=1; got sent=%d, failed=%d", sent, failed)
	}
	if len(dispatched) != 1 || dispatched[0] != "alice@example.com|Alert Subject|Hello Alice" {
		t.Fatalf("unexpected dispatched records: %+v", dispatched)
	}

	// alice@example.com.SendMail must be deleted
	if _, err := os.Stat(okFile); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be deleted after successful send", okFile)
	}
	// bob@example.com.SendMail must remain on disk
	if _, err := os.Stat(failFile); err != nil {
		t.Fatalf("expected %s to be preserved after failed send: %v", failFile, err)
	}
	// notes.txt must remain untouched
	if _, err := os.Stat(ignoredFile); err != nil {
		t.Fatalf("expected %s to remain untouched: %v", ignoredFile, err)
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

func TestBuildMimeMessage(t *testing.T) {
	msg := string(buildMimeMessage("admin@digidocu.dev", "user@example.com", "Test Subject", "Line 1\nLine 2"))
	if !strings.Contains(msg, "From: <admin@digidocu.dev>\r\n") {
		t.Fatalf("missing From header in %q", msg)
	}
	if !strings.Contains(msg, "To: <user@example.com>\r\n") {
		t.Fatalf("missing To header in %q", msg)
	}
	if !strings.Contains(msg, "Subject: Test Subject\r\n") {
		t.Fatalf("missing Subject header in %q", msg)
	}
	if !strings.HasSuffix(msg, "\r\n\r\nLine 1\r\nLine 2\r\n") {
		t.Fatalf("unexpected body formatting in %q", msg)
	}
}
