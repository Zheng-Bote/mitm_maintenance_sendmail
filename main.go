/**
 * SPDX-FileComment: MitM Maintenance SendMail Job
 * SPDX-FileType: SOURCE
 * SPDX-FileContributor: ZHENG Robert
 * SPDX-FileCopyrightText: 2026 ZHENG Robert
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main.go
 * @brief Scheduled CLI utility that dispatches *.SendMail files via SMTP using credentials decrypted from source_credentials.
 * @version 0.1.1
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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	appName          = "MitM Maintenance SendMail"
	version          = "0.1.1"
	xMitmHeaderRegex = regexp.MustCompile(`^(?i)X-MitM-[A-Za-z0-9-]+$`)
)

// mailDirMode is the mode of the outbox: mail files are plaintext, only the scheduler user may access them.
const mailDirMode fs.FileMode = 0o700

const (
	componentName      = "mitm_maintenance_sendmail"
	defaultSource      = "SENDMAIL_SMTP"
	defaultTopic       = "maintenance.sendmail"
	defaultSubject     = "New Message from SendMail"
	defaultPort        = 587
	defaultMaxAttempts = 5
	mailFileSuffix     = ".SendMail"
	failedFileSuffix   = ".failed"
	tempFileSuffix     = ".tmp"
	attemptsFileSuffix = ".attempts"
	smtpTimeout        = 30 * time.Second
)

// TargetDBConfig defines connection parameters for the MitM PostgreSQL database.
type TargetDBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
	DSN      string `json:"dsn"`
	SSLMode  string `json:"sslmode"`
}

// SendMailArgs defines the runtime JSON arguments passed via os.Args[1] by the scheduler.
type SendMailArgs struct {
	SourceName  string `json:"source_name"`
	MailDir     string `json:"mail_dir"`
	MailSubject string `json:"mail_subject"`
	Topic       string `json:"topic"`
	MaxAttempts int    `json:"max_attempts"`
}

// SourceConfig holds the decrypted SMTP configuration from source_credentials.config_payload.
type SourceConfig struct {
	SMTPServer   string `json:"smtp_server"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	SMTPFrom     string `json:"smtp_from"`
	SMTPStartTLS bool   `json:"smtp_starttls"`
	WatchDir     string `json:"watch_dir"`
}

// ParsedMail represents a parsed *.SendMail file (either header-block or legacy format).
type ParsedMail struct {
	To           []string
	Cc           []string
	Subject      string
	ExtraHeaders [][2]string
	Body         string
	HasHeader    bool
}

// OutboxStats summarizes a single run of processMailDir.
type OutboxStats struct {
	Sent             int
	Failed           int
	Pending          int
	FailedFiles      int
	OldestPendingAge time.Duration
}

// smtpConnectionError marks an unreachable SMTP server or failed TLS/Auth handshake (Req. 11).
type smtpConnectionError struct {
	err error
}

func (e *smtpConnectionError) Error() string {
	return e.err.Error()
}

func (e *smtpConnectionError) Unwrap() error {
	return e.err
}

func isSMTPConnectionError(err error) bool {
	var target *smtpConnectionError
	return errors.As(err, &target)
}

// StatusEvent represents a status or audit message sent to the scheduler Unix Domain Socket.
type StatusEvent struct {
	RunID     int    `json:"run_id"`
	Type      string `json:"type"` // "status" or "audit"
	Component string `json:"component"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Progress  int    `json:"progress"`
}

// IPCClient communicates status and audit events to the scheduler; a nil receiver is a no-op.
type IPCClient struct {
	SocketPath string
	RunID      int
	Component  string
	Topic      string
	SourceName string
}

func newIPCClient() *IPCClient {
	runIDStr := os.Getenv("RUN_ID")
	socketPath := os.Getenv("SCHEDULER_SOCKET_PATH")
	if runIDStr == "" || socketPath == "" {
		return nil
	}
	runID, err := strconv.Atoi(runIDStr)
	if err != nil {
		return nil
	}
	return &IPCClient{
		SocketPath: socketPath,
		RunID:      runID,
		Component:  componentName,
	}
}

// SendEvent sends a job status event to the scheduler via Unix Domain Socket.
func (c *IPCClient) SendEvent(status, message string, progress int) {
	if c == nil || c.SocketPath == "" {
		return
	}
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		log.Printf("[IPC ERROR] Failed to connect to scheduler socket: %v", err)
		return
	}
	defer conn.Close()

	if c.Topic != "" && c.SourceName != "" {
		message = fmt.Sprintf("%s: %s: %s", c.Topic, c.SourceName, message)
	}

	event := StatusEvent{
		RunID:    c.RunID,
		Type:     "status",
		Status:   status,
		Message:  message,
		Progress: progress,
	}
	data, _ := json.Marshal(event)
	_, _ = conn.Write(append(data, '\n'))
}

// SendAudit sends a job audit log entry to the scheduler via Unix Domain Socket.
func (c *IPCClient) SendAudit(message string) {
	if c == nil || c.SocketPath == "" {
		return
	}
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		log.Printf("[IPC ERROR] Failed to connect to scheduler socket: %v", err)
		return
	}
	defer conn.Close()

	if c.Topic != "" && c.SourceName != "" {
		message = fmt.Sprintf("%s: %s: %s", c.Topic, c.SourceName, message)
	}

	event := StatusEvent{
		RunID:     c.RunID,
		Type:      "audit",
		Component: c.Component,
		Message:   message,
	}
	data, _ := json.Marshal(event)
	_, _ = conn.Write(append(data, '\n'))
}

func fail(ipc *IPCClient, err error) error {
	msg := err.Error()
	ipc.SendEvent("failed", msg, 0)
	ipc.SendAudit("ERROR: " + msg)
	return err
}

// maskEmail masks an email address for logs and audit events (e.g. "ops@example.com" -> "o***@example.com").
func maskEmail(addr string) string {
	addr = strings.TrimSpace(addr)
	atIdx := strings.IndexByte(addr, '@')
	if atIdx <= 0 || atIdx == len(addr)-1 {
		return "***"
	}
	localRunes := []rune(addr[:atIdx])
	domain := addr[atIdx+1:]
	return string(localRunes[0]) + "***@" + domain
}

func maskEmails(addrs []string) string {
	if len(addrs) == 0 {
		return ""
	}
	masked := make([]string, len(addrs))
	for i, a := range addrs {
		masked[i] = maskEmail(a)
	}
	return strings.Join(masked, ", ")
}

// maskFileName masks the filename prefix if it is a legacy email filename (e.g. "ops@example.com.SendMail" -> "o***@example.com.SendMail").
func maskFileName(fileName string) string {
	for _, suffix := range []string{mailFileSuffix, failedFileSuffix, attemptsFileSuffix, tempFileSuffix} {
		if strings.HasSuffix(fileName, suffix) {
			prefix := strings.TrimSuffix(fileName, suffix)
			if strings.Contains(prefix, "@") {
				return maskEmail(prefix) + suffix
			}
			return fileName
		}
	}
	if strings.Contains(fileName, "@") {
		return maskEmail(fileName)
	}
	return fileName
}

func validateKEK(masterKey string) ([]byte, error) {
	if masterKey == "" {
		return nil, fmt.Errorf("Missing MASTER_KEY environment variable")
	}

	var kek []byte
	if decoded, err := base64.StdEncoding.DecodeString(masterKey); err == nil && len(decoded) == 32 {
		kek = decoded
	} else {
		kek = []byte(masterKey)
	}

	if len(kek) != 32 {
		return nil, fmt.Errorf("MASTER_KEY must be exactly 32 bytes, got %d", len(kek))
	}
	return kek, nil
}

func parseArgs(raw string) (SendMailArgs, error) {
	args := SendMailArgs{
		SourceName:  defaultSource,
		MailSubject: defaultSubject,
		Topic:       defaultTopic,
		MaxAttempts: defaultMaxAttempts,
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return args, nil
	}
	var parsed SendMailArgs
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return SendMailArgs{}, fmt.Errorf("Failed to parse sendmail arguments: %w", err)
	}
	if parsed.SourceName != "" {
		args.SourceName = parsed.SourceName
	}
	if parsed.MailDir != "" {
		args.MailDir = parsed.MailDir
	}
	if parsed.MailSubject != "" {
		args.MailSubject = parsed.MailSubject
	}
	if parsed.Topic != "" {
		args.Topic = parsed.Topic
	}
	if parsed.MaxAttempts < 0 {
		return SendMailArgs{}, fmt.Errorf("max_attempts must be positive, got %d", parsed.MaxAttempts)
	}
	if parsed.MaxAttempts > 0 {
		args.MaxAttempts = parsed.MaxAttempts
	}
	return args, nil
}

func parseSourceConfig(data []byte) (SourceConfig, error) {
	var raw struct {
		SMTPServer   string          `json:"smtp_server"`
		SMTPPort     json.RawMessage `json:"smtp_port"`
		SMTPUsername string          `json:"smtp_username"`
		SMTPPassword string          `json:"smtp_password"`
		SMTPFrom     string          `json:"smtp_from"`
		SMTPStartTLS json.RawMessage `json:"smtp_starttls"`
		WatchDir     string          `json:"watch_dir"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return SourceConfig{}, fmt.Errorf("Failed to parse decrypted SMTP configuration: %w", err)
	}

	cfg := SourceConfig{
		SMTPServer:   strings.TrimSpace(raw.SMTPServer),
		SMTPPort:     defaultPort,
		SMTPUsername: raw.SMTPUsername,
		SMTPPassword: raw.SMTPPassword,
		SMTPFrom:     strings.TrimSpace(raw.SMTPFrom),
		SMTPStartTLS: true,
		WatchDir:     strings.TrimSpace(raw.WatchDir),
	}

	if len(raw.SMTPPort) > 0 && string(raw.SMTPPort) != "null" {
		var pInt int
		if err := json.Unmarshal(raw.SMTPPort, &pInt); err == nil {
			cfg.SMTPPort = pInt
		} else {
			var pStr string
			if err := json.Unmarshal(raw.SMTPPort, &pStr); err == nil && strings.TrimSpace(pStr) != "" {
				parsedPort, err := strconv.Atoi(strings.TrimSpace(pStr))
				if err != nil {
					return SourceConfig{}, fmt.Errorf("invalid smtp_port value %q: %w", pStr, err)
				}
				cfg.SMTPPort = parsedPort
			} else {
				return SourceConfig{}, fmt.Errorf("invalid smtp_port format")
			}
		}
	}

	if len(raw.SMTPStartTLS) > 0 && string(raw.SMTPStartTLS) != "null" {
		var bVal bool
		if err := json.Unmarshal(raw.SMTPStartTLS, &bVal); err == nil {
			cfg.SMTPStartTLS = bVal
		} else {
			var sVal string
			if err := json.Unmarshal(raw.SMTPStartTLS, &sVal); err == nil {
				cfg.SMTPStartTLS = strings.EqualFold(strings.TrimSpace(sVal), "true")
			} else {
				return SourceConfig{}, fmt.Errorf("invalid smtp_starttls format")
			}
		}
	}

	if cfg.SMTPServer == "" {
		return SourceConfig{}, errors.New("smtp_server is required in source_credentials")
	}
	if cfg.SMTPPort <= 0 || cfg.SMTPPort > 65535 {
		return SourceConfig{}, fmt.Errorf("smtp_port out of range: %d", cfg.SMTPPort)
	}
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = cfg.SMTPUsername
	}
	if cfg.SMTPFrom == "" {
		return SourceConfig{}, errors.New("smtp_from is required in source_credentials")
	}
	if cfg.WatchDir == "" {
		cfg.WatchDir = "."
	}

	return cfg, nil
}

func resolveMailDir(sourceWatchDir, cliMailDir string) string {
	if strings.TrimSpace(cliMailDir) != "" {
		return strings.TrimSpace(cliMailDir)
	}
	if strings.TrimSpace(sourceWatchDir) != "" {
		return strings.TrimSpace(sourceWatchDir)
	}
	return "."
}

func loadTargetDBConfig() (TargetDBConfig, string, error) {
	var targetCfg TargetDBConfig
	configSource := "Environment Variables"
	jsonConfig := os.Getenv("MITM_DB_CONFIG_JSON")

	if jsonConfig != "" {
		var fullCfg struct {
			DB struct {
				Host     string `json:"host"`
				Port     int    `json:"port"`
				User     string `json:"user"`
				Password string `json:"password"`
				Database string `json:"database"`
				SSLMode  bool   `json:"sslmode"`
			} `json:"db"`
		}
		if err := json.Unmarshal([]byte(jsonConfig), &fullCfg); err != nil {
			return TargetDBConfig{}, "", fmt.Errorf("Failed to parse MitM database JSON config: %w", err)
		}
		targetCfg.Host = fullCfg.DB.Host
		targetCfg.Port = fullCfg.DB.Port
		targetCfg.User = fullCfg.DB.User
		targetCfg.Password = fullCfg.DB.Password
		targetCfg.Database = fullCfg.DB.Database
		if fullCfg.DB.SSLMode {
			targetCfg.SSLMode = "require"
		} else {
			targetCfg.SSLMode = "disable"
		}
		configSource = "JSON Config (MITM_DB_CONFIG_JSON)"
	} else {
		targetCfg.Host = os.Getenv("MITM_DB_HOST")
		if portStr := os.Getenv("MITM_DB_PORT"); portStr != "" {
			targetCfg.Port, _ = strconv.Atoi(portStr)
		}
		targetCfg.User = os.Getenv("MITM_DB_USER")
		targetCfg.Password = os.Getenv("MITM_DB_PASSWORD")
		targetCfg.Database = os.Getenv("MITM_DB_NAME")
		envSSLMode := os.Getenv("MITM_DB_SSLMODE")
		switch envSSLMode {
		case "", "false":
			targetCfg.SSLMode = "disable"
		case "true":
			targetCfg.SSLMode = "require"
		default:
			targetCfg.SSLMode = envSSLMode
		}
	}

	if targetCfg.Host == "" && targetCfg.DSN == "" {
		return TargetDBConfig{}, "", errors.New("MitM database configuration missing in ENV")
	}
	return targetCfg, configSource, nil
}

func connectTargetDB(ctx context.Context, targetCfg TargetDBConfig) (*pgxpool.Pool, error) {
	dsn := targetCfg.DSN
	if dsn == "" {
		sslMode := targetCfg.SSLMode
		if sslMode == "" {
			sslMode = "disable"
		}
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			targetCfg.User, targetCfg.Password, targetCfg.Host, targetCfg.Port, targetCfg.Database, sslMode)
	}
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	poolCfg.MaxConns = 5
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.MaxConnLifetime = 1 * time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func loadSourceSecrets(ctx context.Context, pool *pgxpool.Pool, sourceName string) ([]byte, []byte, string, []byte, error) {
	var configPayload []byte
	var credentialsNonce []byte
	var dekID string

	err := pool.QueryRow(ctx, `
		SELECT config_payload, nonce, dek_id
		FROM source_credentials
		WHERE source_name = $1 AND is_active = true
		LIMIT 1
	`, sourceName).Scan(&configPayload, &credentialsNonce, &dekID)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("Failed to load source credentials for '%s': %w", sourceName, err)
	}

	var wrappedKey []byte
	err = pool.QueryRow(ctx, `
		SELECT wrapped_key
		FROM storage_keys
		WHERE id = $1 AND is_active = true
		LIMIT 1
	`, dekID).Scan(&wrappedKey)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("Failed to load wrapped DEK (ID: %s): %w", dekID, err)
	}

	return configPayload, credentialsNonce, dekID, wrappedKey, nil
}

func unwrapDEK(kek, wrappedKey []byte) ([]byte, error) {
	if len(wrappedKey) < 12 {
		return nil, errors.New("wrapped DEK is too short")
	}
	kekBlock, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, err
	}
	return kekGCM.Open(nil, wrappedKey[:12], wrappedKey[12:], nil)
}

func decryptPayload(dek, nonce, ciphertext []byte) ([]byte, error) {
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, err
	}
	return dekGCM.Open(nil, nonce, ciphertext, nil)
}

// loginAuth implements smtp.Auth for the AUTH LOGIN mechanism required by providers such as Netcup.
type loginAuth struct {
	username string
	password string
	host     string
}

func newLoginAuth(username, password, host string) smtp.Auth {
	return &loginAuth{username: username, password: password, host: host}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := strings.ToLower(strings.TrimSpace(string(fromServer)))
	switch {
	case strings.Contains(prompt, "username") || strings.Contains(prompt, "user"):
		return []byte(a.username), nil
	case strings.Contains(prompt, "password") || strings.Contains(prompt, "pass"):
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unexpected AUTH LOGIN challenge: %q", string(fromServer))
	}
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

func isValidEmail(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.ContainsAny(addr, " \t\r\n<>") {
		return false
	}
	atIdx := strings.IndexByte(addr, '@')
	if atIdx <= 0 || atIdx != strings.LastIndexByte(addr, '@') || atIdx == len(addr)-1 {
		return false
	}
	domain := addr[atIdx+1:]
	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}

func validateHeaderValue(val string) error {
	for i := 0; i < len(val); i++ {
		b := val[i]
		if b == '\r' || b == '\n' {
			return errors.New("header value contains CR/LF")
		}
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return fmt.Errorf("header value contains control character 0x%02x", b)
		}
	}
	return nil
}

func parseRecipientList(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	var result []string
	for _, part := range parts {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		if err := validateHeaderValue(addr); err != nil {
			return nil, err
		}
		if !isValidEmail(addr) {
			return nil, fmt.Errorf("invalid email address %q", maskEmail(addr))
		}
		result = append(result, addr)
	}
	return result, nil
}

func startsWithKnownHeader(firstLine string) bool {
	colonIdx := strings.IndexByte(firstLine, ':')
	if colonIdx <= 0 {
		return false
	}
	name := strings.TrimSpace(firstLine[:colonIdx])
	switch strings.ToLower(name) {
	case "to", "cc", "subject":
		return true
	default:
		return xMitmHeaderRegex.MatchString(name)
	}
}

// parseMailFile parses a *.SendMail file as either a header-block mail or a legacy mail.
func parseMailFile(fileName string, content []byte, defaultSubject string) (ParsedMail, error) {
	if !strings.HasSuffix(fileName, mailFileSuffix) {
		return ParsedMail{}, fmt.Errorf("unsupported file suffix for %q", maskFileName(fileName))
	}
	prefix := strings.TrimSpace(strings.TrimSuffix(fileName, mailFileSuffix))
	text := string(content)

	firstLine := text
	if nlIdx := strings.IndexByte(text, '\n'); nlIdx >= 0 {
		firstLine = strings.TrimSuffix(text[:nlIdx], "\r")
	}

	isHeaderFile := startsWithKnownHeader(firstLine) || !isValidEmail(prefix)
	if !isHeaderFile {
		if err := validateHeaderValue(defaultSubject); err != nil {
			return ParsedMail{}, fmt.Errorf("invalid default subject: %w", err)
		}
		return ParsedMail{
			To:        []string{prefix},
			Subject:   defaultSubject,
			Body:      text,
			HasHeader: false,
		}, nil
	}

	var parsed ParsedMail
	parsed.HasHeader = true

	// Split lines by \n and strip a single trailing \r from each header line; any remaining \r is a CR injection.
	rest := text
	foundBlankLine := false
	for {
		var line string
		if nlIdx := strings.IndexByte(rest, '\n'); nlIdx >= 0 {
			line = strings.TrimSuffix(rest[:nlIdx], "\r")
			rest = rest[nlIdx+1:]
		} else {
			line = strings.TrimSuffix(rest, "\r")
			rest = ""
		}

		if line == "" {
			foundBlankLine = true
			parsed.Body = rest
			break
		}

		colonIdx := strings.IndexByte(line, ':')
		if colonIdx <= 0 {
			return ParsedMail{}, errors.New("malformed header line (missing colon)")
		}
		name := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])

		if err := validateHeaderValue(name); err != nil {
			return ParsedMail{}, fmt.Errorf("invalid header name: %w", err)
		}
		if err := validateHeaderValue(val); err != nil {
			return ParsedMail{}, fmt.Errorf("invalid header %q: %w", name, err)
		}

		switch strings.ToLower(name) {
		case "to":
			addrs, err := parseRecipientList(val)
			if err != nil {
				return ParsedMail{}, fmt.Errorf("invalid To header: %w", err)
			}
			parsed.To = append(parsed.To, addrs...)
		case "cc":
			addrs, err := parseRecipientList(val)
			if err != nil {
				return ParsedMail{}, fmt.Errorf("invalid Cc header: %w", err)
			}
			parsed.Cc = append(parsed.Cc, addrs...)
		case "subject":
			parsed.Subject = val
		default:
			if xMitmHeaderRegex.MatchString(name) {
				parsed.ExtraHeaders = append(parsed.ExtraHeaders, [2]string{name, val})
			}
		}

		if rest == "" {
			break
		}
	}

	if !foundBlankLine && len(parsed.To) == 0 && parsed.Subject == "" {
		return ParsedMail{}, errors.New("missing header block separator")
	}
	if len(parsed.To) == 0 {
		return ParsedMail{}, errors.New("missing valid To recipient in header block")
	}
	if strings.TrimSpace(parsed.Subject) == "" {
		return ParsedMail{}, errors.New("missing Subject in header block")
	}

	return parsed, nil
}

func buildMimeMessage(from string, mail ParsedMail) ([]byte, error) {
	if err := validateHeaderValue(from); err != nil {
		return nil, fmt.Errorf("invalid From address: %w", err)
	}
	if err := validateHeaderValue(mail.Subject); err != nil {
		return nil, fmt.Errorf("invalid Subject: %w", err)
	}
	for _, r := range mail.To {
		if err := validateHeaderValue(r); err != nil {
			return nil, fmt.Errorf("invalid To address: %w", err)
		}
	}
	for _, r := range mail.Cc {
		if err := validateHeaderValue(r); err != nil {
			return nil, fmt.Errorf("invalid Cc address: %w", err)
		}
	}
	for _, h := range mail.ExtraHeaders {
		if !xMitmHeaderRegex.MatchString(h[0]) {
			return nil, fmt.Errorf("invalid extra header name %q", h[0])
		}
		if err := validateHeaderValue(h[1]); err != nil {
			return nil, fmt.Errorf("invalid header %q: %w", h[0], err)
		}
	}

	encodedSubject := mime.QEncoding.Encode("utf-8", strings.TrimSpace(mail.Subject))
	normalizedBody := strings.ReplaceAll(mail.Body, "\r\n", "\n")
	normalizedBody = strings.ReplaceAll(normalizedBody, "\n", "\r\n")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: <%s>\r\n", strings.TrimSpace(from)))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", formatAddressHeader(mail.To)))
	if len(mail.Cc) > 0 {
		sb.WriteString(fmt.Sprintf("Cc: %s\r\n", formatAddressHeader(mail.Cc)))
	}
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	for _, h := range mail.ExtraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", h[0], h[1]))
	}
	sb.WriteString("\r\n")
	sb.WriteString(normalizedBody)
	if !strings.HasSuffix(normalizedBody, "\r\n") {
		sb.WriteString("\r\n")
	}
	return []byte(sb.String()), nil
}

func formatAddressHeader(addrs []string) string {
	formatted := make([]string, len(addrs))
	for i, a := range addrs {
		formatted[i] = "<" + strings.TrimSpace(a) + ">"
	}
	return strings.Join(formatted, ", ")
}

func uniqueRecipients(to, cc []string) []string {
	seen := make(map[string]bool, len(to)+len(cc))
	var all []string
	for _, addr := range append(append([]string{}, to...), cc...) {
		key := strings.ToLower(strings.TrimSpace(addr))
		if key != "" && !seen[key] {
			seen[key] = true
			all = append(all, strings.TrimSpace(addr))
		}
	}
	return all
}

func sendEmail(ctx context.Context, cfg SourceConfig, mail ParsedMail) error {
	msg, err := buildMimeMessage(cfg.SMTPFrom, mail)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(cfg.SMTPServer, strconv.Itoa(cfg.SMTPPort))
	dialer := &net.Dialer{Timeout: smtpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &smtpConnectionError{err: fmt.Errorf("failed to connect to SMTP server %s: %w", addr, err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	client, err := smtp.NewClient(conn, cfg.SMTPServer)
	if err != nil {
		return &smtpConnectionError{err: fmt.Errorf("failed to create SMTP client: %w", err)}
	}
	defer client.Close()

	if cfg.SMTPStartTLS {
		tlsCfg := &tls.Config{
			ServerName: cfg.SMTPServer,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return &smtpConnectionError{err: fmt.Errorf("STARTTLS failed: %w", err)}
		}
	}

	if cfg.SMTPUsername != "" {
		var auth smtp.Auth
		if ok, mechs := client.Extension("AUTH"); ok && strings.Contains(strings.ToUpper(mechs), "LOGIN") {
			auth = newLoginAuth(cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPServer)
		} else {
			auth = smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPServer)
		}
		if err := client.Auth(auth); err != nil {
			return &smtpConnectionError{err: fmt.Errorf("SMTP authentication failed: %w", err)}
		}
	}

	if err := client.Mail(strings.TrimSpace(cfg.SMTPFrom)); err != nil {
		return fmt.Errorf("MAIL FROM rejected: %w", err)
	}
	for _, rcpt := range uniqueRecipients(mail.To, mail.Cc) {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO rejected for %s: %w", maskEmail(rcpt), err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("failed to write message body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to finalize message data: %w", err)
	}

	return client.Quit()
}

type mailSenderFunc func(ctx context.Context, cfg SourceConfig, mail ParsedMail) error

func attemptsFilePath(mailFilePath string) string {
	base := strings.TrimSuffix(mailFilePath, mailFileSuffix)
	return base + attemptsFileSuffix
}

func failedFilePath(mailFilePath string) string {
	base := strings.TrimSuffix(mailFilePath, mailFileSuffix)
	return base + failedFileSuffix
}

func readAttempts(mailFilePath string) int {
	data, err := os.ReadFile(attemptsFilePath(mailFilePath))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func writeAttempts(mailFilePath string, attempts int) error {
	return os.WriteFile(attemptsFilePath(mailFilePath), []byte(strconv.Itoa(attempts)+"\n"), 0o600)
}

func removeAttempts(mailFilePath string) {
	_ = os.Remove(attemptsFilePath(mailFilePath))
}

func markFileFailed(mailFilePath string) error {
	removeAttempts(mailFilePath)
	return os.Rename(mailFilePath, failedFilePath(mailFilePath))
}

func inspectOutbox(mailDir string, now time.Time) (int, int, time.Duration) {
	entries, err := os.ReadDir(mailDir)
	if err != nil {
		return 0, 0, 0
	}
	pending := 0
	failedFiles := 0
	var oldest time.Time

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, mailFileSuffix):
			pending++
			if info, err := entry.Info(); err == nil {
				if oldest.IsZero() || info.ModTime().Before(oldest) {
					oldest = info.ModTime()
				}
			}
		case strings.HasSuffix(name, failedFileSuffix):
			failedFiles++
		}
	}

	var oldestAge time.Duration
	if !oldest.IsZero() && now.After(oldest) {
		oldestAge = now.Sub(oldest).Round(time.Second)
	}
	return pending, failedFiles, oldestAge
}

// ensureMailDir makes sure the outbox exists as a directory with mode 0700 and is writable.
// A missing directory (including missing parents) is created; another mode is corrected to 0700
// (if that fails, e.g. for a directory of another owner, a warning is returned).
func ensureMailDir(dir string) ([]string, error) {
	where := describePath(dir)
	var notes []string

	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, mailDirMode); err != nil {
			return nil, fmt.Errorf("mail_dir %s does not exist and cannot be created: %w", where, err)
		}
		// MkdirAll applies the umask; set the mode explicitly.
		if err := os.Chmod(dir, mailDirMode); err != nil {
			return nil, fmt.Errorf("mail_dir %s was created, but its mode cannot be set to 0700: %w", where, err)
		}
		notes = append(notes, fmt.Sprintf("Created mail_dir %s with mode 0700", where))
	case err != nil:
		return nil, fmt.Errorf("mail_dir %s is not accessible: %w", where, err)
	case !info.IsDir():
		return nil, fmt.Errorf("mail_dir %s is not a directory", where)
	case info.Mode().Perm() != mailDirMode:
		if err := os.Chmod(dir, mailDirMode); err != nil {
			notes = append(notes, fmt.Sprintf("WARNING: mail_dir %s has mode %04o instead of 0700 and its mode cannot be changed: %v",
				where, info.Mode().Perm(), err))
		} else {
			notes = append(notes, fmt.Sprintf("WARNING: mail_dir %s had mode %04o; mode set to 0700", where, info.Mode().Perm()))
		}
	}

	probe, err := os.CreateTemp(dir, ".write-check-*"+tempFileSuffix)
	if err != nil {
		return notes, fmt.Errorf("mail_dir %s is not writable: %w", where, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return notes, nil
}

// describePath quotes a path; a relative path is followed by its absolute path and the working directory.
func describePath(path string) string {
	if filepath.IsAbs(path) {
		return fmt.Sprintf("%q", path)
	}
	abs, absErr := filepath.Abs(path)
	cwd, cwdErr := os.Getwd()
	if absErr != nil || cwdErr != nil {
		return fmt.Sprintf("%q", path)
	}
	return fmt.Sprintf("%q (%s, working directory %s)", path, abs, cwd)
}

func processMailDir(ctx context.Context, mailDir, defaultSubject string, maxAttempts int, cfg SourceConfig, sendFn mailSenderFunc, ipc *IPCClient) (OutboxStats, error) {
	var stats OutboxStats
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}

	notes, err := ensureMailDir(mailDir)
	for _, note := range notes {
		log.Println(note)
		ipc.SendAudit(note)
	}
	if err != nil {
		return stats, err
	}

	entries, err := os.ReadDir(mailDir)
	if err != nil {
		return stats, fmt.Errorf("Failed to read mail directory '%s': %w", mailDir, err)
	}

	var fileNames []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, tempFileSuffix) || strings.HasSuffix(name, attemptsFileSuffix) || strings.HasSuffix(name, failedFileSuffix) {
			continue
		}
		if strings.HasSuffix(name, mailFileSuffix) {
			fileNames = append(fileNames, name)
		}
	}
	sort.Strings(fileNames)

	for _, fileName := range fileNames {
		if err := ctx.Err(); err != nil {
			return stats, err
		}

		filePath := filepath.Join(mailDir, fileName)
		maskedName := maskFileName(fileName)

		if fInfo, err := os.Stat(filePath); err == nil && fInfo.Mode().Perm()&0o077 != 0 {
			warnMsg := fmt.Sprintf("WARNING: Mail file '%s' is accessible by group or others (mode %04o, expected 0600)", maskedName, fInfo.Mode().Perm())
			log.Println(warnMsg)
			ipc.SendAudit(warnMsg)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to read mail file '%s': %v", maskedName, err)
			log.Println(errMsg)
			ipc.SendAudit("ERROR: " + errMsg)
			stats.Failed++
			continue
		}

		mail, err := parseMailFile(fileName, content, defaultSubject)
		if err != nil {
			_ = markFileFailed(filePath)
			errMsg := fmt.Sprintf("Invalid mail file '%s' renamed to .failed: %v", maskedName, err)
			log.Println(errMsg)
			ipc.SendAudit("ERROR: " + errMsg)
			stats.Failed++
			continue
		}

		maskedRecipients := maskEmails(uniqueRecipients(mail.To, mail.Cc))
		if err := sendFn(ctx, cfg, mail); err != nil {
			if isSMTPConnectionError(err) {
				return stats, err
			}
			attempts := readAttempts(filePath) + 1
			stats.Failed++
			if attempts >= maxAttempts {
				_ = markFileFailed(filePath)
				errMsg := fmt.Sprintf("Mail file '%s' (to %s) failed after %d attempts and was renamed to .failed: %v", maskedName, maskedRecipients, attempts, err)
				log.Println(errMsg)
				ipc.SendAudit("ERROR: " + errMsg)
			} else {
				_ = writeAttempts(filePath, attempts)
				warnMsg := fmt.Sprintf("Failed to send mail file '%s' (to %s, attempt %d/%d): %v", maskedName, maskedRecipients, attempts, maxAttempts, err)
				log.Println(warnMsg)
				ipc.SendAudit(warnMsg)
			}
			continue
		}

		removeAttempts(filePath)
		if err := os.Remove(filePath); err != nil {
			errMsg := fmt.Sprintf("Email sent to %s, but failed to delete file '%s': %v", maskedRecipients, maskedName, err)
			log.Println(errMsg)
			ipc.SendAudit("ERROR: " + errMsg)
			stats.Failed++
			continue
		}

		stats.Sent++
		ipc.SendAudit(fmt.Sprintf("Sent email to %s and deleted '%s'", maskedRecipients, maskedName))
	}

	stats.Pending, stats.FailedFiles, stats.OldestPendingAge = inspectOutbox(mailDir, time.Now())
	ipc.SendAudit(fmt.Sprintf("Outbox status for '%s': sent=%d, failed=%d, pending=%d, failed_files=%d, oldest_pending_age=%s",
		mailDir, stats.Sent, stats.Failed, stats.Pending, stats.FailedFiles, stats.OldestPendingAge))

	return stats, nil
}

func fetchCredentialsFromScheduler() (string, string, error) {
	runIDStr := os.Getenv("RUN_ID")
	socketPath := os.Getenv("SCHEDULER_SOCKET_PATH")
	if runIDStr == "" || socketPath == "" {
		return "", "", errors.New("not running under scheduler")
	}

	runID, err := strconv.Atoi(runIDStr)
	if err != nil {
		return "", "", err
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := map[string]any{
		"type":   "get_credentials",
		"run_id": runID,
	}
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return "", "", err
	}

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		var resp struct {
			MasterKey    string `json:"master_key"`
			DBConfigJSON string `json:"db_config_json"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &resp); err == nil {
			return resp.DBConfigJSON, resp.MasterKey, nil
		}
	}
	return "", "", errors.New("no response or invalid JSON from scheduler")
}

func run(ctx context.Context) error {
	if dbCfg, masterKey, err := fetchCredentialsFromScheduler(); err == nil {
		if dbCfg != "" {
			_ = os.Setenv("MITM_DB_CONFIG_JSON", dbCfg)
		}
		if masterKey != "" {
			_ = os.Setenv("MASTER_KEY", masterKey)
		}
	} else if os.Getenv("RUN_ID") != "" && os.Getenv("SCHEDULER_SOCKET_PATH") != "" {
		log.Printf("[IPC Warning] Failed to get credentials from scheduler: %v", err)
	}

	version = strings.Split(version, "-")[0]
	ipc := newIPCClient()
	ipc.SendEvent("started", fmt.Sprintf("%s (%s) started", appName, version), 0)
	ipc.SendAudit(fmt.Sprintf("%s (%s) started", appName, version))

	rawArgs := ""
	if len(os.Args) >= 2 {
		rawArgs = os.Args[1]
	}
	args, err := parseArgs(rawArgs)
	if err != nil {
		return fail(ipc, err)
	}
	if ipc != nil {
		ipc.Topic = args.Topic
		ipc.SourceName = args.SourceName
	}

	targetCfg, configSource, err := loadTargetDBConfig()
	if err != nil {
		return fail(ipc, err)
	}
	ipc.SendAudit("Loaded database configuration from " + configSource)

	kek, err := validateKEK(os.Getenv("MASTER_KEY"))
	if err != nil {
		return fail(ipc, err)
	}

	pool, err := connectTargetDB(ctx, targetCfg)
	if err != nil {
		return fail(ipc, fmt.Errorf("Failed to connect to MitM database: %w", err))
	}
	defer pool.Close()
	ipc.SendEvent("processing", "Connected to MitM database", 20)

	configPayload, credentialsNonce, _, wrappedDEK, err := loadSourceSecrets(ctx, pool, args.SourceName)
	if err != nil {
		return fail(ipc, err)
	}

	dek, err := unwrapDEK(kek, wrappedDEK)
	if err != nil {
		return fail(ipc, errors.New("Failed to decrypt wrapped DEK (KEK mismatch or corrupted key data)"))
	}
	ipc.SendAudit("Decrypted storage DEK using KEK successfully")

	decryptedConfigBytes, err := decryptPayload(dek, credentialsNonce, configPayload)
	if err != nil {
		return fail(ipc, errors.New("Failed to decrypt source config payload using DEK"))
	}
	ipc.SendAudit("Decrypted SMTP connection credentials payload successfully")

	sourceCfg, err := parseSourceConfig(decryptedConfigBytes)
	if err != nil {
		return fail(ipc, err)
	}

	mailDir := resolveMailDir(sourceCfg.WatchDir, args.MailDir)
	ipc.SendEvent("processing", fmt.Sprintf("Scanning mail directory '%s'", mailDir), 50)

	stats, err := processMailDir(ctx, mailDir, args.MailSubject, args.MaxAttempts, sourceCfg, sendEmail, ipc)
	if err != nil {
		return fail(ipc, err)
	}

	ipc.SendEvent("processing", "Completed mail dispatch", 100)
	ipc.SendAudit(fmt.Sprintf("%s (%s) finished", appName, version))
	log.Printf("SendMail finished. Sent %d emails (Failed: %d, Pending: %d, FailedFiles: %d).",
		stats.Sent, stats.Failed, stats.Pending, stats.FailedFiles)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx)
	cancel()
	if err != nil {
		log.Printf("%s failed: %v", appName, err)
		os.Exit(1)
	}
}
