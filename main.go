/**
 * SPDX-FileComment: MitM Maintenance SendMail Job
 * SPDX-FileType: SOURCE
 * SPDX-FileContributor: ZHENG Robert
 * SPDX-FileCopyrightText: 2026 ZHENG Robert
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main.go
 * @brief Scheduled CLI utility that dispatches *.SendMail files via SMTP using credentials decrypted from source_credentials.
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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	appName = "MitM Maintenance SendMail"
	version = "0.1.0"
)

const (
	componentName  = "mitm_maintenance_sendmail"
	defaultSource  = "SENDMAIL_SMTP"
	defaultTopic   = "maintenance.sendmail"
	defaultSubject = "New Message from SendMail"
	defaultPort    = 587
	mailFileSuffix = ".SendMail"
	smtpTimeout    = 30 * time.Second
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

func extractRecipient(fileName string) (string, bool) {
	if !strings.HasSuffix(fileName, mailFileSuffix) {
		return "", false
	}
	recipient := strings.TrimSpace(strings.TrimSuffix(fileName, mailFileSuffix))
	if recipient == "" || !strings.Contains(recipient, "@") {
		return "", false
	}
	return recipient, true
}

func buildMimeMessage(from, to, subject, body string) []byte {
	cleanFrom := sanitizeHeader(from)
	cleanTo := sanitizeHeader(to)
	encodedSubject := mime.QEncoding.Encode("utf-8", sanitizeHeader(subject))

	normalizedBody := strings.ReplaceAll(body, "\r\n", "\n")
	normalizedBody = strings.ReplaceAll(normalizedBody, "\n", "\r\n")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: <%s>\r\n", cleanFrom))
	sb.WriteString(fmt.Sprintf("To: <%s>\r\n", cleanTo))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(normalizedBody)
	if !strings.HasSuffix(normalizedBody, "\r\n") {
		sb.WriteString("\r\n")
	}
	return []byte(sb.String())
}

func sanitizeHeader(val string) string {
	val = strings.ReplaceAll(val, "\r", "")
	val = strings.ReplaceAll(val, "\n", "")
	return strings.TrimSpace(val)
}

func sendEmail(ctx context.Context, cfg SourceConfig, to, subject, body string) error {
	addr := net.JoinHostPort(cfg.SMTPServer, strconv.Itoa(cfg.SMTPPort))
	dialer := &net.Dialer{Timeout: smtpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	client, err := smtp.NewClient(conn, cfg.SMTPServer)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if cfg.SMTPStartTLS {
		tlsCfg := &tls.Config{
			ServerName: cfg.SMTPServer,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
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
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	if err := client.Mail(sanitizeHeader(cfg.SMTPFrom)); err != nil {
		return fmt.Errorf("MAIL FROM rejected: %w", err)
	}
	if err := client.Rcpt(sanitizeHeader(to)); err != nil {
		return fmt.Errorf("RCPT TO rejected: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	msg := buildMimeMessage(cfg.SMTPFrom, to, subject, body)
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("failed to write message body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to finalize message data: %w", err)
	}

	return client.Quit()
}

type mailSenderFunc func(ctx context.Context, cfg SourceConfig, to, subject, body string) error

func processMailDir(ctx context.Context, mailDir, subject string, cfg SourceConfig, sendFn mailSenderFunc, ipc *IPCClient) (int, int, error) {
	info, err := os.Stat(mailDir)
	if err != nil {
		return 0, 0, fmt.Errorf("Mail directory '%s' is not accessible: %w", mailDir, err)
	}
	if !info.IsDir() {
		return 0, 0, fmt.Errorf("Mail path '%s' is not a directory", mailDir)
	}

	entries, err := os.ReadDir(mailDir)
	if err != nil {
		return 0, 0, fmt.Errorf("Failed to read mail directory '%s': %w", mailDir, err)
	}

	var fileNames []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := extractRecipient(entry.Name()); ok {
			fileNames = append(fileNames, entry.Name())
		}
	}
	sort.Strings(fileNames)

	sentCount := 0
	failedCount := 0

	for _, fileName := range fileNames {
		if err := ctx.Err(); err != nil {
			return sentCount, failedCount, err
		}

		recipient, ok := extractRecipient(fileName)
		if !ok {
			continue
		}

		filePath := filepath.Join(mailDir, fileName)
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Failed to read mail file '%s': %v", fileName, err)
			ipc.SendAudit(fmt.Sprintf("Failed to read mail file '%s': %v", fileName, err))
			failedCount++
			continue
		}

		if err := sendFn(ctx, cfg, recipient, subject, string(content)); err != nil {
			log.Printf("Failed to send email for '%s': %v", fileName, err)
			ipc.SendAudit(fmt.Sprintf("Failed to send email to '%s': %v", recipient, err))
			failedCount++
			continue
		}

		if err := os.Remove(filePath); err != nil {
			log.Printf("Email sent to '%s', but failed to delete file '%s': %v", recipient, fileName, err)
			ipc.SendAudit(fmt.Sprintf("Email sent to '%s', but failed to delete file '%s': %v", recipient, fileName, err))
			failedCount++
			continue
		}

		sentCount++
		ipc.SendAudit(fmt.Sprintf("Sent email to '%s' and deleted '%s'", recipient, fileName))
	}

	return sentCount, failedCount, nil
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

	sentCount, failedCount, err := processMailDir(ctx, mailDir, args.MailSubject, sourceCfg, sendEmail, ipc)
	if err != nil {
		return fail(ipc, err)
	}

	ipc.SendEvent("processing", "Completed mail dispatch", 100)
	ipc.SendAudit(fmt.Sprintf("Successfully sent %d emails from '%s' (Failed: %d)", sentCount, mailDir, failedCount))
	ipc.SendAudit(fmt.Sprintf("%s (%s) finished", appName, version))
	log.Printf("SendMail finished. Sent %d emails (Failed: %d).", sentCount, failedCount)
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
