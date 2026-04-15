package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// FailureType classifies SSH probe failures.
type FailureType int

const (
	FailureNone          FailureType = iota // Success
	FailureAuthDenied                       // Authentication failed (try next key/user)
	FailureNegotiation                      // Algorithm negotiation failed (escalate)
	FailureHostKeyChange                    // Host key mismatch (abort with instruction)
	FailureConnRefused                      // Connection refused (abort)
	FailureTimeout                          // Connection timed out (abort)
	FailureDNS                              // DNS resolution failed (abort)
	FailureUnknown                          // Unknown error
)

func (f FailureType) String() string {
	switch f {
	case FailureNone:
		return "success"
	case FailureAuthDenied:
		return "auth_denied"
	case FailureNegotiation:
		return "negotiation_failed"
	case FailureHostKeyChange:
		return "host_key_changed"
	case FailureConnRefused:
		return "connection_refused"
	case FailureTimeout:
		return "timeout"
	case FailureDNS:
		return "dns_failure"
	default:
		return "unknown"
	}
}

// Retryable returns true if the failure type can be retried with different params.
func (f FailureType) Retryable() bool {
	return f == FailureAuthDenied || f == FailureNegotiation
}

// ClassifyFailure determines the failure type from SSH stderr output.
func ClassifyFailure(stderr string) (FailureType, string) {
	s := strings.ToLower(stderr)

	// Host key changed — abort with clear instruction.
	if strings.Contains(s, "host key verification failed") ||
		strings.Contains(s, "warning: remote host identification has changed") ||
		strings.Contains(s, "offending") {
		return FailureHostKeyChange, extractOffer(stderr)
	}

	// Algorithm negotiation failure.
	if strings.Contains(s, "no matching") &&
		(strings.Contains(s, "key exchange method") ||
			strings.Contains(s, "host key type") ||
			strings.Contains(s, "cipher") ||
			strings.Contains(s, "mac")) {
		return FailureNegotiation, extractOffer(stderr)
	}

	// Auth denied.
	if strings.Contains(s, "permission denied") ||
		strings.Contains(s, "authentication failed") ||
		strings.Contains(s, "no more authentication methods") ||
		strings.Contains(s, "too many authentication failures") {
		return FailureAuthDenied, ""
	}

	// Connection refused.
	if strings.Contains(s, "connection refused") {
		return FailureConnRefused, ""
	}

	// Timeout.
	if strings.Contains(s, "connection timed out") ||
		strings.Contains(s, "operation timed out") {
		return FailureTimeout, ""
	}

	// DNS.
	if strings.Contains(s, "could not resolve hostname") ||
		strings.Contains(s, "name or service not known") ||
		strings.Contains(s, "nodename nor servname") {
		return FailureDNS, ""
	}

	return FailureUnknown, ""
}

// extractOffer pulls the "Their offer:" line from SSH stderr.
func extractOffer(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "their offer:") {
			if _, after, ok := strings.Cut(lower, "their offer:"); ok {
				return strings.TrimSpace(after)
			}
		}
	}
	return ""
}

// ProbeSSHWithPassword runs SSH probe using SSH_ASKPASS to supply password.
// Returns exit code 0 on success, non-zero on failure, plus stderr.
func ProbeSSHWithPassword(host, user, password string, port string, algoLevel AlgoLevel, extraArgs []string) (int, string) {
	args := buildSSHArgs(host, user, "", port, algoLevel, extraArgs)

	probeArgs := []string{
		"-oConnectTimeout=10",
		"-oStrictHostKeyChecking=accept-new",
		"-oNumberOfPasswordPrompts=1",
		"-oPubkeyAuthentication=no",
		"-oPreferredAuthentications=password,keyboard-interactive",
	}
	allArgs := append(probeArgs, args...)
	allArgs = append(allArgs, "exit", "0")

	logDebug("probe (password): ssh %s", strings.Join(allArgs, " "))

	// Create temp askpass script that echoes the password.
	askpass, err := os.CreateTemp("", "sssh-askpass-*")
	if err != nil {
		return 1, fmt.Sprintf("failed to create askpass: %v", err)
	}
	askpassPath := askpass.Name()
	defer os.Remove(askpassPath)

	fmt.Fprintf(askpass, "#!/bin/sh\necho '%s'\n", strings.ReplaceAll(password, "'", "'\\''"))
	askpass.Close()
	os.Chmod(askpassPath, 0700)

	cmd := exec.Command("ssh", allArgs...)
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+askpassPath,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=:0",
	)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	cmd.Stdout = nil
	// Must NOT attach stdin — SSH_ASKPASS only works without tty.
	cmd.Stdin = nil

	err = cmd.Run()
	stderrStr := stderrBuf.String()

	if err == nil {
		return 0, stderrStr
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stderrStr
	}
	return 1, stderrStr
}

// ExecSSHWithPassword replaces process with SSH, using SSH_ASKPASS for password.
func ExecSSHWithPassword(host, user, password string, port string, algoLevel AlgoLevel, extraArgs []string) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}

	// Create askpass script.
	askpass, err := os.CreateTemp("", "sssh-askpass-*")
	if err != nil {
		return fmt.Errorf("failed to create askpass: %w", err)
	}
	askpassPath := askpass.Name()
	// Note: can't defer Remove here — syscall.Exec replaces process.
	// Script in /tmp will be cleaned by OS eventually.

	fmt.Fprintf(askpass, "#!/bin/sh\necho '%s'\n", strings.ReplaceAll(password, "'", "'\\''"))
	askpass.Close()
	os.Chmod(askpassPath, 0700)

	args := buildSSHArgs(host, user, "", port, algoLevel, extraArgs)
	fullArgs := append([]string{"ssh"}, args...)

	env := append(os.Environ(),
		"SSH_ASKPASS="+askpassPath,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=:0",
	)

	logSuccess("connecting (keychain password): ssh %s", strings.Join(args, " "))

	return syscall.Exec(sshPath, fullArgs, env)
}

// ProbeSSH runs a non-interactive SSH probe to test connectivity.
// Returns exit code 0 on success, non-zero on failure, plus stderr.
func ProbeSSH(host, user, key string, port string, algoLevel AlgoLevel, extraArgs []string) (int, string) {
	args := buildSSHArgs(host, user, key, port, algoLevel, extraArgs)

	// Add probe-specific options.
	probeArgs := []string{
		"-oBatchMode=yes",
		"-oConnectTimeout=10",
		"-oStrictHostKeyChecking=accept-new",
		"-oNumberOfPasswordPrompts=0",
	}
	// Probe command: just exit immediately.
	allArgs := append(probeArgs, args...)
	allArgs = append(allArgs, "exit", "0")

	logDebug("probe: ssh %s", strings.Join(allArgs, " "))

	cmd := exec.Command("ssh", allArgs...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	cmd.Stdout = nil
	cmd.Stdin = nil

	err := cmd.Run()
	stderrStr := stderrBuf.String()

	if err == nil {
		return 0, stderrStr
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stderrStr
	}
	return 1, stderrStr
}

// ExecSSH replaces the current process with an interactive SSH session.
// This never returns on success (syscall.Exec replaces the process).
func ExecSSH(host, user, key string, port string, algoLevel AlgoLevel, extraArgs []string) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}

	args := buildSSHArgs(host, user, key, port, algoLevel, extraArgs)
	// syscall.Exec argv[0] = program name.
	fullArgs := append([]string{"ssh"}, args...)

	logSuccess("connecting: ssh %s", strings.Join(args, " "))

	return syscall.Exec(sshPath, fullArgs, os.Environ())
}

// buildSSHArgs constructs the SSH argument list.
func buildSSHArgs(host, user, key string, port string, algoLevel AlgoLevel, extraArgs []string) []string {
	var args []string

	if user != "" {
		args = append(args, "-l", user)
	}
	if key != "" {
		args = append(args, "-i", key)
	}
	if port != "" && port != "22" {
		args = append(args, "-p", port)
	}

	// Add algorithm overrides for this level.
	args = append(args, algoLevel.AlgoArgs()...)

	// Add any extra args the user passed.
	args = append(args, extraArgs...)

	// Host is always last.
	args = append(args, host)

	return args
}

// RetryLoop implements the main retry strategy.
// Order: keychain password → SSH keys → interactive password fallback.
// Each phase escalates through algo levels on negotiation failure.
func RetryLoop(cfg *SSHConfig, host string, users []string, keys []string, extraArgs []string) error {
	attempts := 0

	// ── Phase 1: Keychain password (fastest path) ──
	keychainCreds := KeychainLookupAll(host, cfg.Hostname)
	if keychainCreds.Password != "" {
		logVerbose("phase 1: trying keychain passwords")

		// Build user list for password: keychain user first, then candidates.
		pwUsers := []string{}
		if keychainCreds.User != "" {
			pwUsers = append(pwUsers, keychainCreds.User)
		}
		for _, u := range users {
			if u != keychainCreds.User {
				pwUsers = append(pwUsers, u)
			}
		}

		for _, algoLvl := range AlgoLevels {
			if algoLvl.Level > 0 {
				logVerbose("password: escalating to algo level %d: %s", algoLvl.Level, algoLvl.Description)
			}

			for _, user := range pwUsers {
				attempts++
				logVerbose("attempt %d: user=%s (keychain password) algo=%d", attempts, user, algoLvl.Level)

				exitCode, stderr := ProbeSSHWithPassword(host, user, keychainCreds.Password, cfg.Port, algoLvl, extraArgs)

				if exitCode == 0 {
					err := ExecSSHWithPassword(host, user, keychainCreds.Password, cfg.Port, algoLvl, extraArgs)
					return fmt.Errorf("exec failed: %w", err)
				}

				failType, offer := ClassifyFailure(stderr)
				logDebug("probe result: %s (exit=%d)", failType, exitCode)

				if err := handleFatalFailure(failType, offer, host, cfg); err != nil {
					return err
				}
				if failType == FailureNegotiation {
					break // next algo level
				}
				// FailureAuthDenied → next user
			}
		}
		logVerbose("keychain passwords exhausted, trying keys")
	}

	// ── Phase 2: SSH key rotation ──
	logVerbose("phase 2: trying SSH keys")
	minAlgoLevel := 0
	bestAlgoLevel := -1
	bestUser := ""
	hadAuthDenied := false

	for _, algoLvl := range AlgoLevels {
		if algoLvl.Level < minAlgoLevel {
			continue
		}

		if algoLvl.Level > 0 {
			logVerbose("keys: escalating to algo level %d: %s", algoLvl.Level, algoLvl.Description)
		}

		for _, user := range users {
			for _, key := range keys {
				attempts++
				keyDisplay := key
				if key == "" {
					keyDisplay = "(agent/default)"
				}

				logVerbose("attempt %d: user=%s key=%s algo=%d",
					attempts, user, keyDisplay, algoLvl.Level)

				exitCode, stderr := ProbeSSH(host, user, key, cfg.Port, algoLvl, extraArgs)

				if exitCode == 0 {
					err := ExecSSH(host, user, key, cfg.Port, algoLvl, extraArgs)
					return fmt.Errorf("exec failed: %w", err)
				}

				failType, offer := ClassifyFailure(stderr)
				logDebug("probe result: %s (exit=%d)", failType, exitCode)

				if err := handleFatalFailure(failType, offer, host, cfg); err != nil {
					return err
				}

				switch failType {
				case FailureAuthDenied:
					hadAuthDenied = true
					if bestAlgoLevel < algoLvl.Level {
						bestAlgoLevel = algoLvl.Level
						bestUser = user
					}
					continue
				case FailureNegotiation:
					if offer != "" {
						minLvl := FindMinLevel(offer)
						if minLvl > algoLvl.Level {
							logVerbose("their offer: %s → jumping to level %d", offer, minLvl)
							minAlgoLevel = minLvl
						}
					}
					goto nextAlgoLevel
				default:
					continue
				}
			}
		}
	nextAlgoLevel:
	}

	// ── Phase 3: Interactive password fallback ──
	if hadAuthDenied {
		algoLvl := AlgoLevels[0]
		if bestAlgoLevel >= 0 && bestAlgoLevel < len(AlgoLevels) {
			algoLvl = AlgoLevels[bestAlgoLevel]
		}
		user := bestUser
		if user == "" && len(users) > 0 {
			user = users[0]
		}

		logWarn("phase 3: falling back to interactive password")
		err := ExecSSH(host, user, "", cfg.Port, algoLvl, extraArgs)
		return fmt.Errorf("exec failed: %w", err)
	}

	return fmt.Errorf("exhausted %d attempts", attempts)
}

// handleFatalFailure checks for non-retryable failures and returns error if fatal.
func handleFatalFailure(failType FailureType, offer, host string, cfg *SSHConfig) error {
	switch failType {
	case FailureHostKeyChange:
		logError("HOST KEY CHANGED for %s", host)
		logError("run: ssh-keygen -R %s", cfg.Hostname)
		if cfg.Hostname != host {
			logError("also try: ssh-keygen -R %s", host)
		}
		return fmt.Errorf("host key verification failed")
	case FailureConnRefused:
		logError("connection refused by %s", host)
		return fmt.Errorf("connection refused")
	case FailureTimeout:
		logError("connection timed out for %s", host)
		return fmt.Errorf("connection timed out")
	case FailureDNS:
		logError("cannot resolve %s", host)
		return fmt.Errorf("DNS resolution failed")
	}
	return nil
}
