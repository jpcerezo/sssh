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

// RetryLoop implements the main retry strategy:
// for each algo level → for each user → for each key → probe.
// If all keys fail, falls back to interactive password auth.
func RetryLoop(cfg *SSHConfig, host string, users []string, keys []string, extraArgs []string) error {
	attempts := 0
	minAlgoLevel := 0
	// Track best algo level where host was reachable (auth failed, not negotiation).
	bestAlgoLevel := -1
	bestUser := ""
	hadAuthDenied := false

	for _, algoLvl := range AlgoLevels {
		if algoLvl.Level < minAlgoLevel {
			continue
		}

		if algoLvl.Level > 0 {
			logWarn("escalating to algo level %d: %s", algoLvl.Level, algoLvl.Description)
		}

		for _, user := range users {
			for _, key := range keys {
				attempts++
				keyDisplay := key
				if key == "" {
					keyDisplay = "(agent/default)"
				}

				logInfo("attempt %d: user=%s key=%s algo=%d",
					attempts, user, keyDisplay, algoLvl.Level)

				exitCode, stderr := ProbeSSH(host, user, key, cfg.Port, algoLvl, extraArgs)

				if exitCode == 0 {
					// Success — exec interactive session.
					err := ExecSSH(host, user, key, cfg.Port, algoLvl, extraArgs)
					// If we reach here, exec failed.
					return fmt.Errorf("exec failed: %w", err)
				}

				failType, offer := ClassifyFailure(stderr)
				logDebug("probe result: %s (exit=%d)", failType, exitCode)

				switch failType {
				case FailureAuthDenied:
					hadAuthDenied = true
					// Remember this algo level works for connectivity.
					if bestAlgoLevel < algoLvl.Level {
						bestAlgoLevel = algoLvl.Level
						bestUser = user
					} else if bestAlgoLevel == -1 {
						bestAlgoLevel = algoLvl.Level
						bestUser = user
					}
					continue

				case FailureNegotiation:
					// Smart skip: find minimum level that matches offer.
					if offer != "" {
						minLvl := FindMinLevel(offer)
						if minLvl > algoLvl.Level {
							logInfo("their offer: %s → jumping to level %d", offer, minLvl)
							minAlgoLevel = minLvl
						}
					}
					// Break out of user/key loops, go to next algo level.
					goto nextAlgoLevel

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

				default:
					logDebug("unknown failure, stderr: %s", strings.TrimSpace(stderr))
					continue
				}
			}
		}
	nextAlgoLevel:
	}

	// All key-based attempts exhausted.
	if !hadAuthDenied {
		return fmt.Errorf("exhausted %d attempts", attempts)
	}

	algoLvl := AlgoLevels[0]
	if bestAlgoLevel >= 0 && bestAlgoLevel < len(AlgoLevels) {
		algoLvl = AlgoLevels[bestAlgoLevel]
	}

	// Step 1: Try keychain password (non-interactive).
	keychainCreds := KeychainLookupAll(host, cfg.Hostname)
	if keychainCreds.Password != "" {
		// Try keychain user+password first.
		kcUser := keychainCreds.User
		if kcUser == "" && len(users) > 0 {
			kcUser = users[0]
		}

		logInfo("trying keychain password for user=%s", kcUser)
		exitCode, stderr := ProbeSSHWithPassword(host, kcUser, keychainCreds.Password, cfg.Port, algoLvl, extraArgs)

		if exitCode == 0 {
			err := ExecSSHWithPassword(host, kcUser, keychainCreds.Password, cfg.Port, algoLvl, extraArgs)
			return fmt.Errorf("exec failed: %w", err)
		}

		failType, _ := ClassifyFailure(stderr)
		logDebug("keychain password probe: %s", failType)

		// If keychain user differs from candidates, also try each candidate user with keychain password.
		if failType == FailureAuthDenied {
			for _, user := range users {
				if user == kcUser {
					continue
				}
				logInfo("trying keychain password for user=%s", user)
				exitCode, stderr = ProbeSSHWithPassword(host, user, keychainCreds.Password, cfg.Port, algoLvl, extraArgs)
				if exitCode == 0 {
					err := ExecSSHWithPassword(host, user, keychainCreds.Password, cfg.Port, algoLvl, extraArgs)
					return fmt.Errorf("exec failed: %w", err)
				}
				failType, _ = ClassifyFailure(stderr)
				if failType != FailureAuthDenied {
					break
				}
			}
		}
	}

	// Step 2: Fall back to interactive password prompt.
	user := bestUser
	if user == "" && len(users) > 0 {
		user = users[0]
	}

	logWarn("falling back to interactive password auth")
	err := ExecSSH(host, user, "", cfg.Port, algoLvl, extraArgs)
	return fmt.Errorf("exec failed: %w", err)
}
