package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var (
	debugMode   bool
	verboseMode bool
	version     = "dev"
)

// Known domain suffixes to try when bare hostname has no dots.
var domainSuffixes = []string{
	".inetlabs",
	".de-cix.management",
	".de-cix.net",
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printUsage()
		os.Exit(0)
	}

	if args[0] == "--version" || args[0] == "-V" {
		fmt.Fprintf(os.Stderr, "sssh %s\n", version)
		os.Exit(0)
	}

	// Extract sssh-specific flags before passing rest to SSH.
	var sshArgs []string
	var target string
	explicitUser := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debugMode = true
			verboseMode = true
		case "-v", "--verbose":
			verboseMode = true
		case "-l":
			// User explicitly passed -l user — respect it.
			if i+1 < len(args) {
				explicitUser = args[i+1]
				sshArgs = append(sshArgs, args[i], args[i+1])
				i++
			}
		default:
			sshArgs = append(sshArgs, args[i])
			// First non-flag arg is the target host.
			if target == "" && !strings.HasPrefix(args[i], "-") {
				target = args[i]
			}
		}
	}

	if target == "" {
		logError("no target host specified")
		os.Exit(1)
	}

	// Handle user@host syntax.
	if parts := strings.SplitN(target, "@", 2); len(parts) == 2 {
		explicitUser = parts[0]
		target = parts[1]
	}

	// If bare hostname (no dots), try domain suffixes to find reachable host.
	target = resolveWithDomainSuffix(target)

	logVerbose("resolving config for %s", target)

	cfg, err := ResolveSSHConfig(target)
	if err != nil {
		logError("ssh -G failed: %v", err)
		os.Exit(1)
	}

	logDebug("resolved: hostname=%s user=%s port=%s keys=%v",
		cfg.Hostname, cfg.User, cfg.Port, cfg.IdentityFile)

	// Build user candidates.
	userCandidates := buildUserCandidates(target, explicitUser, cfg)

	logDebug("user candidates: %v", userCandidates)

	// Build key candidates.
	configKeys := cfg.IdentityFile
	discoveredKeys := DiscoverSSHKeys()
	keyCandidates := deduplicateKeys(configKeys, discoveredKeys)

	logDebug("key candidates: %d keys", len(keyCandidates))

	// Filter sshArgs to remove the target (we'll add it back in probe/exec).
	var extraArgs []string
	targetFound := false
	for _, a := range sshArgs {
		if !targetFound && a == target || a == explicitUser+"@"+target {
			targetFound = true
			continue
		}
		extraArgs = append(extraArgs, a)
	}

	// Run retry loop.
	result := RetryLoop(cfg, target, userCandidates, keyCandidates, extraArgs)

	if result != nil {
		logError("all attempts failed: %v", result)
		os.Exit(1)
	}
	// If RetryLoop succeeded, ExecSSH replaced the process. We never reach here.
}

// buildUserCandidates returns ordered list of usernames to try.
func buildUserCandidates(host, explicitUser string, cfg *SSHConfig) []string {
	// If user explicitly passed -l or user@host, only use that.
	if explicitUser != "" {
		return []string{explicitUser}
	}

	var candidates []string
	seen := make(map[string]bool)

	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			candidates = append(candidates, u)
		}
	}

	// 1. User from SSH config (if explicitly set for this host).
	isExplicit, configUser := IsExplicitUser(host)
	if isExplicit {
		add(configUser)
	}

	// 2. Keychain user.
	keychainUser := KeychainUser(host)
	add(keychainUser)

	// 3. Default config user (even if from Host *).
	add(configUser)

	// 4. Current OS user.
	add(CurrentUser())

	return candidates
}

// deduplicateKeys merges config keys and discovered keys, config first.
func deduplicateKeys(configKeys, discoveredKeys []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, k := range configKeys {
		if !seen[k] {
			seen[k] = true
			result = append(result, k)
		}
	}
	for _, k := range discoveredKeys {
		if !seen[k] {
			seen[k] = true
			result = append(result, k)
		}
	}

	// Always include empty string = let SSH use agent/defaults.
	result = append(result, "")
	return result
}

// resolveWithDomainSuffix tries appending known domain suffixes to a bare hostname.
// Returns the first FQDN that resolves via DNS, or the original hostname if none match.
func resolveWithDomainSuffix(host string) string {
	// If host already has dots, it's already qualified — skip.
	if strings.Contains(host, ".") {
		return host
	}

	// Check if bare hostname resolves in SSH config (hostname differs from input).
	cfg, err := ResolveSSHConfig(host)
	if err == nil && cfg.Hostname != host {
		logDebug("bare host %s resolves to %s via ssh config", host, cfg.Hostname)
		return host
	}

	// Try each domain suffix.
	for _, suffix := range domainSuffixes {
		candidate := host + suffix
		logDebug("trying domain suffix: %s", candidate)
		if dnsResolves(candidate) {
			logInfo("resolved %s → %s", host, candidate)
			return candidate
		}
	}

	logDebug("no domain suffix matched for %s, using as-is", host)
	return host
}

// dnsResolves checks if a hostname resolves via DNS.
func dnsResolves(host string) bool {
	cmd := exec.Command("host", "-W", "2", host)
	err := cmd.Run()
	return err == nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `sssh %s — Smart SSH Wrapper

Usage: sssh [--debug] [ssh-options] <host>

Auth order:
  1. Keychain password (for each user candidate)
  2. SSH key rotation (ed25519 → ecdsa → rsa → dsa → agent)
  3. Interactive password prompt

Domain suffix discovery:
  Bare hostnames (no dots) are tried with:
    .inetlabs  .de-cix.management  .de-cix.net

Options:
  -v          Show per-attempt details
  --debug     Show full debug output (implies -v)
  --version   Show version
  --help      Show this help

All other options are passed through to ssh.

Examples:
  sssh proxmox           Connect to known host
  sssh root@192.168.1.1  Explicit user
  sssh --debug router1   Debug connection issues
  sssh mydevice          Tries mydevice.inetlabs, etc.
`, version)
}
