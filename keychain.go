package main

import (
	"os/exec"
	"strings"
)

// KeychainCreds holds username and password from macOS Keychain.
type KeychainCreds struct {
	User     string
	Password string
}

// KeychainUser queries macOS Keychain for the username associated with a host.
// Uses `security find-internet-password -s <host>` to find stored SSH credentials.
// Returns empty string if not found or on error.
func KeychainUser(host string) string {
	creds := KeychainLookup(host)
	return creds.User
}

// KeychainLookup queries macOS Keychain for user+password for a host.
// Tries exact host first, then resolved hostname.
func KeychainLookup(host string) KeychainCreds {
	creds := keychainQuery(host)
	if creds.User != "" {
		return creds
	}
	return KeychainCreds{}
}

// KeychainLookupAll tries multiple server names and returns first match.
// Useful when host alias differs from resolved hostname.
func KeychainLookupAll(hosts ...string) KeychainCreds {
	for _, h := range hosts {
		if h == "" {
			continue
		}
		creds := keychainQuery(h)
		if creds.User != "" {
			return creds
		}
	}
	return KeychainCreds{}
}

// keychainQuery runs security command for a single server name.
func keychainQuery(server string) KeychainCreds {
	var creds KeychainCreds

	// Get metadata (username, etc.).
	cmd := exec.Command("security", "find-internet-password", "-s", server)
	out, err := cmd.Output()
	if err != nil {
		logDebug("keychain: no entry for %s", server)
		return creds
	}

	// Parse "acct" attribute for username.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `"acct"`) {
			if _, after, ok := strings.Cut(line, `="`); ok {
				creds.User = strings.TrimSuffix(after, `"`)
			}
		}
	}

	if creds.User == "" {
		logDebug("keychain: no acct field for %s", server)
		return creds
	}

	// Get password with -w flag (prints just the password).
	pwCmd := exec.Command("security", "find-internet-password", "-s", server, "-a", creds.User, "-w")
	pwOut, err := pwCmd.Output()
	if err != nil {
		logDebug("keychain: got user=%s but no password for %s", creds.User, server)
		return creds
	}

	creds.Password = strings.TrimSpace(string(pwOut))
	if creds.Password != "" {
		logDebug("keychain: found user=%s with password for %s", creds.User, server)
	}

	return creds
}
