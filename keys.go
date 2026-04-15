package main

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

// Key type priority: ed25519 > ecdsa > rsa > dsa.
var keyTypePriority = map[string]int{
	"ed25519": 0,
	"ecdsa":   1,
	"rsa":     2,
	"dsa":     3,
}

// DiscoverSSHKeys finds private keys in ~/.ssh/ and returns them sorted by priority.
func DiscoverSSHKeys() []string {
	u, err := user.Current()
	if err != nil {
		return nil
	}

	sshDir := filepath.Join(u.HomeDir, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}

	type keyEntry struct {
		path     string
		priority int
	}

	var keys []keyEntry

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		name := e.Name()

		// Skip public keys, known_hosts, config, etc.
		if strings.HasSuffix(name, ".pub") ||
			name == "known_hosts" ||
			name == "known_hosts.old" ||
			name == "config" ||
			name == "authorized_keys" ||
			name == "environment" ||
			strings.HasPrefix(name, ".") {
			continue
		}

		fullPath := filepath.Join(sshDir, name)

		// Check if file looks like a private key (starts with -----BEGIN).
		if !looksLikePrivateKey(fullPath) {
			continue
		}

		prio := priorityForKeyName(name)
		keys = append(keys, keyEntry{path: fullPath, priority: prio})
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].priority < keys[j].priority
	})

	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = k.path
	}

	logDebug("discovered %d SSH keys in %s", len(result), sshDir)
	return result
}

// priorityForKeyName extracts key type from filename and returns sort priority.
func priorityForKeyName(name string) int {
	lower := strings.ToLower(name)
	for keyType, prio := range keyTypePriority {
		if strings.Contains(lower, keyType) {
			return prio
		}
	}
	// Unknown type gets lowest priority.
	return 99
}

// looksLikePrivateKey checks if the first line of a file looks like a PEM private key header.
func looksLikePrivateKey(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	header := string(buf[:n])
	return strings.Contains(header, "-----BEGIN") ||
		strings.HasPrefix(header, "openssh-key-v1")
}
