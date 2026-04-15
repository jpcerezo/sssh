package main

import (
	"bufio"
	"bytes"
	"os/exec"
	"os/user"
	"strings"
)

// SSHConfig holds resolved SSH config for a host.
type SSHConfig struct {
	Hostname     string
	User         string
	Port         string
	IdentityFile []string
	ProxyJump    string
	RawOptions   map[string]string
}

// ResolveSSHConfig runs `ssh -G <host>` and parses the output.
// This leverages OpenSSH's own config parser — handles wildcards, Include, Match, etc.
func ResolveSSHConfig(host string) (*SSHConfig, error) {
	cmd := exec.Command("ssh", "-G", host)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseSSHGOutput(out), nil
}

func parseSSHGOutput(data []byte) *SSHConfig {
	cfg := &SSHConfig{
		RawOptions: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		switch key {
		case "hostname":
			cfg.Hostname = value
		case "user":
			cfg.User = value
		case "port":
			cfg.Port = value
		case "identityfile":
			cfg.IdentityFile = append(cfg.IdentityFile, expandTilde(value))
		case "proxyjump":
			cfg.ProxyJump = value
		default:
			cfg.RawOptions[key] = value
		}
	}
	return cfg
}

// IsExplicitUser checks if the User was explicitly set for this host,
// not inherited from `Host *` defaults.
// Method: compare `ssh -G <host>` vs `ssh -G _sssh_dummy_probe_host_`.
// If User differs, it was explicitly set for this host.
func IsExplicitUser(host string) (bool, string) {
	hostCfg, err := ResolveSSHConfig(host)
	if err != nil {
		return false, ""
	}

	dummyCfg, err := ResolveSSHConfig("_sssh_dummy_probe_host_")
	if err != nil {
		return false, hostCfg.User
	}

	if hostCfg.User != dummyCfg.User {
		return true, hostCfg.User
	}
	return false, hostCfg.User
}

// CurrentUser returns the current OS username.
func CurrentUser() string {
	u, err := user.Current()
	if err != nil {
		return "root"
	}
	return u.Username
}

// expandTilde replaces leading ~ with the user's home directory.
func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	u, err := user.Current()
	if err != nil {
		return path
	}
	return u.HomeDir + path[1:]
}
