package main

import (
	"testing"
)

func TestClassifyFailure_AuthDenied(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
	}{
		{"permission denied", "user@host: Permission denied (publickey,keyboard-interactive)."},
		{"too many failures", "Received disconnect from 192.168.1.1: Too many authentication failures"},
		{"no more methods", "user@host: No more authentication methods to try."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ft, _ := ClassifyFailure(tc.stderr)
			if ft != FailureAuthDenied {
				t.Errorf("got %s, want auth_denied", ft)
			}
		})
	}
}

func TestClassifyFailure_Negotiation(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		offer  string
	}{
		{
			"kex",
			"Unable to negotiate with 192.168.1.180 port 22: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
			"diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
		},
		{
			"host key",
			"Unable to negotiate with 192.168.1.180 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss",
			"ssh-rsa,ssh-dss",
		},
		{
			"cipher",
			"Unable to negotiate with 10.0.0.1: no matching cipher found. Their offer: aes128-cbc,3des-cbc",
			"aes128-cbc,3des-cbc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ft, offer := ClassifyFailure(tc.stderr)
			if ft != FailureNegotiation {
				t.Errorf("got %s, want negotiation_failed", ft)
			}
			if offer != tc.offer {
				t.Errorf("offer = %q, want %q", offer, tc.offer)
			}
		})
	}
}

func TestClassifyFailure_HostKeyChanged(t *testing.T) {
	stderr := `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Offending ECDSA key in /Users/user/.ssh/known_hosts:42
Host key verification failed.`

	ft, _ := ClassifyFailure(stderr)
	if ft != FailureHostKeyChange {
		t.Errorf("got %s, want host_key_changed", ft)
	}
}

func TestClassifyFailure_ConnRefused(t *testing.T) {
	ft, _ := ClassifyFailure("ssh: connect to host 192.168.1.1 port 22: Connection refused")
	if ft != FailureConnRefused {
		t.Errorf("got %s, want connection_refused", ft)
	}
}

func TestClassifyFailure_Timeout(t *testing.T) {
	ft, _ := ClassifyFailure("ssh: connect to host 10.0.0.1 port 22: Operation timed out")
	if ft != FailureTimeout {
		t.Errorf("got %s, want timeout", ft)
	}
}

func TestClassifyFailure_DNS(t *testing.T) {
	cases := []string{
		"ssh: Could not resolve hostname badhost: nodename nor servname provided",
		"ssh: Could not resolve hostname badhost: Name or service not known",
	}
	for _, stderr := range cases {
		ft, _ := ClassifyFailure(stderr)
		if ft != FailureDNS {
			t.Errorf("got %s for %q, want dns_failure", ft, stderr)
		}
	}
}

func TestExtractOffer(t *testing.T) {
	stderr := "Unable to negotiate with 192.168.1.180: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\n"
	offer := extractOffer(stderr)
	want := "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
	if offer != want {
		t.Errorf("offer = %q, want %q", offer, want)
	}
}

func TestExtractOffer_NoOffer(t *testing.T) {
	offer := extractOffer("Permission denied (publickey).")
	if offer != "" {
		t.Errorf("offer = %q, want empty", offer)
	}
}

func TestAlgoLevel_MatchesOffer(t *testing.T) {
	lvl1 := AlgoLevels[1]
	lvl2 := AlgoLevels[2]
	lvl3 := AlgoLevels[3]

	// Level 1 should match ssh-rsa offer.
	if !lvl1.MatchesOffer("ssh-rsa,ssh-ed25519") {
		t.Error("level 1 should match ssh-rsa")
	}

	// Level 1 should not match 3des-cbc.
	if lvl1.MatchesOffer("3des-cbc") {
		t.Error("level 1 should not match 3des-cbc")
	}

	// Level 2 should match aes128-cbc.
	if !lvl2.MatchesOffer("aes128-cbc,aes256-cbc") {
		t.Error("level 2 should match aes128-cbc")
	}

	// Level 3 should match 3des-cbc.
	if !lvl3.MatchesOffer("3des-cbc") {
		t.Error("level 3 should match 3des-cbc")
	}
}

func TestFindMinLevel(t *testing.T) {
	cases := []struct {
		offer string
		want  int
	}{
		{"diffie-hellman-group14-sha1", 1},
		{"ssh-rsa", 1},
		{"aes128-cbc", 2},
		{"3des-cbc", 3},
		{"chacha20-poly1305@openssh.com", -1}, // modern, no match
	}
	for _, tc := range cases {
		got := FindMinLevel(tc.offer)
		if got != tc.want {
			t.Errorf("FindMinLevel(%q) = %d, want %d", tc.offer, got, tc.want)
		}
	}
}

func TestAlgoLevel_AlgoArgs(t *testing.T) {
	lvl0 := AlgoLevels[0]
	if args := lvl0.AlgoArgs(); len(args) != 0 {
		t.Errorf("level 0 should have no args, got %v", args)
	}

	lvl1 := AlgoLevels[1]
	args := lvl1.AlgoArgs()
	if len(args) == 0 {
		t.Fatal("level 1 should have args")
	}
	// Check that args use + prefix.
	for _, a := range args {
		if a[0] != '-' {
			t.Errorf("arg should start with -, got %q", a)
		}
		// All should contain =+
		found := false
		for i := range a {
			if a[i] == '=' && i+1 < len(a) && a[i+1] == '+' {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("arg should contain =+, got %q", a)
		}
	}
}

func TestKeyPriority(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{"id_ed25519", 0},
		{"id_ecdsa", 1},
		{"id_rsa", 2},
		{"id_dsa", 3},
		{"id_custom", 99},
	}
	for _, tc := range cases {
		got := priorityForKeyName(tc.name)
		if got != tc.want {
			t.Errorf("priorityForKeyName(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestParseSSHGOutput(t *testing.T) {
	input := []byte(`user root
hostname 192.168.1.120
port 22
identityfile ~/.ssh/id_ed25519
identityfile ~/.ssh/id_rsa
proxyjump none
`)
	cfg := parseSSHGOutput(input)

	if cfg.User != "root" {
		t.Errorf("User = %q, want root", cfg.User)
	}
	if cfg.Hostname != "192.168.1.120" {
		t.Errorf("Hostname = %q, want 192.168.1.120", cfg.Hostname)
	}
	if cfg.Port != "22" {
		t.Errorf("Port = %q, want 22", cfg.Port)
	}
	if len(cfg.IdentityFile) != 2 {
		t.Errorf("IdentityFile count = %d, want 2", len(cfg.IdentityFile))
	}
	if cfg.ProxyJump != "none" {
		t.Errorf("ProxyJump = %q, want none", cfg.ProxyJump)
	}
}

func TestDeduplicateKeys(t *testing.T) {
	config := []string{"/home/user/.ssh/id_ed25519", "/home/user/.ssh/id_rsa"}
	discovered := []string{"/home/user/.ssh/id_rsa", "/home/user/.ssh/id_ecdsa"}

	result := deduplicateKeys(config, discovered)
	// Should be: id_ed25519, id_rsa, id_ecdsa, "" (empty for agent)
	if len(result) != 4 {
		t.Errorf("got %d keys, want 4: %v", len(result), result)
	}
	if result[0] != "/home/user/.ssh/id_ed25519" {
		t.Errorf("first key = %q, want id_ed25519", result[0])
	}
	if result[len(result)-1] != "" {
		t.Error("last entry should be empty string (agent default)")
	}
}

func TestFailureType_Retryable(t *testing.T) {
	retryable := []FailureType{FailureAuthDenied, FailureNegotiation}
	notRetryable := []FailureType{FailureHostKeyChange, FailureConnRefused, FailureTimeout, FailureDNS, FailureUnknown}

	for _, ft := range retryable {
		if !ft.Retryable() {
			t.Errorf("%s should be retryable", ft)
		}
	}
	for _, ft := range notRetryable {
		if ft.Retryable() {
			t.Errorf("%s should not be retryable", ft)
		}
	}
}
