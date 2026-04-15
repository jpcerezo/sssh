package main

import "strings"

// AlgoLevel defines a set of legacy algorithm overrides to append.
type AlgoLevel struct {
	Level       int
	Description string
	KexAlgos    []string // -oKexAlgorithms=+...
	HostKeyAlgs []string // -oHostKeyAlgorithms=+...
	Ciphers     []string // -oCiphers=+...
	MACs        []string // -oMACs=+...
	PubkeyTypes []string // -oPubkeyAcceptedAlgorithms=+...
}

// AlgoLevels defines escalating algorithm compatibility.
// Level 0 = modern defaults (no overrides).
// Each subsequent level appends weaker algorithms.
var AlgoLevels = []AlgoLevel{
	{
		Level:       0,
		Description: "modern defaults",
	},
	{
		Level:       1,
		Description: "legacy RSA + DH group14",
		KexAlgos:    []string{"diffie-hellman-group14-sha1"},
		HostKeyAlgs: []string{"ssh-rsa"},
		PubkeyTypes: []string{"ssh-rsa"},
	},
	{
		Level:       2,
		Description: "legacy DH group1 + CBC ciphers",
		KexAlgos:    []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"},
		HostKeyAlgs: []string{"ssh-rsa"},
		Ciphers:     []string{"aes128-cbc", "aes256-cbc"},
		PubkeyTypes: []string{"ssh-rsa"},
	},
	{
		Level:       3,
		Description: "max compat (3DES, HMAC-SHA1)",
		KexAlgos:    []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"},
		HostKeyAlgs: []string{"ssh-rsa", "ssh-dss"},
		Ciphers:     []string{"aes128-cbc", "aes256-cbc", "3des-cbc"},
		MACs:        []string{"hmac-sha1", "hmac-sha1-96"},
		PubkeyTypes: []string{"ssh-rsa", "ssh-dss"},
	},
}

// AlgoArgs returns SSH command-line arguments for a given level.
// Uses "+" prefix to append to defaults rather than replace.
func (a AlgoLevel) AlgoArgs() []string {
	var args []string
	if len(a.KexAlgos) > 0 {
		args = append(args, "-oKexAlgorithms=+"+strings.Join(a.KexAlgos, ","))
	}
	if len(a.HostKeyAlgs) > 0 {
		args = append(args, "-oHostKeyAlgorithms=+"+strings.Join(a.HostKeyAlgs, ","))
	}
	if len(a.Ciphers) > 0 {
		args = append(args, "-oCiphers=+"+strings.Join(a.Ciphers, ","))
	}
	if len(a.MACs) > 0 {
		args = append(args, "-oMACs=+"+strings.Join(a.MACs, ","))
	}
	if len(a.PubkeyTypes) > 0 {
		args = append(args, "-oPubkeyAcceptedAlgorithms=+"+strings.Join(a.PubkeyTypes, ","))
	}
	return args
}

// MatchesOffer checks if this algo level adds any algorithm from the "Their offer:" line.
func (a AlgoLevel) MatchesOffer(offer string) bool {
	offer = strings.ToLower(offer)
	for _, algo := range a.KexAlgos {
		if strings.Contains(offer, strings.ToLower(algo)) {
			return true
		}
	}
	for _, algo := range a.HostKeyAlgs {
		if strings.Contains(offer, strings.ToLower(algo)) {
			return true
		}
	}
	for _, algo := range a.Ciphers {
		if strings.Contains(offer, strings.ToLower(algo)) {
			return true
		}
	}
	for _, algo := range a.MACs {
		if strings.Contains(offer, strings.ToLower(algo)) {
			return true
		}
	}
	for _, algo := range a.PubkeyTypes {
		if strings.Contains(offer, strings.ToLower(algo)) {
			return true
		}
	}
	return false
}

// FindMinLevel returns the minimum algo level that includes an algo from the offer.
// Returns -1 if no level matches.
func FindMinLevel(offer string) int {
	for _, lvl := range AlgoLevels {
		if lvl.Level == 0 {
			continue
		}
		if lvl.MatchesOffer(offer) {
			return lvl.Level
		}
	}
	return -1
}
