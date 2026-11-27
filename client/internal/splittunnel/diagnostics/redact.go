package diagnostics

import (
	"net/netip"
	"regexp"
	"strings"
)

const (
	redactedSecret = "[redacted-secret]"
	redactedPath   = "[redacted-path]"
	redactedIP     = "[redacted-ip]"
	redactedHost   = "[redacted-host]"
)

var (
	pemKeyRE = regexp.MustCompile(
		`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	secretPairRE = regexp.MustCompile(
		`(?i)\b(token|secret|password|passwd|pwd|credential|credentials|authorization|` +
			`api[_-]?key|private[_-]?key|setup[_-]?key|pre[_-]?shared[_-]?key)\b` +
			`(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)`)
	bearerRE = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)

	windowsPathRE = regexp.MustCompile(`[A-Za-z]:\\[^\s"'<>|]+`)
	unixPathRE    = regexp.MustCompile(`(?:/[A-Za-z0-9._@+-]+){2,}`)

	ipv4RE      = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6TokenRE = regexp.MustCompile(`[0-9A-Fa-f:]{2,}`)

	hostnameRE = regexp.MustCompile(
		`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b`)
)

// SecretFieldName reports whether a structured log field name carries a
// credential and must always be masked.
func SecretFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{
		"token", "secret", "password", "passwd", "pwd", "credential",
		"api_key", "api-key", "apikey", "private_key", "private-key",
		"setup_key", "setup-key", "authorization", "auth",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// RedactSecrets removes private keys and inline credential values. It is
// applied at every log level.
func RedactSecrets(text string) string {
	text = pemKeyRE.ReplaceAllString(text, redactedSecret)
	text = bearerRE.ReplaceAllString(text, "Bearer "+redactedSecret)
	text = secretPairRE.ReplaceAllString(text, `$1$2`+redactedSecret)
	return text
}

// RedactText removes secrets, user and executable paths, IP addresses and
// host names. Support bundles always use this full redaction.
func RedactText(text string) string {
	return redact(text, true, true)
}

// RedactLogText removes secrets and paths at every level. IP addresses and host
// names are removed only at INFO and above, so TRACE and DEBUG can still carry
// a peer address for local debugging.
func RedactLogText(level Level, text string) string {
	return redact(text, level >= LevelInfo, true)
}

func redact(text string, includeAddresses, includePaths bool) string {
	text = RedactSecrets(text)
	if includePaths {
		text = windowsPathRE.ReplaceAllString(text, redactedPath)
		text = unixPathRE.ReplaceAllString(text, redactedPath)
	}
	if includeAddresses {
		text = replaceIPv4(text)
		text = replaceIPv6(text)
		text = hostnameRE.ReplaceAllString(text, redactedHost)
	}
	return text
}

// RedactFields returns a redacted copy of structured log fields. A field whose
// name denotes a credential is masked entirely.
func RedactFields(fields map[string]string, includeAddresses bool) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		if SecretFieldName(key) {
			out[key] = redactedSecret
			continue
		}
		out[key] = redact(value, includeAddresses, true)
	}
	return out
}

func replaceIPv4(text string) string {
	return ipv4RE.ReplaceAllStringFunc(text, func(token string) string {
		addr, err := netip.ParseAddr(token)
		if err != nil || !addr.Is4() {
			return token
		}
		return redactedIP
	})
}

func replaceIPv6(text string) string {
	return ipv6TokenRE.ReplaceAllStringFunc(text, func(token string) string {
		addr, err := netip.ParseAddr(token)
		if err != nil || !addr.Is6() {
			return token
		}
		return redactedIP
	})
}

// RedactSnapshot returns a copy with every free-form string sanitized. The
// counters themselves carry no sensitive data.
func RedactSnapshot(snapshot Snapshot) Snapshot {
	redacted := snapshot
	redacted.Traffic = redactTraffic(snapshot.Traffic)
	redacted.DNS.Reason = RedactText(snapshot.DNS.Reason)
	redacted.Apply.LastError = RedactText(snapshot.Apply.LastError)
	redacted.Apply.Reason = RedactText(snapshot.Apply.Reason)
	redacted.Gateway.BackendState = RedactText(snapshot.Gateway.BackendState)
	redacted.Gateway.Reason = RedactText(snapshot.Gateway.Reason)
	redacted.KillSwitch.Mode = RedactText(snapshot.KillSwitch.Mode)
	redacted.KillSwitch.LastEvent = RedactText(snapshot.KillSwitch.LastEvent)
	redacted.KillSwitch.Reason = RedactText(snapshot.KillSwitch.Reason)
	redacted.Connections.Reason = RedactText(snapshot.Connections.Reason)
	redacted.UnavailableMetrics = redactStrings(snapshot.UnavailableMetrics)
	return redacted
}

func redactTraffic(traffic Traffic) Traffic {
	traffic.Incoming.Reason = RedactText(traffic.Incoming.Reason)
	traffic.Outgoing.Reason = RedactText(traffic.Outgoing.Reason)
	traffic.VPN.Reason = RedactText(traffic.VPN.Reason)
	traffic.Direct.Reason = RedactText(traffic.Direct.Reason)
	traffic.Block.Reason = RedactText(traffic.Block.Reason)
	traffic.Exit.Reason = RedactText(traffic.Exit.Reason)
	traffic.RuleHits.Reason = RedactText(traffic.RuleHits.Reason)
	return traffic
}

func redactStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = RedactText(value)
	}
	return out
}
