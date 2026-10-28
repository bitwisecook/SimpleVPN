package teleport

import (
	"strings"
	"testing"
)

func TestAppLoggerLevelsAndRedaction(t *testing.T) {
	const secret = "do-not-log-this-token"
	logger, normal := testLogger(t, false)
	logger.Debug("hidden debug event", "value", "hidden")
	logger.Info("session event", "session_token", secret, "public_key", "safe-public-value")

	output := normal.String()
	if strings.Contains(output, "hidden debug event") {
		t.Fatal("normal logger emitted a debug event")
	}
	if strings.Contains(output, secret) {
		t.Fatal("normal logger exposed a sensitive value")
	}
	if !strings.Contains(output, `session_token=`+redactedLogValue) {
		t.Fatalf("normal logger did not redact the token: %q", output)
	}
	if !strings.Contains(output, "safe-public-value") {
		t.Fatalf("normal logger unexpectedly redacted a public value: %q", output)
	}

	debugLogger, debug := testLogger(t, true)
	debugLogger.Debug("visible debug event",
		"credential", secret,
		"stun_secret", secret,
		"private_key", secret,
		"authorization", secret,
	)
	if !strings.Contains(debug.String(), "visible debug event") {
		t.Fatalf("debug logger filtered a debug event: %q", debug.String())
	}
	if strings.Contains(debug.String(), secret) {
		t.Fatal("debug logger exposed a sensitive value")
	}
	if strings.Count(debug.String(), redactedLogValue) != 4 {
		t.Fatalf("debug logger did not redact every sensitive attribute: %q", debug.String())
	}
}
