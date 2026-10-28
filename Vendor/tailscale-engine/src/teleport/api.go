package teleport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const apiBase = "https://cloudaccess.svc.ui.com/teleport"

var salt = []byte("52D1FCE0AE4E5E5C8EF15BAE64A0FA570257BD6F48C7F9CD3FC82A26DB5E2976496A27971D7C23C6E6628E712C4E944BBD6DB79AACBA2369D31EB6438AD422FA")

type apiEnvelope struct {
	Token   string      `json:"token"`
	Payload interface{} `json:"payload"`
}

type apiResponse struct {
	TeleportRequestID string      `json:"teleportRequestId"`
	ResponseType      string      `json:"response_type"`
	Token             string      `json:"token"`
	Secret            string      `json:"secret"`
	IceConfiguration  []iceServer `json:"ice_configuration"`
	ServerInfo        serverInfo  `json:"server_info"`
	ClientIP          string      `json:"client_ip"`
	DNSAddrs          []string    `json:"dns_addrs"`
	ConnectionState   any         `json:"connectionStateData"`
	Metadata          any         `json:"metadata"`
	StatusCode        int         `json:"status_code,omitempty"`
}

type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type serverInfo struct {
	PeerDesc    peerDesc `json:"peer_desc"`
	WGPubKey    string   `json:"wg_pub_key"`
	UDPEchoPort int      `json:"udp_echo_port"`
	UDPEchoAddr string   `json:"udp_echo_addr"`
	TunnelMask  int      `json:"tunnel_mask"`
	TunnelAddr  string   `json:"tunnel_addr"`
}

type metadataResponse struct {
	ConnectionStateData struct {
		DeviceID                 string `json:"deviceId"`
		LastStateChangeTimestamp int64  `json:"lastStateChangeTimestamp"`
		State                    string `json:"state"`
	} `json:"connectionStateData"`
	Metadata struct {
		ConsoleDeviceIconId        string `json:"consoleDeviceIconId"`
		ConsoleFingerprintEngineId int    `json:"consoleFingerprintEngineId"`
		ConsoleType                string `json:"consoleType"`
		ConsoleUidbIconId          string `json:"consoleUidbIconId"`
		LocalNetworkName           string `json:"localNetworkName"`
		Location                   struct {
			Lat    string `json:"lat"`
			Long   string `json:"long"`
			Radius int    `json:"radius"`
			Text   string `json:"text"`
		} `json:"location"`
		Name  string `json:"name"`
		Owner struct {
			FirstName string `json:"first_name"`
			FullName  string `json:"full_name"`
			LastName  string `json:"last_name"`
		} `json:"owner"`
		WanIP string `json:"wanIp"`
	} `json:"metadata"`
}

func secretToToken(secret string) (string, error) {
	dk, err := scrypt.Key([]byte(secret), salt, 16384, 8, 1, 64)
	if err != nil {
		return "", err
	}
	h := sha512.Sum512(dk)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(h[:]), "="), nil
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func normalizeInviteSecret(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "teleport.ui.link") || u.User != nil {
			return "", errors.New("--invite URL must be a https://teleport.ui.link/<UUID> invite")
		}
		value = strings.Trim(u.EscapedPath(), "/")
		if strings.Contains(value, "/") || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("--invite URL must contain exactly one UUID path component")
		}
	}
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", errors.New("--invite must be a UUID or https://teleport.ui.link/<UUID>")
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", errors.New("--invite must be a UUID or https://teleport.ui.link/<UUID>")
		}
	}
	return strings.ToLower(value), nil
}

func fetchMetadataContext(ctx context.Context, token string) (*metadataResponse, error) {
	started := time.Now()
	appLog.Debug("API request", "method", http.MethodGet, "path", "/metadata")
	urlStr := apiBase + "/metadata?token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("api GET /metadata request canceled: %w", ctxErr)
		}
		return nil, fmt.Errorf("api GET /metadata request failed: %s", redactAPIError(err, token))
	}
	defer resp.Body.Close()
	appLog.Debug("API response", "method", http.MethodGet, "path", "/metadata", "status", resp.StatusCode, "duration", time.Since(started).Round(time.Millisecond))
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		debugAPIErrorResponse(appLog, http.MethodGet, "/metadata", data, token)
		return nil, fmt.Errorf("api GET /metadata: %s (response body omitted)", resp.Status)
	}
	var out metadataResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StatusCode is 0 for a network-level failure with no response.
type apiError struct {
	StatusCode int
	err        error
}

func (e *apiError) Error() string { return e.err.Error() }
func (e *apiError) Unwrap() error { return e.err }

func (e *apiError) transient() bool {
	return e.StatusCode == 0 || e.StatusCode >= 500 || e.StatusCode == http.StatusTooManyRequests
}

func isTransientAPIError(err error) bool {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return apiErr.transient()
	}
	return false
}

func apiRequestContext(ctx context.Context, baseURL, method, path, token string, body interface{}) (*apiResponse, error) {
	started := time.Now()
	appLog.Debug("API request", "method", method, "path", path, "authenticated", token != "", "has_body", body != nil)
	reqURL := baseURL + path
	if token != "" {
		sep := "?"
		if strings.Contains(reqURL, "?") {
			sep = "&"
		}
		reqURL += sep + "token=" + url.QueryEscape(token)
	}

	var rdr io.Reader
	var reqBody []byte
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = buf
		rdr = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &apiError{err: fmt.Errorf("api %s %s request canceled: %w", method, path, ctxErr)}
		}
		return nil, &apiError{err: fmt.Errorf("api %s %s request failed: %s", method, path, redactAPIError(err, token))}
	}
	defer resp.Body.Close()
	appLog.Debug("API response", "method", method, "path", path, "status", resp.StatusCode, "duration", time.Since(started).Round(time.Millisecond))
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if resp.StatusCode >= 400 {
		knownSecrets := append([]string{token}, collectSensitiveStrings(reqBody)...)
		debugAPIErrorResponse(appLog, method, path, data, knownSecrets...)
		return nil, &apiError{StatusCode: resp.StatusCode, err: fmt.Errorf("api %s %s: %s (response body omitted)", method, path, resp.Status)}
	}
	if resp.StatusCode == http.StatusAccepted || len(data) == 0 {
		return &apiResponse{StatusCode: resp.StatusCode}, nil
	}
	var out apiResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	appLog.Debug("API response decoded", "method", method, "path", path, "response_type", out.ResponseType)
	return &out, nil
}

// maxConsecutivePollErrors caps retries of transient failures before giving up.
const maxConsecutivePollErrors = 5

// apiRequestFunc adapts apiRequestContext to a fixed context and base URL for injection into pollForResponseWithContext.
func apiRequestFunc(ctx context.Context) func(method, path, token string, body interface{}) (*apiResponse, error) {
	return func(method, path, token string, body interface{}) (*apiResponse, error) {
		return apiRequestContext(ctx, apiBase, method, path, token, body)
	}
}

// pollForResponseWithContext polls GET /<requestID> every interval, up to
// maxTries times, until a poll's response_type equals want. It returns nil,
// nil if want never arrived within maxTries. request is injected so tests can
// stub it.
func pollForResponseWithContext(ctx context.Context, request func(method, path, token string, body interface{}) (*apiResponse, error), token, requestID, want string, interval time.Duration, maxTries int) (*apiResponse, error) {
	consecutiveErrors := 0
	for i := 0; i < maxTries; i++ {
		if !waitForContext(ctx, interval) {
			return nil, ctx.Err()
		}
		poll, err := request("GET", "/"+requestID, token, nil)
		if err != nil {
			if !isTransientAPIError(err) {
				return nil, err
			}
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutivePollErrors {
				return nil, err
			}
			appLog.Warn("transient poll failure, retrying", "request_id", requestID, "consecutive_errors", consecutiveErrors, "error", err)
			continue
		}
		consecutiveErrors = 0
		if poll.ResponseType == want {
			return poll, nil
		}
	}
	return nil, nil
}

func waitForContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func redactAPIError(err error, token string) string {
	message := err.Error()
	if token == "" {
		return message
	}
	message = strings.ReplaceAll(message, token, redactedLogValue)
	message = strings.ReplaceAll(message, url.QueryEscape(token), redactedLogValue)
	return message
}

const maxDebugAPIErrorRunes = 4096

func debugAPIErrorResponse(logger *appLogger, method, path string, data []byte, knownSecrets ...string) {
	var response map[string]any
	if err := json.Unmarshal(data, &response); err != nil {
		logger.Debug("API error response body omitted", "method", method, "path", path, "response_bytes", len(data), "reason", "not a JSON object")
		return
	}

	// Error responses are not trusted. Log only conventional diagnostic fields
	// instead of dumping the complete response, which may contain new credentials.
	diagnostic := make(map[string]any)
	for _, key := range []string{"code", "detail", "error", "message", "status", "status_code", "title", "type"} {
		if value, ok := response[key]; ok {
			diagnostic[key] = redactAPIValue(value, knownSecrets)
		}
	}
	if len(diagnostic) == 0 {
		logger.Debug("API error response body omitted", "method", method, "path", path, "response_bytes", len(data), "reason", "no diagnostic fields")
		return
	}

	encoded, err := json.Marshal(diagnostic)
	if err != nil {
		logger.Debug("API error response body omitted", "method", method, "path", path, "response_bytes", len(data), "reason", "diagnostic encoding failed")
		return
	}
	detail := string(encoded)
	runes := []rune(detail)
	if len(runes) > maxDebugAPIErrorRunes {
		detail = string(runes[:maxDebugAPIErrorRunes]) + "…"
	}
	logger.Debug("API error response", "method", method, "path", path, "detail", detail)
}

// walkSensitiveValue recurses through a JSON-decoded value for collectSensitiveStrings,
// calling visit on every string leaf with whether it's under a key sensitiveLogKey flags.
func walkSensitiveValue(value any, sensitiveParent bool, visit func(s string, sensitive bool)) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			walkSensitiveValue(child, sensitiveParent || sensitiveLogKey(key), visit)
		}
	case []any:
		for _, child := range value {
			walkSensitiveValue(child, sensitiveParent, visit)
		}
	case string:
		visit(value, sensitiveParent)
	}
}

// redactAPIValue collapses an entire subtree under a sensitive key to
// redactedLogValue rather than recursing into it, so nested key names don't
// leak alongside the (already redacted) values.
func redactAPIValue(value any, knownSecrets []string) any {
	switch value := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(value))
		for key, child := range value {
			if sensitiveLogKey(key) {
				redacted[key] = redactedLogValue
			} else {
				redacted[key] = redactAPIValue(child, knownSecrets)
			}
		}
		return redacted
	case []any:
		redacted := make([]any, len(value))
		for i, child := range value {
			redacted[i] = redactAPIValue(child, knownSecrets)
		}
		return redacted
	case string:
		return redactKnownSecrets(value, knownSecrets)
	default:
		return value
	}
}

func redactKnownSecrets(value string, knownSecrets []string) string {
	secrets := append([]string(nil), knownSecrets...)
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, redactedLogValue)
		value = strings.ReplaceAll(value, url.QueryEscape(secret), redactedLogValue)
	}
	return value
}

func collectSensitiveStrings(value any) []string {
	if value == nil {
		return nil
	}
	var decoded any
	switch v := value.(type) {
	case []byte:
		if len(v) == 0 {
			return nil
		}
		if err := json.Unmarshal(v, &decoded); err != nil {
			return nil
		}
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return nil
		}
	}
	var secrets []string
	walkSensitiveValue(decoded, false, func(s string, sensitive bool) {
		if sensitive && s != "" {
			secrets = append(secrets, s)
		}
	})
	return secrets
}
