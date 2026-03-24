package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// oauthTokens holds the access and refresh tokens.
type oauthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

// authServerMeta holds OAuth 2.0 Authorization Server Metadata (RFC 8414).
type authServerMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported,omitempty"`
}

// protectedResourceMeta holds OAuth 2.0 Protected Resource Metadata (RFC 9728).
type protectedResourceMeta struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

// oauthManager handles OAuth flows for a single server URL.
type oauthManager struct {
	serverURL string
	mu        sync.Mutex
	tokens    *oauthTokens
	meta      *authServerMeta
	clientID  string
}

// newOAuthManager creates a new OAuth manager for the given server URL.
// It attempts to load cached tokens from disk.
func newOAuthManager(serverURL string) *oauthManager {
	m := &oauthManager{serverURL: serverURL}
	m.tokens = m.loadCachedTokens()
	return m
}

// token returns the current access token, or empty string if none.
func (m *oauthManager) token() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens == nil {
		return ""
	}
	if m.tokens.ExpiresAt > 0 && time.Now().Unix() >= m.tokens.ExpiresAt {
		return "" // expired
	}
	return m.tokens.AccessToken
}

// handleUnauthorized performs the OAuth flow when a 401 is received.
// It discovers metadata, opens the browser, waits for callback, and exchanges the code.
func (m *oauthManager) handleUnauthorized(ctx context.Context, resp *http.Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If we have a refresh token, try that first.
	if m.tokens != nil && m.tokens.RefreshToken != "" && m.meta != nil {
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: attempting token refresh\n")
		if err := m.refreshTokenLocked(ctx); err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: refresh failed, starting new auth flow\n")
	}

	// Discover OAuth metadata.
	if err := m.discoverMetadata(ctx, resp); err != nil {
		return fmt.Errorf("oauth discovery: %w", err)
	}

	// Perform authorization code flow with PKCE.
	return m.authCodeFlowLocked(ctx)
}

// discoverMetadata finds the OAuth authorization server metadata.
func (m *oauthManager) discoverMetadata(ctx context.Context, resp *http.Response) error {
	client := &http.Client{Timeout: 10 * time.Second}
	origin := serverOrigin(m.serverURL)

	// Try Protected Resource Metadata first (RFC 9728).
	// Check WWW-Authenticate header for resource_metadata hint.
	var resourceMetaURL string
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if idx := strings.Index(wwwAuth, "resource_metadata=\""); idx >= 0 {
		rest := wwwAuth[idx+len("resource_metadata=\""):]
		if end := strings.Index(rest, "\""); end >= 0 {
			resourceMetaURL = rest[:end]
		}
	}

	var authServerURL string

	if resourceMetaURL != "" {
		req, _ := http.NewRequestWithContext(ctx, "GET", resourceMetaURL, nil)
		if r, err := client.Do(req); err == nil {
			defer r.Body.Close()
			if r.StatusCode == 200 {
				var prm protectedResourceMeta
				if json.NewDecoder(r.Body).Decode(&prm) == nil && len(prm.AuthorizationServers) > 0 {
					authServerURL = prm.AuthorizationServers[0]
				}
			}
		}
	}

	// Fallback: try well-known at server origin.
	if authServerURL == "" {
		prURL := origin + "/.well-known/oauth-protected-resource"
		req, _ := http.NewRequestWithContext(ctx, "GET", prURL, nil)
		if r, err := client.Do(req); err == nil {
			defer r.Body.Close()
			if r.StatusCode == 200 {
				var prm protectedResourceMeta
				if json.NewDecoder(r.Body).Decode(&prm) == nil && len(prm.AuthorizationServers) > 0 {
					authServerURL = prm.AuthorizationServers[0]
				}
			}
		}
	}

	// Fetch authorization server metadata.
	if authServerURL == "" {
		authServerURL = origin
	}
	asMetaURL := strings.TrimRight(authServerURL, "/") + "/.well-known/oauth-authorization-server"
	fmt.Fprintf(os.Stderr, "mcp-toon-proxy: fetching auth server metadata from %s\n", asMetaURL)

	req, err := http.NewRequestWithContext(ctx, "GET", asMetaURL, nil)
	if err != nil {
		return err
	}
	r, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch auth metadata: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		body, _ := io.ReadAll(r.Body)
		return fmt.Errorf("auth metadata returned %d: %s", r.StatusCode, string(body))
	}

	var meta authServerMeta
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		return fmt.Errorf("decode auth metadata: %w", err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return fmt.Errorf("auth metadata missing required endpoints")
	}
	m.meta = &meta

	// Client registration is deferred to authCodeFlowLocked so we know the
	// redirect_uri (which includes the ephemeral port).
	return nil
}

// dynamicRegister performs OAuth 2.0 Dynamic Client Registration (RFC 7591).
// redirectURI must include the actual port the callback server is listening on.
func (m *oauthManager) dynamicRegister(ctx context.Context, client *http.Client, redirectURI string) error {
	regBody := map[string]any{
		"client_name":                "mcp-toon-proxy",
		"redirect_uris":             []string{redirectURI},
		"grant_types":               []string{"authorization_code", "refresh_token"},
		"response_types":            []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	body, _ := json.Marshal(regBody)

	req, err := http.NewRequestWithContext(ctx, "POST", m.meta.RegistrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.ClientID != "" {
		m.clientID = result.ClientID
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: registered client_id=%s\n", m.clientID)
	}
	return nil
}

// authCodeFlowLocked performs the authorization code + PKCE flow.
// Must be called with m.mu held.
func (m *oauthManager) authCodeFlowLocked(ctx context.Context) error {
	// Generate PKCE.
	verifier := generateCodeVerifier()
	challenge := computeCodeChallenge(verifier)
	state := generateState()

	// Start local callback server FIRST so we know the port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for callback: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	// Now register the client with the correct redirect_uri.
	if m.clientID == "" && m.meta != nil && m.meta.RegistrationEndpoint != "" {
		client := &http.Client{Timeout: 10 * time.Second}
		if err := m.dynamicRegister(ctx, client, redirectURI); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: dynamic registration failed: %v\n", err)
			m.clientID = "mcp-toon-proxy"
		}
	} else if m.clientID == "" {
		m.clientID = "mcp-toon-proxy"
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		returnedState := r.URL.Query().Get("state")
		if returnedState != state {
			errCh <- fmt.Errorf("state mismatch")
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			errCh <- fmt.Errorf("oauth error: %s: %s", errMsg, desc)
			fmt.Fprintf(w, "<html><body><h1>Authentication failed</h1><p>%s: %s</p><p>You can close this tab.</p></body></html>", html.EscapeString(errMsg), html.EscapeString(desc))
			return
		}
		if code == "" {
			errCh <- fmt.Errorf("no code in callback")
			http.Error(w, "No code", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Authentication successful</h1><p>You can close this tab and return to your terminal.</p></body></html>")
		codeCh <- code
	})

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer srv.Shutdown(context.Background())

	// Build authorization URL.
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}

	// Add resource parameter (RFC 8707).
	params.Set("resource", serverOrigin(m.serverURL))

	// Add scope if available.
	if len(m.meta.ScopesSupported) > 0 {
		params.Set("scope", strings.Join(m.meta.ScopesSupported, " "))
	}

	authURL := m.meta.AuthorizationEndpoint + "?" + params.Encode()
	fmt.Fprintf(os.Stderr, "mcp-toon-proxy: opening browser for authentication...\n")
	fmt.Fprintf(os.Stderr, "mcp-toon-proxy: if browser doesn't open, visit:\n%s\n", authURL)

	openBrowser(authURL)

	// Wait for callback.
	select {
	case code := <-codeCh:
		return m.exchangeCode(ctx, code, verifier, redirectURI)
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("oauth timeout waiting for browser callback")
	}
}

// exchangeCode exchanges the authorization code for tokens.
func (m *oauthManager) exchangeCode(ctx context.Context, code, verifier, redirectURI string) error {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {m.clientID},
		"redirect_uri":  {redirectURI},
		"resource":      {serverOrigin(m.serverURL)},
	}

	return m.tokenRequest(ctx, params)
}

// refreshTokenLocked refreshes the access token using the refresh token.
// Must be called with m.mu held.
func (m *oauthManager) refreshTokenLocked(ctx context.Context) error {
	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {m.tokens.RefreshToken},
		"client_id":     {m.clientID},
	}

	return m.tokenRequest(ctx, params)
}

// tokenRequest performs a token endpoint request and updates stored tokens.
func (m *oauthManager) tokenRequest(ctx context.Context, params url.Values) error {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", m.meta.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("no access_token in response: %s", string(body))
	}

	m.tokens = &oauthTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
	}
	if tokenResp.ExpiresIn > 0 {
		m.tokens.ExpiresAt = time.Now().Unix() + tokenResp.ExpiresIn
	}

	m.saveCachedTokens()
	fmt.Fprintf(os.Stderr, "mcp-toon-proxy: authenticated successfully\n")
	return nil
}

// cacheDir returns the directory for storing cached tokens.
func (m *oauthManager) cacheDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "mcp-toon-proxy-tokens")
}

// cacheFile returns the cache file path for this server.
func (m *oauthManager) cacheFile() string {
	// Use a hash of the server URL as the filename.
	h := sha256.Sum256([]byte(m.serverURL))
	name := base64.RawURLEncoding.EncodeToString(h[:16])
	return filepath.Join(m.cacheDir(), name+".json")
}

// loadCachedTokens loads tokens from disk cache.
func (m *oauthManager) loadCachedTokens() *oauthTokens {
	data, err := os.ReadFile(m.cacheFile())
	if err != nil {
		return nil
	}
	var cached struct {
		Tokens   oauthTokens     `json:"tokens"`
		Meta     *authServerMeta `json:"meta,omitempty"`
		ClientID string          `json:"client_id,omitempty"`
	}
	if json.Unmarshal(data, &cached) != nil {
		return nil
	}
	m.meta = cached.Meta
	m.clientID = cached.ClientID
	if cached.Tokens.AccessToken == "" {
		return nil
	}
	fmt.Fprintf(os.Stderr, "mcp-toon-proxy: loaded cached tokens for %s\n", m.serverURL)
	return &cached.Tokens
}

// saveCachedTokens persists tokens to disk.
func (m *oauthManager) saveCachedTokens() {
	dir := m.cacheDir()
	os.MkdirAll(dir, 0700)

	cached := struct {
		Tokens   *oauthTokens    `json:"tokens"`
		Meta     *authServerMeta `json:"meta,omitempty"`
		ClientID string          `json:"client_id,omitempty"`
	}{
		Tokens:   m.tokens,
		Meta:     m.meta,
		ClientID: m.clientID,
	}
	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(m.cacheFile(), data, 0600)
}

// setAuthHeader sets the Authorization header if we have a token.
func (m *oauthManager) setAuthHeader(req *http.Request) {
	if tok := m.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

// generateCodeVerifier generates a PKCE code verifier (43-128 chars).
func generateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// computeCodeChallenge computes the S256 PKCE code challenge.
func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateState generates a random state parameter.
func generateState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// serverOrigin extracts scheme + host from a URL.
func serverOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// openBrowser opens a URL in the default browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		cmd = exec.Command("open", url)
	}
	cmd.Start()
}
