package ghmcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/github/github-mcp-server/pkg/github"
	mcplog "github.com/github/github-mcp-server/pkg/log"
	"github.com/github/github-mcp-server/pkg/raw"
	"github.com/github/github-mcp-server/pkg/translations"
	gogithub "github.com/google/go-github/v72/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
)

type MCPServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// GitHub Token to authenticate with the GitHub API
	Token string

	// EnabledToolsets is a list of toolsets to enable
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#tool-configuration
	EnabledToolsets []string

	// Whether to enable dynamic toolsets
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#dynamic-tool-discovery
	DynamicToolsets bool

	// ReadOnly indicates if we should only offer read-only tools
	ReadOnly bool

	// Translator provides translated text for the server tooling
	Translator translations.TranslationHelperFunc
}

func NewMCPServer(cfg MCPServerConfig) (*server.MCPServer, error) {
	apiHost, err := parseAPIHost(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API host: %w", err)
	}

	// Construct our REST client
	restClient := gogithub.NewClient(nil).WithAuthToken(cfg.Token)
	restClient.UserAgent = fmt.Sprintf("github-mcp-server/%s", cfg.Version)
	restClient.BaseURL = apiHost.baseRESTURL
	restClient.UploadURL = apiHost.uploadURL

	// Construct our GraphQL client
	// We're using NewEnterpriseClient here unconditionally as opposed to NewClient because we already
	// did the necessary API host parsing so that github.com will return the correct URL anyway.
	gqlHTTPClient := &http.Client{
		Transport: &bearerAuthTransport{
			transport: http.DefaultTransport,
			token:     cfg.Token,
		},
	} // We're going to wrap the Transport later in beforeInit
	gqlClient := githubv4.NewEnterpriseClient(apiHost.graphqlURL.String(), gqlHTTPClient)

	// When a client send an initialize request, update the user agent to include the client info.
	beforeInit := func(_ context.Context, _ any, message *mcp.InitializeRequest) {
		userAgent := fmt.Sprintf(
			"github-mcp-server/%s (%s/%s)",
			cfg.Version,
			message.Params.ClientInfo.Name,
			message.Params.ClientInfo.Version,
		)

		restClient.UserAgent = userAgent

		gqlHTTPClient.Transport = &userAgentTransport{
			transport: gqlHTTPClient.Transport,
			agent:     userAgent,
		}
	}

	hooks := &server.Hooks{
		OnBeforeInitialize: []server.OnBeforeInitializeFunc{beforeInit},
	}

	ghServer := github.NewServer(cfg.Version, server.WithHooks(hooks))

	enabledToolsets := cfg.EnabledToolsets
	if cfg.DynamicToolsets {
		// filter "all" from the enabled tool sets
		enabledToolsets = make([]string, 0, len(cfg.EnabledToolsets))
		for _, toolset := range cfg.EnabledToolsets {
			if toolset != "all" {
				enabledToolsets = append(enabledToolsets, toolset)
			}
		}
	}

	getClient := func(_ context.Context) (*gogithub.Client, error) {
		return restClient, nil // closing over client
	}

	getGQLClient := func(_ context.Context) (*githubv4.Client, error) {
		return gqlClient, nil // closing over client
	}

	getRawClient := func(ctx context.Context) (*raw.Client, error) {
		client, err := getClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get GitHub client: %w", err)
		}
		return raw.NewClient(client, apiHost.rawURL), nil // closing over client
	}

	// Create default toolsets
	tsg := github.DefaultToolsetGroup(cfg.ReadOnly, getClient, getGQLClient, getRawClient, cfg.Translator)
	err = tsg.EnableToolsets(enabledToolsets)

	if err != nil {
		return nil, fmt.Errorf("failed to enable toolsets: %w", err)
	}

	// Register all mcp functionality with the server
	tsg.RegisterAll(ghServer)

	if cfg.DynamicToolsets {
		dynamic := github.InitDynamicToolset(ghServer, tsg, cfg.Translator)
		dynamic.RegisterTools(ghServer)
	}

	return ghServer, nil
}

type StdioServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// GitHub Token to authenticate with the GitHub API
	Token string

	// EnabledToolsets is a list of toolsets to enable
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#tool-configuration
	EnabledToolsets []string

	// Whether to enable dynamic toolsets
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#dynamic-tool-discovery
	DynamicToolsets bool

	// ReadOnly indicates if we should only register read-only tools
	ReadOnly bool

	// ExportTranslations indicates if we should export translations
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#i18n--overriding-descriptions
	ExportTranslations bool

	// EnableCommandLogging indicates if we should log commands
	EnableCommandLogging bool

	// Path to the log file if not stderr
	LogFilePath string
}

// RunStdioServer is not concurrent safe.
func RunStdioServer(cfg StdioServerConfig) error {
	// Create app context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, dumpTranslations := translations.TranslationHelper()

	ghServer, err := NewMCPServer(MCPServerConfig{
		Version:         cfg.Version,
		Host:            cfg.Host,
		Token:           cfg.Token,
		EnabledToolsets: cfg.EnabledToolsets,
		DynamicToolsets: cfg.DynamicToolsets,
		ReadOnly:        cfg.ReadOnly,
		Translator:      t,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	stdioServer := server.NewStdioServer(ghServer)

	logrusLogger := logrus.New()
	if cfg.LogFilePath != "" {
		file, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}

		logrusLogger.SetLevel(logrus.DebugLevel)
		logrusLogger.SetOutput(file)
	}
	stdLogger := log.New(logrusLogger.Writer(), "stdioserver", 0)
	stdioServer.SetErrorLogger(stdLogger)

	if cfg.ExportTranslations {
		// Once server is initialized, all translations are loaded
		dumpTranslations()
	}

	// Start listening for messages
	errC := make(chan error, 1)
	go func() {
		in, out := io.Reader(os.Stdin), io.Writer(os.Stdout)

		if cfg.EnableCommandLogging {
			loggedIO := mcplog.NewIOLogger(in, out, logrusLogger)
			in, out = loggedIO, loggedIO
		}

		errC <- stdioServer.Listen(ctx, in, out)
	}()

	// Output github-mcp-server string
	_, _ = fmt.Fprintf(os.Stderr, "GitHub MCP Server running on stdio\n")

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logrusLogger.Infof("shutting down server...")
	case err := <-errC:
		if err != nil {
			return fmt.Errorf("error running server: %w", err)
		}
	}

	return nil
}

type apiHost struct {
	baseRESTURL *url.URL
	graphqlURL  *url.URL
	uploadURL   *url.URL
	rawURL      *url.URL
}

func newDotcomHost() (apiHost, error) {
	baseRestURL, err := url.Parse("https://api.github.com/")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom REST URL: %w", err)
	}

	gqlURL, err := url.Parse("https://api.github.com/graphql")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom GraphQL URL: %w", err)
	}

	uploadURL, err := url.Parse("https://uploads.github.com")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom Upload URL: %w", err)
	}

	rawURL, err := url.Parse("https://raw.githubusercontent.com/")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom Raw URL: %w", err)
	}

	return apiHost{
		baseRESTURL: baseRestURL,
		graphqlURL:  gqlURL,
		uploadURL:   uploadURL,
		rawURL:      rawURL,
	}, nil
}

func newGHECHost(hostname string) (apiHost, error) {
	u, err := url.Parse(hostname)
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC URL: %w", err)
	}

	// Unsecured GHEC would be an error
	if u.Scheme == "http" {
		return apiHost{}, fmt.Errorf("GHEC URL must be HTTPS")
	}

	restURL, err := url.Parse(fmt.Sprintf("https://api.%s/", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC REST URL: %w", err)
	}

	gqlURL, err := url.Parse(fmt.Sprintf("https://api.%s/graphql", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC GraphQL URL: %w", err)
	}

	uploadURL, err := url.Parse(fmt.Sprintf("https://uploads.%s", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC Upload URL: %w", err)
	}

	rawURL, err := url.Parse(fmt.Sprintf("https://raw.%s/", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC Raw URL: %w", err)
	}

	return apiHost{
		baseRESTURL: restURL,
		graphqlURL:  gqlURL,
		uploadURL:   uploadURL,
		rawURL:      rawURL,
	}, nil
}

func newGHESHost(hostname string) (apiHost, error) {
	u, err := url.Parse(hostname)
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES URL: %w", err)
	}

	restURL, err := url.Parse(fmt.Sprintf("%s://%s/api/v3/", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES REST URL: %w", err)
	}

	gqlURL, err := url.Parse(fmt.Sprintf("%s://%s/api/graphql", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES GraphQL URL: %w", err)
	}

	uploadURL, err := url.Parse(fmt.Sprintf("%s://%s/api/uploads/", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES Upload URL: %w", err)
	}
	rawURL, err := url.Parse(fmt.Sprintf("%s://%s/raw/", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES Raw URL: %w", err)
	}

	return apiHost{
		baseRESTURL: restURL,
		graphqlURL:  gqlURL,
		uploadURL:   uploadURL,
		rawURL:      rawURL,
	}, nil
}

// Note that this does not handle ports yet, so development environments are out.
func parseAPIHost(s string) (apiHost, error) {
	if s == "" {
		return newDotcomHost()
	}

	u, err := url.Parse(s)
	if err != nil {
		return apiHost{}, fmt.Errorf("could not parse host as URL: %s", s)
	}

	if u.Scheme == "" {
		return apiHost{}, fmt.Errorf("host must have a scheme (http or https): %s", s)
	}

	if strings.HasSuffix(u.Hostname(), "github.com") {
		return newDotcomHost()
	}

	if strings.HasSuffix(u.Hostname(), "ghe.com") {
		return newGHECHost(s)
	}

	return newGHESHost(s)
}

type userAgentTransport struct {
	transport http.RoundTripper
	agent     string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.agent)
	return t.transport.RoundTrip(req)
}

type bearerAuthTransport struct {
	transport http.RoundTripper
	token     string
}

func (t *bearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}

// MultiUserHTTPServerConfig holds config for the multi-user HTTP server
// (no global token, per-request tokens)
type MultiUserHTTPServerConfig struct {
	Version         string
	Host            string
	EnabledToolsets []string
	DynamicToolsets bool
	ReadOnly        bool
	Port            int
}

// RunMultiUserHTTPServer starts a streamable HTTP server that supports per-request GitHub tokens
func RunMultiUserHTTPServer(cfg MultiUserHTTPServerConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create session manager for multi-user sessions
	sessionManager := NewSessionManager(cfg)

	// Create HTTP handler that manages sessions
	handler := &multiUserHandler{
		sessionManager: sessionManager,
	}

	// Setup HTTP server with proper timeouts
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "GitHub MCP Server running in multi-user HTTP mode on :%d\n", cfg.Port)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "Shutting down server...\n")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}
}

// Session represents an MCP session with associated GitHub token
type Session struct {
	ID          string
	Token       string
	Server      *server.MCPServer
	HTTPHandler http.Handler
	Created     time.Time
	LastUsed    time.Time
}

// SessionManager manages MCP sessions for multi-user HTTP mode
type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
	cfg      MultiUserHTTPServerConfig
}

// NewSessionManager creates a new session manager
func NewSessionManager(cfg MultiUserHTTPServerConfig) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		cfg:      cfg,
	}
	
	// Start cleanup goroutine
	go sm.cleanupRoutine()
	
	return sm
}

// cleanupRoutine periodically removes expired sessions
func (sm *SessionManager) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		sm.mutex.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			// Remove sessions older than 1 hour or unused for 30 minutes
			if now.Sub(session.Created) > time.Hour || now.Sub(session.LastUsed) > 30*time.Minute {
				delete(sm.sessions, id)
			}
		}
		sm.mutex.Unlock()
	}
}

// generateSessionID creates a new unique session ID
func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// CreateSession creates a new MCP session for the given token
func (sm *SessionManager) CreateSession(token string) (*Session, error) {
	sessionID := generateSessionID()
	
	// Parse API host
	apiHost, err := parseAPIHost(sm.cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API host: %w", err)
	}
	
	t, _ := translations.TranslationHelper()
	
	// Create token-aware client factories for this session
	getClient := func(ctx context.Context) (*gogithub.Client, error) {
		client := gogithub.NewClient(nil).WithAuthToken(token)
		client.UserAgent = fmt.Sprintf("github-mcp-server/%s", sm.cfg.Version)
		client.BaseURL = apiHost.baseRESTURL
		client.UploadURL = apiHost.uploadURL
		return client, nil
	}
	
	getGQLClient := func(ctx context.Context) (*githubv4.Client, error) {
		httpClient := &http.Client{
			Transport: &bearerAuthTransport{
				transport: http.DefaultTransport,
				token:     token,
			},
		}
		return githubv4.NewEnterpriseClient(apiHost.graphqlURL.String(), httpClient), nil
	}
	
	// Create MCP server for this session
	ghServer := github.NewServer(sm.cfg.Version)
	
	enabledToolsets := sm.cfg.EnabledToolsets
	if sm.cfg.DynamicToolsets {
		enabledToolsets = make([]string, 0, len(sm.cfg.EnabledToolsets))
		for _, toolset := range sm.cfg.EnabledToolsets {
			if toolset != "all" {
				enabledToolsets = append(enabledToolsets, toolset)
			}
		}
	}
	
	// Create and register toolsets for this session
	tsg := github.DefaultToolsetGroup(sm.cfg.ReadOnly, getClient, getGQLClient, t)
	if err := tsg.EnableToolsets(enabledToolsets); err != nil {
		return nil, fmt.Errorf("failed to enable toolsets: %w", err)
	}

	contextToolset := github.InitContextToolset(getClient, t)
	github.RegisterResources(ghServer, getClient, t)

	// Register the tools with the server
	tsg.RegisterTools(ghServer)
	contextToolset.RegisterTools(ghServer)

	if sm.cfg.DynamicToolsets {
		dynamic := github.InitDynamicToolset(ghServer, tsg, t)
		dynamic.RegisterTools(ghServer)
	}
	
	// Create HTTP handler for this session
	httpHandler := server.NewStreamableHTTPServer(ghServer)
	
	session := &Session{
		ID:          sessionID,
		Token:       token,
		Server:      ghServer,
		HTTPHandler: httpHandler,
		Created:     time.Now(),
		LastUsed:    time.Now(),
	}
	
	sm.mutex.Lock()
	sm.sessions[sessionID] = session
	sm.mutex.Unlock()
	
	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	session, exists := sm.sessions[sessionID]
	if exists {
		session.LastUsed = time.Now()
	}
	return session, exists
}

// multiUserHandler handles MCP sessions for multi-user HTTP mode
type multiUserHandler struct {
	sessionManager *SessionManager
}

func (h *multiUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := extractTokenFromRequest(r)
	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing GitHub token in Authorization header"}`))
		return
	}
	
	// Parse the MCP request to handle session management
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var mcpRequest struct {
		Jsonrpc string      `json:"jsonrpc"`
		ID      interface{} `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
	}
	
	if err := json.Unmarshal(body, &mcpRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	// Handle initialize method - create new session
	if mcpRequest.Method == "initialize" {
		session, err := h.sessionManager.CreateSession(token)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      mcpRequest.ID,
				"error": map[string]interface{}{
					"code":    -32603,
					"message": fmt.Sprintf("Failed to create session: %v", err),
				},
			})
			return
		}
		
		// Forward the initialize request to the session's HTTP handler
		// but first restore the body
		newReq := r.Clone(r.Context())
		newReq.Body = io.NopCloser(strings.NewReader(string(body)))
		
		// Use a response recorder to capture the response
		recorder := &responseRecorder{body: &strings.Builder{}, headers: make(http.Header)}
		session.HTTPHandler.ServeHTTP(recorder, newReq)
		
		// Parse the response and add session ID
		var response map[string]interface{}
		if err := json.Unmarshal([]byte(recorder.body.String()), &response); err != nil {
			http.Error(w, "Failed to parse server response", http.StatusInternalServerError)
			return
		}
		
		// Add session ID to the response
		if result, ok := response["result"].(map[string]interface{}); ok {
			result["sessionId"] = session.ID
		}
		
		// Copy headers and write response
		for k, v := range recorder.headers {
			w.Header()[k] = v
		}
		w.WriteHeader(recorder.statusCode)
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// For non-initialize methods, get session ID from request
	sessionID := r.Header.Get("X-MCP-Session-ID")
	if sessionID == "" {
		// Try to extract from URL query parameter as fallback
		sessionID = r.URL.Query().Get("session_id")
	}
	
	if sessionID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      mcpRequest.ID,
			"error": map[string]interface{}{
				"code":    -32602,
				"message": "Missing session ID. Use X-MCP-Session-ID header or session_id query parameter",
			},
		})
		return
	}
	
	session, exists := h.sessionManager.GetSession(sessionID)
	if !exists {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      mcpRequest.ID,
			"error": map[string]interface{}{
				"code":    -32602,
				"message": "Invalid session ID",
			},
		})
		return
	}
	
	// Verify token matches session
	if session.Token != token {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      mcpRequest.ID,
			"error": map[string]interface{}{
				"code":    -32602,
				"message": "Token mismatch for session",
			},
		})
		return
	}
	
	// Forward the request to the session's HTTP handler
	newReq := r.Clone(r.Context())
	newReq.Body = io.NopCloser(strings.NewReader(string(body)))
	
	// Use the session's HTTP handler to process the request
	session.HTTPHandler.ServeHTTP(w, newReq)
}

// responseRecorder captures HTTP responses for modification
type responseRecorder struct {
	statusCode int
	headers    http.Header
	body       *strings.Builder
}

func (r *responseRecorder) Header() http.Header {
	return r.headers
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

// extractTokenFromRequest extracts the GitHub token from the Authorization header
func extractTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	
	// Only accept proper Bearer token format
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	
	token := strings.TrimPrefix(authHeader, "Bearer ")
	// Basic validation - non-empty and reasonable length
	if len(token) < 10 {
		return ""
	}
	
	return token
}
