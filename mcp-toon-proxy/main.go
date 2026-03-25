package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	toon "github.com/toon-format/toon-go"
)

// jsonRPCRequest is a minimal JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: mcp-toon-proxy <mode> <target> [args...]\n")
		fmt.Fprintf(os.Stderr, "  modes: stdio, http, sse\n")
		fmt.Fprintf(os.Stderr, "  stdio: mcp-toon-proxy stdio <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "  http:  mcp-toon-proxy http <url> [header:value ...]\n")
		fmt.Fprintf(os.Stderr, "  sse:   mcp-toon-proxy sse <url> [header:value ...]\n")
		os.Exit(1)
	}

	mode := os.Args[1]
	switch mode {
	case "stdio":
		runStdio(os.Args[2], os.Args[3:]...)
	case "http":
		headers := parseHeaders(os.Args[3:])
		runHTTP(os.Args[2], headers)
	case "sse":
		headers := parseHeaders(os.Args[3:])
		runSSE(os.Args[2], headers)
	default:
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: unknown mode %q\n", mode)
		os.Exit(1)
	}
}

func parseHeaders(args []string) map[string]string {
	headers := make(map[string]string)
	for _, arg := range args {
		if idx := strings.Index(arg, ":"); idx > 0 {
			headers[strings.TrimSpace(arg[:idx])] = strings.TrimSpace(arg[idx+1:])
		}
	}
	return headers
}

// runStdio wraps a child stdio MCP server (original behavior).
func runStdio(command string, args ...string) {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr

	childIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: stdin pipe: %v\n", err)
		os.Exit(1)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: stdout pipe: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: start child: %v\n", err)
		os.Exit(1)
	}

	var mu sync.Mutex
	toolCallIDs := make(map[string]bool)
	var wg sync.WaitGroup

	// Upstream: Claude → child.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer childIn.Close()
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			trackRequest(line, &mu, toolCallIDs)
			if _, err := childIn.Write(line); err != nil {
				fmt.Fprintf(os.Stderr, "mcp-toon-proxy: write to child: %v\n", err)
				return
			}
			if _, err := childIn.Write([]byte("\n")); err != nil {
				fmt.Fprintf(os.Stderr, "mcp-toon-proxy: write to child: %v\n", err)
				return
			}
		}
	}()

	// Downstream: child → Claude.
	wg.Add(1)
	go func() {
		defer wg.Done()
		transformStream(childOut, os.Stdout, &mu, toolCallIDs)
	}()

	// Forward signals to child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
	}()

	wg.Wait()
	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

// runHTTP wraps an HTTP (streamable) MCP server.
// Each JSON-RPC request from stdin is POSTed; the response is transformed and written to stdout.
func runHTTP(url string, headers map[string]string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	var mu sync.Mutex
	toolCallIDs := make(map[string]bool)
	oauth := newOAuthManager(url)

	client := &http.Client{}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	sessionID := ""

	for scanner.Scan() {
		line := scanner.Bytes()
		trackRequest(line, &mu, toolCallIDs)

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(line))
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: http request: %v\n", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		oauth.setAuthHeader(req)
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: http do: %v\n", err)
			continue
		}

		// Handle 401 — perform OAuth flow and retry.
		if resp.StatusCode == 401 {
			resp.Body.Close()
			if err := oauth.handleUnauthorized(ctx, resp); err != nil {
				fmt.Fprintf(os.Stderr, "mcp-toon-proxy: oauth: %v\n", err)
				continue
			}
			// Retry the request with the new token.
			req, err = http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(line))
			if err != nil {
				fmt.Fprintf(os.Stderr, "mcp-toon-proxy: http retry request: %v\n", err)
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			oauth.setAuthHeader(req)
			if sessionID != "" {
				req.Header.Set("Mcp-Session-Id", sessionID)
			}
			resp, err = client.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mcp-toon-proxy: http retry: %v\n", err)
				continue
			}
		}

		// Capture session ID from response.
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			sessionID = sid
		}

		isSSE := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: http read body: %v\n", err)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: http status %d: %s\n", resp.StatusCode, string(body))
			// Still forward the body — it may contain a JSON-RPC error.
		}

		// If the server responded with SSE format, extract JSON from data: lines.
		if isSSE {
			scanner := bufio.NewScanner(bytes.NewReader(body))
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, "data:") {
					continue
				}
				data := []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				if len(data) == 0 {
					continue
				}
				if maybeTransform(data, &mu, toolCallIDs, writer) {
					writer.WriteByte('\n')
					writer.Flush()
				} else {
					writer.Write(data)
					writer.WriteByte('\n')
					writer.Flush()
				}
			}
			continue
		}

		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			continue
		}

		if maybeTransform(body, &mu, toolCallIDs, writer) {
			writer.WriteByte('\n')
			writer.Flush()
		} else {
			writer.Write(body)
			writer.WriteByte('\n')
			writer.Flush()
		}
	}
}

// runSSE wraps an SSE MCP server.
// Connects to the SSE endpoint, discovers the message POST URL, then:
//   - Reads JSON-RPC from stdin → POSTs to message URL
//   - Reads SSE events → transforms and writes JSON-RPC lines to stdout
func runSSE(sseURL string, headers map[string]string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	var mu sync.Mutex
	toolCallIDs := make(map[string]bool)
	oauth := newOAuthManager(sseURL)

	client := &http.Client{}

	// Connect to SSE endpoint (with OAuth retry on 401).
	connectSSE := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", sseURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "text/event-stream")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		oauth.setAuthHeader(req)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 401 {
			resp.Body.Close()
			if err := oauth.handleUnauthorized(ctx, resp); err != nil {
				return nil, fmt.Errorf("oauth: %w", err)
			}
			// Retry with token.
			req, err = http.NewRequestWithContext(ctx, "GET", sseURL, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "text/event-stream")
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			oauth.setAuthHeader(req)
			return client.Do(req)
		}

		return resp, nil
	}

	resp, err := connectSSE()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse connect: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse status %d: %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	// Wait for the "endpoint" event to get the POST URL.
	messageURL := make(chan string, 1)

	// Read SSE stream in background.
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)
		writer := bufio.NewWriter(os.Stdout)
		defer writer.Flush()

		var eventType string
		var dataLines []string

		for scanner.Scan() {
			line := scanner.Text()

			if line == "" {
				// End of event — dispatch.
				if len(dataLines) > 0 {
					data := strings.Join(dataLines, "\n")
					if eventType == "endpoint" {
						// Resolve relative URL.
						url := resolveURL(sseURL, strings.TrimSpace(data))
						select {
						case messageURL <- url:
						default:
						}
					} else if eventType == "message" || eventType == "" {
						// JSON-RPC message from server.
						dataBytes := []byte(data)
						if maybeTransform(dataBytes, &mu, toolCallIDs, writer) {
							writer.WriteByte('\n')
							writer.Flush()
						} else {
							writer.Write(dataBytes)
							writer.WriteByte('\n')
							writer.Flush()
						}
					}
				}
				eventType = ""
				dataLines = nil
				continue
			}

			if strings.HasPrefix(line, "event:") {
				eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimPrefix(line, "data:"))
			}
		}

		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse read: %v\n", err)
		}
		cancel()
	}()

	// Wait for endpoint URL.
	var postURL string
	select {
	case postURL = <-messageURL:
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse endpoint: %s\n", postURL)
	case <-ctx.Done():
		os.Exit(1)
	}

	// Read stdin and POST to message endpoint.
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		line := scanner.Bytes()
		trackRequest(line, &mu, toolCallIDs)

		postReq, err := http.NewRequestWithContext(ctx, "POST", postURL, bytes.NewReader(line))
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse post: %v\n", err)
			continue
		}
		postReq.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			postReq.Header.Set(k, v)
		}
		oauth.setAuthHeader(postReq)

		postResp, err := client.Do(postReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse post: %v\n", err)
			continue
		}
		io.Copy(io.Discard, postResp.Body)
		postResp.Body.Close()

		if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "mcp-toon-proxy: sse post status %d\n", postResp.StatusCode)
		}
	}
}

// resolveURL resolves a potentially relative URL against a base URL.
func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	// Extract scheme + host from base.
	idx := strings.Index(base, "://")
	if idx < 0 {
		return ref
	}
	rest := base[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return base + ref
	}
	return base[:idx+3+slashIdx] + ref
}

// trackRequest records the request ID if it's a tools/call.
func trackRequest(line []byte, mu *sync.Mutex, toolCallIDs map[string]bool) {
	var req jsonRPCRequest
	if json.Unmarshal(line, &req) == nil && req.Method == "tools/call" && req.ID != nil {
		idStr := string(req.ID)
		mu.Lock()
		toolCallIDs[idStr] = true
		mu.Unlock()
	}
}

// transformStream reads newline-delimited JSON-RPC from r, transforms tool call
// responses, and writes to w.
func transformStream(r io.Reader, w io.Writer, mu *sync.Mutex, toolCallIDs map[string]bool) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)
	writer := bufio.NewWriter(w)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Bytes()
		if maybeTransform(line, mu, toolCallIDs, writer) {
			writer.WriteByte('\n')
			writer.Flush()
		} else {
			writer.Write(line)
			writer.WriteByte('\n')
			writer.Flush()
		}
	}
}

// maybeTransform checks if the line is a JSON-RPC response to a tools/call
// request, and if so, converts JSON text content to TOON. Returns true if the
// line was handled (transformed and written).
func maybeTransform(line []byte, mu *sync.Mutex, toolCallIDs map[string]bool, w io.Writer) bool {
	var msg map[string]json.RawMessage
	if json.Unmarshal(line, &msg) != nil {
		return false
	}
	idRaw, hasID := msg["id"]
	_, hasResult := msg["result"]
	if !hasID || !hasResult {
		return false
	}

	idStr := string(idRaw)
	mu.Lock()
	isToolCall := toolCallIDs[idStr]
	if isToolCall {
		delete(toolCallIDs, idStr)
	}
	mu.Unlock()
	if !isToolCall {
		return false
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(msg["result"], &result) != nil {
		return false
	}

	changed := false
	for i := range result.Content {
		if result.Content[i].Type != "text" {
			continue
		}
		var parsed any
		if json.Unmarshal([]byte(result.Content[i].Text), &parsed) != nil {
			continue
		}
		encoded, err := toon.MarshalString(parsed)
		if err != nil {
			continue
		}
		result.Content[i].Text = encoded
		changed = true
	}

	if !changed {
		return false
	}

	newResult, err := json.Marshal(result)
	if err != nil {
		return false
	}
	msg["result"] = json.RawMessage(newResult)

	out, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	if _, err := w.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-toon-proxy: write output: %v\n", err)
		return false
	}
	return true
}
