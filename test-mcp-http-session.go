package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type MCPRequest struct {
	Jsonrpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type MCPResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

func main() {
	serverURL := "http://localhost:8080/v1/mcp"
	token := os.Getenv("GITHUB_TOKEN") // Use environment variable instead
	
	client := &http.Client{Timeout: 10 * time.Second}
	
	fmt.Println("🧪 Testing MCP HTTP Session Management")
	fmt.Println("======================================")
	
	// Test 1: Initialize - should return session ID
	fmt.Println("\n1. Testing MCP Initialize...")
	initReq := MCPRequest{
		Jsonrpc: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"clientInfo": map[string]string{
				"name":    "test-client",
				"version": "1.0.0",
			},
			"capabilities": map[string]interface{}{},
		},
	}
	
	initResp, err := sendMCPRequest(client, serverURL, token, "", initReq)
	if err != nil {
		fmt.Printf("❌ Initialize failed: %v\n", err)
		return
	}
	
	if initResp.Error != nil {
		fmt.Printf("❌ Initialize error: %v\n", initResp.Error)
		return
	}
	
	fmt.Printf("✅ Initialize successful: %v\n", initResp.Result)
	
	// Extract session ID from initialize response
	var sessionID string
	if result, ok := initResp.Result.(map[string]interface{}); ok {
		if sid, ok := result["sessionId"].(string); ok {
			sessionID = sid
			fmt.Printf("📋 Session ID: %s\n", sessionID)
		}
	}
	
	if sessionID == "" {
		fmt.Printf("❌ No session ID returned from initialize\n")
		return
	}
	
	// Test 2: Tools List with session ID
	fmt.Println("\n2. Testing tools/list with session...")
	listReq := MCPRequest{
		Jsonrpc: "2.0",
		ID:      2,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}
	
	listResp, err := sendMCPRequest(client, serverURL, token, sessionID, listReq)
	if err != nil {
		fmt.Printf("❌ Tools list failed: %v\n", err)
		return
	}
	
	if listResp.Error != nil {
		fmt.Printf("❌ Tools list error: %v\n", listResp.Error)
		return
	}
	
	fmt.Printf("✅ Tools list successful\n")
	if result, ok := listResp.Result.(map[string]interface{}); ok {
		if tools, ok := result["tools"].([]interface{}); ok {
			fmt.Printf("   Found %d tools\n", len(tools))
		}
	}
	
	// Test 3: Call get_me tool with session ID
	fmt.Println("\n3. Testing tools/call get_me with session...")
	callReq := MCPRequest{
		Jsonrpc: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "get_me",
			"arguments": map[string]interface{}{},
		},
	}
	
	callResp, err := sendMCPRequest(client, serverURL, token, sessionID, callReq)
	if err != nil {
		fmt.Printf("❌ Tools call failed: %v\n", err)
		return
	}
	
	if callResp.Error != nil {
		fmt.Printf("❌ Tools call error: %v\n", callResp.Error)
		return
	}
	
	fmt.Printf("✅ Tools call successful\n")
	
	// Test 4: Test without session ID (should fail)
	fmt.Println("\n4. Testing tools/list without session (should fail)...")
	failReq := MCPRequest{
		Jsonrpc: "2.0",
		ID:      4,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}
	
	failResp, err := sendMCPRequest(client, serverURL, token, "", failReq)
	if err != nil {
		fmt.Printf("✅ Expected failure: %v\n", err)
	} else if failResp.Error != nil {
		fmt.Printf("✅ Expected error: %v\n", failResp.Error)
	} else {
		fmt.Printf("❌ Should have failed without session ID\n")
	}
	
	fmt.Println("\n🎯 All tests completed!")
}

func sendMCPRequest(client *http.Client, serverURL, token, sessionID string, req MCPRequest) (*MCPResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	
	// Add session ID header if provided
	if sessionID != "" {
		httpReq.Header.Set("X-MCP-Session-ID", sessionID)
	}
	
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &mcpResp, nil
}