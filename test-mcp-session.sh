#!/bin/bash

# Proper MCP session test with initialization
GITHUB_TOKEN="${GITHUB_TOKEN:-your-github-token-here}"
SERVER_URL="http://localhost:8080/v1/mcp"

echo "🚀 Testing MCP Session Flow"
echo ""

# Create a proper MCP session by sending multiple requests
{
  # 1. Initialize
  echo '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "clientInfo": {"name": "test-client", "version": "1.0.0"},
      "capabilities": {}
    }
  }'
  
  # 2. List tools
  echo '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'
  
  # 3. Call get_me tool
  echo '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "get_me",
      "arguments": {}
    }
  }'
  
} | curl -s \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -d @- \
  "$SERVER_URL" | jq .