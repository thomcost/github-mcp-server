#!/bin/bash

# Test script for multi-user GitHub MCP server
# Usage: ./test-multiuser.sh [PORT] [GITHUB_TOKEN]

PORT=${1:-8080}
GITHUB_TOKEN=${2:-""}

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Usage: $0 [PORT] GITHUB_TOKEN"
    echo "Example: $0 8080 ghp_your_token_here"
    exit 1
fi

SERVER_URL="http://localhost:$PORT"
MCP_ENDPOINT="$SERVER_URL/v1/mcp"

echo "🚀 Testing GitHub MCP Server in multi-user mode"
echo "Server: $SERVER_URL"
echo "Endpoint: $MCP_ENDPOINT"
echo ""

# Test 1: Request without Authorization header (should fail)
echo "❌ Test 1: Request without Authorization header"
curl -s -w "HTTP %{http_code}\n" \
     -H "Content-Type: application/json" \
     -d '{"test":"no_auth"}' \
     "$MCP_ENDPOINT"
echo ""

# Test 2: Request with invalid Authorization header (should fail)
echo "❌ Test 2: Request with invalid Authorization header"
curl -s -w "HTTP %{http_code}\n" \
     -H "Content-Type: application/json" \
     -H "Authorization: InvalidFormat" \
     -d '{"test":"invalid_auth"}' \
     "$MCP_ENDPOINT"
echo ""

# Test 3: Request with valid Authorization header - Initialize
echo "✅ Test 3: MCP Initialize with valid token"
INIT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GITHUB_TOKEN" \
     -d '{
       "jsonrpc": "2.0",
       "id": 1,
       "method": "initialize",
       "params": {
         "protocolVersion": "2024-11-05",
         "clientInfo": {
           "name": "test-client",
           "version": "1.0.0"
         },
         "capabilities": {}
       }
     }' \
     "$MCP_ENDPOINT")

HTTP_CODE=$(echo "$INIT_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$INIT_RESPONSE" | grep -v "HTTP_CODE:")

echo "HTTP $HTTP_CODE"
echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
echo ""

# Test 4: Tool call with valid token - get_me
echo "✅ Test 4: Tool call - get_me"
TOOL_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GITHUB_TOKEN" \
     -d '{
       "jsonrpc": "2.0",
       "id": 2,
       "method": "tools/call",
       "params": {
         "name": "get_me",
         "arguments": {}
       }
     }' \
     "$MCP_ENDPOINT")

HTTP_CODE=$(echo "$TOOL_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$TOOL_RESPONSE" | grep -v "HTTP_CODE:")

echo "HTTP $HTTP_CODE"
echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
echo ""

echo "🎯 Test completed!"
echo ""
echo "Expected results:"
echo "- Tests 1-2: HTTP 401 (Unauthorized)"
echo "- Tests 3-4: HTTP 200 with valid JSON responses"