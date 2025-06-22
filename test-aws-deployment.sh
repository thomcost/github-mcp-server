#!/bin/bash

# Test script for AWS-deployed GitHub MCP server
# Usage: ./test-aws-deployment.sh YOUR_GITHUB_TOKEN

GITHUB_TOKEN=${1:-""}
SERVER_URL="http://github-mcp-multiuser-alb-1409031611.us-east-1.elb.amazonaws.com/v1/mcp"

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Usage: $0 YOUR_GITHUB_TOKEN"
    echo "Example: $0 ghp_your_token_here"
    exit 1
fi

echo "🚀 Testing GitHub MCP Server on AWS"
echo "Server: $SERVER_URL"
echo ""

# Test 1: No auth (should get 401)
echo "❌ Test 1: Request without Authorization (expecting 401)"
curl -s -w "HTTP %{http_code}\n" \
     -H "Content-Type: application/json" \
     -d '{"test":"no_auth"}' \
     "$SERVER_URL"
echo ""

# Test 2: Initialize with auth
echo "✅ Test 2: MCP Initialize with GitHub token"
curl -s -w "\nHTTP %{http_code}\n" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GITHUB_TOKEN" \
     -d '{
       "jsonrpc": "2.0",
       "id": 1,
       "method": "initialize",
       "params": {
         "protocolVersion": "2024-11-05",
         "clientInfo": {"name": "test-client", "version": "1.0.0"},
         "capabilities": {}
       }
     }' \
     "$SERVER_URL" | jq . 2>/dev/null || cat
echo ""

# Test 3: List available tools
echo "✅ Test 3: List available tools"
curl -s -w "\nHTTP %{http_code}\n" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GITHUB_TOKEN" \
     -d '{
       "jsonrpc": "2.0",
       "id": 2,
       "method": "tools/list",
       "params": {}
     }' \
     "$SERVER_URL" | jq . 2>/dev/null || cat
echo ""

# Test 4: Call get_me tool
echo "✅ Test 4: Call get_me tool"
curl -s -w "\nHTTP %{http_code}\n" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GITHUB_TOKEN" \
     -d '{
       "jsonrpc": "2.0",
       "id": 3,
       "method": "tools/call",
       "params": {
         "name": "get_me",
         "arguments": {}
       }
     }' \
     "$SERVER_URL" | jq . 2>/dev/null || cat
echo ""

echo "🎯 Test completed!"