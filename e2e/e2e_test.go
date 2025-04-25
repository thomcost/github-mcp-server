//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v69/github"
	mcpClient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"
)

var (
	// Shared variables and sync.Once instances to ensure one-time execution
	getTokenOnce sync.Once
	token        string

	buildOnce  sync.Once
	buildError error
)

// getE2EToken ensures the environment variable is checked only once and returns the token
func getE2EToken(t *testing.T) string {
	getTokenOnce.Do(func() {
		token = os.Getenv("GITHUB_MCP_SERVER_E2E_TOKEN")
		if token == "" {
			t.Fatalf("GITHUB_MCP_SERVER_E2E_TOKEN environment variable is not set")
		}
	})
	return token
}

// ensureDockerImageBuilt makes sure the Docker image is built only once across all tests
func ensureDockerImageBuilt(t *testing.T) {
	buildOnce.Do(func() {
		t.Log("Building Docker image for e2e tests...")
		cmd := exec.Command("docker", "build", "-t", "github/e2e-github-mcp-server", ".")
		cmd.Dir = ".." // Run this in the context of the root, where the Dockerfile is located.
		output, err := cmd.CombinedOutput()
		buildError = err
		if err != nil {
			t.Logf("Docker build output: %s", string(output))
		}
	})

	// Check if the build was successful
	require.NoError(t, buildError, "expected to build Docker image successfully")
}

// ClientOpts holds configuration options for the MCP client setup
type ClientOpts struct {
	// Environment variables to set before starting the client
	EnvVars map[string]string
}

// ClientOption defines a function type for configuring ClientOpts
type ClientOption func(*ClientOpts)

// WithEnvVars returns an option that adds environment variables to the client options
func WithEnvVars(envVars map[string]string) ClientOption {
	return func(opts *ClientOpts) {
		opts.EnvVars = envVars
	}
}

// setupMCPClient sets up the test environment and returns an initialized MCP client
// It handles token retrieval, Docker image building, and applying the provided options
func setupMCPClient(t *testing.T, options ...ClientOption) *mcpClient.Client {
	// Get token and ensure Docker image is built
	token := getE2EToken(t)
	ensureDockerImageBuilt(t)

	// Create and configure options
	opts := &ClientOpts{
		EnvVars: make(map[string]string),
	}

	// Apply all options to configure the opts struct
	for _, option := range options {
		option(opts)
	}

	// Prepare Docker arguments
	args := []string{
		"docker",
		"run",
		"-i",
		"--rm",
		"-e",
		"GITHUB_PERSONAL_ACCESS_TOKEN", // Personal access token is all required
	}

	// Add all environment variables to the Docker arguments
	for key := range opts.EnvVars {
		args = append(args, "-e", key)
	}

	// Add the image name
	args = append(args, "github/e2e-github-mcp-server")

	// Construct the env vars for the MCP Client to execute docker with
	dockerEnvVars := make([]string, 0, len(opts.EnvVars)+1)
	dockerEnvVars = append(dockerEnvVars, fmt.Sprintf("GITHUB_PERSONAL_ACCESS_TOKEN=%s", token))
	for key, value := range opts.EnvVars {
		dockerEnvVars = append(dockerEnvVars, fmt.Sprintf("%s=%s", key, value))
	}

	// Create the client
	t.Log("Starting Stdio MCP client...")
	client, err := mcpClient.NewStdioMCPClient(args[0], dockerEnvVars, args[1:]...)
	require.NoError(t, err, "expected to create client successfully")
	t.Cleanup(func() {
		require.NoError(t, client.Close(), "expected to close client successfully")
	})

	// Initialize the client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	request := mcp.InitializeRequest{}
	request.Params.ProtocolVersion = "2025-03-26"
	request.Params.ClientInfo = mcp.Implementation{
		Name:    "e2e-test-client",
		Version: "0.0.1",
	}

	result, err := client.Initialize(ctx, request)
	require.NoError(t, err, "failed to initialize client")
	require.Equal(t, "github-mcp-server", result.ServerInfo.Name, "unexpected server name")

	return client
}

func TestGetMe(t *testing.T) {
	t.Parallel()

	mcpClient := setupMCPClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// When we call the "get_me" tool
	request := mcp.CallToolRequest{}
	request.Params.Name = "get_me"

	response, err := mcpClient.CallTool(ctx, request)
	require.NoError(t, err, "expected to call 'get_me' tool successfully")

	require.False(t, response.IsError, "expected result not to be an error")
	require.Len(t, response.Content, 1, "expected content to have one item")

	textContent, ok := response.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected content to be of type TextContent")

	var trimmedContent struct {
		Login string `json:"login"`
	}
	err = json.Unmarshal([]byte(textContent.Text), &trimmedContent)
	require.NoError(t, err, "expected to unmarshal text content successfully")

	// Then the login in the response should match the login obtained via the same
	// token using the GitHub API.
	ghClient := github.NewClient(nil).WithAuthToken(getE2EToken(t))
	user, _, err := ghClient.Users.Get(context.Background(), "")
	require.NoError(t, err, "expected to get user successfully")
	require.Equal(t, trimmedContent.Login, *user.Login, "expected login to match")

}

func TestToolsets(t *testing.T) {
	t.Parallel()

	mcpClient := setupMCPClient(
		t,
		WithEnvVars(map[string]string{
			"GITHUB_TOOLSETS": "repos,issues",
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	request := mcp.ListToolsRequest{}
	response, err := mcpClient.ListTools(ctx, request)
	require.NoError(t, err, "expected to list tools successfully")

	// We could enumerate the tools here, but we'll need to expose that information
	// declaratively in the MCP server, so for the moment let's just check the existence
	// of an issue and repo tool, and the non-existence of a pull_request tool.
	var toolsContains = func(expectedName string) bool {
		return slices.ContainsFunc(response.Tools, func(tool mcp.Tool) bool {
			return tool.Name == expectedName
		})
	}

	require.True(t, toolsContains("get_issue"), "expected to find 'get_issue' tool")
	require.True(t, toolsContains("list_branches"), "expected to find 'list_branches' tool")
	require.False(t, toolsContains("get_pull_request"), "expected not to find 'get_pull_request' tool")
}

func TestPullRequestReview(t *testing.T) {
	t.Parallel()

	mcpClient := setupMCPClient(t)

	ctx := context.Background()

	// First, who am I
	getMeRequest := mcp.CallToolRequest{}
	getMeRequest.Params.Name = "get_me"

	t.Log("Getting current user...")
	resp, err := mcpClient.CallTool(ctx, getMeRequest)
	require.NoError(t, err, "expected to call 'get_me' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	require.False(t, resp.IsError, "expected result not to be an error")
	require.Len(t, resp.Content, 1, "expected content to have one item")

	textContent, ok := resp.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected content to be of type TextContent")

	var trimmedGetMeText struct {
		Login string `json:"login"`
	}
	err = json.Unmarshal([]byte(textContent.Text), &trimmedGetMeText)
	require.NoError(t, err, "expected to unmarshal text content successfully")

	currentOwner := trimmedGetMeText.Login

	// Then create a repository with a README (via autoInit)
	repoName := fmt.Sprintf("github-mcp-server-e2e-%s-%d", t.Name(), time.Now().UnixMilli())
	createRepoRequest := mcp.CallToolRequest{}
	createRepoRequest.Params.Name = "create_repository"
	createRepoRequest.Params.Arguments = map[string]any{
		"name":     repoName,
		"private":  true,
		"autoInit": true,
	}

	t.Logf("Creating repository %s/%s...", currentOwner, repoName)
	_, err = mcpClient.CallTool(ctx, createRepoRequest)
	require.NoError(t, err, "expected to call 'get_me' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	// Cleanup the repository after the test
	t.Cleanup(func() {
		// MCP Server doesn't support deletions, but we can use the GitHub Client
		ghClient := github.NewClient(nil).WithAuthToken(getE2EToken(t))
		t.Logf("Deleting repository %s/%s...", currentOwner, repoName)
		_, err := ghClient.Repositories.Delete(context.Background(), currentOwner, repoName)
		require.NoError(t, err, "expected to delete repository successfully")
	})

	// Create a branch on which to create a new commit
	createBranchRequest := mcp.CallToolRequest{}
	createBranchRequest.Params.Name = "create_branch"
	createBranchRequest.Params.Arguments = map[string]any{
		"owner":       currentOwner,
		"repo":        repoName,
		"branch":      "test-branch",
		"from_branch": "main",
	}

	t.Logf("Creating branch in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, createBranchRequest)
	require.NoError(t, err, "expected to call 'create_branch' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	// Create a commit with a new file
	commitRequest := mcp.CallToolRequest{}
	commitRequest.Params.Name = "create_or_update_file"
	commitRequest.Params.Arguments = map[string]any{
		"owner":   currentOwner,
		"repo":    repoName,
		"path":    "test-file.txt",
		"content": fmt.Sprintf("Created by e2e test %s", t.Name()),
		"message": "Add test file",
		"branch":  "test-branch",
	}

	t.Logf("Creating commit with new file in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, commitRequest)
	require.NoError(t, err, "expected to call 'create_or_update_file' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	textContent, ok = resp.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected content to be of type TextContent")

	var trimmedCommitText struct {
		SHA string `json:"sha"`
	}
	err = json.Unmarshal([]byte(textContent.Text), &trimmedCommitText)
	require.NoError(t, err, "expected to unmarshal text content successfully")
	commitId := trimmedCommitText.SHA

	// Create a pull request
	prRequest := mcp.CallToolRequest{}
	prRequest.Params.Name = "create_pull_request"
	prRequest.Params.Arguments = map[string]any{
		"owner":    currentOwner,
		"repo":     repoName,
		"title":    "Test PR",
		"body":     "This is a test PR",
		"head":     "test-branch",
		"base":     "main",
		"commitId": commitId,
	}

	t.Logf("Creating pull request in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, prRequest)
	require.NoError(t, err, "expected to call 'create_pull_request' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	// Create a review for the pull request, but we can't approve it
	// because the current owner also owns the PR.
	createPendingPullRequestReviewRequest := mcp.CallToolRequest{}
	createPendingPullRequestReviewRequest.Params.Name = "mvp_create_pending_pull_request_review"
	createPendingPullRequestReviewRequest.Params.Arguments = map[string]any{
		"owner":      currentOwner,
		"repo":       repoName,
		"pullNumber": 1,
	}

	t.Logf("Creating pending review for pull request in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, createPendingPullRequestReviewRequest)
	require.NoError(t, err, "expected to call 'mvp_create_pending_pull_request_review' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	textContent, ok = resp.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected content to be of type TextContent")

	var trimmedReviewRequestResponse struct {
		PullRequestReviewID string `json:"pullRequestReviewID"`
	}
	err = json.Unmarshal([]byte(textContent.Text), &trimmedReviewRequestResponse)
	require.NoError(t, err, "expected to unmarshal text content successfully")
	pullRequestReviewId := trimmedReviewRequestResponse.PullRequestReviewID

	// Add a review comment
	addReviewCommentRequest := mcp.CallToolRequest{}
	addReviewCommentRequest.Params.Name = "mvp_add_pull_request_review_comment"
	addReviewCommentRequest.Params.Arguments = map[string]any{
		"path":                "test-file.txt",
		"body":                "Very nice!",
		"line":                1,
		"pullRequestReviewID": pullRequestReviewId,
	}

	t.Logf("Adding review comment to pull request in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, addReviewCommentRequest)
	require.NoError(t, err, "expected to call 'add_pull_request_review_comment' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	// Submit the review
	submitReviewRequest := mcp.CallToolRequest{}
	submitReviewRequest.Params.Name = "mvp_submit_pull_request_review"
	submitReviewRequest.Params.Arguments = map[string]any{
		"event":               "COMMENT", // the only event we can use as the creator of the PR
		"body":                "Needs improvement!",
		"pullRequestReviewID": pullRequestReviewId,
	}

	t.Logf("Submitting review for pull request in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, submitReviewRequest)
	require.NoError(t, err, "expected to call 'mvp_submit_pull_request_review' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	// Finally, get the review and see that it has been created
	getPullRequestsReview := mcp.CallToolRequest{}
	getPullRequestsReview.Params.Name = "get_pull_request_reviews"
	getPullRequestsReview.Params.Arguments = map[string]any{
		"owner":      currentOwner,
		"repo":       repoName,
		"pullNumber": 1,
	}

	t.Logf("Getting reviews for pull request in %s/%s...", currentOwner, repoName)
	resp, err = mcpClient.CallTool(ctx, getPullRequestsReview)
	require.NoError(t, err, "expected to call 'get_pull_request_reviews' tool successfully")
	require.False(t, resp.IsError, fmt.Sprintf("expected result not to be an error: %+v", resp))

	textContent, ok = resp.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected content to be of type TextContent")

	var reviews []struct {
		NodeID string `json:"node_id"`
	}
	err = json.Unmarshal([]byte(textContent.Text), &reviews)
	require.NoError(t, err, "expected to unmarshal text content successfully")

	// Check our review is the only one in the list
	require.Len(t, reviews, 1, "expected to find one review")
	require.Equal(t, pullRequestReviewId, reviews[0].NodeID, "expected to find our review in the list")
}
