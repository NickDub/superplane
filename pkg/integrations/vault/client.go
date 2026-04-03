package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/superplanehq/superplane/pkg/core"
)

const (
	// MaxResponseSize is the maximum allowed response size (2MB)
	MaxResponseSize = 2 * 1024 * 1024

	// Authentication types
	AuthTypeToken   = "token"
	AuthTypeAppRole = "approle"
)

// Client is the Vault HTTP client
type Client struct {
	http      core.HTTPContext
	baseURL   string
	namespace string
	token     string
}

// SecretResponse represents the response from reading a secret
type SecretResponse struct {
	Data     map[string]any `json:"data"`
	Metadata SecretMetadata `json:"metadata"`
}

// SecretMetadata contains metadata about a secret version
type SecretMetadata struct {
	Version     int    `json:"version"`
	CreatedTime string `json:"created_time"`
}

// MetadataResponse represents the response from reading secret metadata
type MetadataResponse struct {
	CurrentVersion int            `json:"current_version"`
	UpdatedTime    string         `json:"updated_time"`
	CreatedTime    string         `json:"created_time"`
	Versions       map[string]any `json:"versions"`
}

// vaultResponse wraps Vault API responses that have a data field
type vaultResponse struct {
	Data json.RawMessage `json:"data"`
}

// appRoleLoginResponse represents the AppRole login response
type appRoleLoginResponse struct {
	Auth appRoleAuth `json:"auth"`
}

type appRoleAuth struct {
	ClientToken string `json:"client_token"`
}

// NewClient creates a new Vault client with the given HTTP context and integration configuration.
// It supports both Token and AppRole authentication methods.
func NewClient(httpCtx core.HTTPContext, integration core.IntegrationContext) (*Client, error) {
	baseURL, err := requiredConfig(integration, "baseUrl")
	if err != nil {
		return nil, err
	}

	baseURL, err = normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}

	namespace := optionalConfig(integration, "namespace")

	authMethod, err := requiredConfig(integration, "authMethod")
	if err != nil {
		return nil, err
	}

	var token string

	switch authMethod {
	case AuthTypeToken:
		token, err = requiredConfig(integration, "token")
		if err != nil {
			return nil, fmt.Errorf("token is required when authMethod is token")
		}
	case AuthTypeAppRole:
		roleID, err := requiredConfig(integration, "roleId")
		if err != nil {
			return nil, fmt.Errorf("roleId is required when authMethod is approle")
		}
		secretID, err := requiredConfig(integration, "secretId")
		if err != nil {
			return nil, fmt.Errorf("secretId is required when authMethod is approle")
		}
		mountPath := optionalConfig(integration, "approleMountPath")
		if mountPath == "" {
			mountPath = "approle"
		}

		token, err = authenticateAppRole(httpCtx, baseURL, namespace, mountPath, roleID, secretID)
		if err != nil {
			return nil, fmt.Errorf("AppRole authentication failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid authMethod %q: must be 'token' or 'approle'", authMethod)
	}

	return &Client{
		http:      httpCtx,
		baseURL:   baseURL,
		namespace: namespace,
		token:     token,
	}, nil
}

// authenticateAppRole performs AppRole login and returns the client token
func authenticateAppRole(httpCtx core.HTTPContext, baseURL, namespace, mountPath, roleID, secretID string) (string, error) {
	loginURL := fmt.Sprintf("%s/v1/auth/%s/login", baseURL, mountPath)

	payload := map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AppRole login request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AppRole login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
	}

	resp, err := httpCtx.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute AppRole login request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := readLimitedBody(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("AppRole login failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	var loginResp appRoleLoginResponse
	if err := json.Unmarshal(responseBody, &loginResp); err != nil {
		return "", fmt.Errorf("failed to parse AppRole login response: %w", err)
	}

	if loginResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole login response did not contain a client token")
	}

	return loginResp.Auth.ClientToken, nil
}

// ReadSecret reads a secret from the KV v2 secrets engine
func (c *Client) ReadSecret(mountPath, secretPath string) (*SecretResponse, error) {
	apiPath := fmt.Sprintf("/v1/%s/data/%s", mountPath, secretPath)

	responseBody, statusCode, err := c.execRequest(http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret not found at path '%s/%s'", mountPath, secretPath)
	}

	if statusCode == http.StatusForbidden {
		return nil, fmt.Errorf("permission denied: cannot read secret at '%s/%s'", mountPath, secretPath)
	}

	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("failed to read secret with status %d: %s", statusCode, string(responseBody))
	}

	var vaultResp vaultResponse
	if err := json.Unmarshal(responseBody, &vaultResp); err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	var secretResp SecretResponse
	if err := json.Unmarshal(vaultResp.Data, &secretResp); err != nil {
		return nil, fmt.Errorf("failed to parse secret data: %w", err)
	}

	return &secretResp, nil
}

// ReadSecretMetadata reads the metadata for a secret from the KV v2 secrets engine
func (c *Client) ReadSecretMetadata(mountPath, secretPath string) (*MetadataResponse, error) {
	apiPath := fmt.Sprintf("/v1/%s/metadata/%s", mountPath, secretPath)

	responseBody, statusCode, err := c.execRequest(http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret not found at path '%s/%s'", mountPath, secretPath)
	}

	if statusCode == http.StatusForbidden {
		return nil, fmt.Errorf("permission denied: cannot read secret at '%s/%s'", mountPath, secretPath)
	}

	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("failed to read secret metadata with status %d: %s", statusCode, string(responseBody))
	}

	var vaultResp vaultResponse
	if err := json.Unmarshal(responseBody, &vaultResp); err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	var metadataResp MetadataResponse
	if err := json.Unmarshal(vaultResp.Data, &metadataResp); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadataResp, nil
}

// TestConnection verifies the client can authenticate with Vault by looking up the current token
func (c *Client) TestConnection() error {
	responseBody, statusCode, err := c.execRequest(http.MethodGet, "/v1/auth/token/lookup-self", nil)
	if err != nil {
		return fmt.Errorf("failed to test connection: %w", err)
	}

	if statusCode == http.StatusForbidden {
		return fmt.Errorf("permission denied: token does not have permission to lookup itself")
	}

	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("connection test failed with status %d: %s", statusCode, string(responseBody))
	}

	return nil
}

// execRequest executes an HTTP request to the Vault API
func (c *Client) execRequest(method, path string, body io.Reader) ([]byte, int, error) {
	apiURL := c.baseURL + path

	req, err := http.NewRequest(method, apiURL, body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return responseBody, resp.StatusCode, nil
}

// readLimitedBody reads the response body with a size limit
func readLimitedBody(body io.Reader) ([]byte, error) {
	limitedReader := io.LimitReader(body, int64(MaxResponseSize)+1)
	responseBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if len(responseBody) > MaxResponseSize {
		return nil, fmt.Errorf("response too large: exceeds maximum size of %d bytes", MaxResponseSize)
	}

	return responseBody, nil
}

// requiredConfig reads a required configuration value
func requiredConfig(ctx core.IntegrationContext, name string) (string, error) {
	value, err := ctx.GetConfig(name)
	if err != nil {
		return "", fmt.Errorf("%s is required", name)
	}

	s := strings.TrimSpace(string(value))
	if s == "" {
		return "", fmt.Errorf("%s is required", name)
	}

	return s, nil
}

// optionalConfig reads an optional configuration value
func optionalConfig(ctx core.IntegrationContext, name string) string {
	value, err := ctx.GetConfig(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(value))
}

// normalizeBaseURL validates and normalizes the base URL
func normalizeBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid baseURL: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid baseURL: must include scheme and host (e.g. https://vault.example.com)")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid baseURL: unsupported scheme %q (expected http or https)", parsed.Scheme)
	}

	// Remove trailing slashes
	return strings.TrimSuffix(baseURL, "/"), nil
}
