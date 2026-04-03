package vault

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/superplanehq/superplane/test/support/contexts"
)

func Test__NewClient(t *testing.T) {
	httpCtx := &contexts.HTTPContext{}

	t.Run("missing baseUrl returns error", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"authMethod": AuthTypeToken,
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "baseUrl is required")
	})

	t.Run("invalid baseUrl without scheme returns error", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "vault.example.com",
			"authMethod": AuthTypeToken,
			"token":      "test-token",
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "must include scheme and host")
	})

	t.Run("invalid baseUrl with unsupported scheme returns error", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "ftp://vault.example.com",
			"authMethod": AuthTypeToken,
			"token":      "test-token",
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "unsupported scheme")
	})

	t.Run("missing authType returns error", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl": "https://vault.example.com",
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "authMethod is required")
	})

	t.Run("invalid authMethod returns error", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": "invalid",
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "invalid authMethod")
	})

	t.Run("token auth requires token", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeToken,
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "token is required")
	})

	t.Run("creates token auth client successfully", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com/",
			"authMethod": AuthTypeToken,
			"token":      "test-token",
		}}

		client, err := NewClient(httpCtx, integrationCtx)
		require.NoError(t, err)
		assert.Equal(t, "https://vault.example.com", client.baseURL)
		assert.Equal(t, "test-token", client.token)
	})

	t.Run("creates token auth client with namespace", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeToken,
			"token":      "test-token",
			"namespace":  "admin/team-a",
		}}

		client, err := NewClient(httpCtx, integrationCtx)
		require.NoError(t, err)
		assert.Equal(t, "admin/team-a", client.namespace)
	})

	t.Run("approle auth requires roleID", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeAppRole,
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "roleId is required")
	})

	t.Run("approle auth requires secretID", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeAppRole,
			"roleId":     "test-role-id",
		}}
		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "secretId is required")
	})

	t.Run("creates approle auth client successfully", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"auth": {
							"client_token": "approle-client-token"
						}
					}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeAppRole,
			"roleId":     "test-role-id",
			"secretId":   "test-secret-id",
		}}

		client, err := NewClient(httpCtx, integrationCtx)
		require.NoError(t, err)
		assert.Equal(t, "approle-client-token", client.token)

		// Verify the AppRole login request
		require.Len(t, httpCtx.Requests, 1)
		req := httpCtx.Requests[0]
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Contains(t, req.URL.String(), "/v1/auth/approle/login")
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	})

	t.Run("creates approle auth client with custom mount path", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"auth": {"client_token": "approle-token"}
					}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":          "https://vault.example.com",
			"authMethod":       AuthTypeAppRole,
			"roleId":           "test-role-id",
			"secretId":         "test-secret-id",
			"approleMountPath": "custom-approle",
		}}

		_, err := NewClient(httpCtx, integrationCtx)
		require.NoError(t, err)

		require.Len(t, httpCtx.Requests, 1)
		assert.Contains(t, httpCtx.Requests[0].URL.String(), "/v1/auth/custom-approle/login")
	})

	t.Run("approle auth with namespace sets header", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"auth": {"client_token": "approle-token"}
					}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeAppRole,
			"roleId":     "test-role-id",
			"secretId":   "test-secret-id",
			"namespace":  "admin/team-a",
		}}

		_, err := NewClient(httpCtx, integrationCtx)
		require.NoError(t, err)

		require.Len(t, httpCtx.Requests, 1)
		assert.Equal(t, "admin/team-a", httpCtx.Requests[0].Header.Get("X-Vault-Namespace"))
	})

	t.Run("approle auth failure returns error", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"errors": ["invalid role_id"]}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{Configuration: map[string]any{
			"baseUrl":    "https://vault.example.com",
			"authMethod": AuthTypeAppRole,
			"roleId":     "invalid-role-id",
			"secretId":   "test-secret-id",
		}}

		_, err := NewClient(httpCtx, integrationCtx)
		require.ErrorContains(t, err, "AppRole authentication failed")
	})
}

func Test__Client__ReadSecret(t *testing.T) {
	t.Run("reads secret successfully", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"data": {
							"data": {"username": "admin", "password": "secret123"},
							"metadata": {"version": 3, "created_time": "2024-01-15T10:30:00Z"}
						}
					}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		secret, err := client.ReadSecret("secret", "myapp/config")
		require.NoError(t, err)
		assert.Equal(t, "admin", secret.Data["username"])
		assert.Equal(t, "secret123", secret.Data["password"])
		assert.Equal(t, 3, secret.Metadata.Version)
		assert.Equal(t, "2024-01-15T10:30:00Z", secret.Metadata.CreatedTime)

		// Verify request
		require.Len(t, httpCtx.Requests, 1)
		req := httpCtx.Requests[0]
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, "https://vault.example.com/v1/secret/data/myapp/config", req.URL.String())
		assert.Equal(t, "test-token", req.Header.Get("X-Vault-Token"))
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	})

	t.Run("includes namespace header when set", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"data": {
							"data": {"key": "value"},
							"metadata": {"version": 1, "created_time": "2024-01-15T10:30:00Z"}
						}
					}`)),
				},
			},
		}

		client := &Client{
			http:      httpCtx,
			baseURL:   "https://vault.example.com",
			token:     "test-token",
			namespace: "admin/team-a",
		}

		_, err := client.ReadSecret("secret", "myapp/config")
		require.NoError(t, err)

		require.Len(t, httpCtx.Requests, 1)
		assert.Equal(t, "admin/team-a", httpCtx.Requests[0].Header.Get("X-Vault-Namespace"))
	})

	t.Run("returns error for 404 not found", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{"errors": []}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecret("secret", "nonexistent/path")
		require.ErrorContains(t, err, "secret not found at path 'secret/nonexistent/path'")
	})

	t.Run("returns error for 403 forbidden", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"errors": ["permission denied"]}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecret("secret", "restricted/path")
		require.ErrorContains(t, err, "permission denied: cannot read secret at 'secret/restricted/path'")
	})

	t.Run("returns error for other status codes", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader(`internal server error`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecret("secret", "myapp/config")
		require.ErrorContains(t, err, "status 500")
	})

	t.Run("returns error for invalid JSON response", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`not-json`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecret("secret", "myapp/config")
		require.ErrorContains(t, err, "failed to parse")
	})

	t.Run("returns error for response too large", func(t *testing.T) {
		largeBody := strings.Repeat("x", MaxResponseSize+1)
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(largeBody)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecret("secret", "myapp/config")
		require.ErrorContains(t, err, "response too large")
	})
}

func Test__Client__ReadSecretMetadata(t *testing.T) {
	t.Run("reads metadata successfully", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"data": {
							"current_version": 5,
							"created_time": "2024-01-01T00:00:00Z",
							"updated_time": "2024-01-15T10:30:00Z",
							"versions": {
								"1": {"created_time": "2024-01-01T00:00:00Z"},
								"5": {"created_time": "2024-01-15T10:30:00Z"}
							}
						}
					}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		metadata, err := client.ReadSecretMetadata("secret", "myapp/config")
		require.NoError(t, err)
		assert.Equal(t, 5, metadata.CurrentVersion)
		assert.Equal(t, "2024-01-01T00:00:00Z", metadata.CreatedTime)
		assert.Equal(t, "2024-01-15T10:30:00Z", metadata.UpdatedTime)
		assert.NotNil(t, metadata.Versions)

		// Verify request
		require.Len(t, httpCtx.Requests, 1)
		req := httpCtx.Requests[0]
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, "https://vault.example.com/v1/secret/metadata/myapp/config", req.URL.String())
	})

	t.Run("returns error for 404 not found", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{"errors": []}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecretMetadata("secret", "nonexistent/path")
		require.ErrorContains(t, err, "secret not found at path 'secret/nonexistent/path'")
	})

	t.Run("returns error for 403 forbidden", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"errors": ["permission denied"]}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		_, err := client.ReadSecretMetadata("secret", "restricted/path")
		require.ErrorContains(t, err, "permission denied: cannot read secret at 'secret/restricted/path'")
	})
}

func Test__Client__TestConnection(t *testing.T) {
	t.Run("succeeds when token lookup works", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"data": {
							"accessor": "token-accessor",
							"policies": ["default"]
						}
					}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		err := client.TestConnection()
		require.NoError(t, err)

		// Verify request
		require.Len(t, httpCtx.Requests, 1)
		req := httpCtx.Requests[0]
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, "https://vault.example.com/v1/auth/token/lookup-self", req.URL.String())
		assert.Equal(t, "test-token", req.Header.Get("X-Vault-Token"))
	})

	t.Run("includes namespace header when set", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data": {}}`)),
				},
			},
		}

		client := &Client{
			http:      httpCtx,
			baseURL:   "https://vault.example.com",
			token:     "test-token",
			namespace: "admin/team-a",
		}

		err := client.TestConnection()
		require.NoError(t, err)

		require.Len(t, httpCtx.Requests, 1)
		assert.Equal(t, "admin/team-a", httpCtx.Requests[0].Header.Get("X-Vault-Namespace"))
	})

	t.Run("returns error for 403 forbidden", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"errors": ["permission denied"]}`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "invalid-token",
		}

		err := client.TestConnection()
		require.ErrorContains(t, err, "permission denied")
	})

	t.Run("returns error for other status codes", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(strings.NewReader(`service unavailable`)),
				},
			},
		}

		client := &Client{
			http:    httpCtx,
			baseURL: "https://vault.example.com",
			token:   "test-token",
		}

		err := client.TestConnection()
		require.ErrorContains(t, err, "status 503")
	})
}

func Test__normalizeBaseURL(t *testing.T) {
	t.Run("removes trailing slash", func(t *testing.T) {
		result, err := normalizeBaseURL("https://vault.example.com/")
		require.NoError(t, err)
		assert.Equal(t, "https://vault.example.com", result)
	})

	t.Run("accepts URL without trailing slash", func(t *testing.T) {
		result, err := normalizeBaseURL("https://vault.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://vault.example.com", result)
	})

	t.Run("accepts http scheme", func(t *testing.T) {
		result, err := normalizeBaseURL("http://vault.internal:8200")
		require.NoError(t, err)
		assert.Equal(t, "http://vault.internal:8200", result)
	})

	t.Run("rejects missing scheme", func(t *testing.T) {
		_, err := normalizeBaseURL("vault.example.com")
		require.ErrorContains(t, err, "must include scheme and host")
	})

	t.Run("rejects unsupported scheme", func(t *testing.T) {
		_, err := normalizeBaseURL("ftp://vault.example.com")
		require.ErrorContains(t, err, "unsupported scheme")
	})
}
